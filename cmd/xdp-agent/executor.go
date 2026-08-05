// executor.go —— dispatch 指令 → eBPF map 写入。
//
// 与 main.go 分离的理由:这层要能在没有内核、没有 root 的环境里被测试。
// 它只依赖一个抽象的 map 写入接口,而不是 *ebpf.Map。
//
// 这个文件的存在本身是一次事故的产物:此前 xdp_filter.c 从单级 ban_list
// 重构成两级 target_hosts + src_ban 时,agent 的写入逻辑没有同步 ——
// agent 仍在找已不存在的 map 名,启动即 Fatalf,而单测只覆盖了纯函数,
// 完全没有触及 map 加载与写入。现在把这条路径抽象出来并补上测试。
package main

import (
	"fmt"
	"log"
	"net/netip"
	"time"

	"github.com/xdpban/xdp-ban/internal/banmap"
)

// mapWriter 是 eBPF map 的最小写入抽象。
// *ebpf.Map 天然满足;测试用内存实现替换。
type mapWriter interface {
	Put(key, value any) error
	Delete(key any) error
}

// banMaps 聚合执行封禁所需的三张 map。
type banMaps struct {
	globalBans  mapWriter // src_ban_global: 源前缀 → ban_value
	targetHosts mapWriter // target_hosts:   dst_ip  → target_id
	srcBans     mapWriter // src_ban:        (target_id, 源前缀) → ban_value

	// bootTime 用于把 TTL 换算成 bpf_ktime_get_ns 基准。
	// 必须在进程启动时读一次系统启动时刻,不能用进程启动时刻 ——
	// XDP 侧的 ktime 是系统 uptime,不是进程 uptime。
	bootTime time.Time

	// nextTargetID 分配 target_id。0 保留不用,便于把"未分配"与 id=0 区分开。
	nextTargetID uint32
	targetIDs    map[string]uint32 // dst_ip 字符串 → 已分配的 target_id
}

func newBanMaps(global, targets, src mapWriter, bootTime time.Time) *banMaps {
	return &banMaps{
		globalBans:  global,
		targetHosts: targets,
		srcBans:     src,
		bootTime:    bootTime,
		nextTargetID: 1,
		targetIDs:   make(map[string]uint32),
	}
}

// ScopedPayload 是范围封禁的下发载荷。
// 控制面在 dispatch.Payload 里给出目标主机与展开后的源前缀列表。
type ScopedPayload struct {
	TargetIP string   `json:"target_ip"`
	Prefixes []string `json:"prefixes"`
}

// Apply 执行一条 dispatch 指令。
//
// 两种形态:
//   - 单点封禁:payload.Target 是 IP 或 CIDR,写全局表(封该源,不限目标)
//   - 范围封禁:payload.ScopedTarget 非空,写 target_hosts + src_ban
//
// 幂等:map Put 是覆盖语义,重复下发同一条指令结果相同。
func (m *banMaps) Apply(p *BanPayload) error {
	deadline := banmap.KtimeDeadline(m.bootTime, time.Now(), p.TTLSecs)
	val := banmap.EncodeValue(banmap.Value{
		ExpiresAt: deadline,
		RuleID:    uint32(p.ReqID),
	})

	// 范围封禁:目标主机 + 一批源前缀
	if p.ScopedTarget != "" {
		return m.applyScoped(p, val)
	}

	// 单点封禁:走全局表
	prefix, err := banmap.ParseIPv4Prefix(p.Target)
	if err != nil {
		return err
	}
	key, err := banmap.EncodeGlobalKey(prefix)
	if err != nil {
		return err
	}
	if err := m.globalBans.Put(key, val); err != nil {
		return fmt.Errorf("写 %s (%s): %w", banmap.MapGlobalBans, prefix, err)
	}
	log.Printf("  ✓ 全局封禁 %s (TTL=%ds)", prefix, p.TTLSecs)
	return nil
}

// applyScoped 写定向封禁。
//
// 顺序很关键:**先写 target_hosts,再写 src_ban**。
// 反过来的话,在两次写之间到达的包会因为 target_hosts 里还没有该目标
// 而走 CNT_NOT_TARGET 快路径放行 —— 规则已在 src_ban 里却不生效。
// 虽然窗口只有微秒级,但攻击流量下微秒也是成千上万个包。
func (m *banMaps) applyScoped(p *BanPayload, val []byte) error {
	targetAddr, err := netip.ParseAddr(p.ScopedTarget)
	if err != nil {
		return fmt.Errorf("非法目标主机 %q: %w", p.ScopedTarget, err)
	}
	if !targetAddr.Is4() {
		return fmt.Errorf("目标仅支持 IPv4: %q", p.ScopedTarget)
	}

	tid, err := m.ensureTarget(targetAddr)
	if err != nil {
		return err
	}

	// 逐条写源前缀。部分失败时不回滚已写入的部分:
	// 少封一部分比全不封安全,且 dispatch 会被标记 failed 让运维知道。
	var written int
	for _, s := range p.Prefixes {
		prefix, err := banmap.ParseIPv4Prefix(s)
		if err != nil {
			return fmt.Errorf("第 %d 条前缀: %w(已写入 %d 条)", written+1, err, written)
		}
		key, err := banmap.EncodeSrcKey(tid, prefix)
		if err != nil {
			return fmt.Errorf("第 %d 条前缀: %w(已写入 %d 条)", written+1, err, written)
		}
		if err := m.srcBans.Put(key, val); err != nil {
			// map 满会在这里返回 E2BIG。明确报错,绝不静默丢规则。
			return fmt.Errorf("写 %s (%s → %s): %w(已写入 %d 条)",
				banmap.MapSrcBans, prefix, targetAddr, err, written)
		}
		written++
	}

	log.Printf("  ✓ 定向封禁 %d 条源前缀 → %s (target_id=%d, TTL=%ds)",
		written, targetAddr, tid, p.TTLSecs)
	return nil
}

// ensureTarget 保证目标主机已在 target_hosts 中,返回其 target_id。
// 同一目标重复调用返回同一 id —— 否则同一主机的多条规则会分散到
// 不同 target_id 下,只有最后一个 id 对应的规则生效。
func (m *banMaps) ensureTarget(addr netip.Addr) (uint32, error) {
	s := addr.String()
	if tid, ok := m.targetIDs[s]; ok {
		return tid, nil
	}

	tid := m.nextTargetID
	key, err := banmap.EncodeTargetKey(addr)
	if err != nil {
		return 0, err
	}
	if err := m.targetHosts.Put(key, banmap.EncodeTargetID(tid)); err != nil {
		return 0, fmt.Errorf("写 %s (%s): %w", banmap.MapTargetHosts, addr, err)
	}

	m.targetIDs[s] = tid
	m.nextTargetID++
	return tid, nil
}
