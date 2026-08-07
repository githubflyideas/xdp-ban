// exec_loop.go —— 执行层的启动与轮询循环。
//
// 这层原属独立进程 cmd/xdp-agent 的 main.go(通过 HTTP 拉取指令)。
// 合并后不再有 HTTP:runExecutorLoop 直接查 model.Dispatch 表,
// 直接调用 banMaps.Apply,直接写回状态,没有网络往返也没有第二套鉴权。
package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"gorm.io/gorm"

	"github.com/xdpban/xdp-ban/internal/banmap"
	"github.com/xdpban/xdp-ban/internal/model"
)

// BanPayload 指令内容(与 internal/dispatch.BanPayload 的 JSON 契约一致,
// 由 contract_test.go 锁定)。
//
// 两种形态由字段组合区分:
//   - 单点封禁:Target 有值,ScopedTarget 为空 → 写全局表
//   - 范围封禁:ScopedTarget + Prefixes 有值   → 写 target_hosts + src_ban
type BanPayload struct {
	Target  string `json:"target"`
	TTLSecs int64  `json:"ttl_secs"`
	NodeID  string `json:"node_id"`
	ReqID   uint   `json:"req_id"`
	BanID   string `json:"ban_id"`
	Backend string `json:"backend"`
	Reason  string `json:"reason"`

	// 范围封禁专用
	ScopedTarget string   `json:"scoped_target,omitempty"`
	Prefixes     []string `json:"prefixes,omitempty"`
}

// startExecutor 加载嵌入的 eBPF bytecode,attach 到 iface,返回可执行
// 封禁指令的 banMaps 与一个清理函数(defer 调用,负责 detach + 释放 map)。
//
// 失败即 Fatalf:map 缺失、bytecode 为空、attach 失败都是启动期不可恢复
// 的错误 —— 宁可拒绝启动,不要留一个"看着在跑但从不生效"的进程。
func startExecutor(db *gorm.DB, iface string) (*banMaps, func()) {
	if len(xdpFilterBytecode) == 0 {
		log.Fatalf("嵌入的 eBPF bytecode 为空:请先运行 `make bpf` 编译 bpf/xdp_filter.c,再重新构建本程序")
	}
	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(xdpFilterBytecode))
	if err != nil {
		log.Fatalf("load ebpf spec: %v", err)
	}
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		log.Fatalf("create ebpf collection: %v", err)
	}

	// 取出三张 map。缺任何一张都是致命的 —— bytecode 与本程序版本不匹配,
	// 继续跑只会静默不生效。宁可启动失败。
	maps, err := resolveMaps(coll)
	if err != nil {
		coll.Close()
		log.Fatalf("%v", err)
	}
	log.Printf("✓ eBPF map 就绪: %s / %s / %s",
		banmap.MapGlobalBans, banmap.MapTargetHosts, banmap.MapSrcBans)

	ifc, err := net.InterfaceByName(iface)
	if err != nil {
		coll.Close()
		log.Fatalf("查找网卡 %q 失败: %v", iface, err)
	}

	prog := coll.Programs["xdp_filter"]
	if prog == nil {
		coll.Close()
		log.Fatalf("内嵌 bytecode 缺少 xdp_filter 程序 —— bytecode 与本程序版本不匹配")
	}

	lnk, err := link.AttachXDP(link.XDPOptions{
		Program:   prog,
		Interface: ifc.Index,
	})
	if err != nil {
		coll.Close()
		log.Fatalf("attach XDP 程序到 %s 失败: %v ——"+
			"常见原因:权限不足(需 root/CAP_NET_ADMIN)、网卡不支持 XDP、"+
			"或已有另一个 XDP 程序占用该网卡", iface, err)
	}
	log.Printf("✓ XDP 封禁程序已挂载到 %s", iface)

	boot, err := systemBootTime()
	if err != nil {
		lnk.Close()
		coll.Close()
		log.Fatalf("读取系统启动时刻(TTL 换算依赖它): %v", err)
	}
	log.Printf("✓ 系统启动于 %s,TTL 将换算为 ktime 基准", boot.Format(time.RFC3339))

	bm := newBanMaps(
		maps[banmap.MapGlobalBans],
		maps[banmap.MapTargetHosts],
		maps[banmap.MapSrcBans],
		boot,
	)

	closeFn := func() {
		lnk.Close()
		coll.Close()
	}
	return bm, closeFn
}

// runExecutorLoop 周期性扫描待执行的 dispatch 并直接执行(不经 HTTP)。
//
// 与旧的 xdp-agent 轮询循环相比,唯一的差别是数据来源:那里是
// GET /api/v1/dispatch/pending 的 HTTP 响应,这里是同一张表的直接查询。
// 执行、回执、审计的语义完全不变。
func runExecutorLoop(db *gorm.DB, bm *banMaps, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for range ticker.C {
		pollAndExecute(db, bm)
	}
}

func pollAndExecute(db *gorm.DB, bm *banMaps) {
	var dispatches []model.Dispatch
	if err := db.Where("state = ?", "pending").Limit(50).Find(&dispatches).Error; err != nil {
		log.Printf("查询待执行 dispatch 失败: %v", err)
		return
	}
	if len(dispatches) == 0 {
		return
	}
	log.Printf("获取 %d 条待执行指令", len(dispatches))

	for _, d := range dispatches {
		var payload BanPayload
		if err := json.Unmarshal([]byte(d.Payload), &payload); err != nil {
			log.Printf("指令 #%d payload 解析失败: %v", d.ID, err)
			markFailed(db, &d, fmt.Sprintf("parse error: %v", err))
			continue
		}

		log.Printf("执行指令 #%d: %s", d.ID, describePayload(&payload))

		if err := bm.Apply(&payload); err != nil {
			log.Printf("指令 #%d 执行失败: %v", d.ID, err)
			markFailed(db, &d, err.Error())
			continue
		}

		markAcked(db, &d)
		log.Printf("指令 #%d 执行成功", d.ID)
	}
}

func describePayload(p *BanPayload) string {
	if p.ScopedTarget != "" {
		return fmt.Sprintf("范围封禁 %d 条源前缀 → %s (TTL=%ds)",
			len(p.Prefixes), p.ScopedTarget, p.TTLSecs)
	}
	return fmt.Sprintf("全局封禁 %s (TTL=%ds)", p.Target, p.TTLSecs)
}

func markAcked(db *gorm.DB, d *model.Dispatch) {
	now := time.Now()
	if err := db.Model(d).Updates(map[string]any{
		"state":    "acked",
		"acked_at": now,
	}).Error; err != nil {
		log.Printf("指令 #%d 标记 acked 失败: %v", d.ID, err)
		return
	}
	_ = model.WriteAudit(db, nil, "executor", "Dispatch", strconv.FormatUint(uint64(d.ID), 10), "acked", "")
}

func markFailed(db *gorm.DB, d *model.Dispatch, errMsg string) {
	if err := db.Model(d).Updates(map[string]any{
		"state":      "failed",
		"last_error": errMsg,
		"attempts":   d.Attempts + 1,
	}).Error; err != nil {
		log.Printf("指令 #%d 标记 failed 失败: %v", d.ID, err)
		return
	}
	_ = model.WriteAudit(db, nil, "executor", "Dispatch", strconv.FormatUint(uint64(d.ID), 10), "failed", errMsg)
}

// resolveMaps 按名字取出所需的 map,任一缺失即报错。
//
// map 名是字符串查找,编译器抓不到不一致 —— 所以这里一次性全部校验,
// 并把名字集中在 internal/banmap 的常量里。
func resolveMaps(coll *ebpf.Collection) (map[string]*ebpf.Map, error) {
	want := []string{banmap.MapGlobalBans, banmap.MapTargetHosts, banmap.MapSrcBans}
	out := make(map[string]*ebpf.Map, len(want))
	var missing []string
	for _, name := range want {
		m := coll.Maps[name]
		if m == nil {
			missing = append(missing, name)
			continue
		}
		out[name] = m
	}
	if len(missing) > 0 {
		return nil, fmt.Errorf("eBPF bytecode 中缺少 map: %s —— "+
			"bytecode 与本程序版本不匹配,请重新 `make bpf && make build`",
			strings.Join(missing, ", "))
	}
	return out, nil
}

// systemBootTime 从 /proc/uptime 推算系统启动时刻。
//
// 为什么必须是**系统**启动时刻而非进程启动时刻:XDP 侧的
// bpf_ktime_get_ns() 返回系统 uptime。用进程启动时刻算 deadline,
// 在一台已运行数天的机器上会让所有封禁立刻被判成过期。
func systemBootTime() (time.Time, error) {
	b, err := os.ReadFile("/proc/uptime")
	if err != nil {
		return time.Time{}, err
	}
	fields := strings.Fields(string(b))
	if len(fields) == 0 {
		return time.Time{}, fmt.Errorf("/proc/uptime 格式异常: %q", string(b))
	}
	secs, err := strconv.ParseFloat(fields[0], 64)
	if err != nil {
		return time.Time{}, fmt.Errorf("解析 uptime %q: %w", fields[0], err)
	}
	return time.Now().Add(-time.Duration(secs * float64(time.Second))), nil
}
