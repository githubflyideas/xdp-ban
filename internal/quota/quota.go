// Package quota —— 资源配额与准入控制。
//
// 存在理由:按国家/AS 封禁会一次性引入成千上万条前缀。若不设闸门,
// 三类资源会先后被打爆,而且失败方式都不友好:
//
//  1. eBPF LPM_TRIE 满 → bpf_map_update_elem 返回 E2BIG。
//     内核不会崩,但规则静默不生效 —— 界面显示"已封禁"而流量照进,
//     这是最危险的失败模式。
//
//  2. 内核 locked memory(RLIMIT_MEMLOCK)耗尽 → map 创建/扩容失败。
//     LPM_TRIE 的节点是不可换出的内核内存,26 万条约 15–25 MB。
//     多个 map 叠加可能触及系统限制。
//
//  3. 用户态内存 → 前缀库常驻约 80 MB;若再把每条展开的 CIDR 都写进
//     SQLite 的 dispatch 表,单次操作会产生数万行,DB 膨胀且下发变慢。
//
// 对策是"在提交前就拒绝",而不是在下发时失败:
//   - 单条规则前缀数上限(防一次点击吃掉整个表)
//   - 全局表项水位线(留出余量给人工精准封禁,不被批量规则挤占)
//   - 覆盖地址占比上限(防误封半个互联网)
//   - 存储上的规则按"选择器 + 展开后前缀数"记账,不逐条落库
package quota

import (
	"fmt"
	"net/netip"
	"sync"
)

// 默认限额。与 bpf/xdp_filter.c 的 MAX_SRC_BANS 保持一致关系:
// 全局水位线必须显著小于 map 容量,给运行时的精准封禁留空间。
const (
	// MapCapacity 必须与 xdp_filter.c 的 MAX_SRC_BANS 相同。
	// 不一致会导致用户态以为还有余量而内核已满。
	MapCapacity = 262144

	// GlobalHighWater 全局使用上限 = 容量的 80%。
	// 留 20% 是刻意的:攻击进行中时运维需要能立刻加一条精准封禁,
	// 不能因为之前批量导入了几个国家就无法操作。
	GlobalHighWater = MapCapacity * 80 / 100

	// PerRuleMaxPrefixes 单条规则展开后的前缀数上限。
	// 32768 大致相当于一个中型国家或大型 AS;超过这个量级
	// 应当拆分或改用上游清洗,而不是塞进单机 XDP。
	PerRuleMaxPrefixes = 32768

	// MaxAddressShare 单条规则允许覆盖的 IPv4 空间占比上限(百万分之)。
	// 250000/1e6 = 25%。超过 25% 基本等于"封掉小半个互联网",
	// 几乎总是误操作,必须显式确认才能越过。
	MaxAddressSharePPM = 250000
)

// TotalIPv4 可用于占比计算
const TotalIPv4 = uint64(1) << 32

// Usage 当前资源占用
type Usage struct {
	Prefixes  int // 已占用的 LPM 表项数
	Rules     int // 规则条数(与前缀数不是 1:1)
	Targets   int // 受保护目标主机数
	Capacity  int
	HighWater int
}

// Free 剩余可用表项(相对水位线,不是相对物理容量)
func (u Usage) Free() int {
	free := u.HighWater - u.Prefixes
	if free < 0 {
		return 0
	}
	return free
}

// UtilizationPPM 水位使用率(百万分之),便于界面画进度条
func (u Usage) UtilizationPPM() int {
	if u.HighWater == 0 {
		return 0
	}
	return int(uint64(u.Prefixes) * 1000000 / uint64(u.HighWater))
}

// Tracker 记账器。
//
// 它记的是"承诺量"而非"实际写入量":规则一旦被批准就先占额度,
// 避免多人同时提交时各自看到充足余量、实际叠加起来超限。
type Tracker struct {
	mu       sync.RWMutex
	prefixes int
	rules    int
	targets  int
}

func NewTracker() *Tracker { return &Tracker{} }

func (t *Tracker) Usage() Usage {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return Usage{
		Prefixes:  t.prefixes,
		Rules:     t.rules,
		Targets:   t.targets,
		Capacity:  MapCapacity,
		HighWater: GlobalHighWater,
	}
}

// Reserve 预占额度。成功返回 nil,失败返回可直接展示给用户的错误。
func (t *Tracker) Reserve(prefixCount int) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.prefixes+prefixCount > GlobalHighWater {
		return &QuotaError{
			Kind:      KindGlobalFull,
			Requested: prefixCount,
			Available: GlobalHighWater - t.prefixes,
		}
	}
	t.prefixes += prefixCount
	t.rules++
	return nil
}

// Release 释放额度(规则被撤销/过期清理后调用)
func (t *Tracker) Release(prefixCount int) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.prefixes -= prefixCount
	if t.prefixes < 0 {
		t.prefixes = 0
	}
	t.rules--
	if t.rules < 0 {
		t.rules = 0
	}
}

// SetBaseline 从数据库恢复已有占用(启动时调用)
func (t *Tracker) SetBaseline(prefixes, rules, targets int) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.prefixes, t.rules, t.targets = prefixes, rules, targets
}

// ---- 准入检查 ----

// Decision 准入结果
type Decision struct {
	Allowed        bool
	RequiresOverride bool   // 需要管理员显式勾选"我确认"才能越过
	Reason         string   // 给用户看的说明
	PrefixCount    int
	AddressCount   uint64
	AddressSharePPM int
}

// Check 在提交前评估一条按国家/AS 的封禁规则。
//
// 三档结论:
//   - Allowed=true, RequiresOverride=false  → 直接放行
//   - Allowed=true, RequiresOverride=true   → 影响面过大,需二次确认
//   - Allowed=false                          → 硬性拒绝,任何确认都不放行
func Check(t *Tracker, cidrs []netip.Prefix) Decision {
	d := Decision{PrefixCount: len(cidrs)}
	for _, c := range cidrs {
		d.AddressCount += uint64(1) << (32 - c.Bits())
	}
	d.AddressSharePPM = int(d.AddressCount * 1000000 / TotalIPv4)

	if len(cidrs) == 0 {
		d.Reason = "该选择未匹配到任何 IP 前缀(前缀库可能未导入或选择条件过窄)"
		return d
	}

	// 硬限制 1:单条规则前缀数
	if len(cidrs) > PerRuleMaxPrefixes {
		d.Reason = fmt.Sprintf(
			"该选择展开为 %d 条前缀,超过单条规则上限 %d。"+
				"单机 XDP 不适合承载这个量级,建议缩小范围(按 AS 而非整个国家)"+
				"或在上游做清洗。",
			len(cidrs), PerRuleMaxPrefixes)
		return d
	}

	// 硬限制 2:全局水位
	u := t.Usage()
	if len(cidrs) > u.Free() {
		d.Reason = fmt.Sprintf(
			"需要 %d 条表项,当前仅剩 %d 条(水位线 %d / 容量 %d)。"+
				"请先清理过期规则,或调高 MAX_SRC_BANS 后重新编译 eBPF。",
			len(cidrs), u.Free(), u.HighWater, u.Capacity)
		return d
	}

	d.Allowed = true

	// 软限制:覆盖占比过大 → 需二次确认
	if d.AddressSharePPM > MaxAddressSharePPM {
		d.RequiresOverride = true
		d.Reason = fmt.Sprintf(
			"该选择覆盖 %.1f%% 的 IPv4 地址空间(%d 条前缀)。"+
				"范围异常大,请确认这是有意为之。",
			float64(d.AddressSharePPM)/10000, len(cidrs))
		return d
	}

	d.Reason = fmt.Sprintf("将占用 %d 条表项(剩余 %d),覆盖 %.4f%% 的 IPv4 空间。",
		len(cidrs), u.Free()-len(cidrs), float64(d.AddressSharePPM)/10000)
	return d
}

// ---- 错误类型 ----

type QuotaKind string

const (
	KindGlobalFull QuotaKind = "global_full"
	KindPerRule    QuotaKind = "per_rule"
)

type QuotaError struct {
	Kind      QuotaKind
	Requested int
	Available int
}

func (e *QuotaError) Error() string {
	return fmt.Sprintf("配额不足(%s):需要 %d 条表项,可用 %d 条",
		e.Kind, e.Requested, e.Available)
}
