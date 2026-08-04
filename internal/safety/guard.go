// Package safety —— 独立安全兜底层(从 Rails safety_guard.rb 平移,决策不变)。
// 陈竞凯:独立于所有业务逻辑的 safety monitor,任何封禁下发前的最后否决,无旁路。
package safety

import (
	"fmt"
	"net/netip"
)

// Guard 安全兜底层。protectedSet 是绝对保护集(独立数据源)。
type Guard struct {
	protected []netip.Prefix
}

// New 构造。hardcoded 硬编码兜底(环回等)恒保护;extra 来自配置/探测/DB。
func New(extra []string) *Guard {
	g := &Guard{}
	// 硬编码兜底:环回、本机(永远保护)——对应 Ruby 版 load_protected_set 第 1 步
	for _, c := range []string{"127.0.0.0/8", "::1/128", "0.0.0.0/32"} {
		if p, err := netip.ParsePrefix(c); err == nil {
			g.protected = append(g.protected, p)
		}
	}
	g.Add(extra...)
	return g
}

// Add 追加保护条目(网关/DNS/核心业务;来自探测或 DB)
func (g *Guard) Add(targets ...string) {
	for _, t := range targets {
		if p, err := toPrefix(t); err == nil {
			g.protected = append(g.protected, p)
		}
	}
}

// AssertSafe 最终否决判断。命中(或双向覆盖)保护集 → 返回 Veto 错误。
// 对应 Ruby SafetyGuard.assert_safe!;任何下发前必须调用。
func (g *Guard) AssertSafe(target string) error {
	t, err := toPrefix(target)
	if err != nil {
		// 合法性存疑 → 保守否决(fail-safe),与 Ruby 版一致
		return fmt.Errorf("SAFETY VETO: 目标 %s 非法或无法判定(%v),保守否决", target, err)
	}
	for _, p := range g.protected {
		// 双向包含:目标是保护IP、或目标大段覆盖保护IP,都否决
		if p.Overlaps(t) {
			return fmt.Errorf("SAFETY VETO: 目标 %s 命中绝对保护集(%s),封禁被最终否决", target, p)
		}
	}
	return nil
}

// VetoReason 供 UI/预检:会被否决则返回原因,否则空
func (g *Guard) VetoReason(target string) string {
	if err := g.AssertSafe(target); err != nil {
		return err.Error()
	}
	return ""
}

// toPrefix 把 IP 或 CIDR 统一成 Prefix(单 IP 视为 /32 或 /128)
func toPrefix(s string) (netip.Prefix, error) {
	if p, err := netip.ParsePrefix(s); err == nil {
		return p, nil
	}
	addr, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Prefix{}, err
	}
	bits := 32
	if addr.Is6() {
		bits = 128
	}
	return netip.PrefixFrom(addr, bits), nil
}
