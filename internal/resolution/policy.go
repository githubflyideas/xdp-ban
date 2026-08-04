// Package resolution —— 裁决规则(从 Rails resolution_policy.rb 平移,决策不变)。
// 冰河/Lisp 视角:优先级/覆盖是声明式数据(RULES 表),改优先级=改数据不改代码。
package resolution

// Effect 裁决效果
type Effect string

const (
	Pass Effect = "pass"
	Drop Effect = "drop"
)

// Rule 一条裁决规则
type Rule struct {
	Source     string
	Precedence int // 越小优先级越高
	Effect     Effect
	Note       string
}

// Rules 声明式裁决表 —— "谁压过谁"的唯一事实源(与 Ruby RULES 逐条对齐)。
var Rules = []Rule{
	{"__safety__", 0, Pass, "绝对保护集,永不封(SafetyGuard 独立强制)"},
	{"allowlist", 10, Pass, "白名单免封,压过所有黑名单"},
	{"blacklist_manual", 20, Drop, "人工封禁"},
	{"blacklist_blackhole", 30, Drop, "BGP/blackhole 黑洞"},
	{"blacklist_intel", 40, Drop, "威胁情报(将来)"},
}

// Resolution 裁决结果
type Resolution struct {
	Effect       Effect
	DecidedBy    string
	Contributing []string
	Reason       string
}

// Resolve 核心裁决(对应 Ruby ResolutionPolicy.resolve)。
// hitSources: 该 IP 命中的来源;safetyVeto: 是否命中保护集。
func Resolve(hitSources []string, safetyVeto bool) Resolution {
	// 安全兜底最高:命中即无条件 pass
	if safetyVeto {
		return Resolution{Pass, "__safety__", hitSources, "命中绝对保护集,安全兜底强制放行"}
	}
	// 按 precedence 从高到低,第一个命中的来源做主
	best := -1
	var winner *Rule
	for i := range Rules {
		r := &Rules[i]
		if r.Source == "__safety__" {
			continue
		}
		if contains(hitSources, r.Source) {
			if winner == nil || r.Precedence < best {
				best = r.Precedence
				winner = r
			}
		}
	}
	if winner == nil {
		return Resolution{Pass, "", nil, "无任何来源命中,默认放行"}
	}
	return Resolution{winner.Effect, winner.Source, hitSources, winner.Note}
}

// Explain 诚实反馈(对应 Ruby explain):操作后解释该 IP 真实命运。
func Explain(action string, r Resolution) string {
	switch {
	case action == "ban" && r.Effect == Drop:
		return "封禁已生效,当前该 IP 被丢弃(裁决来源:" + r.DecidedBy + ")"
	case action == "ban" && r.Effect == Pass:
		return "⚠️ 封禁已记录,但当前【未拦截】—— " + r.DecidedBy + " 优先级更高(" + r.Reason + ")。要真拦截需先处理 " + r.DecidedBy
	case action == "unban" && r.Effect == Pass:
		return "解封成功,当前该 IP 已放行"
	case action == "unban" && r.Effect == Drop:
		return "⚠️ 解封成功,但该 IP 当前【仍被丢弃】—— 仍被 " + r.DecidedBy + " 拦着(" + r.Reason + ")。需一并处理 " + r.DecidedBy
	default:
		return "操作已执行,当前有效状态:" + string(r.Effect)
	}
}

func contains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}
