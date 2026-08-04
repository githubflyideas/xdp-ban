// Package policy —— 权限矩阵(从 Rails app/policies/permission.rb 一比一平移)。
// 决策不变:集中式能力矩阵,单一事实源;后端强制,前端显隐只是体验(小测铁律)。
package policy

// Capability 能力标识
type Capability string

const (
	DashboardView       Capability = "dashboard_view"
	BanRequestCreate    Capability = "ban_request_create"
	BanRequestView      Capability = "ban_request_view"
	BanRequestApprove   Capability = "ban_request_approve"
	BanRequestReject    Capability = "ban_request_reject"
	UnbanExecute        Capability = "unban_execute"
	AllowlistManage     Capability = "allowlist_manage"
	SourcePolicyManage  Capability = "source_policy_manage"
	AuditView           Capability = "audit_view"
	UserManage          Capability = "user_manage"
	SystemConfig        Capability = "system_config"
)

// Roles 角色(FortiMail 风格,高→低),与 Rails 版一致
var Roles = []string{"admin", "approver", "operator", "viewer"}

// matrix 角色→能力。就是"不同权限不同界面"的唯一依据(与 Rails MATRIX 逐条对齐)。
var matrix = map[string][]Capability{
	"admin": {
		DashboardView, BanRequestCreate, BanRequestView, BanRequestApprove,
		BanRequestReject, UnbanExecute, AllowlistManage, SourcePolicyManage,
		AuditView, UserManage, SystemConfig,
	},
	"approver": {
		DashboardView, BanRequestView, BanRequestApprove, BanRequestReject,
		UnbanExecute, AllowlistManage, AuditView,
	},
	"operator": {
		DashboardView, BanRequestCreate, BanRequestView, AuditView,
	},
	"viewer": {
		DashboardView, BanRequestView, AuditView,
	},
}

// Allow 后端强制的唯一入口(对应 Rails Permission.allow?)
func Allow(role string, cap Capability) bool {
	caps, ok := matrix[role]
	if !ok {
		return false
	}
	for _, c := range caps {
		if c == cap {
			return true
		}
	}
	return false
}

// NavSection 左导航项
type NavSection struct {
	Key   string
	Label string
	Cap   Capability
}

// NavSections 该角色能看到的功能区。
// 只列出已实现路由的区块——导航项与真实页面一一对应,不给死链。
func NavSections(role string) []NavSection {
	all := []NavSection{
		{"dashboard", "Dashboard", DashboardView},
		{"bans", "封禁请求", BanRequestView},
		{"scoped", "范围封禁", BanRequestView},
		{"sampling", "采样配置", SystemConfig},
		{"prefixdb", "IP 库管理", SystemConfig},
		{"audit", "审计日志", AuditView},
		{"report", "合规报告", AuditView},
		{"users", "用户管理", UserManage},
	}
	var out []NavSection
	for _, s := range all {
		if Allow(role, s.Cap) {
			out = append(out, s)
		}
	}
	return out
}
