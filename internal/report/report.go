// Package report —— 合规报告导出(CSV / HTML-to-print)。
//
// 存在理由:等保测评、ISO 27001、SOC 2 都要求"特权操作有审批、可追溯"的
// **书面证据**。审计日志躺在数据库里不算证据 —— 测评时要能导出一份
// 说清"谁在何时封了什么、谁批的、为什么"的文件。
//
// 这是这个项目最接近"客户愿意付钱"的功能:抗 D 能力客户可以自研,
// 合规证据他们没法自己变出来。
//
// 格式选择:
//   - CSV  —— 给测评人员做数据核对与二次统计,Excel 直接打开
//   - HTML —— 带页眉页脚与统计摘要,浏览器打印即得 PDF。
//     不引入 PDF 库是刻意的:纯 Go 的 PDF 生成器都要处理中文字体嵌入,
//     要么二进制暴涨几 MB(嵌字体),要么在没装字体的机器上出方块。
//     浏览器打印用系统字体,中文永不出错,且用户可自选纸张与页边距。
package report

import (
	"encoding/csv"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"

	"gorm.io/gorm"

	"github.com/xdpban/xdp-ban/internal/model"
)

// Filter 报告的时间与内容范围
type Filter struct {
	From time.Time
	To   time.Time
	// IncludeSampling 是否包含采样率变更等系统配置操作。
	// 测评通常只关心封禁类特权操作,默认不含,避免噪声淹没重点。
	IncludeSampling bool
}

// Row 报告中的一行:一次完整的封禁生命周期。
//
// 刻意做成"以封禁为主体"而不是"以审计事件为主体":
// 测评人员问的是"这条封禁是谁批的",不是"11:03 发生了什么事件"。
// 后者是原始日志,前者才是证据。
type Row struct {
	Kind        string // ban | scoped_ban
	ID          uint
	Target      string
	Scope       string // 源范围(范围封禁才有)
	Reason      string
	State       string
	Requester   string
	Approver    string
	ApprovalWay string // 界面审批 / 邮件链接
	OverrideAck bool   // 是否越过了大范围警告
	RequestedAt time.Time
	ApprovedAt  *time.Time
	ExpiresAt   *time.Time
	TTL         string
	PrefixCount int
}

// Summary 报告首页的统计摘要。测评人员先看这个。
type Summary struct {
	From, To          time.Time
	GeneratedAt       time.Time
	GeneratedBy       string
	TotalBans         int
	Approved          int
	Rejected          int
	SafetyBlocked     int // 被保护集否决的次数 —— 这是"有防误封机制"的证据
	SelfApprovalDenied int // 四眼原则拦截次数
	OverrideCount     int // 大范围封禁的显式确认次数
	DistinctApprovers int
	DistinctTargets   int
}

// Build 汇总指定区间的封禁记录。
func Build(db *gorm.DB, f Filter, generatedBy string) (*Summary, []Row, error) {
	users, err := loadUsers(db)
	if err != nil {
		return nil, nil, err
	}

	var rows []Row

	// 普通封禁请求
	var reqs []model.BanRequest
	if err := db.Where("created_at >= ? AND created_at <= ?", f.From, f.To).
		Order("created_at asc").Find(&reqs).Error; err != nil {
		return nil, nil, fmt.Errorf("查询封禁请求: %w", err)
	}
	for i := range reqs {
		rows = append(rows, banRequestRow(&reqs[i], users))
	}

	// 范围封禁
	var scoped []model.ScopedBan
	if err := db.Where("created_at >= ? AND created_at <= ?", f.From, f.To).
		Order("created_at asc").Find(&scoped).Error; err != nil {
		return nil, nil, fmt.Errorf("查询范围封禁: %w", err)
	}
	for i := range scoped {
		rows = append(rows, scopedBanRow(&scoped[i], users))
	}

	sum := summarize(db, f, rows, generatedBy)
	return sum, rows, nil
}

func banRequestRow(r *model.BanRequest, users map[uint]string) Row {
	row := Row{
		Kind: "ban", ID: r.ID, Target: r.Target, Reason: r.Reason,
		State: r.State, RequestedAt: r.CreatedAt,
		Requester: userName(users, r.RequestedByID),
		Approver:  userName(users, r.ApprovedByID),
		ExpiresAt: r.ExpiresAt,
		TTL:       formatTTL(r.TTLSeconds),
	}
	row.ApprovalWay = approvalWay(r.ApprovedByPolicy)
	if r.EffectiveAt != nil {
		row.ApprovedAt = r.EffectiveAt
	}
	return row
}

func scopedBanRow(s *model.ScopedBan, users map[uint]string) Row {
	return Row{
		Kind: "scoped_ban", ID: s.ID, Target: s.TargetIP,
		Scope: scopeLabel(s), Reason: s.Reason, State: s.State,
		RequestedAt: s.CreatedAt,
		Requester:   userName(users, s.RequestedByID),
		Approver:    userName(users, s.ApprovedByID),
		ApprovalWay: "界面审批",
		OverrideAck: s.OverrideAck,
		ApprovedAt:  s.EffectiveAt,
		ExpiresAt:   s.ExpiresAt,
		TTL:         formatTTL(s.TTLSeconds),
		PrefixCount: s.PrefixCount,
	}
}

func summarize(db *gorm.DB, f Filter, rows []Row, by string) *Summary {
	s := &Summary{
		From: f.From, To: f.To,
		GeneratedAt: time.Now(), GeneratedBy: by,
		TotalBans: len(rows),
	}
	approvers := map[string]bool{}
	targets := map[string]bool{}
	for _, r := range rows {
		switch r.State {
		case "active", "expired", "revoked":
			s.Approved++
		case "rejected":
			s.Rejected++
		case "safety_blocked":
			s.SafetyBlocked++
		}
		if r.OverrideAck {
			s.OverrideCount++
		}
		if r.Approver != "" && r.Approver != "-" {
			approvers[r.Approver] = true
		}
		targets[r.Target] = true
	}
	s.DistinctApprovers = len(approvers)
	s.DistinctTargets = len(targets)

	// 四眼原则的拦截次数来自审计日志。
	// 这个数字是"机制真的在跑"的证据 —— 比在文档里声称有机制有力得多。
	var denied int64
	db.Model(&model.AuditLog{}).
		Where("occurred_at >= ? AND occurred_at <= ? AND event = ?",
			f.From, f.To, "self_approval_denied").
		Count(&denied)
	s.SelfApprovalDenied = int(denied)

	return s
}

// ---- CSV ----

// WriteCSV 输出给测评人员做数据核对的表格。
// 带 UTF-8 BOM:不加的话 Excel(尤其中文 Windows)会把中文显示成乱码,
// 这是实际交付时最常见的投诉。
func WriteCSV(w io.Writer, sum *Summary, rows []Row) error {
	if _, err := w.Write([]byte{0xEF, 0xBB, 0xBF}); err != nil {
		return err
	}

	cw := csv.NewWriter(w)
	defer cw.Flush()

	// 报告头:导出人与区间必须在文件里,否则脱离系统就无法自证
	meta := [][]string{
		{"xdp-ban 封禁操作合规报告"},
		{"统计区间", sum.From.Format("2006-01-02 15:04:05") + " ~ " + sum.To.Format("2006-01-02 15:04:05")},
		{"导出时间", sum.GeneratedAt.Format("2006-01-02 15:04:05")},
		{"导出人", sum.GeneratedBy},
		{"封禁总数", strconv.Itoa(sum.TotalBans)},
		{"已批准", strconv.Itoa(sum.Approved)},
		{"已驳回", strconv.Itoa(sum.Rejected)},
		{"被保护集否决", strconv.Itoa(sum.SafetyBlocked)},
		{"大范围显式确认", strconv.Itoa(sum.OverrideCount)},
		{"参与审批人数", strconv.Itoa(sum.DistinctApprovers)},
		{},
	}
	for _, m := range meta {
		if err := cw.Write(m); err != nil {
			return err
		}
	}

	header := []string{
		"类型", "编号", "目标地址", "源范围", "原因", "状态",
		"提交人", "审批人", "审批方式", "大范围确认",
		"提交时间", "生效时间", "到期时间", "封禁时长", "前缀数",
	}
	if err := cw.Write(header); err != nil {
		return err
	}

	for _, r := range rows {
		rec := []string{
			kindLabel(r.Kind), strconv.FormatUint(uint64(r.ID), 10),
			r.Target, r.Scope, r.Reason, stateLabel(r.State),
			dash(r.Requester), dash(r.Approver), dash(r.ApprovalWay),
			boolLabel(r.OverrideAck),
			r.RequestedAt.Format("2006-01-02 15:04:05"),
			timePtr(r.ApprovedAt), timePtr(r.ExpiresAt),
			r.TTL, prefixLabel(r.PrefixCount),
		}
		if err := cw.Write(rec); err != nil {
			return err
		}
	}
	return cw.Error()
}

// ---- 辅助 ----

func loadUsers(db *gorm.DB) (map[uint]string, error) {
	var us []model.User
	if err := db.Find(&us).Error; err != nil {
		return nil, fmt.Errorf("查询用户: %w", err)
	}
	m := make(map[uint]string, len(us))
	for _, u := range us {
		m[u.ID] = u.Username
	}
	return m, nil
}

func userName(m map[uint]string, id *uint) string {
	if id == nil {
		return ""
	}
	if n, ok := m[*id]; ok {
		return n
	}
	return "user#" + strconv.FormatUint(uint64(*id), 10)
}

func approvalWay(policy string) string {
	switch policy {
	case "email_link":
		return "邮件链接"
	case "":
		return ""
	default:
		return policy
	}
}

func scopeLabel(s *model.ScopedBan) string {
	var parts []string
	if s.Country != "" {
		parts = append(parts, s.Country)
	}
	if s.ASN != 0 {
		parts = append(parts, "AS"+strconv.FormatUint(uint64(s.ASN), 10))
	}
	return strings.Join(parts, " + ")
}

func formatTTL(secs *int64) string {
	if secs == nil || *secs == 0 {
		return "永久"
	}
	d := time.Duration(*secs) * time.Second
	switch {
	case d >= 24*time.Hour:
		return fmt.Sprintf("%.0f 天", d.Hours()/24)
	case d >= time.Hour:
		return fmt.Sprintf("%.0f 小时", d.Hours())
	default:
		return fmt.Sprintf("%.0f 分钟", d.Minutes())
	}
}

func kindLabel(k string) string {
	if k == "scoped_ban" {
		return "范围封禁"
	}
	return "单点封禁"
}

func stateLabel(s string) string {
	switch s {
	case "pending":
		return "待审批"
	case "active":
		return "生效中"
	case "rejected":
		return "已驳回"
	case "expired":
		return "已过期"
	case "revoked":
		return "已撤销"
	case "safety_blocked":
		return "保护集否决"
	default:
		return s
	}
}

func boolLabel(b bool) string {
	if b {
		return "是"
	}
	return "否"
}

func dash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

func timePtr(t *time.Time) string {
	if t == nil {
		return "-"
	}
	return t.Format("2006-01-02 15:04:05")
}

func prefixLabel(n int) string {
	if n == 0 {
		return "-"
	}
	return strconv.Itoa(n)
}
