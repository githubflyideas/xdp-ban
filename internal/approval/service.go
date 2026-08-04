// Package approval —— 邮件审批生成与管理(六铁律)。
// 关键:链接一次性 token、超期失效、四眼原则。
package approval

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log"
	"time"

	"gorm.io/gorm"

	"github.com/xdpban/xdp-ban/internal/model"
)

// TokenTTL 是邮件审批链接的有效期。短窗口是刻意的:
// 审批链接等价于一次特权操作,泄漏窗口越短越好。
const TokenTTL = 10 * time.Minute

// Service 审批服务
type Service struct {
	db       *gorm.DB
	baseURL  string                            // 邮件中的链接前缀,如 https://xdpban.example.com
	mailSend func(to, subj, body string) error // 可注入,便于测试
}

func NewService(db *gorm.DB, baseURL string) *Service {
	return &Service{
		db:      db,
		baseURL: baseURL,
		mailSend: func(to, subj, body string) error {
			// 占位:真实生产集成 SendGrid/Mailgun 或 SMTP
			log.Printf("[MAIL] To:%s\nSubj:%s\nBody:\n%s\n", to, subj, body)
			return nil
		},
	}
}

// GenTokensAndSend 生成一次性审批令牌并邮件通知 approver。
//
// 四眼原则在这里落地:候选 approver 集合显式排除提交者本人,
// 所以邮件链接天然不可能落到提交者手上。
func (s *Service) GenTokensAndSend(req *model.BanRequest, requesterID *uint) error {
	if req.ApprovalMode != "manual_dual" {
		return nil
	}

	// 查找 admin/approver 作为审批人,排除提交者
	q := s.db.Where("role IN ? AND active = ?", []string{"admin", "approver"}, true)
	if requesterID != nil {
		q = q.Where("id <> ?", *requesterID)
	}
	var approvers []model.User
	if err := q.Limit(2).Find(&approvers).Error; err != nil {
		return fmt.Errorf("查找审批人: %w", err)
	}
	if len(approvers) == 0 {
		// 没有第二个人可审批:记审计,留待人工在界面处理,不阻塞提交
		_ = model.WriteAudit(s.db, requesterID, "system", "BanRequest",
			fmt.Sprint(req.ID), "approval_mail_skipped", "无可用审批人")
		return nil
	}

	approver := approvers[0]

	token := randToken()
	now := time.Now()
	approvalToken := &model.ApprovalToken{
		BanRequestID: req.ID,
		ApproverID:   approver.ID,
		Token:        token,
		ExpiresAt:    now.Add(TokenTTL),
		SentToEmail:  approver.Email,
	}
	if err := s.db.Create(approvalToken).Error; err != nil {
		return fmt.Errorf("创建审批令牌: %w", err)
	}

	requester := "unknown"
	if requesterID != nil {
		requester = fmt.Sprintf("user#%d", *requesterID)
	}

	approveLink := fmt.Sprintf("%s/approve/%s", s.baseURL, token)
	subject := fmt.Sprintf("[xdp-ban] 审批请求:%s", req.Target)
	body := fmt.Sprintf(`您收到一条 xdp-ban 审批请求，请点击下方链接审批（%s 内有效）:

目标: %s
原因: %s
提交者: %s

审批链接:
%s

此链接一次性，用后失效。
`, TokenTTL, req.Target, req.Reason, requester, approveLink)

	if err := s.mailSend(approver.Email, subject, body); err != nil {
		// 邮件失败不回滚令牌:审批人仍可在界面里处理,链接也仍然有效
		log.Printf("发送审批邮件到 %s 失败: %v", approver.Email, err)
		_ = model.WriteAudit(s.db, requesterID, "mail", "ApprovalToken",
			fmt.Sprint(approvalToken.ID), "mail_failed", err.Error())
		return nil
	}

	_ = model.WriteAudit(s.db, requesterID, "mail", "ApprovalToken",
		fmt.Sprint(approvalToken.ID), "mail_sent", approver.Email)
	return nil
}

func randToken() string {
	b := make([]byte, 24)
	rand.Read(b)
	return hex.EncodeToString(b)
}
