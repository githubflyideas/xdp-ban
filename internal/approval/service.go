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

// Service 审批服务
type Service struct {
	db       *gorm.DB
	baseURL  string // 邮件中的链接前缀,如 https://xdpban.example.com
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

// GenTokensAndSend 审批通过后调用:生成 token 并发邮件通知 approver。
// 四眼原则:不能让 requester 来批。自动选下一个 admin/approver。
func (s *Service) GenTokensAndSend(req *model.BanRequest, requesterID *uint) error {
	// 检查是否需要邮件审批(可从配置),这里默认 manual_dual 的第二阶段要邮件
	if req.ApprovalMode != "manual_dual" {
		return nil
	}

	// 查找一个 admin 或 approver 来批(且不是 requester)
	var approvers []model.User
	s.db.Where("role IN (?) AND active = ? AND id != ?", []string{"admin", "approver"}, true, requesterID).
		Limit(2).Find(&approvers)

	if len(approvers) == 0 {
		// 没有其他 approver,跳过邮件阶段(可改成返回错误)
		return nil
	}

	// 发给第一个 approver
	approver := approvers[0]

	// 生成一次性 token(10 分钟有效)
	token := randToken()
	now := time.Now()
	expiresAt := now.Add(10 * time.Minute)

	approvalToken := &model.ApprovalToken{
		BanRequestID: req.ID,
		ApproverID:   approver.ID,
		Token:        token,
		ExpiresAt:    expiresAt,
		SentToEmail:  approver.Email,
	}
	if err := s.db.Create(approvalToken).Error; err != nil {
		return err
	}

	// 记录审计
	model.WriteAudit(s.db, req.RequestedByID, "approver", "ApprovalToken", fmt.Sprint(approvalToken.ID), "sent", "")

	// 拼邮件链接 + 发送
	approveLink := fmt.Sprintf("%s/approve/%s", s.baseURL, token)
	subject := fmt.Sprintf("[xdp-ban] 审批请求:%s", req.Target)
	body := fmt.Sprintf(`您收到一条 xdp-ban 审批请求，请点击下方链接审批（10 分钟内有效）:

目标: %s
原因: %s
提交者: (requester ID %d)

批准链接:
%s

此链接一次性，用后失效。
`, req.Target, req.Reason, *req.RequestedByID, approveLink)

	if err := s.mailSend(approver.Email, subject, body); err != nil {
		log.Printf("send approval mail to %s: %v", approver.Email, err)
		// 不中断流程,日志记录即可
	}

	model.WriteAudit(s.db, req.RequestedByID, "mail", "ApprovalToken", fmt.Sprint(approvalToken.ID), "mail_sent", approver.Email)
	return nil
}

func randToken() string {
	b := make([]byte, 24)
	rand.Read(b)
	return hex.EncodeToString(b)
}
