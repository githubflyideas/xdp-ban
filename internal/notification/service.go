// Package notification —— 通知服务(邮件、Webhook、企业组件集成)
package notification

import (
	"log"
)

// Service 通知服务
type Service struct {
	mailServer string
	mailFrom   string
}

func NewService(mailServer, mailFrom string) *Service {
	return &Service{
		mailServer: mailServer,
		mailFrom:   mailFrom,
	}
}

// NotifyBanCreated 新封禁请求通知 approver
func (s *Service) NotifyBanCreated(approverEmail, target, reason string, approveLink string) error {
	body := "新的封禁请求需要审批：\n\n" +
		"目标: " + target + "\n" +
		"原因: " + reason + "\n" +
		"审批链接: " + approveLink + "\n\n" +
		"此链接 10 分钟内有效"

	return s.sendMail(approverEmail, "[xdp-ban] 新封禁审批请求", body)
}

// NotifyBanApproved 封禁已批准
func (s *Service) NotifyBanApproved(requesterEmail, target string) error {
	body := "您提交的封禁请求已批准：\n\n" +
		"目标: " + target + "\n" +
		"状态: 已生效\n"
	return s.sendMail(requesterEmail, "[xdp-ban] 封禁请求已批准", body)
}

func (s *Service) sendMail(to, subject, body string) error {
	// 占位:真实生产集成 SendGrid/SES
	log.Printf("[MAIL] To: %s\nSubject: %s\n%s\n", to, subject, body)
	return nil
}
