// Package dispatch —— 下发指令服务(核心流程:审批通过 → 生成 dispatch → 通过 SafetyGuard 和 ResolutionPolicy)。
package dispatch

import (
	"encoding/json"
	"fmt"
	"time"

	"gorm.io/gorm"

	"github.com/xdpban/xdp-ban/internal/model"
	"github.com/xdpban/xdp-ban/internal/resolution"
	"github.com/xdpban/xdp-ban/internal/safety"
)

// Service 下发核心逻辑
type Service struct {
	db    *gorm.DB
	guard *safety.Guard
}

// NewService 构造
func NewService(db *gorm.DB, guard *safety.Guard) *Service {
	return &Service{db: db, guard: guard}
}

// BanPayload 下发的物理封禁指令。
//
// 字段组合决定 agent 走哪条执行路径,必须与 cmd/xdpban/exec_loop.go 的
// BanPayload 保持一致 —— 这是跨进程的 JSON 契约:
//   - Target 有值、ScopedTarget 为空 → 写 src_ban_global(封该源,不限目标)
//   - ScopedTarget + Prefixes 有值   → 写 target_hosts + src_ban(定向封禁)
type BanPayload struct {
	Target  string `json:"target"`
	TTLSecs int64  `json:"ttl_secs"` // 0=永久
	NodeID  string `json:"node_id"`  // 下发到哪个节点/agent
	ReqID   uint   `json:"req_id"`   // 追溯源
	BanID   string `json:"ban_id"`   // 幂等键
	Backend string `json:"backend"`  // 恒为 xdp:执行层是纯 eBPF
	Reason  string `json:"reason"`

	// 范围封禁专用:目标单主机 + 展开后的源前缀列表
	ScopedTarget string   `json:"scoped_target,omitempty"`
	Prefixes     []string `json:"prefixes,omitempty"`
}

// CreateDispatch 审批通过后调用:生成 dispatch 指令。
// 责任链:
//   1. SafetyGuard 最终否决
//   2. ResolutionPolicy 算优先级
//   3. 幂等(ban_id)去重
//   4. 返回 Dispatch + Explain 供 UI 展示
func (s *Service) CreateDispatch(req *model.BanRequest) (*model.Dispatch, string, error) {
	// 1. SafetyGuard 检查:命中保护集 → 绝对拒绝
	if err := s.guard.AssertSafe(req.Target); err != nil {
		s.db.Model(req).Update("state", "safety_blocked")
		return nil, err.Error(), err
	}

	// 2. ResolutionPolicy: 当前 IP 有没有更高优先级的来源在拦它
	res := resolution.Resolve([]string{req.Source}, false)

	// 3. 幂等键:同一请求 + 同一目标恒定映射到同一 ban_id
	banID := fmt.Sprintf("ban-%d-%s", req.ID, req.Target)

	// 已存在同 ban_id 的指令则直接复用,避免重复审批/重放造成重复下发
	var existing model.Dispatch
	if err := s.db.Where("ban_id = ?", banID).First(&existing).Error; err == nil {
		return &existing, resolution.Explain("ban", res), nil
	}

	// 4. 载荷。TTLSeconds 为 nil 表示永久封禁(阶梯最高级),不能直接解引用。
	ttl := int64(0)
	if req.TTLSeconds != nil {
		ttl = *req.TTLSeconds
	}
	payload := BanPayload{
		Target:  req.Target,
		TTLSecs: ttl,
		NodeID:  "local",
		ReqID:   req.ID,
		BanID:   banID,
		Backend: "xdp", // 执行层是纯 eBPF/XDP,不经 nftables
		Reason:  req.Reason,
	}
	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		return nil, "", fmt.Errorf("marshal payload: %w", err)
	}

	// 5. 写 dispatch
	dispatch := &model.Dispatch{
		BanRequestID: req.ID,
		BanID:        banID,
		NodeID:       "local",
		Payload:      string(payloadJSON),
		State:        "pending",
	}
	if err := s.db.Create(dispatch).Error; err != nil {
		return nil, "", fmt.Errorf("create dispatch: %w", err)
	}

	// 6. 审计
	_ = model.WriteAudit(s.db, req.ApprovedByID, "dispatch", "Dispatch",
		fmt.Sprint(dispatch.ID), "created", string(payloadJSON))

	// 7. 返回裁决理由
	return dispatch, resolution.Explain("ban", res), nil
}

// CreateScopedDispatch 范围封禁审批通过后调用:把选择器展开的前缀列表
// 打包成一条 dispatch 指令。
//
// 为什么把上万条前缀塞进一条指令而不是拆成上万条 dispatch:
// dispatch 是审计与回执的单位,一次审批就该对应一条可追溯的下发记录。
// 拆开会让审计列表被同一次操作淹没,也让"这次封禁到底成功没有"变得
// 无法回答(一万条里成功 9998 条算成功吗?)。
// agent 侧逐条写 map,任一条失败即整条指令标记 failed 并报出已写入数。
func (s *Service) CreateScopedDispatch(sb *model.ScopedBan, prefixes []string) (*model.Dispatch, string, error) {
	// SafetyGuard 对目标主机做最终否决 —— 与单点封禁同一道闸门,无旁路
	if err := s.guard.AssertSafe(sb.TargetIP); err != nil {
		s.db.Model(sb).Update("state", "safety_blocked")
		return nil, err.Error(), err
	}

	res := resolution.Resolve([]string{"manual"}, false)

	// 幂等键带上 scoped 前缀,避免与单点封禁的 ban_id 空间冲突
	banID := fmt.Sprintf("scoped-%d-%s", sb.ID, sb.TargetIP)
	var existing model.Dispatch
	if err := s.db.Where("ban_id = ?", banID).First(&existing).Error; err == nil {
		return &existing, resolution.Explain("ban", res), nil
	}

	ttl := int64(0)
	if sb.TTLSeconds != nil {
		ttl = *sb.TTLSeconds
	}
	payload := BanPayload{
		TTLSecs:      ttl,
		NodeID:       "local",
		ReqID:        sb.ID,
		BanID:        banID,
		Backend:      "xdp",
		Reason:       sb.Reason,
		ScopedTarget: sb.TargetIP,
		Prefixes:     prefixes,
	}
	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		return nil, "", fmt.Errorf("marshal scoped payload: %w", err)
	}

	dispatch := &model.Dispatch{
		BanRequestID: sb.ID,
		BanID:        banID,
		NodeID:       "local",
		Payload:      string(payloadJSON),
		State:        "pending",
	}
	if err := s.db.Create(dispatch).Error; err != nil {
		return nil, "", fmt.Errorf("create scoped dispatch: %w", err)
	}

	// 审计只记摘要不记全部前缀:上万条前缀写进审计详情会让日志不可读,
	// 且这些前缀可由选择器 + ResolvedAt 重现。
	detail := fmt.Sprintf("target=%s prefixes=%d ttl=%ds",
		sb.TargetIP, len(prefixes), ttl)
	_ = model.WriteAudit(s.db, sb.ApprovedByID, "dispatch", "Dispatch",
		fmt.Sprint(dispatch.ID), "created", detail)

	return dispatch, resolution.Explain("ban", res), nil
}

// MarkAcked 智能体确认接收
func (s *Service) MarkAcked(dispatch *model.Dispatch) error {
	now := time.Now()
	return s.db.Model(dispatch).Updates(map[string]any{
		"state":    "acked",
		"acked_at": now,
	}).Error
}

// MarkFailed 记录执行失败。attempts 递增供运维判断是否反复失败。
func (s *Service) MarkFailed(dispatch *model.Dispatch, errMsg string) error {
	return s.db.Model(dispatch).Updates(map[string]any{
		"state":      "failed",
		"last_error": errMsg,
		"attempts":   dispatch.Attempts + 1,
	}).Error
}
