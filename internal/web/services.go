package web

import (
	"time"

	"gorm.io/gorm"

	"github.com/xdpban/xdp-ban/internal/dispatch"
	"github.com/xdpban/xdp-ban/internal/escalation"
	"github.com/xdpban/xdp-ban/internal/model"
	"github.com/xdpban/xdp-ban/internal/safety"
)

// guard 构造安全兜底层:硬编码环回等 + DB 中的保护集。
//
// 每次调用都重新从 DB 读一遍,而不是缓存单例——保护集是运维随时会改的
// 安全边界,读一次几十行比"改了没生效"的事故便宜得多。
func (h *Handler) guard() *safety.Guard {
	g := safety.New(nil)
	var targets []model.ProtectedTarget
	if err := h.db.Where("active = ?", true).Find(&targets).Error; err == nil {
		for _, t := range targets {
			g.Add(t.Target)
		}
	}
	return g
}

// dispatches 返回下发服务(携带当前保护集快照)
func (h *Handler) dispatches() *dispatch.Service {
	return dispatch.NewService(h.db, h.guard())
}

// nextTTL 根据阶梯状态算出该目标本次封禁的 TTL(秒)。
// 返回 nil 表示永久封禁(阶梯顶格)。
func (h *Handler) nextTTL(target string) *int64 {
	var ladder model.BanLadder
	err := h.db.Where("target = ?", target).First(&ladder).Error

	p := escalation.NewPenalty(target)
	if err == nil {
		p.Level = ladder.Level
		p.OffenseCount = ladder.OffenseCount
		if ladder.ObserveUntil != nil {
			p.ObserveUntil = *ladder.ObserveUntil
		}
	}

	// 观察期内再犯 → 升级;观察期已过 → 维持当前级
	ttl := p.CurrentTTL()
	if p.Observing() && p.Level < len(escalation.Ladder)-1 {
		ttl = escalation.Ladder[p.Level+1]
	}
	if ttl == 0 {
		return nil // 永久
	}
	return &ttl
}

// recordLadder 在封禁生效后推进阶梯状态。
func (h *Handler) recordLadder(target string) {
	var ladder model.BanLadder
	err := h.db.Where("target = ?", target).First(&ladder).Error

	p := escalation.NewPenalty(target)
	escalate := false
	if err == nil {
		p.Level = ladder.Level
		p.OffenseCount = ladder.OffenseCount
		if ladder.ObserveUntil != nil {
			p.ObserveUntil = *ladder.ObserveUntil
		}
		escalate = p.Observing() // 观察期内再犯才升级
	}

	p.RegisterBan(escalate)

	now := time.Now()
	row := model.BanLadder{
		Target:       target,
		Level:        p.Level,
		OffenseCount: p.OffenseCount,
		LastBannedAt: &now,
		Permanent:    p.Permanent(),
	}
	if !p.ObserveUntil.IsZero() {
		ou := p.ObserveUntil
		row.ObserveUntil = &ou
	}
	if !p.ExpiresAt.IsZero() {
		ea := p.ExpiresAt
		row.ExpiresAt = &ea
	}

	if err == gorm.ErrRecordNotFound {
		h.db.Create(&row)
		return
	}
	h.db.Model(&ladder).Updates(map[string]any{
		"level":          row.Level,
		"offense_count":  row.OffenseCount,
		"last_banned_at": row.LastBannedAt,
		"observe_until":  row.ObserveUntil,
		"expires_at":     row.ExpiresAt,
		"permanent":      row.Permanent,
	})
}
