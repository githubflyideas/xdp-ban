// Package escalation —— 阶梯封禁(从 Rails ban_penalty.rb 平移,逻辑不变)。
// 治 fail2ban 最痛的病:一解封攻击者立刻接着打。惩罚记住历史,不每次从零开始。
package escalation

import "time"

// Ladder 阶梯时长表(秒),索引=level;最后一级 0 表示永久(彻底黑名单,自然长出)。
// 与 Ruby LADDER 一致:10分钟→1小时→1天→7天→永久。
var Ladder = []int64{600, 3600, 86400, 604800, 0}

const (
	ObserveWindow     = int64(3600) // 观察期默认 1 小时
	ActivityThreshold = uint64(5)   // 观察期内信号增量 > 此值 视为"还在打"
)

// Penalty 一个 IP 的阶梯封禁状态(对应 BanPenalty 模型)
type Penalty struct {
	Target          string
	Level           int
	OffenseCount    int
	LastBannedAt    time.Time
	ObserveUntil    time.Time
	ExpiresAt       time.Time
	BaselinePackets uint64 // 进观察期时的信号基准
	now             func() time.Time
}

func NewPenalty(target string) *Penalty {
	return &Penalty{Target: target, now: time.Now}
}

// CurrentTTL 本级封禁时长(秒);0 = 永久。对应 current_ttl。
func (p *Penalty) CurrentTTL() int64 {
	i := p.Level
	if i > len(Ladder)-1 {
		i = len(Ladder) - 1
	}
	return Ladder[i]
}

func (p *Penalty) Permanent() bool { return p.CurrentTTL() == 0 }

// clock 允许测试注入时间
func (p *Penalty) clock() time.Time {
	if p.now != nil {
		return p.now()
	}
	return time.Now()
}

// Observing 是否在观察期内(对应 observing?)
func (p *Penalty) Observing() bool {
	return !p.ObserveUntil.IsZero() && p.clock().Before(p.ObserveUntil)
}

// RegisterBan 触发一次封禁,推进状态,返回本次 TTL(秒;0=永久)。对应 register_ban!。
// escalate=true 时升一级(观察期内再犯)。
func (p *Penalty) RegisterBan(escalate bool) int64 {
	if escalate {
		p.Level++
		if p.Level > len(Ladder)-1 {
			p.Level = len(Ladder) - 1 // 封顶不溢出
		}
	}
	p.OffenseCount++
	now := p.clock()
	p.LastBannedAt = now
	ttl := p.CurrentTTL()
	if ttl > 0 {
		p.ExpiresAt = now.Add(time.Duration(ttl) * time.Second)
		// 解封后进入观察期
		p.ObserveUntil = p.ExpiresAt.Add(time.Duration(ObserveWindow) * time.Second)
	} else {
		p.ExpiresAt = time.Time{} // 永久
		p.ObserveUntil = time.Time{}
	}
	return ttl
}

// StillAttacking 依据信号增量判断是否还在打(对应 still_attacking?)
func (p *Penalty) StillAttacking(nowPackets uint64) bool {
	if nowPackets < p.BaselinePackets {
		return false
	}
	return (nowPackets - p.BaselinePackets) > ActivityThreshold
}

// MaybeDecay 观察期已过且未再犯 → 降级(对应 maybe_decay!)
func (p *Penalty) MaybeDecay() {
	if p.Observing() {
		return
	}
	if p.Level > 0 {
		p.Level--
	}
}
