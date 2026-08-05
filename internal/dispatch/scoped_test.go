package dispatch

import (
	"encoding/json"
	"testing"

	"github.com/xdpban/xdp-ban/internal/model"
	"github.com/xdpban/xdp-ban/internal/safety"
)

// 范围封禁的下发载荷必须带 scoped_target + prefixes,
// 且**不能**带 target —— agent 靠这个字段组合判断走哪条执行路径。
// 带错了会让定向封禁被当成单点封禁写进全局表,
// 后果是"封了整个国家打向所有主机"而不是只保护指定那台。
func TestCreateScopedDispatch_PayloadShape(t *testing.T) {
	db := newTestDB(t)
	svc := NewService(db, safety.New(nil))

	ttl := int64(3600)
	approver := uint(9)
	sb := &model.ScopedBan{
		TargetIP: "10.0.1.100", Country: "CN", ASN: 4134,
		PrefixCount: 2, TTLSeconds: &ttl, ApprovedByID: &approver,
		Reason: "AS 洪水",
	}
	if err := db.Create(sb).Error; err != nil {
		t.Fatalf("create scoped ban: %v", err)
	}

	prefixes := []string{"203.0.113.0/24", "198.51.100.0/24"}
	d, _, err := svc.CreateScopedDispatch(sb, prefixes)
	if err != nil {
		t.Fatalf("CreateScopedDispatch: %v", err)
	}

	var p BanPayload
	if err := json.Unmarshal([]byte(d.Payload), &p); err != nil {
		t.Fatalf("payload 不是合法 JSON: %v", err)
	}

	if p.ScopedTarget != "10.0.1.100" {
		t.Errorf("scoped_target = %q,期望 10.0.1.100", p.ScopedTarget)
	}
	if len(p.Prefixes) != 2 {
		t.Errorf("prefixes 数量 = %d,期望 2", len(p.Prefixes))
	}
	if p.Target != "" {
		t.Errorf("范围封禁的 target 必须为空,否则 agent 会误判成单点封禁写进全局表,实际 %q", p.Target)
	}
	if p.TTLSecs != 3600 {
		t.Errorf("ttl_secs = %d,期望 3600", p.TTLSecs)
	}
	if p.Backend != "xdp" {
		t.Errorf("backend = %q,期望 xdp", p.Backend)
	}
}

// 单点封禁反过来:必须有 target、不能有 scoped_target
func TestCreateDispatch_PayloadHasNoScopedFields(t *testing.T) {
	db := newTestDB(t)
	svc := NewService(db, safety.New(nil))

	req := &model.BanRequest{Target: "203.0.113.7", Source: "manual"}
	db.Create(req)

	d, _, err := svc.CreateDispatch(req)
	if err != nil {
		t.Fatalf("CreateDispatch: %v", err)
	}

	var p BanPayload
	json.Unmarshal([]byte(d.Payload), &p)

	if p.Target != "203.0.113.7" {
		t.Errorf("target = %q,期望 203.0.113.7", p.Target)
	}
	if p.ScopedTarget != "" || len(p.Prefixes) != 0 {
		t.Errorf("单点封禁不该带范围字段: scoped_target=%q prefixes=%v",
			p.ScopedTarget, p.Prefixes)
	}
}

// 幂等键必须区分两类封禁,否则 id 相同的单点与范围封禁会互相覆盖
func TestScopedAndSingleBanIDsDoNotCollide(t *testing.T) {
	db := newTestDB(t)
	svc := NewService(db, safety.New(nil))

	req := &model.BanRequest{Target: "10.0.1.100", Source: "manual"}
	db.Create(req)
	d1, _, err := svc.CreateDispatch(req)
	if err != nil {
		t.Fatalf("CreateDispatch: %v", err)
	}

	sb := &model.ScopedBan{TargetIP: "10.0.1.100", Country: "CN"}
	db.Create(sb)
	d2, _, err := svc.CreateScopedDispatch(sb, []string{"1.0.0.0/8"})
	if err != nil {
		t.Fatalf("CreateScopedDispatch: %v", err)
	}

	if d1.BanID == d2.BanID {
		t.Errorf("两类封禁产生了相同 ban_id %q —— 会互相覆盖", d1.BanID)
	}
}

// 范围封禁的目标同样要过 SafetyGuard —— 与单点封禁同一道闸门,无旁路。
// 不查的话,把网关设成"被保护目标"再封全世界的源,等于自断网络。
func TestCreateScopedDispatch_SafetyVetoOnTarget(t *testing.T) {
	db := newTestDB(t)
	svc := NewService(db, safety.New([]string{"10.0.0.0/8"}))

	sb := &model.ScopedBan{TargetIP: "10.0.1.100", Country: "CN", State: "active"}
	db.Create(sb)

	d, explain, err := svc.CreateScopedDispatch(sb, []string{"1.0.0.0/8"})
	if err == nil {
		t.Fatal("目标命中保护集时必须拒绝")
	}
	if d != nil {
		t.Error("被否决时不应生成指令")
	}
	if explain == "" {
		t.Error("应返回可展示给用户的否决原因")
	}

	var reloaded model.ScopedBan
	db.First(&reloaded, sb.ID)
	if reloaded.State != "safety_blocked" {
		t.Errorf("state = %q,期望 safety_blocked", reloaded.State)
	}
}

func TestCreateScopedDispatch_Idempotent(t *testing.T) {
	db := newTestDB(t)
	svc := NewService(db, safety.New(nil))

	sb := &model.ScopedBan{TargetIP: "10.0.1.100", Country: "CN"}
	db.Create(sb)

	first, _, err := svc.CreateScopedDispatch(sb, []string{"1.0.0.0/8"})
	if err != nil {
		t.Fatalf("首次: %v", err)
	}
	second, _, err := svc.CreateScopedDispatch(sb, []string{"1.0.0.0/8"})
	if err != nil {
		t.Fatalf("重复: %v", err)
	}
	if first.ID != second.ID {
		t.Errorf("重复调用产生了不同指令: %d vs %d", first.ID, second.ID)
	}
}
