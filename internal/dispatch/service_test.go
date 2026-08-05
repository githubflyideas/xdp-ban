package dispatch

import (
	"encoding/json"
	"testing"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/xdpban/xdp-ban/internal/model"
	"github.com/xdpban/xdp-ban/internal/safety"
)

func newTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open("file::memory:?cache=shared"), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	})
	if err != nil {
		t.Fatalf("open in-memory db: %v", err)
	}
	if err := db.AutoMigrate(&model.BanRequest{}, &model.Dispatch{},
		&model.AuditLog{}, &model.ScopedBan{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	// 每个用例开始时清表,避免 shared cache 下的相互污染
	db.Exec("DELETE FROM dispatches")
	db.Exec("DELETE FROM ban_requests")
	db.Exec("DELETE FROM scoped_bans")
	db.Exec("DELETE FROM audit_logs")
	return db
}

// 永久封禁(阶梯顶格)的 TTLSeconds 是 nil。
// 早先的实现直接 *req.TTLSeconds,一到永久封禁就 panic,整个进程挂掉。
func TestCreateDispatch_NilTTLMeansPermanent(t *testing.T) {
	db := newTestDB(t)
	svc := NewService(db, safety.New(nil))

	req := &model.BanRequest{Target: "203.0.113.7", Source: "manual", State: "active"}
	if err := db.Create(req).Error; err != nil {
		t.Fatalf("create request: %v", err)
	}

	d, _, err := svc.CreateDispatch(req)
	if err != nil {
		t.Fatalf("CreateDispatch 在 TTLSeconds=nil 时报错: %v", err)
	}

	var payload BanPayload
	if err := json.Unmarshal([]byte(d.Payload), &payload); err != nil {
		t.Fatalf("payload 不是合法 JSON: %v", err)
	}
	if payload.TTLSecs != 0 {
		t.Errorf("永久封禁的 ttl_secs 应为 0,实际 %d", payload.TTLSecs)
	}
}

func TestCreateDispatch_CarriesTTL(t *testing.T) {
	db := newTestDB(t)
	svc := NewService(db, safety.New(nil))

	ttl := int64(3600)
	req := &model.BanRequest{Target: "203.0.113.8", Source: "manual", TTLSeconds: &ttl}
	db.Create(req)

	d, _, err := svc.CreateDispatch(req)
	if err != nil {
		t.Fatalf("CreateDispatch: %v", err)
	}
	var payload BanPayload
	json.Unmarshal([]byte(d.Payload), &payload)
	if payload.TTLSecs != 3600 {
		t.Errorf("ttl_secs = %d, 期望 3600", payload.TTLSecs)
	}
	// 执行层是纯 XDP,载荷不应再声明 nftables
	if payload.Backend != "xdp" {
		t.Errorf("backend = %q, 期望 xdp", payload.Backend)
	}
}

// 同一请求重复审批/重放不得产生第二条下发指令,否则 agent 会重复写 map。
func TestCreateDispatch_Idempotent(t *testing.T) {
	db := newTestDB(t)
	svc := NewService(db, safety.New(nil))

	req := &model.BanRequest{Target: "203.0.113.9", Source: "manual"}
	db.Create(req)

	first, _, err := svc.CreateDispatch(req)
	if err != nil {
		t.Fatalf("首次 CreateDispatch: %v", err)
	}
	second, _, err := svc.CreateDispatch(req)
	if err != nil {
		t.Fatalf("重复 CreateDispatch: %v", err)
	}

	if first.ID != second.ID {
		t.Errorf("重复调用产生了不同指令: %d vs %d", first.ID, second.ID)
	}

	var n int64
	db.Model(&model.Dispatch{}).Where("ban_id = ?", first.BanID).Count(&n)
	if n != 1 {
		t.Errorf("同一 ban_id 的指令条数 = %d, 期望 1", n)
	}
}

// SafetyGuard 是最后一道否决,命中保护集必须拒绝下发并标记状态。
func TestCreateDispatch_SafetyVeto(t *testing.T) {
	db := newTestDB(t)
	svc := NewService(db, safety.New([]string{"10.0.0.0/8"}))

	req := &model.BanRequest{Target: "10.1.2.3", Source: "manual", State: "active"}
	db.Create(req)

	d, explain, err := svc.CreateDispatch(req)
	if err == nil {
		t.Fatal("命中保护集时 CreateDispatch 应返回错误")
	}
	if d != nil {
		t.Error("被否决时不应生成指令")
	}
	if explain == "" {
		t.Error("应返回可展示给用户的否决原因")
	}

	var reloaded model.BanRequest
	db.First(&reloaded, req.ID)
	if reloaded.State != "safety_blocked" {
		t.Errorf("state = %q, 期望 safety_blocked", reloaded.State)
	}

	var n int64
	db.Model(&model.Dispatch{}).Count(&n)
	if n != 0 {
		t.Errorf("被否决后仍写入了 %d 条指令", n)
	}
}
