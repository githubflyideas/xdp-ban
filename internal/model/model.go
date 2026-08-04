// Package model —— 数据模型与持久化(GORM + 纯 Go SQLite / glebarez)。
// 单二进制:glebarez/sqlite 底层 modernc.org/sqlite 为纯 Go,CGO_ENABLED=0 即可静态编译。
// 数据落一个 .db 文件,拷贝即备份;部署 = 一个二进制 + 一个 db 文件。
package model

import (
	"time"

	"github.com/glebarez/sqlite"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// User 用户与角色
type User struct {
	ID           uint   `gorm:"primaryKey"`
	Username     string `gorm:"uniqueIndex;not null"`
	Email        string
	PasswordHash string
	Role         string `gorm:"not null;default:viewer"` // admin/approver/operator/viewer
	Active       bool   `gorm:"not null;default:true"`
	AuthSource   string `gorm:"not null;default:local"` // local | ldap(占位)
	LDAPDn       string
	LastLoginAt  *time.Time
	CreatedAt    time.Time
	UpdatedAt    time.Time
}

func (u *User) SetPassword(pw string) error {
	h, err := bcrypt.GenerateFromPassword([]byte(pw), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	u.PasswordHash = string(h)
	return nil
}
func (u *User) CheckPassword(pw string) bool {
	return bcrypt.CompareHashAndPassword([]byte(u.PasswordHash), []byte(pw)) == nil
}
func (u *User) Label() string { return "user:" + u.Username }

// BanRequest 封禁请求(业务真相 + 审批生命周期)
type BanRequest struct {
	ID              uint   `gorm:"primaryKey"`
	ActionType      string `gorm:"not null"` // ban/unban/allow/unallow
	Target          string `gorm:"index;not null"`
	Source          string `gorm:"not null;default:manual"` // manual/blackhole/...
	ApprovalMode    string `gorm:"not null;default:manual_dual"`
	State           string `gorm:"index;not null;default:pending"`
	RequestedByID   *uint
	ApprovedByID    *uint
	ApprovedByPolicy string
	SecondApproverID *uint
	Reason          string
	TTLSeconds      *int64
	Conditions      string // JSON
	EffectiveAt     *time.Time
	ExpiresAt       *time.Time
	ClearedAt       *time.Time
	CreatedAt       time.Time
	UpdatedAt       time.Time
}

// Dispatch 下发指令(WAL;审批通过后生成)
type Dispatch struct {
	ID           uint   `gorm:"primaryKey"`
	BanRequestID uint   `gorm:"not null"`
	BanID        string `gorm:"index;not null"` // 幂等键
	NodeID       string `gorm:"not null;default:local"`
	Payload      string `gorm:"not null"` // JSON
	State        string `gorm:"index;not null;default:pending"` // pending/acked/failed
	LastError    string
	Attempts     int
	AckedAt      *time.Time
	CreatedAt    time.Time
	UpdatedAt    time.Time
}

// AuditLog 审计(只增不可改;应用层禁 update/delete)
type AuditLog struct {
	ID         uint   `gorm:"primaryKey"`
	UserID     *uint
	ActorLabel string
	EntityType string `gorm:"index;not null"`
	EntityID   string `gorm:"index"`
	Event      string `gorm:"not null"`
	Detail     string // JSON
	OccurredAt time.Time `gorm:"not null"`
	CreatedAt  time.Time
}

// ApprovalToken 邮件审批一次性令牌
type ApprovalToken struct {
	ID           uint   `gorm:"primaryKey"`
	BanRequestID uint   `gorm:"not null"`
	ApproverID   uint   `gorm:"not null"`
	Token        string `gorm:"uniqueIndex;not null"`
	ExpiresAt    time.Time `gorm:"index;not null"`
	UsedAt       *time.Time
	SentToEmail  string
	CreatedAt    time.Time
}

// ProtectedTarget 绝对保护集(安全兜底层读取)
type ProtectedTarget struct {
	ID          uint   `gorm:"primaryKey"`
	Target      string `gorm:"uniqueIndex;not null"`
	Label       string
	Active      bool `gorm:"not null;default:true"`
	CreatedByID *uint
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

// BanLadder 阶梯封禁状态(治理层智能;每 IP 记级别与观察期)
type BanLadder struct {
	ID           uint   `gorm:"primaryKey"`
	Target       string `gorm:"uniqueIndex;not null"`
	Level        int    `gorm:"not null;default:0"`
	OffenseCount int    `gorm:"not null;default:0"`
	LastBannedAt *time.Time
	ObserveUntil *time.Time
	ExpiresAt    *time.Time
	Permanent    bool `gorm:"not null;default:false"`
	CreatedAt    time.Time
	UpdatedAt    time.Time
}

// Open 打开数据库并迁移。path 为 .db 文件路径。
func Open(path string) (*gorm.DB, error) {
	db, err := gorm.Open(sqlite.Open(path), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Warn),
	})
	if err != nil {
		return nil, err
	}
	if err := db.AutoMigrate(
		&User{}, &BanRequest{}, &Dispatch{}, &AuditLog{},
		&ApprovalToken{}, &ProtectedTarget{}, &BanLadder{},
	); err != nil {
		return nil, err
	}
	return db, nil
}

// WriteAudit 审计写入(只增)。应用层唯一写审计入口。
func WriteAudit(db *gorm.DB, userID *uint, actor, entityType, entityID, event, detailJSON string) error {
	return db.Create(&AuditLog{
		UserID: userID, ActorLabel: actor, EntityType: entityType,
		EntityID: entityID, Event: event, Detail: detailJSON,
		OccurredAt: time.Now(),
	}).Error
}
