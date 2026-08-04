// Package model —— 数据模型与持久化(GORM + 纯 Go SQLite / glebarez)。
// 单二进制:glebarez/sqlite 底层 modernc.org/sqlite 为纯 Go,CGO_ENABLED=0 即可静态编译。
// 数据落一个 .db 文件,拷贝即备份;部署 = 一个二进制 + 一个 db 文件。
package model

import (
	"fmt"
	"strings"
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

// ScopedBan 范围封禁规则:按国家 / AS 选择源地址范围,保护单台目标主机。
//
// 关键设计:**不逐条存储展开后的前缀**。
// 一个国家可展开成上万条 CIDR,逐条落库会让单次操作产生上万行,
// DB 膨胀、审批列表不可读、下发变慢。这里只存"选择器 + 展开数量",
// 前缀在下发时由 prefixdb 重新展开。代价是前缀库更新后同一规则的
// 展开结果可能变化 —— 这是想要的行为(封禁跟随 BGP 现实),
// 但必须记录 ResolvedAt 与 PrefixCount 以便发现漂移。
type ScopedBan struct {
	ID uint `gorm:"primaryKey"`

	// 目标:只允许单台主机(/32)。见 bpf/xdp_filter.c 的说明 ——
	// 目标带前缀会让二维最长匹配无法用 LPM_TRIE 表达。
	TargetIP string `gorm:"index;not null"`

	// 源范围选择器
	Country string `gorm:"index"` // ISO alpha-2,空 = 不限
	ASN     uint32 `gorm:"index"` // 0 = 不限

	// 展开结果的记账(用于配额、界面展示、漂移检测)
	PrefixCount int   `gorm:"not null"`
	AddressCount uint64 `gorm:"not null"`
	ResolvedAt  time.Time

	Reason     string
	State      string `gorm:"index;not null;default:pending"` // pending/active/rejected/expired/revoked
	TTLSeconds *int64

	RequestedByID *uint
	ApprovedByID  *uint
	// OverrideAck 记录管理员是否显式确认了"影响面过大"的警告。
	// 这是审计要点:大范围封禁必须能追溯到某人明确点过确认。
	OverrideAck bool `gorm:"not null;default:false"`

	EffectiveAt *time.Time
	ExpiresAt   *time.Time
	RevokedAt   *time.Time
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

// Label 供界面与审计展示
func (s *ScopedBan) Label() string {
	scope := "任意源"
	switch {
	case s.Country != "" && s.ASN != 0:
		scope = s.Country + "/AS" + itoa64(uint64(s.ASN))
	case s.Country != "":
		scope = s.Country
	case s.ASN != 0:
		scope = "AS" + itoa64(uint64(s.ASN))
	}
	return scope + " → " + s.TargetIP
}

func itoa64(v uint64) string {
	if v == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for v > 0 {
		i--
		b[i] = byte('0' + v%10)
		v /= 10
	}
	return string(b[i:])
}

// Open 打开数据库并迁移。path 为 .db 文件路径。
//
// SQLite 调优说明(这些不是可选项,少一个就会在并发下出问题):
//
//   - WAL 模式:默认的 journal 模式下写事务会阻塞所有读。Gin 是并发的,
//     仪表板的读查询会被一次审批写卡住。WAL 让读写互不阻塞。
//   - busy_timeout:并发写仍会短暂争锁,不设超时会直接返回 SQLITE_BUSY
//     (表现为随机的 "database is locked" 500 错误)。给 5s 让它自己重试。
//   - foreign_keys:SQLite 默认不强制外键,显式打开。
//   - synchronous=NORMAL:WAL 下这是安全与性能的常规折中(掉电最多丢
//     最近若干事务,不会损坏库)。审计要求更严可改 FULL。
//   - MaxOpenConns(1) 之外的取舍:modernc SQLite 写并发靠文件锁,
//     放开写连接只会把争抢从 Go 层挪到文件锁层。这里读写分离:
//     允许多读连接,写靠 busy_timeout 串行化。
func Open(path string) (*gorm.DB, error) {
	dsn := path + "?_pragma=journal_mode(WAL)" +
		"&_pragma=busy_timeout(5000)" +
		"&_pragma=foreign_keys(ON)" +
		"&_pragma=synchronous(NORMAL)"

	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Warn),
		// 预编译语句缓存。pprof 显示未开启时 modernc.org/sqlite 的
		// yy_reduce(SQL 语法分析)占 CPU 约 17% —— 每次查询都在重新
		// 解析同样的 SQL。开启后同一语句只解析一次。
		PrepareStmt: true,
		// 跳过默认事务:GORM 默认给每个单条写操作包一层事务,
		// 在 SQLite 上这是额外的 BEGIN/COMMIT 往返。需要原子性的地方
		// 我们显式用 db.Transaction(见审批令牌消费)。
		SkipDefaultTransaction: true,
	})
	if err != nil {
		return nil, err
	}

	sqlDB, err := db.DB()
	if err != nil {
		return nil, err
	}
	// 连接池:上限压得低是刻意的 —— SQLite 是单文件嵌入库,
	// 连接数堆高只会加剧文件锁争抢,而非提升吞吐。
	sqlDB.SetMaxOpenConns(8)
	sqlDB.SetMaxIdleConns(4)
	sqlDB.SetConnMaxLifetime(time.Hour)

	if err := db.AutoMigrate(
		&User{}, &BanRequest{}, &Dispatch{}, &AuditLog{},
		&ApprovalToken{}, &ProtectedTarget{}, &BanLadder{}, &ScopedBan{},
	); err != nil {
		return nil, err
	}

	// 确认 WAL 真的生效 —— DSN pragma 写错名字时驱动会静默忽略,
	// 不验证的话会以为开了 WAL 其实没开,并发问题到生产才暴露。
	var mode string
	if err := db.Raw("PRAGMA journal_mode").Scan(&mode).Error; err != nil {
		return nil, fmt.Errorf("检查 journal_mode: %w", err)
	}
	if !strings.EqualFold(mode, "wal") {
		return nil, fmt.Errorf("期望 WAL 模式,实际为 %q(并发读写会互相阻塞)", mode)
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
