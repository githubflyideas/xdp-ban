// Command xdp-ban —— 单二进制封禁治理平台。
// 看见即封禁:eBPF 流量采样 + 治理式封禁。
//
// 构建单静态二进制:
//   CGO_ENABLED=0 go build -ldflags "-s -w" -o xdp-ban ./cmd/xdpban
// 运行:
//   ./xdp-ban            # 默认 :8080,数据落 ./xdpban.db
package main

import (
	"log"
	"net/http"
	"os"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"

	"github.com/xdpban/xdp-ban/internal/model"
	"github.com/xdpban/xdp-ban/internal/policy"
	"github.com/xdpban/xdp-ban/internal/web"
)

func main() {
	dbPath := env("XDPBAN_DB", "xdpban.db")
	addr := env("XDPBAN_ADDR", ":8080")

	db, err := model.Open(dbPath)
	if err != nil {
		log.Fatalf("open db: %v", err)
	}
	seed(db)

	r := gin.New()
	r.Use(gin.Recovery())
	web.Register(r, db)

	log.Printf("xdp-ban listening on %s (db=%s)", addr, dbPath)
	if err := r.Run(addr); err != nil {
		log.Fatal(err)
	}
}

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

// seed 初始账号 + 保护集(仅当空库)。生产首次登录须改密码。
func seed(db *gorm.DB) {
	var n int64
	db.Model(&model.User{}).Count(&n)
	if n > 0 {
		return
	}
	accounts := []struct{ u, r, p string }{
		{"admin", "admin", "admin12345"},
		{"approver", "approver", "approver12345"},
		{"operator", "operator", "operator12345"},
		{"viewer", "viewer", "viewer12345"},
	}
	for _, a := range accounts {
		u := &model.User{Username: a.u, Role: a.r, Active: true, AuthSource: "local",
			Email: a.u + "@example.com"}
		_ = u.SetPassword(a.p)
		db.Create(u)
	}
	for _, p := range []struct{ t, l string }{
		{"127.0.0.0/8", "环回(硬保护)"},
		{"8.8.8.8", "公共DNS示例"},
	} {
		db.Create(&model.ProtectedTarget{Target: p.t, Label: p.l, Active: true})
	}
	_ = policy.Roles
	log.Println("seeded default accounts (change passwords!)")
}

// 便于健康探测
var _ = http.StatusOK
