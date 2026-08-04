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
	"github.com/xdpban/xdp-ban/internal/prefixdb"
	"github.com/xdpban/xdp-ban/internal/web"
)

// Version 由 -ldflags "-X main.Version=..." 注入
var Version = "dev"

func main() {
	dbPath := env("XDPBAN_DB", "xdpban.db")
	addr := env("XDPBAN_ADDR", ":8080")

	log.Printf("xdp-ban %s starting", Version)

	db, err := model.Open(dbPath)
	if err != nil {
		log.Fatalf("open db: %v", err)
	}
	seed(db)

	// 前缀库是可选的:没有它,按国家/AS 封禁功能在界面上提示未导入,
	// 其余功能照常。不因缺少一个可选数据文件而拒绝启动。
	//
	// 加载顺序:显式指定的 XDPBAN_PREFIX_DB 优先,否则用数据目录中
	// 由界面同步/上传产生的文件。这样一次配置之后,后续都从界面维护。
	loadPrefixDB()

	r := gin.New()
	r.Use(gin.Recovery())
	r.Use(gin.Logger())
	web.Register(r, db)
	web.RegisterAPI(r, db)

	// pprof 默认关闭:暴露内存布局与 goroutine 栈,只在排查时开
	if web.PprofEnabled() {
		web.RegisterPprof(r)
		log.Printf("pprof 已启用: %s/debug/pprof/ (务必仅绑定内网)", addr)
	}

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

// loadPrefixDB 加载 IP 前缀库。
//
// 优先级:XDPBAN_PREFIX_DB(显式指定)> 数据目录中的界面维护文件。
// 两者都没有时只记一条提示 —— 这是可选功能,不该阻塞启动。
func loadPrefixDB() {
	candidates := []string{}
	if p := os.Getenv("XDPBAN_PREFIX_DB"); p != "" {
		candidates = append(candidates, p)
	}
	candidates = append(candidates, prefixdb.ActivePath())

	for _, p := range candidates {
		if _, err := os.Stat(p); err != nil {
			continue
		}
		pdb, err := prefixdb.Load(p)
		if err != nil {
			log.Printf("加载前缀库 %s 失败: %v", p, err)
			continue
		}
		prefixdb.SetGlobal(pdb)
		st := pdb.Stats()
		log.Printf("前缀库已加载(%s): %d 条区间, %d 个国家, %d 个 AS",
			p, st.Entries, st.Countries, st.ASNs)

		// 本地覆盖规则要在主库之上生效
		if err := prefixdb.Reload(); err != nil && p == prefixdb.ActivePath() {
			log.Printf("应用本地覆盖规则: %v", err)
		}
		return
	}
	log.Printf("未找到 IP 前缀库,按国家/AS 封禁功能不可用 —— 可在界面「IP 库管理」中同步或上传")
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
		{"::1/128", "IPv6 环回"},
		{"8.8.8.8", "公共DNS示例"},
	} {
		db.Create(&model.ProtectedTarget{Target: p.t, Label: p.l, Active: true})
	}
	_ = policy.Roles
	log.Println("seeded default accounts (change passwords!)")
}

// 便于健康探测
var _ = http.StatusOK
