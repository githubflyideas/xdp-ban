// Command xdp-ban —— 单二进制封禁治理平台 + 执行器。
// 看见即封禁:eBPF 流量采样(独立的 xdp-sampler 进程)+ 治理式封禁执行(本进程)。
//
// 本进程原本拆成两个二进制:xdp-ban(Gin/GORM 控制面,只管审批与下发排队)
// 和 xdp-agent(纯执行器,轮询 xdp-ban 的 HTTP API 拉取指令、写 eBPF map)。
// 合并的理由:两者本就部署在同一台主机、同一次生命周期里,拆开只多了一趟
// 本地 HTTP 回环(下发指令要先落库,再靠 agent 用 HTTP 轮询自己的服务器
// 才能读出来),外加一套重复的 API Key 鉴权。合并后 executor 直接查 DB、
// 直接调用同一个 Apply,指令生效延迟从"一个轮询周期"降到"审批提交那一刻"。
//
// xdp-sampler 仍是独立二进制:它跑在镜像口上做纯采样,只读不拦截,
// 与本进程的执行逻辑没有共享状态,没有合并的理由。
//
// 构建单静态二进制:
//
//	CGO_ENABLED=0 go build -ldflags "-s -w" -o xdp-ban ./cmd/xdpban
//
// 运行(需 root,因为要 attach XDP 程序到网卡):
//
//	sudo ./xdp-ban -iface eth0     # 默认 :8080,数据落 ./xdpban.db
package main

import (
	"flag"
	"log"
	"net/http"
	"os"
	"time"

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

	// XDP 封禁执行的挂载网卡。-iface 优先于环境变量,两者都没给则拒绝启动 ——
	// 静默不挂 XDP 程序等于"界面显示已封禁,流量照样进来",这是最危险的
	// 失败模式,宁可启动失败也不要默默跳过执行层。
	ifaceFlag := flag.String("iface", "", "XDP 封禁程序挂载的网卡(业务口,不是采样镜像口)")
	pollInterval := flag.Duration("poll-interval", 5*time.Second, "扫描待执行 dispatch 的间隔")
	flag.Parse()

	iface := *ifaceFlag
	if iface == "" {
		iface = os.Getenv("XDPBAN_IFACE")
	}
	if iface == "" {
		log.Fatalf("必须指定 XDP 封禁网卡:-iface <ifname> 或环境变量 XDPBAN_IFACE。" +
			"这是执行层生效的前提,没有它封禁只会停留在审批记录里,不会真正拦截流量。")
	}

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

	// 执行层:加载 eBPF、attach 到网卡、启动轮询循环。
	// 失败即 Fatalf——启动期不可恢复的错误必须快速失败,不能让一个
	// "看起来在跑但从不生效"的进程留在生产上。
	bm, closeXDP := startExecutor(db, iface)
	defer closeXDP()
	go runExecutorLoop(db, bm, *pollInterval)

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

	log.Printf("xdp-ban listening on %s (db=%s, xdp iface=%s)", addr, dbPath, iface)
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
