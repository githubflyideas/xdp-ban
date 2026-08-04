package web

import (
	"net/http/pprof"
	"runtime"

	"github.com/gin-gonic/gin"
)

// RegisterPprof 挂载 net/http/pprof 端点。
//
// 默认不启用:pprof 会暴露内存布局、goroutine 栈等信息,
// 在生产上开放等于送出一份内部结构地图。仅当 XDPBAN_PPROF 非空时挂载,
// 并且应只绑定在内网/回环地址上。
//
// 同时打开 block/mutex 采样 —— 这两项默认关闭(采样率 0),
// 不打开的话 block.pprof / mutex.pprof 永远是空的,
// 而 SQLite 争锁和会话锁争用恰恰只能从这两个 profile 看出来。
func RegisterPprof(r *gin.Engine) {
	// 每 10000 次阻塞事件采一次,开销可忽略但足以定位热点
	runtime.SetBlockProfileRate(10000)
	runtime.SetMutexProfileFraction(100)

	g := r.Group("/debug/pprof")
	g.GET("/", gin.WrapF(pprof.Index))
	g.GET("/cmdline", gin.WrapF(pprof.Cmdline))
	g.GET("/profile", gin.WrapF(pprof.Profile))
	g.GET("/symbol", gin.WrapF(pprof.Symbol))
	g.POST("/symbol", gin.WrapF(pprof.Symbol))
	g.GET("/trace", gin.WrapF(pprof.Trace))
	// 以下由 Index 按名字分发,显式注册以便直接 curl
	for _, name := range []string{"heap", "goroutine", "block", "mutex", "threadcreate", "allocs"} {
		g.GET("/"+name, gin.WrapH(pprof.Handler(name)))
	}
}

// PprofEnabled 是否应挂载 pprof
func PprofEnabled() bool {
	return envOr("XDPBAN_PPROF", "") != ""
}
