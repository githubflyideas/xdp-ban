package web

import (
	"log"
	"os"
	"time"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"

	"github.com/xdpban/xdp-ban/internal/model"
)

// apiKey 是 agent / sampler 访问 /api/v1 的共享密钥。
// 生产部署应改为 mTLS 或 per-node token;这里保持单密钥以匹配单二进制的部署形态。
func apiKey() string {
	if v := os.Getenv("XDPBAN_API_KEY"); v != "" {
		return v
	}
	return "changeme"
}

// RegisterAPI 注册供执行器/采样器调用的 JSON 端点。
//
// 注意:这些路由不走浏览器会话,只认 X-API-Key。
func RegisterAPI(r *gin.Engine, db *gorm.DB) {
	api := r.Group("/api/v1", apiAuth())
	{
		// 执行器轮询与回执
		api.GET("/dispatch/pending", getDispatchPending(db))
		api.POST("/dispatch/:id/ack", markDispatchAck(db))
		api.POST("/dispatch/:id/fail", markDispatchFail(db))

		// 采样器上报
		api.POST("/samples", receiveSamples(db))
	}
}

// apiAuth 校验 X-API-Key。密钥不匹配一律 401,不区分"缺失"与"错误"。
func apiAuth() gin.HandlerFunc {
	want := apiKey()
	return func(c *gin.Context) {
		if c.GetHeader("X-API-Key") != want {
			c.AbortWithStatusJSON(401, gin.H{"error": "unauthorized"})
			return
		}
		c.Next()
	}
}

func getDispatchPending(db *gorm.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		var dispatches []model.Dispatch
		if err := db.Where("state = ?", "pending").Limit(50).Find(&dispatches).Error; err != nil {
			c.JSON(500, gin.H{"error": err.Error()})
			return
		}
		c.JSON(200, dispatches)
	}
}

func markDispatchAck(db *gorm.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		var d model.Dispatch
		if db.First(&d, c.Param("id")).Error != nil {
			c.JSON(404, gin.H{"error": "not found"})
			return
		}
		now := time.Now()
		if err := db.Model(&d).Updates(map[string]any{"state": "acked", "acked_at": now}).Error; err != nil {
			c.JSON(500, gin.H{"error": err.Error()})
			return
		}
		_ = model.WriteAudit(db, nil, "agent", "Dispatch", itoa(d.ID), "acked", "")
		c.JSON(200, gin.H{"ok": true})
	}
}

func markDispatchFail(db *gorm.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		var d model.Dispatch
		if db.First(&d, c.Param("id")).Error != nil {
			c.JSON(404, gin.H{"error": "not found"})
			return
		}

		// agent 以 JSON 体或表单提交错误原因,两种都接受
		errMsg := c.PostForm("error")
		if errMsg == "" {
			var body struct {
				Error string `json:"error"`
			}
			if err := c.ShouldBindJSON(&body); err == nil {
				errMsg = body.Error
			}
		}

		if err := db.Model(&d).Updates(map[string]any{
			"state":      "failed",
			"last_error": errMsg,
			"attempts":   d.Attempts + 1,
		}).Error; err != nil {
			c.JSON(500, gin.H{"error": err.Error()})
			return
		}
		_ = model.WriteAudit(db, nil, "agent", "Dispatch", itoa(d.ID), "failed", errMsg)
		c.JSON(200, gin.H{"ok": true})
	}
}

// FlowSample 采样器上报的单条流统计
type FlowSample struct {
	SrcIP     string `json:"src_ip"`
	DstIP     string `json:"dst_ip"`
	SrcPort   int    `json:"src_port"`
	DstPort   int    `json:"dst_port"`
	Proto     string `json:"proto"`
	PktCount  int64  `json:"pkt_count"`
	ByteCount int64  `json:"byte_count"`
	LastSeen  int64  `json:"last_seen_unix"`
}

// SampleReport 一次上报的完整载荷。
//
// NetflowTarget 是新增字段:xdp-sampler 把自己的启动参数(接口/采样率/
// NetFlow 目标)捎带在周期上报里,xdp-ban 的「采样与流量」页借此展示
// 当前采样器配置(只读),不需要为此新开一条反向查询接口。
type SampleReport struct {
	Timestamp     int64          `json:"timestamp"`
	Device        string         `json:"device"`
	SamplingN     int            `json:"sampling_n"`
	NetflowTarget string         `json:"netflow_target,omitempty"`
	Flows         []FlowSample   `json:"flows"`
	GlobalStat    map[string]any `json:"global_stat"`
}

// receiveSamples 接收采样上报,写入内存环形缓冲供仪表板读取。
//
// 采样数据是高频、可丢弃的观测值,不落 SQLite——避免把审计库变成时序库。
func receiveSamples(db *gorm.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		var report SampleReport
		if err := c.ShouldBindJSON(&report); err != nil {
			c.JSON(400, gin.H{"error": err.Error()})
			return
		}

		SampleStore.Put(report)
		log.Printf("[samples] device=%s flows=%d sampling=1/%d",
			report.Device, len(report.Flows), report.SamplingN)

		c.JSON(200, gin.H{"ok": true, "accepted": len(report.Flows)})
	}
}
