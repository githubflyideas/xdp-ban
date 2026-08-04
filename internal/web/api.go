package web

import (
	"encoding/json"
	"fmt"
	"log"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"

	"github.com/xdpban/xdp-ban/internal/model"
	"github.com/xdpban/xdp-ban/internal/policy"
	"github.com/xdpban/xdp-ban/internal/dispatch"
	"github.com/xdpban/xdp-ban/internal/approval"
	"github.com/xdpban/xdp-ban/internal/safety"
)

// API 返回 JSON 的端点
func RegisterAPI(r *gin.Engine, db *gorm.DB) {
	api := r.Group("/api/v1", apiAuth(db))
	{
		// 获取 dispatch 指令(智能体轮询)
		api.GET("/dispatch/pending", getDispatchPending(db))
		api.POST("/dispatch/:id/ack", markDispatchAck(db))
		api.POST("/dispatch/:id/fail", markDispatchFail(db))

		// 采样上报端点
		api.POST("/samples", reportSamples(db))
	}
}

func getDispatchPending(db *gorm.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		var dispatches []model.Dispatch
		db.Where("state = ?", "pending").Limit(10).Find(&dispatches)
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
		db.Model(&d).Updates(map[string]any{"state": "acked", "acked_at": now})
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
		errMsg := c.PostForm("error")
		d.Attempts++
		d.LastError = errMsg
		db.Model(&d).Updates(map[string]any{"state": "failed", "last_error": errMsg, "attempts": d.Attempts})
		c.JSON(200, gin.H{"ok": true})
	}
}

// FlowSample 上报的流统计
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

// SampleReport 采样上报载荷
type SampleReport struct {
	Timestamp  int64           `json:"timestamp"`
	Device     string          `json:"device"`
	SamplingN  int             `json:"sampling_n"`
	Flows      []FlowSample    `json:"flows"`
	GlobalStat map[string]interface{} `json:"global_stat"`
}

// reportSamples 接收采样数据上报
func reportSamples(db *gorm.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		var report SampleReport
		if err := c.BindJSON(&report); err != nil {
			c.JSON(400, gin.H{"error": err.Error()})
			return
		}

		// 存储流量统计(可用于仪表板展示、告警)
		log.Printf("[SAMPLES] device=%s flows=%d sampling_n=%d",
			report.Device, len(report.Flows), report.SamplingN)

		// 示例:存到 Redis/时序库 或内存缓冲(这里省略具体实现)
		// 可后续扩展为威胁检测:异常流量告警等

		c.JSON(200, gin.H{"ok": true})
	}
}

// Helper: 整合 dispatch + approval + safety guard
func createBanWithApproval(db *gorm.DB, req *model.BanRequest, baseURL string) error {
	// 1. 初始化
	guard := safety.New([]string{}) // 加载保护集
	var protTargets []model.ProtectedTarget
	db.Where("active = ?", true).Find(&protTargets)
	for _, pt := range protTargets {
		guard.Add(pt.Target)
	}

	dispatchSvc := dispatch.NewService(db, guard)
	approvalSvc := approval.NewService(db, baseURL)

	// 2. 检查是否安全(SafetyGuard)
	if err := guard.AssertSafe(req.Target); err != nil {
		db.Model(req).Update("state", "safety_blocked")
		return err
	}

	// 3. 需要邮件审批 → 生成 token 发送
	if err := approvalSvc.GenTokensAndSend(req, req.RequestedByID); err != nil {
		log.Printf("approval send error: %v", err)
	}

	return nil
}

// JSON 响应格式
type APIResp struct {
	Code int    `json:"code"`
	Msg  string `json:"msg"`
	Data any    `json:"data,omitempty"`
}
