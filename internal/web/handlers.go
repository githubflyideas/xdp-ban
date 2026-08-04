// Package web —— Gin 路由、认证、按角色的界面。权限后端强制(小测铁律)。
package web

import (
	"io"
	"log"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"

	"github.com/xdpban/xdp-ban/internal/approval"
	"github.com/xdpban/xdp-ban/internal/model"
	"github.com/xdpban/xdp-ban/internal/policy"
)

type Handler struct {
	db        *gorm.DB
	approvals *approval.Service
	// samplerURL 是 xdp-sampler 的控制端点,用于下发采样率
	samplerURL string
}

// 极简会话:内存 token→userID(单机单实例;生产可换 cookie 签名/Redis)
var sessions = map[string]uint{}

func Register(r *gin.Engine, db *gorm.DB) {
	baseURL := envOr("XDPBAN_BASE_URL", "http://localhost:8080")
	h := &Handler{
		db:         db,
		approvals:  approval.NewService(db, baseURL),
		samplerURL: envOr("XDPBAN_SAMPLER_URL", "http://localhost:9090"),
	}
	r.SetHTMLTemplate(templates())

	r.GET("/login", h.loginPage)
	r.POST("/login", h.doLogin)
	r.GET("/logout", h.logout)

	// 对外审批端点(唯一公网路由;部署时单独暴露 + HTTPS + 限流)
	r.GET("/approve/:token", h.approveShow)
	r.POST("/approve/:token", h.approveDo)

	// 静态资源
	r.StaticFile("/favicon.ico", "favicon.ico")

	auth := r.Group("/", h.requireLogin)
	{
		auth.GET("/", h.dashboard)
		auth.GET("/dashboard", h.dashboard)
		auth.GET("/bans", h.requireCap(policy.BanRequestView), h.bansList)
		auth.GET("/bans/new", h.requireCap(policy.BanRequestCreate), h.banNew)
		auth.POST("/bans", h.requireCap(policy.BanRequestCreate), h.banCreate)
		auth.POST("/bans/:id/approve", h.requireCap(policy.BanRequestApprove), h.banApprove)
		auth.POST("/bans/:id/reject", h.requireCap(policy.BanRequestReject), h.banReject)
		auth.GET("/bans/:id", h.requireCap(policy.BanRequestView), h.banDetail)

		// 采样管理(新增)
		auth.GET("/sampling", h.requireCap(policy.DashboardView), h.samplingConfig)
		auth.POST("/api/sampling/rate", h.requireCap(policy.SystemConfig), h.setSamplingRate)

		// 用户管理(admin only)
		auth.GET("/users", h.requireCap(policy.UserManage), h.usersList)
		auth.POST("/users/:id/password", h.requireCap(policy.UserManage), h.userChangePassword)

		// 审计日志(仅查看)
		auth.GET("/audit", h.requireCap(policy.AuditView), h.auditLog)
	}
}

// ---- 认证 ----
func (h *Handler) currentUser(c *gin.Context) *model.User {
	tok, err := c.Cookie("sid")
	if err != nil {
		return nil
	}
	uid, ok := sessions[tok]
	if !ok {
		return nil
	}
	var u model.User
	if h.db.First(&u, uid).Error != nil || !u.Active {
		return nil
	}
	return &u
}

func (h *Handler) requireLogin(c *gin.Context) {
	if h.currentUser(c) == nil {
		c.Redirect(http.StatusFound, "/login")
		c.Abort()
	}
}

// requireCap 后端强制权限(前端隐藏只是体验,这里才是墙)
func (h *Handler) requireCap(cap policy.Capability) gin.HandlerFunc {
	return func(c *gin.Context) {
		u := h.currentUser(c)
		if u == nil || !policy.Allow(u.Role, cap) {
			c.HTML(http.StatusForbidden, "error.html", gin.H{"msg": "无权限执行此操作"})
			c.Abort()
		}
	}
}

func (h *Handler) loginPage(c *gin.Context) {
	c.HTML(http.StatusOK, "login.html", gin.H{})
}

func (h *Handler) doLogin(c *gin.Context) {
	var u model.User
	err := h.db.Where("username = ? AND active = ?", c.PostForm("username"), true).First(&u).Error
	if err != nil || u.AuthSource != "local" || !u.CheckPassword(c.PostForm("password")) {
		c.HTML(http.StatusUnauthorized, "login.html", gin.H{"err": "用户名或密码错误,或账号已停用"})
		return
	}
	tok := randToken()
	sessions[tok] = u.ID
	c.SetCookie("sid", tok, 3600*8, "/", "", false, true)
	now := time.Now()
	h.db.Model(&u).Update("last_login_at", now)
	model.WriteAudit(h.db, &u.ID, u.Label(), "User", itoa(u.ID), "login", "")
	c.Redirect(http.StatusFound, "/dashboard")
}

func (h *Handler) logout(c *gin.Context) {
	if tok, err := c.Cookie("sid"); err == nil {
		delete(sessions, tok)
	}
	c.Redirect(http.StatusFound, "/login")
}

// ---- Dashboard ----
func (h *Handler) dashboard(c *gin.Context) {
	u := h.currentUser(c)
	var pending, active, failed int64
	h.db.Model(&model.BanRequest{}).Where("state = ?", "pending").Count(&pending)
	h.db.Model(&model.BanRequest{}).Where("state = ?", "active").Count(&active)
	h.db.Model(&model.Dispatch{}).Where("state = ?", "failed").Count(&failed)
	c.HTML(http.StatusOK, "dashboard.html", gin.H{
		"u": u, "nav": policy.NavSections(u.Role),
		"pending": pending, "active": active, "failed": failed,
		"canCreate": policy.Allow(u.Role, policy.BanRequestCreate),
	})
}

// ---- 封禁请求 ----
func (h *Handler) bansList(c *gin.Context) {
	u := h.currentUser(c)
	var reqs []model.BanRequest
	h.db.Order("created_at desc").Limit(200).Find(&reqs)
	c.HTML(http.StatusOK, "bans.html", gin.H{
		"u": u, "nav": policy.NavSections(u.Role), "reqs": reqs,
		"canCreate":  policy.Allow(u.Role, policy.BanRequestCreate),
		"canApprove": policy.Allow(u.Role, policy.BanRequestApprove),
	})
}

func (h *Handler) banNew(c *gin.Context) {
	u := h.currentUser(c)
	c.HTML(http.StatusOK, "ban_new.html", gin.H{"u": u, "nav": policy.NavSections(u.Role)})
}

func (h *Handler) banCreate(c *gin.Context) {
	u := h.currentUser(c)
	target := strings.TrimSpace(c.PostForm("target"))
	nav := policy.NavSections(u.Role)

	if target == "" {
		c.HTML(http.StatusBadRequest, "ban_new.html", gin.H{"u": u, "nav": nav, "err": "目标不能为空"})
		return
	}

	// 提交阶段就做一次安全预检:被保护集覆盖的目标根本不该进审批队列,
	// 让提交者立刻知道原因,而不是等审批后才在下发环节静默失败。
	if reason := h.guard().VetoReason(target); reason != "" {
		c.HTML(http.StatusBadRequest, "ban_new.html", gin.H{"u": u, "nav": nav, "err": reason})
		return
	}

	// 阶梯封禁:按该目标的历史决定本次 TTL
	ttl := h.nextTTL(target)

	req := model.BanRequest{
		ActionType: "ban", Target: target, Source: "manual",
		Reason: strings.TrimSpace(c.PostForm("reason")), State: "pending",
		RequestedByID: &u.ID, ApprovalMode: "manual_dual",
		TTLSeconds: ttl,
	}
	if err := h.db.Create(&req).Error; err != nil {
		c.HTML(http.StatusInternalServerError, "ban_new.html", gin.H{"u": u, "nav": nav, "err": err.Error()})
		return
	}
	_ = model.WriteAudit(h.db, &u.ID, u.Label(), "BanRequest", itoa(req.ID), "created", target)

	// 生成邮件审批令牌并通知 approver(四眼原则由 approval 服务保证不发给提交者)
	if err := h.approvals.GenTokensAndSend(&req, &u.ID); err != nil {
		log.Printf("发送审批通知失败 req=%d: %v", req.ID, err)
	}

	c.Redirect(http.StatusFound, "/bans")
}

func (h *Handler) banApprove(c *gin.Context) {
	u := h.currentUser(c)
	var req model.BanRequest
	if h.db.First(&req, c.Param("id")).Error != nil {
		c.Redirect(http.StatusFound, "/bans")
		return
	}

	// 四眼原则
	if req.RequestedByID != nil && *req.RequestedByID == u.ID {
		c.HTML(http.StatusForbidden, "error.html", gin.H{"msg": "不能审批自己提交的请求(四眼原则)"})
		return
	}
	if req.State != "pending" {
		c.HTML(http.StatusConflict, "error.html", gin.H{"msg": "该请求已处理,当前状态:" + req.State})
		return
	}

	now := time.Now()
	updates := map[string]any{
		"state":          "active",
		"approved_by_id": u.ID,
		"effective_at":   now,
	}
	if req.TTLSeconds != nil && *req.TTLSeconds > 0 {
		expires := now.Add(time.Duration(*req.TTLSeconds) * time.Second)
		updates["expires_at"] = expires
	}
	if err := h.db.Model(&req).Updates(updates).Error; err != nil {
		c.HTML(http.StatusInternalServerError, "error.html", gin.H{"msg": err.Error()})
		return
	}
	req.ApprovedByID = &u.ID
	_ = model.WriteAudit(h.db, &u.ID, u.Label(), "BanRequest", itoa(req.ID), "approved", "")

	// 生成下发指令:SafetyGuard 在此处是最后一道否决,无旁路
	if _, explain, err := h.dispatches().CreateDispatch(&req); err != nil {
		c.HTML(http.StatusForbidden, "error.html", gin.H{"msg": explain})
		return
	}

	// 推进阶梯状态,使下一次封禁时长自然增长
	h.recordLadder(req.Target)

	c.Redirect(http.StatusFound, "/bans")
}

func (h *Handler) banReject(c *gin.Context) {
	u := h.currentUser(c)
	var req model.BanRequest
	if h.db.First(&req, c.Param("id")).Error == nil {
		h.db.Model(&req).Update("state", "rejected")
		model.WriteAudit(h.db, &u.ID, u.Label(), "BanRequest", itoa(req.ID), "rejected", "")
	}
	c.Redirect(http.StatusFound, "/bans")
}

// banDetail 查看详情
func (h *Handler) banDetail(c *gin.Context) {
	u := h.currentUser(c)
	var req model.BanRequest
	if h.db.First(&req, c.Param("id")).Error != nil {
		c.Redirect(http.StatusFound, "/bans")
		return
	}
	var approver model.User
	if req.ApprovedByID != nil {
		h.db.First(&approver, *req.ApprovedByID)
	}
	c.HTML(http.StatusOK, "ban_detail.html", gin.H{
		"u": u, "nav": policy.NavSections(u.Role),
		"req": req, "approver": approver,
		"canApprove": policy.Allow(u.Role, policy.BanRequestApprove) && req.State == "pending",
	})
}

// ---- 用户管理 ----
func (h *Handler) usersList(c *gin.Context) {
	u := h.currentUser(c)
	var users []model.User
	h.db.Find(&users)
	c.HTML(http.StatusOK, "users.html", gin.H{
		"u": u, "nav": policy.NavSections(u.Role), "users": users,
	})
}

func (h *Handler) userChangePassword(c *gin.Context) {
	u := h.currentUser(c)
	var target model.User
	if h.db.First(&target, c.Param("id")).Error != nil {
		c.HTML(http.StatusNotFound, "error.html", gin.H{"msg": "用户不存在"})
		return
	}
	newPwd := c.PostForm("password")
	if newPwd == "" {
		c.HTML(http.StatusBadRequest, "error.html", gin.H{"msg": "密码不能为空"})
		return
	}
	_ = target.SetPassword(newPwd)
	h.db.Model(&target).Update("password_hash", target.PasswordHash)
	model.WriteAudit(h.db, &u.ID, u.Label(), "User", itoa(target.ID), "password_changed", "")
	c.Redirect(http.StatusFound, "/users")
}

// ---- 审计日志 ----
func (h *Handler) auditLog(c *gin.Context) {
	u := h.currentUser(c)
	var logs []model.AuditLog
	h.db.Order("occurred_at desc").Limit(500).Find(&logs)
	c.HTML(http.StatusOK, "audit.html", gin.H{
		"u": u, "nav": policy.NavSections(u.Role), "logs": logs,
	})
}

// ---- 采样管理 ----

// samplingConfig 展示采样配置页:当前采样率 + 最近观测到的流量。
func (h *Handler) samplingConfig(c *gin.Context) {
	u := h.currentUser(c)
	c.HTML(http.StatusOK, "sampling.html", gin.H{
		"u": u, "nav": policy.NavSections(u.Role),
		"canConfigure": policy.Allow(u.Role, policy.SystemConfig),
		"samplerURL":   h.samplerURL,
		"currentN":     SampleStore.SamplingN(),
		"topFlows":     SampleStore.TopFlows(5*time.Minute, 20),
	})
}

// setSamplingRate 把新的采样率转发给 xdp-sampler 的控制端点。
//
// xdp-ban 自己不碰 eBPF map——采样器才是那份 map 的持有者;
// 这里只做校验、转发、审计。
func (h *Handler) setSamplingRate(c *gin.Context) {
	u := h.currentUser(c)

	rate, err := parseRate(c.PostForm("rate"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	samplerURL := strings.TrimSpace(c.PostForm("sampler_url"))
	if samplerURL == "" {
		samplerURL = h.samplerURL
	}

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.PostForm(samplerURL+"/api/sampling/rate", url.Values{
		"rate": {strconv.Itoa(rate)},
	})
	if err != nil {
		c.JSON(http.StatusBadGateway, gin.H{"error": "无法连接采样器: " + err.Error()})
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		c.JSON(http.StatusBadGateway, gin.H{
			"error": "采样器拒绝请求: " + strings.TrimSpace(string(body)),
		})
		return
	}

	_ = model.WriteAudit(h.db, &u.ID, u.Label(), "SamplingConfig", "1",
		"rate_changed", strconv.Itoa(rate))

	c.JSON(http.StatusOK, gin.H{"ok": true, "rate": rate})
}

// ---- 对外审批(唯一公网路由;部署时单独暴露 + HTTPS + 限流)----
func (h *Handler) approveShow(c *gin.Context) {
	var token model.ApprovalToken
	if h.db.Where("token = ? AND expires_at > ? AND used_at IS NULL", c.Param("token"), time.Now()).First(&token).Error != nil {
		c.HTML(http.StatusNotFound, "error.html", gin.H{"msg": "审批链接已失效或已使用"})
		return
	}
	var req model.BanRequest
	h.db.First(&req, token.BanRequestID)
	c.HTML(http.StatusOK, "approve.html", gin.H{"token": token, "req": req})
}

func (h *Handler) approveDo(c *gin.Context) {
	action := c.PostForm("action") // approve / reject
	if action != "approve" && action != "reject" {
		c.HTML(http.StatusBadRequest, "error.html", gin.H{"msg": "非法操作"})
		return
	}

	now := time.Now()
	var token model.ApprovalToken
	var req model.BanRequest

	// 令牌消费与状态推进放在一个事务里:
	// used_at 的写入必须与审批结果同生共死,否则重放窗口会打开。
	err := h.db.Transaction(func(tx *gorm.DB) error {
		if err := tx.Where("token = ? AND expires_at > ? AND used_at IS NULL",
			c.Param("token"), now).First(&token).Error; err != nil {
			return err
		}
		if err := tx.First(&req, token.BanRequestID).Error; err != nil {
			return err
		}
		if req.State != "pending" {
			return errStateConflict
		}
		// 四眼原则:令牌本不该发给提交者,这里再兜一道
		if req.RequestedByID != nil && *req.RequestedByID == token.ApproverID {
			return errSelfApproval
		}

		if err := tx.Model(&token).Update("used_at", now).Error; err != nil {
			return err
		}

		if action == "approve" {
			updates := map[string]any{
				"state":              "active",
				"approved_by_id":     token.ApproverID,
				"approved_by_policy": "email_link",
				"effective_at":       now,
			}
			if req.TTLSeconds != nil && *req.TTLSeconds > 0 {
				updates["expires_at"] = now.Add(time.Duration(*req.TTLSeconds) * time.Second)
			}
			return tx.Model(&req).Updates(updates).Error
		}
		return tx.Model(&req).Update("state", "rejected").Error
	})

	switch {
	case err == errSelfApproval:
		c.HTML(http.StatusForbidden, "error.html", gin.H{"msg": "不能审批自己提交的请求(四眼原则)"})
		return
	case err == errStateConflict:
		c.HTML(http.StatusConflict, "error.html", gin.H{"msg": "该请求已被处理"})
		return
	case err != nil:
		c.HTML(http.StatusNotFound, "error.html", gin.H{"msg": "审批链接已失效或已使用"})
		return
	}

	actor := "approver:" + itoa(token.ApproverID)
	if action == "approve" {
		_ = model.WriteAudit(h.db, &token.ApproverID, actor, "BanRequest", itoa(req.ID), "approved_external", "")
		req.ApprovedByID = &token.ApproverID
		if _, explain, derr := h.dispatches().CreateDispatch(&req); derr != nil {
			c.HTML(http.StatusForbidden, "error.html", gin.H{"msg": explain})
			return
		}
		h.recordLadder(req.Target)
	} else {
		_ = model.WriteAudit(h.db, &token.ApproverID, actor, "BanRequest", itoa(req.ID), "rejected_external", "")
	}

	c.HTML(http.StatusOK, "approve_done.html", gin.H{"action": action, "success": true})
}
