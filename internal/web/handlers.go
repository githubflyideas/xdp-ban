// Package web —— Gin 路由、认证、按角色的界面。权限后端强制(小测铁律)。
package web

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"

	"github.com/xdpban/xdp-ban/internal/model"
	"github.com/xdpban/xdp-ban/internal/policy"
)

type Handler struct{ db *gorm.DB }

// 极简会话:内存 token→userID(单机单实例;生产可换 cookie 签名/Redis)
var sessions = map[string]uint{}

func Register(r *gin.Engine, db *gorm.DB) {
	h := &Handler{db: db}
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
	req := model.BanRequest{
		ActionType: "ban", Target: c.PostForm("target"), Source: "manual",
		Reason: c.PostForm("reason"), State: "pending", RequestedByID: &u.ID,
		ApprovalMode: "manual_dual",
	}
	if req.Target == "" {
		c.HTML(http.StatusBadRequest, "ban_new.html", gin.H{"u": u, "nav": policy.NavSections(u.Role), "err": "目标不能为空"})
		return
	}
	h.db.Create(&req)
	model.WriteAudit(h.db, &u.ID, u.Label(), "BanRequest", itoa(req.ID), "created", "")
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
	now := time.Now()
	h.db.Model(&req).Updates(map[string]any{"state": "active", "approved_by_id": u.ID, "effective_at": now})
	model.WriteAudit(h.db, &u.ID, u.Label(), "BanRequest", itoa(req.ID), "approved", "")
	// TODO: DispatchService 生成 dispatch → 经 SafetyGuard → 下发 agent
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
func (h *Handler) samplingConfig(c *gin.Context) {
	u := h.currentUser(c)
	c.HTML(http.StatusOK, "sampling.html", gin.H{
		"u": u, "nav": policy.NavSections(u.Role),
		"canConfigure": policy.Allow(u.Role, policy.SystemConfig),
	})
}

func (h *Handler) setSamplingRate(c *gin.Context) {
	u := h.currentUser(c)
	rate := c.PostForm("rate")
	if rate == "" {
		c.JSON(400, gin.H{"error": "rate required"})
		return
	}

	// 转发到 xdp-sampler 的 HTTP API
	samplerURL := c.PostForm("sampler_url")
	if samplerURL == "" {
		samplerURL = "http://localhost:9090"  // 默认
	}

	// 调用 xdp-sampler /api/sampling/rate
	resp, err := http.PostForm(samplerURL+"/api/sampling/rate", map[string][]string{
		"rate": {rate},
	})
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	defer resp.Body.Close()

	// 审计
	model.WriteAudit(h.db, &u.ID, u.Label(), "SamplingConfig", "1", "rate_changed", rate)

	c.JSON(200, gin.H{"ok": true, "rate": rate})
}

// ---- 对外审批(占位;完整六铁律逻辑复用 internal/approval)----
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
	var token model.ApprovalToken
	if h.db.Where("token = ? AND expires_at > ? AND used_at IS NULL", c.Param("token"), time.Now()).First(&token).Error != nil {
		c.HTML(http.StatusNotFound, "error.html", gin.H{"msg": "审批链接已失效或已使用"})
		return
	}
	var req model.BanRequest
	if h.db.First(&req, token.BanRequestID).Error != nil {
		c.HTML(http.StatusNotFound, "error.html", gin.H{"msg": "请求不存在"})
		return
	}

	action := c.PostForm("action") // approve / reject
	now := time.Now()
	h.db.Model(&token).Update("used_at", now)

	if action == "approve" {
		h.db.Model(&req).Updates(map[string]any{
			"state":               "active",
			"approved_by_id":      token.ApproverID,
			"approved_by_policy":  "email_link",
			"effective_at":        now,
		})
		model.WriteAudit(h.db, &token.ApproverID, "approver:"+itoa(token.ApproverID), "BanRequest", itoa(req.ID), "approved_external", "")
	} else {
		h.db.Model(&req).Update("state", "rejected")
		model.WriteAudit(h.db, &token.ApproverID, "approver:"+itoa(token.ApproverID), "BanRequest", itoa(req.ID), "rejected_external", "")
	}

	c.HTML(http.StatusOK, "approve_done.html", gin.H{"action": action, "success": true})
}
