package web

// 用户管理 handler。
//
// 三条硬约束,都在后端强制(界面隐藏按钮只是体验):
//
//  1. **不能删除或停用自己** —— 防止管理员把自己锁在系统外面。
//     这不是理论风险:停用自己后需要直接改数据库才能恢复。
//
//  2. **必须保留至少一个启用的 admin** —— 否则系统进入无人能管理的状态,
//     用户管理页面本身也进不去。
//
//  3. **改密码 / 停用 / 删除都立即吊销该用户全部会话** —— 否则旧 cookie
//     仍然畅通,"停用"变成一句空话。
//
// 另外:删除用户不级联删除他提交过的封禁请求。审计要求可追溯,
// 把历史记录一起删掉等于销毁证据。RequestedByID 会变成悬空引用,
// 界面显示为 "user#<id>"。

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"

	"github.com/xdpban/xdp-ban/internal/model"
	"github.com/xdpban/xdp-ban/internal/policy"
)

// minPasswordLen 与界面 minlength 保持一致。
// 8 位是下限而非推荐值 —— 生产应接 LDAP/SSO 而不是靠本地密码。
const minPasswordLen = 8

// usersList 用户列表。
//
// 关键修正:此前把 Active(账号是否启用)显示成"在线",导致
// 所有启用的账号都被标成在线。现在拆成两列 —— 账号状态来自数据库,
// 当前会话来自 sessionStore。
func (h *Handler) usersList(c *gin.Context) {
	h.renderUsers(c, http.StatusOK, "", "")
}

func (h *Handler) renderUsers(c *gin.Context, code int, errMsg, okMsg string) {
	u := h.currentUser(c)
	var users []model.User
	h.db.Order("id asc").Find(&users)

	c.HTML(code, "users.html", gin.H{
		"u": u, "nav": policy.NavSections(u.Role),
		"users":  users,
		"online": h.sessions.OnlineUsers(),
		"err":    errMsg,
		"ok":     okMsg,
	})
}

// userCreate 新增用户
func (h *Handler) userCreate(c *gin.Context) {
	actor := h.currentUser(c)

	username := strings.TrimSpace(c.PostForm("username"))
	email := strings.TrimSpace(c.PostForm("email"))
	role := strings.TrimSpace(c.PostForm("role"))
	password := c.PostForm("password")

	if username == "" {
		h.renderUsers(c, http.StatusBadRequest, "用户名不能为空", "")
		return
	}
	if !validRole(role) {
		h.renderUsers(c, http.StatusBadRequest, "非法角色: "+role, "")
		return
	}
	if len(password) < minPasswordLen {
		h.renderUsers(c, http.StatusBadRequest,
			fmt.Sprintf("密码至少 %d 位", minPasswordLen), "")
		return
	}

	// 用户名唯一。依赖数据库唯一索引会报出难读的 SQL 错误,这里先查一次。
	var n int64
	h.db.Model(&model.User{}).Where("username = ?", username).Count(&n)
	if n > 0 {
		h.renderUsers(c, http.StatusConflict, "用户名已存在: "+username, "")
		return
	}

	nu := &model.User{
		Username: username, Email: email, Role: role,
		Active: true, AuthSource: "local",
	}
	if err := nu.SetPassword(password); err != nil {
		h.renderUsers(c, http.StatusInternalServerError, "设置密码失败: "+err.Error(), "")
		return
	}
	if err := h.db.Create(nu).Error; err != nil {
		h.renderUsers(c, http.StatusInternalServerError, err.Error(), "")
		return
	}

	_ = model.WriteAudit(h.db, &actor.ID, actor.Label(), "User", itoa(nu.ID),
		"created", fmt.Sprintf("username=%s role=%s", username, role))
	h.renderUsers(c, http.StatusOK, "", "已创建用户 "+username+"(角色 "+role+")")
}

// userChangeRole 修改角色
func (h *Handler) userChangeRole(c *gin.Context) {
	actor := h.currentUser(c)

	target, ok := h.loadTargetUser(c)
	if !ok {
		return
	}
	role := strings.TrimSpace(c.PostForm("role"))
	if !validRole(role) {
		h.renderUsers(c, http.StatusBadRequest, "非法角色: "+role, "")
		return
	}
	if role == target.Role {
		h.renderUsers(c, http.StatusOK, "", "")
		return
	}

	// 降级最后一个 admin 会让系统失去管理能力
	if target.Role == "admin" && role != "admin" && h.countActiveAdmins(target.ID) == 0 {
		h.renderUsers(c, http.StatusConflict,
			"不能降级最后一个启用的 admin —— 系统将失去管理能力", "")
		return
	}

	old := target.Role
	if err := h.db.Model(target).Update("role", role).Error; err != nil {
		h.renderUsers(c, http.StatusInternalServerError, err.Error(), "")
		return
	}

	// 角色变了,已有会话的权限判断依赖 DB 里的 role,下次请求就会生效。
	// 但为了让变更立即可见(且避免用户拿着旧界面误操作),仍吊销会话。
	h.sessions.DeleteByUser(target.ID)

	_ = model.WriteAudit(h.db, &actor.ID, actor.Label(), "User", itoa(target.ID),
		"role_changed", fmt.Sprintf("%s: %s → %s", target.Username, old, role))
	h.renderUsers(c, http.StatusOK, "",
		fmt.Sprintf("%s 的角色已改为 %s(需重新登录)", target.Username, role))
}

// userToggleActive 启用 / 停用
func (h *Handler) userToggleActive(c *gin.Context) {
	actor := h.currentUser(c)

	target, ok := h.loadTargetUser(c)
	if !ok {
		return
	}
	if target.ID == actor.ID {
		h.renderUsers(c, http.StatusForbidden,
			"不能停用自己的账号 —— 那会把你锁在系统外面", "")
		return
	}

	// 停用最后一个 admin 同样会让系统失去管理能力
	if target.Active && target.Role == "admin" && h.countActiveAdmins(target.ID) == 0 {
		h.renderUsers(c, http.StatusConflict,
			"不能停用最后一个启用的 admin", "")
		return
	}

	newState := !target.Active
	if err := h.db.Model(target).Update("active", newState).Error; err != nil {
		h.renderUsers(c, http.StatusInternalServerError, err.Error(), "")
		return
	}

	verb := "enabled"
	msg := "已启用 " + target.Username
	if !newState {
		verb = "disabled"
		msg = "已停用 " + target.Username + ",其会话已吊销"
		// 停用必须立即吊销会话,否则"停用"只是数据库里的一个字段
		h.sessions.DeleteByUser(target.ID)
	}

	_ = model.WriteAudit(h.db, &actor.ID, actor.Label(), "User", itoa(target.ID),
		verb, target.Username)
	h.renderUsers(c, http.StatusOK, "", msg)
}

// userDelete 删除用户。
//
// 不级联删除其提交过的封禁请求 —— 审计要可追溯,删历史等于销毁证据。
// 那些记录的 RequestedByID 会成为悬空引用,报告里显示 "user#<id>"。
func (h *Handler) userDelete(c *gin.Context) {
	actor := h.currentUser(c)

	target, ok := h.loadTargetUser(c)
	if !ok {
		return
	}
	if target.ID == actor.ID {
		h.renderUsers(c, http.StatusForbidden, "不能删除自己的账号", "")
		return
	}
	if target.Role == "admin" && h.countActiveAdmins(target.ID) == 0 {
		h.renderUsers(c, http.StatusConflict, "不能删除最后一个启用的 admin", "")
		return
	}

	name := target.Username
	// 先记审计再删:删掉之后 target.ID 对应的用户已不存在,
	// 但审计需要留下"谁删了谁"这条记录。
	_ = model.WriteAudit(h.db, &actor.ID, actor.Label(), "User", itoa(target.ID),
		"deleted", name)

	if err := h.db.Delete(target).Error; err != nil {
		h.renderUsers(c, http.StatusInternalServerError, err.Error(), "")
		return
	}
	h.sessions.DeleteByUser(target.ID)

	h.renderUsers(c, http.StatusOK, "",
		"已删除用户 "+name+"(其历史封禁记录保留在审计中)")
}

// userChangePassword 重置密码
func (h *Handler) userChangePassword(c *gin.Context) {
	actor := h.currentUser(c)

	target, ok := h.loadTargetUser(c)
	if !ok {
		return
	}
	newPwd := c.PostForm("password")
	if len(newPwd) < minPasswordLen {
		h.renderUsers(c, http.StatusBadRequest,
			fmt.Sprintf("密码至少 %d 位", minPasswordLen), "")
		return
	}

	if err := target.SetPassword(newPwd); err != nil {
		h.renderUsers(c, http.StatusInternalServerError, err.Error(), "")
		return
	}
	if err := h.db.Model(target).Update("password_hash", target.PasswordHash).Error; err != nil {
		h.renderUsers(c, http.StatusInternalServerError, err.Error(), "")
		return
	}
	// 改密必须吊销已有会话,否则旧 cookie 仍然畅通
	h.sessions.DeleteByUser(target.ID)

	_ = model.WriteAudit(h.db, &actor.ID, actor.Label(), "User", itoa(target.ID),
		"password_changed", target.Username)

	msg := "已重置 " + target.Username + " 的密码,其会话已吊销"
	if target.ID == actor.ID {
		msg = "密码已修改,请重新登录"
	}
	h.renderUsers(c, http.StatusOK, "", msg)
}

// ---- 辅助 ----

func (h *Handler) loadTargetUser(c *gin.Context) (*model.User, bool) {
	var target model.User
	if h.db.First(&target, c.Param("id")).Error != nil {
		h.renderUsers(c, http.StatusNotFound, "用户不存在", "")
		return nil, false
	}
	return &target, true
}

// countActiveAdmins 统计除 excludeID 之外还有几个启用的 admin。
// 用于判断"这是不是最后一个 admin"。
func (h *Handler) countActiveAdmins(excludeID uint) int {
	var n int64
	h.db.Model(&model.User{}).
		Where("role = ? AND active = ? AND id <> ?", "admin", true, excludeID).
		Count(&n)
	return int(n)
}

func validRole(role string) bool {
	for _, r := range policy.Roles {
		if r == role {
			return true
		}
	}
	return false
}
