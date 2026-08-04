package web

import (
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/gin-gonic/gin"

	"github.com/xdpban/xdp-ban/internal/model"
	"github.com/xdpban/xdp-ban/internal/policy"
	"github.com/xdpban/xdp-ban/internal/prefixdb"
)

// maxUploadSize 上传文件上限。
// iptoasn 的 v4 库压缩后约 10 MB、解压 40 MB+;留到 256 MB
// 以容纳含 IPv6 的合并库与未压缩上传。
const maxUploadSize = 256 << 20

// prefixDBPage IP 库管理页
func (h *Handler) prefixDBPage(c *gin.Context) {
	u := h.currentUser(c)

	data := gin.H{
		"u": u, "nav": policy.NavSections(u.Role),
		"sources":      prefixdb.Sources,
		"syncStatus":   prefixdb.Status(),
		"dataDir":      prefixdb.DataDir(),
		"overridePath": prefixdb.OverridePath(),
		"canManage":    policy.Allow(u.Role, policy.SystemConfig),
	}
	if db := prefixdb.Global(); db != nil {
		data["stats"] = db.Stats()
	}
	// 本地覆盖文件内容直接放进文本框编辑 —— 这个文件是给人手写的,
	// 做成结构化表单反而不如直接编辑文本高效(运维习惯 vim 那套)
	if b, err := os.ReadFile(prefixdb.OverridePath()); err == nil {
		data["overrideText"] = string(b)
	}
	c.HTML(http.StatusOK, "prefixdb.html", data)
}

// prefixDBSync 从选定上游同步
func (h *Handler) prefixDBSync(c *gin.Context) {
	u := h.currentUser(c)

	src, ok := prefixdb.SourceByID(c.PostForm("source"))
	if !ok {
		c.HTML(http.StatusBadRequest, "error.html", gin.H{"msg": "未知数据源"})
		return
	}

	// 同步可能耗时数分钟(下载 + 解析 120 万条),放后台并让界面轮询状态。
	// 同步阻塞 HTTP 请求会撞上反向代理的超时,用户看到 504 却不知道
	// 后台其实还在跑。
	go func() {
		if err := prefixdb.SyncFrom(src); err != nil {
			_ = model.WriteAudit(h.db, &u.ID, u.Label(), "PrefixDB", src.ID,
				"sync_failed", err.Error())
			return
		}
		detail := ""
		if db := prefixdb.Global(); db != nil {
			st := db.Stats()
			detail = fmt.Sprintf("entries=%d countries=%d asns=%d",
				st.Entries, st.Countries, st.ASNs)
		}
		_ = model.WriteAudit(h.db, &u.ID, u.Label(), "PrefixDB", src.ID, "synced", detail)
	}()

	_ = model.WriteAudit(h.db, &u.ID, u.Label(), "PrefixDB", src.ID, "sync_started", src.URL)
	c.Redirect(http.StatusFound, "/prefixdb")
}

// prefixDBStatus 供界面轮询同步进度
func (h *Handler) prefixDBStatus(c *gin.Context) {
	st := prefixdb.Status()
	resp := gin.H{
		"in_progress": st.InProgress,
		"source":      st.SourceID,
		"bytes":       st.BytesRead,
		"entries":     st.Entries,
		"error":       st.Err,
	}
	if db := prefixdb.Global(); db != nil {
		s := db.Stats()
		resp["loaded_entries"] = s.Entries
		resp["loaded_at"] = s.LoadedAt
	}
	c.JSON(http.StatusOK, resp)
}

// prefixDBUpload 处理离线上传。
//
// 这是隔离网环境的主路径,不是退路:很多政企客户的运维网段根本不出网,
// 只能在别处下载再拷进来。
func (h *Handler) prefixDBUpload(c *gin.Context) {
	u := h.currentUser(c)

	fh, err := c.FormFile("dbfile")
	if err != nil {
		c.HTML(http.StatusBadRequest, "error.html", gin.H{"msg": "请选择要上传的文件"})
		return
	}
	if fh.Size > maxUploadSize {
		c.HTML(http.StatusRequestEntityTooLarge, "error.html", gin.H{
			"msg": fmt.Sprintf("文件过大(%.1f MB),上限 %d MB",
				float64(fh.Size)/(1<<20), maxUploadSize>>20)})
		return
	}

	format := c.PostForm("format")
	if format == "" {
		format = "ip2asn_tsv"
	}

	f, err := fh.Open()
	if err != nil {
		c.HTML(http.StatusInternalServerError, "error.html", gin.H{"msg": err.Error()})
		return
	}
	defer f.Close()

	n, err := prefixdb.ImportUpload(f, format)
	if err != nil {
		_ = model.WriteAudit(h.db, &u.ID, u.Label(), "PrefixDB", "upload",
			"upload_failed", err.Error())
		c.HTML(http.StatusBadRequest, "error.html", gin.H{"msg": err.Error()})
		return
	}

	detail := fmt.Sprintf("file=%s size=%d format=%s entries=%d",
		fh.Filename, fh.Size, format, n)
	_ = model.WriteAudit(h.db, &u.ID, u.Label(), "PrefixDB", "upload", "uploaded", detail)
	c.Redirect(http.StatusFound, "/prefixdb")
}

// prefixDBSaveOverride 保存本地优先规则。
//
// 先校验再落盘:写坏的覆盖文件会让下次启动时整库加载报错。
// 校验失败时原文件保持不动,并把错误行号告诉用户。
func (h *Handler) prefixDBSaveOverride(c *gin.Context) {
	u := h.currentUser(c)
	text := c.PostForm("overrides")

	if err := prefixdb.ValidateOverrides(strings.NewReader(text)); err != nil {
		c.HTML(http.StatusBadRequest, "error.html", gin.H{
			"msg": "本地规则格式有误,未保存:" + err.Error()})
		return
	}

	if err := os.MkdirAll(prefixdb.DataDir(), 0o755); err != nil {
		c.HTML(http.StatusInternalServerError, "error.html", gin.H{"msg": err.Error()})
		return
	}
	if err := os.WriteFile(prefixdb.OverridePath(), []byte(text), 0o644); err != nil {
		c.HTML(http.StatusInternalServerError, "error.html", gin.H{"msg": err.Error()})
		return
	}

	// 立即重载使规则生效。主库不存在时只保存文件,不报错 ——
	// 用户可能先写规则再导入库。
	reloadNote := ""
	if err := prefixdb.Reload(); err != nil {
		reloadNote = " (主库尚未导入,规则将在导入后生效)"
	}

	_ = model.WriteAudit(h.db, &u.ID, u.Label(), "PrefixDB", "overrides",
		"overrides_saved", fmt.Sprintf("bytes=%d%s", len(text), reloadNote))
	c.Redirect(http.StatusFound, "/prefixdb")
}
