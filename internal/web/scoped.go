package web

import (
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/xdpban/xdp-ban/internal/model"
	"github.com/xdpban/xdp-ban/internal/policy"
	"github.com/xdpban/xdp-ban/internal/prefixdb"
	"github.com/xdpban/xdp-ban/internal/quota"
)

// scopedBanNew 展示"按国家/AS 封禁"表单
func (h *Handler) scopedBanNew(c *gin.Context) {
	u := h.currentUser(c)
	db := prefixdb.Global()

	data := gin.H{
		"u": u, "nav": policy.NavSections(u.Role),
		"usage": h.quota.Usage(),
	}
	if db == nil {
		data["dbMissing"] = true
		data["dbHint"] = "前缀库未导入。下载 https://iptoasn.com/data/ip2asn-v4.tsv.gz " +
			"后设置 XDPBAN_PREFIX_DB 指向该文件并重启。"
	} else {
		st := db.Stats()
		data["dbStats"] = st
		data["countries"] = db.Countries()
	}
	c.HTML(http.StatusOK, "scoped_new.html", data)
}

// scopedASNSearch 提供 AS 号搜索(界面异步调用)。
// 全球十万级 AS 无法用下拉框穷举,只能搜。
func (h *Handler) scopedASNSearch(c *gin.Context) {
	db := prefixdb.Global()
	if db == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "前缀库未导入"})
		return
	}
	q := strings.TrimSpace(c.Query("q"))
	if len(q) < 2 {
		c.JSON(http.StatusOK, gin.H{"results": []any{}})
		return
	}
	c.JSON(http.StatusOK, gin.H{"results": db.SearchASN(q, 30)})
}

// scopedPreview 提交前的影响面预估。
//
// 这是资源保护的第一道闸:让人在点"提交"之前就看到会占多少表项、
// 覆盖多少地址空间。不做这一步,用户只能靠猜,然后在下发时炸。
func (h *Handler) scopedPreview(c *gin.Context) {
	db := prefixdb.Global()
	if db == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "前缀库未导入"})
		return
	}

	sel, err := parseSelector(c)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	cidrs, err := db.Resolve(sel)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	d := quota.Check(h.quota, cidrs)
	samples := make([]string, 0, 12)
	for i, p := range cidrs {
		if i >= 12 {
			break
		}
		samples = append(samples, p.String())
	}

	c.JSON(http.StatusOK, gin.H{
		"selector":          sel.String(),
		"prefix_count":      d.PrefixCount,
		"address_count":     d.AddressCount,
		"address_share_pct": float64(d.AddressSharePPM) / 10000,
		"allowed":           d.Allowed,
		"requires_override": d.RequiresOverride,
		"reason":            d.Reason,
		"samples":           samples,
		"usage":             h.quota.Usage(),
	})
}

// scopedBanCreate 提交范围封禁请求
func (h *Handler) scopedBanCreate(c *gin.Context) {
	u := h.currentUser(c)
	nav := policy.NavSections(u.Role)
	fail := func(code int, msg string) {
		c.HTML(code, "scoped_new.html", gin.H{
			"u": u, "nav": nav, "err": msg,
			"usage": h.quota.Usage(),
		})
	}

	db := prefixdb.Global()
	if db == nil {
		fail(http.StatusServiceUnavailable, "前缀库未导入,无法按国家/AS 封禁")
		return
	}

	// 目标必须是单台主机。这不是界面偏好,是 XDP 侧数据结构的硬约束:
	// 目标带前缀就需要二维最长匹配,LPM_TRIE 表达不了。
	targetIP, err := parseHostTarget(c.PostForm("target_ip"))
	if err != nil {
		fail(http.StatusBadRequest, err.Error())
		return
	}

	// 目标也要过保护集:别把自己的网关当成"被保护主机"再去封它的全世界来源
	if reason := h.guard().VetoReason(targetIP); reason != "" {
		fail(http.StatusBadRequest, "目标地址被保护集拒绝:"+reason)
		return
	}

	sel, err := parseSelector(c)
	if err != nil {
		fail(http.StatusBadRequest, err.Error())
		return
	}

	cidrs, err := db.Resolve(sel)
	if err != nil {
		fail(http.StatusBadRequest, err.Error())
		return
	}

	d := quota.Check(h.quota, cidrs)
	if !d.Allowed {
		fail(http.StatusBadRequest, d.Reason)
		return
	}
	overrideAck := c.PostForm("override_ack") != ""
	if d.RequiresOverride && !overrideAck {
		fail(http.StatusBadRequest, d.Reason+" 如确认无误,请勾选“我已确认影响范围”后重新提交。")
		return
	}

	// 预占配额。放在创建记录之前:多人同时提交时,先到先得,
	// 避免各自看到充足余量、合起来超限。
	if err := h.quota.Reserve(d.PrefixCount); err != nil {
		fail(http.StatusConflict, err.Error())
		return
	}

	ttl := h.nextTTL(targetIP)
	sb := model.ScopedBan{
		TargetIP:     targetIP,
		Country:      sel.Country,
		ASN:          sel.ASN,
		PrefixCount:  d.PrefixCount,
		AddressCount: d.AddressCount,
		ResolvedAt:   time.Now(),
		Reason:       strings.TrimSpace(c.PostForm("reason")),
		State:        "pending",
		TTLSeconds:   ttl,
		RequestedByID: &u.ID,
		OverrideAck:  overrideAck && d.RequiresOverride,
	}
	if err := h.db.Create(&sb).Error; err != nil {
		h.quota.Release(d.PrefixCount) // 建记录失败要退还额度
		fail(http.StatusInternalServerError, err.Error())
		return
	}

	detail := fmt.Sprintf("scope=%s target=%s prefixes=%d addresses=%d override=%v",
		sel.String(), targetIP, d.PrefixCount, d.AddressCount, sb.OverrideAck)
	_ = model.WriteAudit(h.db, &u.ID, u.Label(), "ScopedBan", itoa(sb.ID), "created", detail)

	c.Redirect(http.StatusFound, "/scoped")
}

// scopedBanList 范围封禁列表
func (h *Handler) scopedBanList(c *gin.Context) {
	u := h.currentUser(c)
	var bans []model.ScopedBan
	h.db.Order("created_at desc").Limit(200).Find(&bans)
	c.HTML(http.StatusOK, "scoped_list.html", gin.H{
		"u": u, "nav": policy.NavSections(u.Role), "bans": bans,
		"usage":      h.quota.Usage(),
		"canCreate":  policy.Allow(u.Role, policy.BanRequestCreate),
		"canApprove": policy.Allow(u.Role, policy.BanRequestApprove),
	})
}

// scopedBanApprove 批准范围封禁,并生成下发指令
func (h *Handler) scopedBanApprove(c *gin.Context) {
	u := h.currentUser(c)
	var sb model.ScopedBan
	if h.db.First(&sb, c.Param("id")).Error != nil {
		c.Redirect(http.StatusFound, "/scoped")
		return
	}
	if sb.RequestedByID != nil && *sb.RequestedByID == u.ID {
		_ = model.WriteAudit(h.db, &u.ID, u.Label(), "ScopedBan", itoa(sb.ID),
			"self_approval_denied", "")
		c.HTML(http.StatusForbidden, "error.html", gin.H{"msg": "不能审批自己提交的请求(四眼原则)"})
		return
	}
	if sb.State != "pending" {
		c.HTML(http.StatusConflict, "error.html", gin.H{"msg": "该请求已处理,当前状态:" + sb.State})
		return
	}

	now := time.Now()
	updates := map[string]any{
		"state": "active", "approved_by_id": u.ID, "effective_at": now,
	}
	if sb.TTLSeconds != nil && *sb.TTLSeconds > 0 {
		updates["expires_at"] = now.Add(time.Duration(*sb.TTLSeconds) * time.Second)
	}
	if err := h.db.Model(&sb).Updates(updates).Error; err != nil {
		c.HTML(http.StatusInternalServerError, "error.html", gin.H{"msg": err.Error()})
		return
	}
	sb.ApprovedByID = &u.ID
	_ = model.WriteAudit(h.db, &u.ID, u.Label(), "ScopedBan", itoa(sb.ID), "approved", sb.Label())

	// 重新展开源前缀并生成下发指令。
	//
	// 为什么此时重新展开而不是用提交时的结果:前缀库可能已更新,
	// 封禁应跟随 BGP 现实。代价是展开数量可能与提交时的配额记账有偏差,
	// 所以这里比对并记录漂移 —— 有偏差时按实际数量修正配额。
	pdb := prefixdb.Global()
	if pdb == nil {
		c.HTML(http.StatusServiceUnavailable, "error.html", gin.H{
			"msg": "前缀库不可用,无法展开源范围。请先在「IP 库管理」导入。"})
		return
	}
	cidrs, err := pdb.Resolve(prefixdb.Selector{Country: sb.Country, ASN: sb.ASN})
	if err != nil {
		c.HTML(http.StatusInternalServerError, "error.html", gin.H{"msg": err.Error()})
		return
	}

	if len(cidrs) != sb.PrefixCount {
		drift := fmt.Sprintf("提交时 %d 条,下发时 %d 条", sb.PrefixCount, len(cidrs))
		_ = model.WriteAudit(h.db, &u.ID, u.Label(), "ScopedBan", itoa(sb.ID),
			"prefix_drift", drift)
		// 按实际数量修正配额占用,否则账面会与内核实际占用长期不符
		h.quota.Release(sb.PrefixCount)
		if err := h.quota.Reserve(len(cidrs)); err != nil {
			h.quota.Reserve(sb.PrefixCount) // 恢复原占用,避免账面归零
			c.HTML(http.StatusConflict, "error.html", gin.H{
				"msg": "前缀库更新后该规则展开量超出配额:" + err.Error()})
			return
		}
		h.db.Model(&sb).Updates(map[string]any{
			"prefix_count": len(cidrs), "resolved_at": now,
		})
	}

	prefixes := make([]string, 0, len(cidrs))
	for _, p := range cidrs {
		prefixes = append(prefixes, p.String())
	}

	if _, explain, err := h.dispatches().CreateScopedDispatch(&sb, prefixes); err != nil {
		c.HTML(http.StatusForbidden, "error.html", gin.H{"msg": explain})
		return
	}

	// 推进阶梯状态,使同一目标下次被攻击时封禁时长自然增长
	h.recordLadder(sb.TargetIP)

	c.Redirect(http.StatusFound, "/scoped")
}

// scopedBanReject 驳回,并退还提交时预占的额度
func (h *Handler) scopedBanReject(c *gin.Context) {
	u := h.currentUser(c)
	var sb model.ScopedBan
	if h.db.First(&sb, c.Param("id")).Error != nil {
		c.Redirect(http.StatusFound, "/scoped")
		return
	}
	if sb.State != "pending" {
		c.Redirect(http.StatusFound, "/scoped")
		return
	}
	h.db.Model(&sb).Update("state", "rejected")
	h.quota.Release(sb.PrefixCount) // 提交时占的额度必须退回
	_ = model.WriteAudit(h.db, &u.ID, u.Label(), "ScopedBan", itoa(sb.ID), "rejected", sb.Label())
	c.Redirect(http.StatusFound, "/scoped")
}

// scopedBanRevoke 撤销并退还配额
func (h *Handler) scopedBanRevoke(c *gin.Context) {
	u := h.currentUser(c)
	var sb model.ScopedBan
	if h.db.First(&sb, c.Param("id")).Error != nil {
		c.Redirect(http.StatusFound, "/scoped")
		return
	}
	// 只有仍在占用额度的状态才需要释放,避免重复 Release 把计数做成负数
	if sb.State != "active" {
		c.Redirect(http.StatusFound, "/scoped")
		return
	}

	now := time.Now()
	h.db.Model(&sb).Updates(map[string]any{"state": "revoked", "revoked_at": now})
	h.quota.Release(sb.PrefixCount)
	_ = model.WriteAudit(h.db, &u.ID, u.Label(), "ScopedBan", itoa(sb.ID), "revoked", sb.Label())
	c.Redirect(http.StatusFound, "/scoped")
}

// ---- 输入解析 ----

// parseHostTarget 目标必须是 IPv4 单主机。
// 显式拒绝 CIDR 而不是"取网络地址"—— 静默改写用户意图比报错危险。
func parseHostTarget(raw string) (string, error) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return "", fmt.Errorf("必须指定目标主机 IP")
	}
	if strings.Contains(s, "/") {
		// 允许 /32 写法,但其余前缀一律拒绝
		ip, netw, err := net.ParseCIDR(s)
		if err != nil {
			return "", fmt.Errorf("目标地址格式非法:%q", raw)
		}
		ones, bits := netw.Mask.Size()
		if bits != 32 || ones != 32 {
			return "", fmt.Errorf("目标只能是单台主机(/32),收到 %q。"+
				"这是 XDP 侧数据结构的限制:目标带前缀需要二维最长匹配,LPM_TRIE 无法表达", raw)
		}
		s = ip.String()
	}
	ip := net.ParseIP(s)
	if ip == nil {
		return "", fmt.Errorf("目标地址格式非法:%q", raw)
	}
	v4 := ip.To4()
	if v4 == nil {
		return "", fmt.Errorf("目标暂不支持 IPv6:%q", raw)
	}
	return v4.String(), nil
}

func parseSelector(c *gin.Context) (prefixdb.Selector, error) {
	country := strings.ToUpper(strings.TrimSpace(c.PostForm("country")))
	if country == "" {
		country = strings.ToUpper(strings.TrimSpace(c.Query("country")))
	}
	asnRaw := strings.TrimSpace(c.PostForm("asn"))
	if asnRaw == "" {
		asnRaw = strings.TrimSpace(c.Query("asn"))
	}

	var asn uint32
	if asnRaw != "" {
		cleaned := strings.TrimPrefix(strings.TrimPrefix(asnRaw, "AS"), "as")
		n, err := strconv.ParseUint(cleaned, 10, 32)
		if err != nil {
			return prefixdb.Selector{}, fmt.Errorf("AS 号格式非法:%q", asnRaw)
		}
		asn = uint32(n)
	}

	if country == "" && asn == 0 {
		return prefixdb.Selector{}, fmt.Errorf("必须至少指定国家或 AS 号")
	}
	return prefixdb.Selector{Country: country, ASN: asn}, nil
}
