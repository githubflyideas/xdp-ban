package web

import (
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/xdpban/xdp-ban/internal/model"
	"github.com/xdpban/xdp-ban/internal/policy"
	"github.com/xdpban/xdp-ban/internal/report"
)

// reportPage 合规报告导出页
func (h *Handler) reportPage(c *gin.Context) {
	u := h.currentUser(c)
	now := time.Now()
	c.HTML(http.StatusOK, "report.html", gin.H{
		"u": u, "nav": policy.NavSections(u.Role),
		// 默认给上个自然月:测评通常按月或按季取证
		"defaultFrom": firstOfLastMonth(now).Format("2006-01-02"),
		"defaultTo":   now.Format("2006-01-02"),
	})
}

// reportExport 生成并下载报告。
//
// 导出本身也是一次特权操作:报告包含全部封禁历史与审批人姓名,
// 所以要记审计 —— 谁在什么时候取走了哪个区间的证据。
func (h *Handler) reportExport(c *gin.Context) {
	u := h.currentUser(c)

	from, to, err := parseDateRange(c.Query("from"), c.Query("to"))
	if err != nil {
		c.HTML(http.StatusBadRequest, "error.html", gin.H{"msg": err.Error()})
		return
	}

	format := c.Query("format")
	if format != "csv" && format != "html" {
		format = "html"
	}

	sum, rows, err := report.Build(h.db, report.Filter{From: from, To: to}, u.Username)
	if err != nil {
		c.HTML(http.StatusInternalServerError, "error.html", gin.H{"msg": err.Error()})
		return
	}

	detail := fmt.Sprintf("format=%s from=%s to=%s rows=%d",
		format, from.Format("2006-01-02"), to.Format("2006-01-02"), len(rows))
	_ = model.WriteAudit(h.db, &u.ID, u.Label(), "ComplianceReport", "-", "exported", detail)

	stamp := from.Format("20060102") + "-" + to.Format("20060102")

	if format == "csv" {
		c.Header("Content-Type", "text/csv; charset=utf-8")
		c.Header("Content-Disposition",
			`attachment; filename="xdpban-compliance-`+stamp+`.csv"`)
		if err := report.WriteCSV(c.Writer, sum, rows); err != nil {
			// 响应头已发出,无法再改状态码,只能记日志
			_ = model.WriteAudit(h.db, &u.ID, u.Label(), "ComplianceReport", "-",
				"export_failed", err.Error())
		}
		return
	}

	// HTML 在浏览器里打开(不下载),用户点打印即得 PDF
	c.Header("Content-Type", "text/html; charset=utf-8")
	if err := report.WriteHTML(c.Writer, sum, rows); err != nil {
		_ = model.WriteAudit(h.db, &u.ID, u.Label(), "ComplianceReport", "-",
			"export_failed", err.Error())
	}
}

func parseDateRange(fromStr, toStr string) (time.Time, time.Time, error) {
	const layout = "2006-01-02"
	now := time.Now()

	from := firstOfLastMonth(now)
	if fromStr != "" {
		t, err := time.ParseInLocation(layout, fromStr, time.Local)
		if err != nil {
			return time.Time{}, time.Time{}, fmt.Errorf("起始日期格式应为 YYYY-MM-DD:%q", fromStr)
		}
		from = t
	}

	to := now
	if toStr != "" {
		t, err := time.ParseInLocation(layout, toStr, time.Local)
		if err != nil {
			return time.Time{}, time.Time{}, fmt.Errorf("结束日期格式应为 YYYY-MM-DD:%q", toStr)
		}
		// 含当天:用户填 2026-08-05 意思是"到 8 月 5 日结束",不是"到 0 点"
		to = t.Add(24*time.Hour - time.Nanosecond)
	}

	if to.Before(from) {
		return time.Time{}, time.Time{}, fmt.Errorf("结束日期早于起始日期")
	}
	return from, to, nil
}

func firstOfLastMonth(now time.Time) time.Time {
	y, m, _ := now.Date()
	return time.Date(y, m, 1, 0, 0, 0, 0, now.Location()).AddDate(0, -1, 0)
}
