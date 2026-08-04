package report

import (
	"html/template"
	"io"
)

// WriteHTML 输出可直接浏览器打印成 PDF 的报告。
//
// 为什么不生成真 PDF:纯 Go 的 PDF 库都要自己处理中文字体嵌入 ——
// 要么把字体打进二进制(几 MB 膨胀,与"单文件部署"冲突),
// 要么在没装对应字体的机器上出方块。浏览器打印用系统字体,
// 中文永不出错,且用户能自选纸张与页边距。
//
// @page 与 print 媒体查询已调好:A4 纵向、表头每页重复、隐藏按钮。
func WriteHTML(w io.Writer, sum *Summary, rows []Row) error {
	return reportTpl.Execute(w, map[string]any{
		"sum":  sum,
		"rows": rows,
	})
}

var reportTpl = template.Must(template.New("report").Funcs(template.FuncMap{
	"kindLabel":  kindLabel,
	"stateLabel": stateLabel,
	"boolLabel":  boolLabel,
	"dash":       dash,
	"timePtr":    timePtr,
	"prefixLbl":  prefixLabel,
}).Parse(reportHTML))

const reportHTML = `<!doctype html><html lang="zh"><head><meta charset="utf-8">
<title>xdp-ban 封禁操作合规报告</title>
<style>
@page { size: A4 portrait; margin: 14mm 10mm; }
body{font-family:-apple-system,"Segoe UI","PingFang SC","Microsoft YaHei",sans-serif;
  color:#1a2433;font-size:11px;line-height:1.55;margin:0;padding:24px}
h1{font-size:19px;margin:0 0 4px}
.sub{color:#67748a;font-size:11px;margin-bottom:20px}
.meta{display:grid;grid-template-columns:repeat(4,1fr);gap:10px;margin-bottom:18px}
.meta div{border:1px solid #d5dae3;border-radius:4px;padding:8px 10px}
.meta .n{font-size:18px;font-weight:700}
.meta .l{color:#67748a;font-size:10px;margin-top:2px}
.ctrl{background:#f2f7f2;border:1px solid #cde0cd;border-radius:4px;padding:10px 12px;margin-bottom:18px}
.ctrl h3{margin:0 0 6px;font-size:12px;color:#2e5c2e}
.ctrl p{margin:2px 0;font-size:10.5px;color:#3f5f3f}
table{width:100%;border-collapse:collapse;font-size:9.5px}
thead{display:table-header-group}
th,td{border:1px solid #d5dae3;padding:4px 5px;text-align:left;vertical-align:top}
th{background:#f2f5f9;font-size:9px;text-transform:uppercase;color:#556}
tr{page-break-inside:avoid}
.mono{font-family:"SF Mono",Menlo,Consolas,monospace}
.ov{color:#a3271a;font-weight:700}
.foot{margin-top:16px;color:#8a94a6;font-size:9.5px;border-top:1px solid #e3e7ee;padding-top:8px}
.noprint{margin-bottom:16px}
@media print{ .noprint{display:none} body{padding:0} }
</style></head><body>

<div class="noprint">
<button onclick="window.print()" style="padding:8px 16px;cursor:pointer">打印 / 另存为 PDF</button>
<span style="color:#67748a;font-size:11px;margin-left:10px">
在打印对话框中选择"另存为 PDF"即可得到可归档的报告文件。</span>
</div>

<h1>封禁操作合规报告</h1>
<div class="sub">
统计区间 {{.sum.From.Format "2006-01-02 15:04"}} — {{.sum.To.Format "2006-01-02 15:04"}}
&nbsp;·&nbsp; 导出人 {{.sum.GeneratedBy}}
&nbsp;·&nbsp; 导出时间 {{.sum.GeneratedAt.Format "2006-01-02 15:04:05"}}
</div>

<div class="meta">
<div><div class="n">{{.sum.TotalBans}}</div><div class="l">封禁操作总数</div></div>
<div><div class="n">{{.sum.Approved}}</div><div class="l">经审批生效</div></div>
<div><div class="n">{{.sum.Rejected}}</div><div class="l">审批驳回</div></div>
<div><div class="n">{{.sum.DistinctApprovers}}</div><div class="l">参与审批人数</div></div>
</div>

<div class="ctrl">
<h3>控制措施执行情况</h3>
<p>· <strong>四眼原则</strong>:提交人不得审批自己的请求。本区间内拦截 {{.sum.SelfApprovalDenied}} 次。</p>
<p>· <strong>保护集否决</strong>:关键地址不可被封禁,由独立于业务逻辑的安全层强制。本区间内否决 {{.sum.SafetyBlocked}} 次。</p>
<p>· <strong>大范围二次确认</strong>:覆盖超过 25% IPv4 空间的封禁需操作人显式确认。本区间内确认 {{.sum.OverrideCount}} 次。</p>
<p>· <strong>审计留痕</strong>:所有状态变更只增不改,应用层禁止 update/delete。</p>
</div>

<table>
<thead><tr>
<th>类型</th><th>编号</th><th>目标地址</th><th>源范围</th><th>原因</th><th>状态</th>
<th>提交人</th><th>审批人</th><th>方式</th><th>提交时间</th><th>到期</th><th>时长</th>
</tr></thead>
<tbody>
{{range .rows}}<tr>
<td>{{kindLabel .Kind}}</td>
<td>#{{.ID}}</td>
<td class="mono">{{.Target}}</td>
<td>{{dash .Scope}}{{if .OverrideAck}} <span class="ov">[已确认大范围]</span>{{end}}</td>
<td>{{.Reason}}</td>
<td>{{stateLabel .State}}</td>
<td>{{dash .Requester}}</td>
<td>{{dash .Approver}}</td>
<td>{{dash .ApprovalWay}}</td>
<td>{{.RequestedAt.Format "01-02 15:04"}}</td>
<td>{{timePtr .ExpiresAt}}</td>
<td>{{.TTL}}</td>
</tr>
{{else}}<tr><td colspan="12" style="text-align:center;color:#8a94a6">该区间内无封禁操作记录</td></tr>
{{end}}</tbody>
</table>

<div class="foot">
本报告由 xdp-ban 自动生成,数据源为系统审计日志(只增不可修改)。
报告内容可通过系统内"审计日志"页面逐条复核。
</div>
</body></html>`
