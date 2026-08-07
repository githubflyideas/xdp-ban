package web

import "html/template"

// templates 返回内嵌的全部页面模板(FortiMail 风格企业控制台)。
// 内嵌进二进制 —— 单文件部署,无外部模板文件。
func templates() *template.Template {
	// 模板函数:界面里需要做少量算术(水位条宽度、余量),
	// 在 Go 里算好再传更啰嗦,这里给两个最小助手。
	funcs := template.FuncMap{
		"divPPM": func(ppm int) int { // 百万分之 → 百分之
			p := ppm / 10000
			if p > 100 {
				return 100
			}
			return p
		},
		"sub": func(a, b int) int { return a - b },
	}
	t := template.New("").Funcs(funcs)
	template.Must(t.New("_head").Parse(headTpl))
	template.Must(t.New("login.html").Parse(loginTpl))
	template.Must(t.New("dashboard.html").Parse(dashTpl))
	template.Must(t.New("bans.html").Parse(bansTpl))
	template.Must(t.New("ban_new.html").Parse(banNewTpl))
	template.Must(t.New("ban_detail.html").Parse(banDetailTpl))
	template.Must(t.New("sampling.html").Parse(samplingTpl))
	template.Must(t.New("scoped_new.html").Parse(scopedNewTpl))
	template.Must(t.New("scoped_list.html").Parse(scopedListTpl))
	template.Must(t.New("report.html").Parse(reportTpl))
	template.Must(t.New("prefixdb.html").Parse(prefixDBTpl))
	template.Must(t.New("users.html").Parse(usersTpl))
	template.Must(t.New("audit.html").Parse(auditTpl))
	template.Must(t.New("error.html").Parse(errTpl))
	template.Must(t.New("approve.html").Parse(approveTpl))
	template.Must(t.New("approve_done.html").Parse(approveDoneTpl))
	return t
}

const headTpl = `<style>
:root{--ink:#0f1b2d;--steel:#1e3050;--paper:#eef1f5;--accent:#d9411e;--ok:#1f9d55;--warn:#d98a1e;--bad:#cf2f2f;--txt:#1a2433;--muted:#67748a}
*{box-sizing:border-box}body{margin:0;font-family:-apple-system,"Segoe UI",Roboto,"PingFang SC","Microsoft YaHei",sans-serif;color:var(--txt);background:var(--paper);font-size:15px}
.mono{font-family:"SF Mono",Menlo,Consolas,monospace}
.topbar{height:50px;background:var(--ink);color:#fff;display:flex;align-items:center;padding:0 16px;gap:14px}
.brand{font-weight:700;letter-spacing:.5px;font-size:17px}.brand b{color:var(--accent)}
.spacer{flex:1}.who{font-size:14px;color:#b9c4d6}.who .role{background:var(--steel);padding:2px 8px;border-radius:3px;margin-left:6px;text-transform:uppercase;font-size:11px}
.topbar a{color:#b9c4d6;text-decoration:none;font-size:14px}.topbar a:hover{color:#fff}
.shell{display:flex;min-height:calc(100vh - 50px)}
.side{width:210px;background:var(--steel)}.side a{display:block;color:#c3cee0;text-decoration:none;padding:12px 18px;border-left:3px solid transparent;font-size:14px}
.side a:hover{background:#243a5e;color:#fff}.main{flex:1;padding:22px 26px}
h1{font-size:21px;margin:0 0 18px}
.card{background:#fff;border:1px solid #d5dae3;border-radius:4px;margin-bottom:16px}.card .hd{padding:11px 14px;border-bottom:1px solid #e3e7ee;font-weight:600;background:#f7f9fc;font-size:15px}.card .bd{padding:14px}
table{width:100%;border-collapse:collapse}th,td{text-align:left;padding:9px 12px;border-bottom:1px solid #eceff4;font-size:14px}th{color:var(--muted);text-transform:uppercase;font-size:12px;background:#fafbfd}
.st{display:inline-flex;align-items:center;gap:6px}.st::before{content:"";width:8px;height:8px;border-radius:50%}
.st.ok::before{background:var(--ok)}.st.warn::before{background:var(--warn)}.st.bad::before{background:var(--bad)}.st.mut::before{background:var(--muted)}
.btn{display:inline-block;padding:8px 16px;border-radius:3px;border:1px solid #c3ccd9;background:#fff;color:var(--txt);text-decoration:none;cursor:pointer;font-size:14px}
.btn.primary{background:var(--ink);color:#fff;border-color:var(--ink)}.btn.danger{background:var(--accent);color:#fff;border-color:var(--accent)}
.stats{display:grid;grid-template-columns:repeat(3,1fr);gap:14px}.stat{background:#fff;border:1px solid #d5dae3;border-radius:4px;padding:16px}.stat .n{font-size:30px;font-weight:700}.stat .l{color:var(--muted);font-size:13px;margin-top:6px}.stat.bad .n{color:var(--bad)}
label{display:block;font-size:13px;color:var(--muted);margin:12px 0 4px;font-weight:600}
input,select{width:100%;padding:9px 10px;border:1px solid #c3ccd9;border-radius:3px;font-size:14px}
.flash{padding:11px 14px;border-radius:4px;margin-bottom:16px}.flash.err{background:#fbe9e7;border:1px solid #f2c2ba;color:#a3271a}
</style>`

const navTpl = `<div class="topbar"><span class="brand">XDP<b>-ban</b></span><span class="spacer"></span>
<span class="who">{{.u.Username}}<span class="role">{{.u.Role}}</span></span><a href="/logout">退出</a></div>
<div class="shell"><aside class="side">{{range .nav}}<a href="/{{.Key}}">{{.Label}}</a>{{end}}</aside><main class="main">`

const loginTpl = `<!doctype html><html><head><meta charset="utf-8"><title>xdp-ban</title>{{template "_head"}}</head>
<body><div style="max-width:360px;margin:9vh auto">
<div style="text-align:center;margin-bottom:24px"><div style="font-size:26px;font-weight:700;color:#0f1b2d">XDP<span style="color:#d9411e">-ban</span></div>
<div style="color:#67748a;font-size:12px;margin-top:4px">See it. Ban it.</div></div>
<div class="card"><div class="hd">登录 / Sign in</div><div class="bd">
{{if .err}}<div class="flash err">{{.err}}</div>{{end}}
<form method="post" action="/login"><label>用户名</label><input name="username" autofocus>
<label>密码</label><input type="password" name="password">
<div style="margin-top:18px"><button class="btn primary" style="width:100%">登录</button></div></form>
</div></div></div></body></html>`

const dashTpl = `<!doctype html><html><head><meta charset="utf-8"><title>Dashboard · xdp-ban</title>{{template "_head"}}</head>
<body>` + navTpl + `<h1>Dashboard</h1>
<div class="stats"><div class="stat"><div class="n">{{.pending}}</div><div class="l">待审批</div></div>
<div class="stat"><div class="n">{{.active}}</div><div class="l">生效中封禁</div></div>
<div class="stat {{if .failed}}bad{{end}}"><div class="n">{{.failed}}</div><div class="l">下发失败</div></div></div>
<div class="card" style="margin-top:16px"><div class="hd">快速操作</div><div class="bd">
{{if .canCreate}}<a class="btn primary" href="/bans/new">新建封禁请求</a> {{end}}<a class="btn" href="/bans">查看全部请求</a>
</div></div></main></div></body></html>`

const bansTpl = `<!doctype html><html><head><meta charset="utf-8"><title>封禁请求 · xdp-ban</title>{{template "_head"}}</head>
<body>` + navTpl + `<h1>封禁请求</h1>
{{if .canCreate}}<p><a class="btn primary" href="/bans/new">新建封禁请求</a></p>{{end}}
<div class="card"><table><thead><tr><th>目标</th><th>动作</th><th>来源</th><th>状态</th><th>时间</th><th></th></tr></thead><tbody>
{{range .reqs}}<tr><td class="mono">{{.Target}}</td><td>{{.ActionType}}</td><td>{{.Source}}</td>
<td><span class="st {{if eq .State "active"}}ok{{else if eq .State "pending"}}warn{{else}}mut{{end}}">{{.State}}</span></td>
<td>{{.CreatedAt.Format "01-02 15:04"}}</td>
<td>{{if and $.canApprove (eq .State "pending")}}
<form method="post" action="/bans/{{.ID}}/approve" style="display:inline"><button class="btn primary">批准</button></form>
<form method="post" action="/bans/{{.ID}}/reject" style="display:inline"><button class="btn danger">驳回</button></form>{{end}}</td></tr>
{{end}}</tbody></table></div></main></div></body></html>`

const banNewTpl = `<!doctype html><html><head><meta charset="utf-8"><title>新建 · xdp-ban</title>{{template "_head"}}</head>
<body>` + navTpl + `<h1>新建封禁请求</h1>
<div class="card" style="max-width:460px"><div class="bd">
{{if .err}}<div class="flash err">{{.err}}</div>{{end}}
{{if .target}}<div class="flash" style="background:#eef4ff;border:1px solid #c3d4f0;color:#1e3050">已根据采样流量预填,请核对后提交审批。</div>{{end}}
<form method="post" action="/bans"><label>目标 IP / CIDR</label><input name="target" value="{{.target}}" placeholder="203.0.113.7 或 203.0.113.0/24" required>
<label>原因</label><input name="reason" value="{{.reason}}" placeholder="ssh 爆破 / 恶意扫描" required>
<div style="margin-top:18px"><button class="btn primary">提交请求</button> <a class="btn" href="/bans">取消</a></div></form>
</div></div></main></div></body></html>`

const banDetailTpl = `<!doctype html><html><head><meta charset="utf-8"><title>详情 · xdp-ban</title>{{template "_head"}}</head>
<body>` + navTpl + `<h1>封禁请求详情</h1>
<div class="card"><div class="bd"><table style="width:auto">
<tr><td style="font-weight:600;width:120px">目标:</td><td class="mono">{{.req.Target}}</td></tr>
<tr><td style="font-weight:600">原因:</td><td>{{.req.Reason}}</td></tr>
<tr><td style="font-weight:600">状态:</td><td><span class="st {{if eq .req.State "active"}}ok{{else if eq .req.State "pending"}}warn{{else}}mut{{end}}">{{.req.State}}</span></td></tr>
<tr><td style="font-weight:600">提交时间:</td><td>{{.req.CreatedAt.Format "2006-01-02 15:04:05"}}</td></tr>
{{if .req.ApprovedByID}}<tr><td style="font-weight:600">批准者:</td><td>{{.approver.Username}}</td></tr>
<tr><td style="font-weight:600">批准时间:</td><td>{{.req.UpdatedAt.Format "2006-01-02 15:04:05"}}</td></tr>{{end}}
</table></div></div>
{{if .canApprove}}<div class="card"><div class="bd">
<form method="post" action="/bans/{{.req.ID}}/approve" style="display:inline"><button class="btn primary">批准</button></form>
<form method="post" action="/bans/{{.req.ID}}/reject" style="display:inline"><button class="btn danger">驳回</button></form>
</div></div>{{end}}
</main></div></body></html>`

const auditTpl = `<!doctype html><html><head><meta charset="utf-8"><title>审计 · xdp-ban</title>{{template "_head"}}</head>
<body>` + navTpl + `<h1>审计日志</h1>
<div class="card"><table><thead><tr><th>时间</th><th>用户</th><th>实体</th><th>事件</th></tr></thead><tbody>
{{range .logs}}<tr><td>{{.OccurredAt.Format "01-02 15:04:05"}}</td><td>{{.ActorLabel}}</td>
<td>{{.EntityType}}#{{.EntityID}}</td><td>{{.Event}}</td></tr>
{{end}}</tbody></table></div>
</main></div></body></html>`

const samplingTpl = `<!doctype html><html><head><meta charset="utf-8"><title>采样与流量 · xdp-ban</title>{{template "_head"}}</head>
<body>` + navTpl + `<h1>采样与实时流量</h1>

<div class="card" style="max-width:520px"><div class="hd">采样率</div><div class="bd">
<p style="color:#67748a;margin-top:0;font-size:14px">当前 <strong>1/{{.currentN}}</strong> 包采样。值越小采样越密集,CPU 与上报带宽开销相应增加。</p>
{{if .canConfigure}}
<form id="samplingForm">
<label>采样比率 (1/N) — 步长 2x</label>
<select id="samplingRate" name="rate">
  {{$cur := .currentN}}
  <option value="1024"  {{if eq $cur 1024 }}selected{{end}}>1 / 1,024</option>
  <option value="2048"  {{if eq $cur 2048 }}selected{{end}}>1 / 2,048</option>
  <option value="4096"  {{if eq $cur 4096 }}selected{{end}}>1 / 4,096</option>
  <option value="8192"  {{if eq $cur 8192 }}selected{{end}}>1 / 8,192</option>
  <option value="16384" {{if eq $cur 16384}}selected{{end}}>1 / 16,384</option>
  <option value="32768" {{if eq $cur 32768}}selected{{end}}>1 / 32,768</option>
  <option value="65536" {{if eq $cur 65536}}selected{{end}}>1 / 65,536</option>
</select>
<label style="margin-top:14px">采样器地址</label>
<input type="text" id="samplerURL" name="sampler_url" value="{{.samplerURL}}">
<div style="margin-top:18px"><button class="btn primary" type="button" onclick="setSamplingRate()">立即应用</button></div>
</form>
<div id="result" style="margin-top:14px"></div>
{{else}}<p style="color:#98a2b3">你的角色只能查看,调整采样率需要系统配置权限。</p>{{end}}
</div></div>

<div class="card"><div class="hd">近 5 分钟 Top 30 流量(采样观测)</div><div class="bd">
<p style="color:#67748a;margin-top:0;font-size:14px">最吵的源在最上面。看到异常源,直接点「封禁此源」发起治理流程 —— 目标已按流量方向预填。
需要历史趋势、按国家/AS 的多维分析,请用 ElastiFlow(见 <span class="mono">deploy/elastiflow/</span>)。</p>
<table><thead><tr><th>源地址</th><th>目标</th><th>协议</th><th>采样包数</th><th>采样字节</th><th></th></tr></thead><tbody>
{{range .topFlows}}<tr>
<td class="mono">{{.SrcIP}}{{if .SrcPort}}:{{.SrcPort}}{{end}}</td>
<td class="mono">{{.DstIP}}{{if .DstPort}}:{{.DstPort}}{{end}}</td>
<td>{{.Proto}}</td>
<td>{{.PktCount}}</td>
<td>{{.ByteCount}}</td>
<td>
{{if $.canBan}}<a class="btn danger" href="/bans/new?target={{.SrcIP}}&reason=采样观测:{{.SrcIP}} 高频打向 {{.DstIP}}({{.Proto}})">封禁此源</a>{{end}}
</td></tr>
{{else}}<tr><td colspan="6" style="color:#98a2b3">暂无采样数据。确认 xdp-sampler 正在运行并上报到本机 /api/v1/samples。</td></tr>
{{end}}</tbody></table>
</div></div>

<script>
function setSamplingRate() {
  const rate = document.getElementById('samplingRate').value;
  const samplerURL = document.getElementById('samplerURL').value;
  const resultDiv = document.getElementById('result');
  fetch('/api/sampling/rate', {
    method: 'POST',
    headers: {'Content-Type': 'application/x-www-form-urlencoded'},
    body: 'rate=' + encodeURIComponent(rate) + '&sampler_url=' + encodeURIComponent(samplerURL)
  })
  .then(r => r.json())
  .then(data => {
    if (data.ok) {
      resultDiv.innerHTML = '<div class="flash" style="background:#e8f5e9;border:1px solid #c8e6c9;color:#2e7d32">✓ 采样率已更新: 1/' + rate + '</div>';
    } else {
      resultDiv.innerHTML = '<div class="flash err">' + data.error + '</div>';
    }
  })
  .catch(e => {
    resultDiv.innerHTML = '<div class="flash err">错误: ' + e.message + '</div>';
  });
}
</script>
</main></div></body></html>`

const errTpl = `<!doctype html><html><head><meta charset="utf-8"><title>xdp-ban</title>{{template "_head"}}</head>
<body><div style="max-width:440px;margin:9vh auto"><div class="card"><div class="hd">提示</div><div class="bd">{{.msg}}<p><a class="btn" href="/dashboard">返回</a></p></div></div></div></body></html>`

const approveTpl = `<!doctype html><html><head><meta charset="utf-8"><title>审批 · xdp-ban</title>{{template "_head"}}</head>
<body><div style="max-width:460px;margin:8vh auto"><div class="card"><div class="hd">邮件审批确认</div><div class="bd">
<p><strong>请求目标:</strong> <span class="mono">{{.req.Target}}</span></p>
<p><strong>原因:</strong> {{.req.Reason}}</p>
<p style="color:#98a2b3;font-size:12px;margin-top:16px">点击下方按钮确认审批此请求。链接一次性有效。</p>
<div style="display:flex;gap:10px;margin-top:18px">
<form method="post" action="/approve/{{.token.Token}}" style="flex:1"><input type="hidden" name="action" value="approve">
<button class="btn primary" style="width:100%">批准请求</button></form>
<form method="post" action="/approve/{{.token.Token}}" style="flex:1"><input type="hidden" name="action" value="reject">
<button class="btn danger" style="width:100%">驳回请求</button></form>
</div></div></div></div></body></html>`

const approveDoneTpl = `<!doctype html><html><head><meta charset="utf-8"><title>已完成</title>{{template "_head"}}</head>
<body><div style="max-width:440px;margin:8vh auto"><div class="card"><div class="hd">✓ {{if eq .action "approve"}}已批准{{else}}已驳回{{end}}</div><div class="bd">
<p>{{if eq .action "approve"}}封禁请求已批准并下发执行。{{else}}封禁请求已驳回。{{end}}</p>
<p style="color:#98a2b3;font-size:12px;margin-top:14px">此链接已失效,不能再次使用。</p></div></div></div></body></html>`
