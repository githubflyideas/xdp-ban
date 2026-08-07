package web

// 用户管理界面。
//
// 用户是治理体系的主体 —— 谁能提交、谁能审批,全靠这张表。
// 所以这里的每个动作都记审计,且有三条硬约束(见 users.go 的注释):
// 不能删自己、不能停用自己、必须保留至少一个启用的 admin。

const usersTpl = `<!doctype html><html><head><meta charset="utf-8"><title>用户管理 · xdp-ban</title>{{template "_head"}}
<style>
.role-badge{display:inline-block;padding:2px 8px;border-radius:3px;font-size:12px;font-weight:600}
.role-admin{background:#fbe9e7;color:#a3271a}
.role-approver{background:#e8f0fe;color:#1a4480}
.role-operator{background:#e8f5e9;color:#2e7d32}
.role-viewer{background:#f1f3f5;color:#5f6b7a}
.inline-form{display:inline}
.act{white-space:nowrap}
.act form{display:inline;margin-right:4px}
.pw-input{width:130px;display:inline-block;padding:6px 8px;font-size:13px}
.newuser{display:grid;grid-template-columns:1fr 1fr 1fr 1fr auto;gap:10px;align-items:end}
.self{color:#98a2b3;font-size:12px}
</style></head>
<body>` + navTpl + `<h1>用户管理</h1>

{{if .err}}<div class="flash err">{{.err}}</div>{{end}}
{{if .ok}}<div class="flash" style="background:#e8f5e9;border:1px solid #c8e6c9;color:#2e7d32">{{.ok}}</div>{{end}}

<div class="card"><div class="hd">新增用户</div><div class="bd">
<form method="post" action="/users">
<div class="newuser">
  <div><label>用户名</label><input name="username" required placeholder="zhangsan"></div>
  <div><label>邮箱(邮件审批用)</label><input name="email" type="email" placeholder="zhangsan@example.com"></div>
  <div><label>角色</label>
    <select name="role">
      <option value="viewer">viewer — 只读</option>
      <option value="operator">operator — 可提交封禁</option>
      <option value="approver">approver — 可审批、解封</option>
      <option value="admin">admin — 全部权限</option>
    </select>
  </div>
  <div><label>初始密码(至少 8 位)</label><input name="password" type="password" required minlength="8"></div>
  <div><button class="btn primary">创建</button></div>
</div>
</form>
<div style="color:#67748a;font-size:13px;margin-top:10px">
四眼原则要求提交人与审批人不同,所以至少需要两个能操作的账号
(一个 operator + 一个 approver,或两个 admin)。
</div>
</div></div>

<div class="card"><div class="hd">用户列表</div><div class="bd" style="padding:0">
<table><thead><tr>
<th>用户名</th><th>邮箱</th><th>角色</th><th>账号状态</th><th>当前会话</th><th>最后登录</th><th>操作</th>
</tr></thead><tbody>
{{range .users}}<tr>
<td><strong>{{.Username}}</strong>{{if eq .ID $.u.ID}} <span class="self">(你)</span>{{end}}</td>
<td>{{if .Email}}{{.Email}}{{else}}<span style="color:#c3ccd9">—</span>{{end}}</td>
<td>
  <form method="post" action="/users/{{.ID}}/role" class="inline-form">
    <select name="role" onchange="this.form.submit()" style="width:auto;padding:4px 6px;font-size:13px">
      <option value="viewer"   {{if eq .Role "viewer"}}selected{{end}}>viewer</option>
      <option value="operator" {{if eq .Role "operator"}}selected{{end}}>operator</option>
      <option value="approver" {{if eq .Role "approver"}}selected{{end}}>approver</option>
      <option value="admin"    {{if eq .Role "admin"}}selected{{end}}>admin</option>
    </select>
  </form>
</td>
<td>{{if .Active}}<span class="st ok">启用</span>{{else}}<span class="st mut">已停用</span>{{end}}</td>
<td>{{if index $.online .ID}}<span class="st ok">在线</span>{{else}}<span class="st mut">离线</span>{{end}}</td>
<td>{{if .LastLoginAt}}{{.LastLoginAt.Format "01-02 15:04"}}{{else}}<span style="color:#c3ccd9">从未登录</span>{{end}}</td>
<td class="act">
  <form method="post" action="/users/{{.ID}}/password">
    <input class="pw-input" type="password" name="password" placeholder="新密码" minlength="8" required>
    <button class="btn">改密</button>
  </form>
  {{if ne .ID $.u.ID}}
    <form method="post" action="/users/{{.ID}}/toggle">
      <button class="btn">{{if .Active}}停用{{else}}启用{{end}}</button>
    </form>
    <form method="post" action="/users/{{.ID}}/delete"
          onsubmit="return confirm('删除用户 {{.Username}}?该用户提交过的封禁记录会保留,但审计里将只剩用户 ID。')">
      <button class="btn danger">删除</button>
    </form>
  {{end}}
</td></tr>
{{end}}</tbody></table>
</div></div>

<div class="card"><div class="hd">权限矩阵</div><div class="bd" style="padding:0">
<table><thead><tr><th>能力</th><th>admin</th><th>approver</th><th>operator</th><th>viewer</th></tr></thead><tbody>
<tr><td>查看仪表板 / 采样</td><td>✓</td><td>✓</td><td>✓</td><td>✓</td></tr>
<tr><td>查看封禁请求</td><td>✓</td><td>✓</td><td>✓</td><td>✓</td></tr>
<tr><td>查看审计 / 导出合规报告</td><td>✓</td><td>✓</td><td>✓</td><td>✓</td></tr>
<tr><td>提交封禁请求</td><td>✓</td><td></td><td>✓</td><td></td></tr>
<tr><td>审批 / 驳回</td><td>✓</td><td>✓</td><td></td><td></td></tr>
<tr><td>撤销封禁</td><td>✓</td><td>✓</td><td></td><td></td></tr>
<tr><td>系统配置 / IP 库</td><td>✓</td><td></td><td></td><td></td></tr>
<tr><td>用户管理</td><td>✓</td><td></td><td></td><td></td></tr>
</tbody></table>
</div></div>

<div style="color:#67748a;font-size:13px;margin-bottom:20px">
<strong>约束说明:</strong>不能删除或停用自己的账号(防止把自己锁在外面);
系统必须保留至少一个启用的 admin;改密码或停用会立即吊销该用户的全部会话。
所有变更均记入审计日志。
</div>
</main></div></body></html>`
