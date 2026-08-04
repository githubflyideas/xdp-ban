package web

// 范围封禁界面。
//
// 交互设计的三个决定:
//
//  1. **国家用下拉,AS 用搜索**。国家只有 ~250 个,下拉能装下且按前缀数
//     排序有信息量;AS 有十万级,下拉框会卡死浏览器,只能异步搜索。
//
//  2. **提交前强制预览**。"预览影响"按钮返回前缀数、地址占比、表项余量。
//     用户在点提交前就知道这一条规则的代价 —— 这是防止打爆资源的第一道闸,
//     也比"提交后报错"体验好得多。
//
//  3. **目标输入框独立且醒目**。只能填 /32,界面直接说明原因(XDP 侧
//     LPM_TRIE 无法做二维最长匹配),而不是只丢一句"格式错误"。

const scopedNewTpl = `<!doctype html><html><head><meta charset="utf-8"><title>范围封禁 · xdp-ban</title>{{template "_head"}}
<style>
.scope-grid{display:grid;grid-template-columns:1fr 1fr;gap:16px}
.hint{color:#67748a;font-size:11.5px;margin-top:4px;line-height:1.5}
.gauge{height:8px;background:#e3e7ee;border-radius:4px;overflow:hidden;margin:8px 0}
.gauge i{display:block;height:100%;background:#1f9d55}
.gauge.warn i{background:#d98a1e}.gauge.bad i{background:#cf2f2f}
.pv{background:#f7f9fc;border:1px solid #d5dae3;border-radius:4px;padding:12px;margin-top:14px;font-size:12.5px}
.pv .big{font-size:22px;font-weight:700}
.pv.ok{border-left:3px solid #1f9d55}.pv.warn{border-left:3px solid #d98a1e}.pv.bad{border-left:3px solid #cf2f2f}
.asn-results{border:1px solid #c3ccd9;border-top:0;max-height:190px;overflow-y:auto;display:none;background:#fff}
.asn-results div{padding:7px 10px;cursor:pointer;font-size:12.5px;border-bottom:1px solid #f0f2f6}
.asn-results div:hover{background:#eef4ff}
.samples{font-family:"SF Mono",Menlo,monospace;font-size:11px;color:#4a5568;margin-top:8px;line-height:1.7}
.req-note{background:#fff8e6;border:1px solid #f0d48a;border-radius:4px;padding:10px 12px;font-size:12px;color:#7a5b12;margin-bottom:16px}
</style></head>
<body>` + navTpl + `<h1>范围封禁 —— 按国家 / AS 选择源地址</h1>

{{if .dbMissing}}
<div class="flash err">{{.dbHint}}</div>
{{else}}

<div class="req-note">
<strong>目标必须是单台主机(/32)。</strong>
这不是界面偏好,而是 XDP 侧的结构约束:内核用 LPM_TRIE 对<em>源前缀</em>做最长匹配,
若目标也带前缀就变成二维最长匹配,LPM_TRIE 表达不了,只能退化为每包遍历 —— 在 XDP 里不可接受。
</div>

{{if .err}}<div class="flash err">{{.err}}</div>{{end}}

<div class="card"><div class="hd">eBPF 表项水位</div><div class="bd">
{{with .usage}}
<div class="gauge{{if gt .UtilizationPPM 800000}} bad{{else if gt .UtilizationPPM 600000}} warn{{end}}">
  <i style="width:{{divPPM .UtilizationPPM}}%"></i>
</div>
<div class="hint">已用 <strong>{{.Prefixes}}</strong> / 水位线 {{.HighWater}}(物理容量 {{.Capacity}},
预留 {{sub .Capacity .HighWater}} 条给攻击进行中的精准封禁)&nbsp;·&nbsp;
活跃规则 {{.Rules}} 条,保护目标 {{.Targets}} 台</div>
{{end}}
{{with .dbStats}}
<div class="hint">前缀库:{{.Entries}} 条区间 · {{.Countries}} 个国家 · {{.ASNs}} 个 AS
<span class="mono" style="color:#98a2b3">({{.SourcePath}})</span></div>
{{end}}
</div></div>

<form method="post" action="/scoped" id="scopedForm">
<div class="card"><div class="hd">① 目标主机(必填,只能 /32)</div><div class="bd">
<input name="target_ip" id="targetIP" placeholder="10.0.1.100" required>
<div class="hint">要保护的服务器地址。范围封禁只对流向该主机的流量生效,不影响其他业务。</div>
</div></div>

<div class="card"><div class="hd">② 源地址范围(至少填一项;都填为交集)</div><div class="bd">
<div class="scope-grid">
  <div>
    <label>国家 / 地区</label>
    <select name="country" id="country">
      <option value="">— 不限 —</option>
      {{range .countries}}<option value="{{.Code}}">{{.Code}} ({{.CIDRBlocks}} 段)</option>{{end}}
    </select>
    <div class="hint">括号内是该国在前缀库中的区间数,可粗略预判表项开销。</div>
  </div>
  <div>
    <label>AS 号</label>
    <input id="asnSearch" placeholder="输入 AS 号或名称,如 4134 / CHINANET" autocomplete="off">
    <div class="asn-results" id="asnResults"></div>
    <input type="hidden" name="asn" id="asnValue">
    <div class="hint" id="asnPicked">全球有十万级 AS,故用搜索而非下拉。</div>
  </div>
</div>
<label style="margin-top:14px">封禁原因</label>
<input name="reason" placeholder="例:该 AS 持续对 10.0.1.100:443 发起 SYN 洪水" required>
</div></div>

<div class="card"><div class="hd">③ 影响面预览(提交前必须查看)</div><div class="bd">
<button type="button" class="btn" onclick="preview()">预览影响</button>
<div id="pvBox"></div>
<div id="overrideBox" style="display:none;margin-top:12px">
  <label style="display:flex;align-items:center;gap:8px;font-weight:600;color:#a3271a">
    <input type="checkbox" name="override_ack" value="1" style="width:auto">
    我已确认影响范围,继续提交
  </label>
  <div class="hint">此确认会记入审计,可追溯到操作人。</div>
</div>
</div></div>

<div style="margin-bottom:24px">
<button class="btn primary" id="submitBtn" disabled>提交审批</button>
<a class="btn" href="/scoped">取消</a>
<span class="hint" id="submitHint" style="margin-left:10px">请先预览影响面</span>
</div>
</form>

<script>
var asnTimer = null;
document.getElementById('asnSearch').addEventListener('input', function(e){
  clearTimeout(asnTimer);
  var q = e.target.value.trim();
  var box = document.getElementById('asnResults');
  if (q.length < 2) { box.style.display='none'; return; }
  asnTimer = setTimeout(function(){
    fetch('/scoped/asn-search?q=' + encodeURIComponent(q))
      .then(function(r){ return r.json(); })
      .then(function(d){
        var rs = d.results || [];
        if (!rs.length) { box.style.display='none'; return; }
        box.innerHTML = rs.map(function(a){
          return '<div data-asn="'+a.ASN+'" data-name="'+esc(a.Name)+'">'
               + 'AS'+a.ASN+' · '+esc(a.Name)+' <span style="color:#98a2b3">['+a.Country+', '+a.CIDRBlocks+' 段]</span></div>';
        }).join('');
        box.style.display='block';
        Array.prototype.forEach.call(box.children, function(el){
          el.onclick = function(){
            document.getElementById('asnValue').value = el.dataset.asn;
            document.getElementById('asnSearch').value = 'AS'+el.dataset.asn+' · '+el.dataset.name;
            document.getElementById('asnPicked').textContent = '已选 AS'+el.dataset.asn;
            box.style.display='none';
            invalidate();
          };
        });
      });
  }, 250);
});

['country','targetIP'].forEach(function(id){
  document.getElementById(id).addEventListener('change', invalidate);
});

function invalidate(){
  document.getElementById('submitBtn').disabled = true;
  document.getElementById('submitHint').textContent = '选择已变更,请重新预览';
  document.getElementById('overrideBox').style.display = 'none';
}

function esc(s){ var d=document.createElement('div'); d.textContent=s||''; return d.innerHTML; }

function preview(){
  var body = new URLSearchParams({
    country: document.getElementById('country').value,
    asn: document.getElementById('asnValue').value
  });
  var box = document.getElementById('pvBox');
  box.innerHTML = '<div class="pv">计算中…</div>';

  fetch('/scoped/preview', {
    method:'POST',
    headers:{'Content-Type':'application/x-www-form-urlencoded'},
    body: body
  }).then(function(r){ return r.json(); }).then(function(d){
    if (d.error) { box.innerHTML = '<div class="pv bad">'+esc(d.error)+'</div>'; return; }

    var cls = d.allowed ? (d.requires_override ? 'warn' : 'ok') : 'bad';
    var html = '<div class="pv '+cls+'">'
      + '<div><span class="big">'+d.prefix_count+'</span> 条 eBPF 表项'
      + ' &nbsp;·&nbsp; 覆盖 '+d.address_count.toLocaleString()+' 个地址'
      + ' ('+d.address_share_pct.toFixed(4)+'% 的 IPv4 空间)</div>'
      + '<div style="margin-top:8px">'+esc(d.reason)+'</div>';
    if (d.samples && d.samples.length) {
      html += '<div class="samples">前缀示例:'+d.samples.map(esc).join('  ')+' …</div>';
    }
    html += '</div>';
    box.innerHTML = html;

    document.getElementById('overrideBox').style.display = d.requires_override ? 'block' : 'none';
    document.getElementById('submitBtn').disabled = !d.allowed;
    document.getElementById('submitHint').textContent = d.allowed ? '' : '当前配置无法提交';
  });
}
</script>
{{end}}
</main></div></body></html>`

const scopedListTpl = `<!doctype html><html><head><meta charset="utf-8"><title>范围封禁 · xdp-ban</title>{{template "_head"}}
<style>
.gauge{height:8px;background:#e3e7ee;border-radius:4px;overflow:hidden;margin:8px 0}
.gauge i{display:block;height:100%;background:#1f9d55}
.gauge.warn i{background:#d98a1e}.gauge.bad i{background:#cf2f2f}
.hint{color:#67748a;font-size:11.5px}
</style></head>
<body>` + navTpl + `<h1>范围封禁</h1>

<div class="card"><div class="hd">eBPF 表项水位</div><div class="bd">
{{with .usage}}
<div class="gauge{{if gt .UtilizationPPM 800000}} bad{{else if gt .UtilizationPPM 600000}} warn{{end}}">
  <i style="width:{{divPPM .UtilizationPPM}}%"></i>
</div>
<div class="hint">已用 <strong>{{.Prefixes}}</strong> / 水位线 {{.HighWater}} · 剩余 {{.Free}} 条 ·
活跃规则 {{.Rules}} 条 · 保护目标 {{.Targets}} 台</div>
{{end}}
</div></div>

{{if .canCreate}}<p><a class="btn primary" href="/scoped/new">新建范围封禁</a></p>{{end}}

<div class="card"><table><thead><tr>
<th>目标主机</th><th>源范围</th><th>表项</th><th>覆盖地址</th><th>状态</th><th>提交时间</th><th></th>
</tr></thead><tbody>
{{range .bans}}<tr>
<td class="mono">{{.TargetIP}}</td>
<td>{{if .Country}}<strong>{{.Country}}</strong>{{end}}{{if .ASN}} AS{{.ASN}}{{end}}
{{if .OverrideAck}}<span style="color:#cf2f2f;font-size:10px;margin-left:6px">已确认大范围</span>{{end}}</td>
<td>{{.PrefixCount}}</td>
<td>{{.AddressCount}}</td>
<td><span class="st {{if eq .State "active"}}ok{{else if eq .State "pending"}}warn{{else}}mut{{end}}">{{.State}}</span></td>
<td>{{.CreatedAt.Format "01-02 15:04"}}</td>
<td>
{{if and $.canApprove (eq .State "pending")}}
<form method="post" action="/scoped/{{.ID}}/approve" style="display:inline"><button class="btn primary">批准</button></form>
<form method="post" action="/scoped/{{.ID}}/reject" style="display:inline"><button class="btn danger">驳回</button></form>{{end}}
{{if eq .State "active"}}
<form method="post" action="/scoped/{{.ID}}/revoke" style="display:inline"><button class="btn danger">撤销</button></form>{{end}}
</td></tr>
{{else}}<tr><td colspan="7" style="color:#98a2b3">暂无范围封禁规则</td></tr>
{{end}}</tbody></table></div>
</main></div></body></html>`
