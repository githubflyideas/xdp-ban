package web

// IP 前缀库管理界面。
//
// 三个区块对应三种现实处境:能出网的用在线同步、隔离网的用上传、
// 数据判错的用本地覆盖。三者可以叠加,本地覆盖始终优先。

const prefixDBTpl = `<!doctype html><html><head><meta charset="utf-8"><title>IP 库管理 · xdp-ban</title>{{template "_head"}}
<style>
.src{border:1px solid #d5dae3;border-radius:4px;padding:12px 14px;margin-bottom:10px;display:flex;gap:14px;align-items:flex-start}
.src input[type=radio]{width:auto;margin-top:3px}
.src .n{font-weight:600;font-size:13px}
.src .u{font-family:"SF Mono",Menlo,monospace;font-size:10.5px;color:#67748a;word-break:break-all}
.src .note{font-size:11.5px;color:#67748a;margin-top:3px;line-height:1.6}
.src .lic{font-size:10.5px;color:#98a2b3;margin-top:2px}
.stat{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin-bottom:6px}
.stat div{border:1px solid #d5dae3;border-radius:4px;padding:10px 12px}
.stat .n{font-size:19px;font-weight:700}.stat .l{color:#67748a;font-size:10.5px;margin-top:2px}
textarea{width:100%;min-height:190px;font-family:"SF Mono",Menlo,Consolas,monospace;
  font-size:12px;padding:10px;border:1px solid #c3ccd9;border-radius:3px;line-height:1.7}
.spec{background:#f7f9fc;border-left:3px solid #1e3050;padding:10px 13px;font-size:11.5px;
  line-height:1.8;margin-bottom:10px;font-family:"SF Mono",Menlo,monospace}
.syncing{background:#fff8e6;border:1px solid #f0d48a;border-radius:4px;padding:10px 12px;
  font-size:12px;color:#7a5b12;margin-bottom:14px}
.why{background:#f7f9fc;border-left:3px solid #1e3050;padding:12px 14px;margin-bottom:18px;
  font-size:12.5px;line-height:1.7}
</style></head>
<body>` + navTpl + `<h1>IP 前缀库管理</h1>

<div class="why">
按国家 / AS 封禁依赖这份数据。<strong>多源可选</strong>是因为单一上游宕机或改格式就会让功能失效,
而且不同源的口径不同 —— iptoasn 反映 BGP 实际公告,RIR 记录反映注册归属,两者对同一网段的判断可能不一致。
<strong>本地覆盖规则</strong>优先于任何数据源:商业 IP 库经常判错某个网段的归属,而你的运维知道真相。
</div>

{{if .stats}}
<div class="card"><div class="hd">当前生效的库</div><div class="bd">
<div class="stat">
<div><div class="n">{{.stats.Entries}}</div><div class="l">IP 区间</div></div>
<div><div class="n">{{.stats.Countries}}</div><div class="l">国家 / 地区</div></div>
<div><div class="n">{{.stats.ASNs}}</div><div class="l">自治系统</div></div>
<div><div class="n">{{.stats.OverrideCount}}</div><div class="l">本地覆盖规则</div></div>
</div>
<div style="color:#67748a;font-size:13px;margin-top:8px">
加载时间 {{.stats.LoadedAt.Format "2006-01-02 15:04:05"}} ·
<span class="mono">{{.stats.SourcePath}}</span></div>
</div></div>
{{else}}
<div class="flash err">尚未导入 IP 前缀库,按国家 / AS 封禁功能不可用。
请用下方任一方式导入，推荐在能出网的机器上手动下载后通过"上传文件"导入。</div>
{{end}}

<div id="syncBox"></div>

<div class="card"><div class="hd">方式一:在线同步(需出网)</div><div class="bd">
<p style="color:#67748a;font-size:14px;margin-top:0">
从 RIR 官方 FTP 直接拉取 IP 分配记录。含国家归属,不含 AS 号。
如需含 AS 号的数据,请在能出网的机器上下载
<a href="https://iptoasn.com/data/ip2asn-v4.tsv.gz" target="_blank" style="color:#1e3050">iptoasn.com/data/ip2asn-v4.tsv.gz</a>
后通过下方"方式二"上传。
</p>
<form method="post" action="/prefixdb/sync">
{{range $i, $s := .sources}}
<label class="src">
  <input type="radio" name="source" value="{{$s.ID}}"{{if eq $i 0}} checked{{end}}>
  <span>
    <span class="n">{{$s.Name}}</span>
    <div class="u">{{$s.URL}}</div>
    <div class="note">{{$s.Note}}</div>
    <div class="lic">许可:{{$s.License}}</div>
  </span>
</label>
{{end}}
<div style="margin-top:14px">
<button class="btn primary">开始同步</button>
<span style="color:#98a2b3;font-size:13px;margin-left:10px">
下载与解析在后台进行,可能需要数分钟;期间旧库继续服务。</span>
</div>
</form>
</div></div>

<div class="card"><div class="hd">方式二:上传文件(隔离网环境)</div><div class="bd">
<form method="post" action="/prefixdb/upload" enctype="multipart/form-data">
<label>数据文件(支持 .tsv / .tsv.gz,自动识别是否压缩)</label>
<input type="file" name="dbfile" required>
<label style="margin-top:12px">文件格式</label>
<select name="format">
  <option value="ip2asn_tsv">IPtoASN TSV(start end asn country name)</option>
  <option value="rir_delegated">RIR delegated-extended(APNIC / RIPE / ARIN 等)</option>
</select>
<div style="margin-top:14px">
<button class="btn primary">上传并启用</button>
<span style="color:#98a2b3;font-size:11.5px;margin-left:10px">
解析失败时不会替换现有库。MaxMind GeoLite2 需要账号,可下载后走这条路径。</span>
</div>
</form>
</div></div>

<div class="card"><div class="hd">方式三:本地优先规则(手工维护,优先级最高)</div><div class="bd">
<div class="spec">
# 每行一条,支持 CIDR 或起止区间;# 起始为注释<br>
# &lt;范围&gt;  &lt;国家码&gt;  [ASN]  [备注]<br>
203.0.113.0/24&nbsp;&nbsp;CN&nbsp;&nbsp;4134&nbsp;&nbsp;实测由本地 ISP 运营,库里判成 US<br>
198.51.100.0&nbsp;&nbsp;198.51.100.255&nbsp;&nbsp;SG&nbsp;&nbsp;0&nbsp;&nbsp;手工修正
</div>
<form method="post" action="/prefixdb/overrides">
<textarea name="overrides" spellcheck="false" placeholder="# 一行一条规则,留空表示无本地覆盖">{{.overrideText}}</textarea>
<div style="margin-top:12px">
<button class="btn primary">保存并立即生效</button>
<span style="color:#98a2b3;font-size:11.5px;margin-left:10px">
文件位置 <span class="mono">{{.overridePath}}</span>,也可直接用编辑器改后重启。
保存前会校验,格式有误则不写入。</span>
</div>
</form>
</div></div>

<script>
function poll(){
  fetch('/prefixdb/status').then(function(r){return r.json()}).then(function(d){
    var box = document.getElementById('syncBox');
    if (d.in_progress) {
      box.innerHTML = '<div class="syncing">正在同步 <strong>'+esc(d.source)+
        '</strong> … 已下载 '+(d.bytes/1048576).toFixed(1)+' MB。此页面会自动刷新。</div>';
      setTimeout(poll, 2000);
    } else if (d.error) {
      box.innerHTML = '<div class="flash err">同步失败:'+esc(d.error)+'</div>';
    } else if (box.innerHTML.indexOf('正在同步') >= 0) {
      location.reload();  // 刚刚完成,刷新以显示新统计
    }
  }).catch(function(){});
}
function esc(s){var d=document.createElement('div');d.textContent=s||'';return d.innerHTML}
poll();
</script>
</main></div></body></html>`
