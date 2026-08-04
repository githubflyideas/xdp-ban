<div align="center">

# XDP-ban

**看见即封禁**

eBPF 流量采样 + 治理式封禁 —— 一个二进制文件搞定。

[English](README.md) · 中文 · [日本語](README.ja.md) · [한국어](README.ko.md)

</div>

---

大多数工具只能**看**流量,或者只能**封**——从不兼得,而且背后都拖着一套沉重的系统。XDP-ban 两者都做,而且只是一个可以拷了就跑的静态二进制文件。

它用 eBPF 采样入向流量,让你看清谁在打这台主机,然后把它封掉——经过真正的审批、角色权限和审计留痕。封禁在最靠前的位置执行(**XDP / nftables / iptables**),对屡屡来犯的攻击者,封禁时长阶梯式升级。

<div align="center">
<img src="docs/img/dashboard.svg" width="49%"/> <img src="docs/img/bans.svg" width="49%"/>
<img src="docs/img/ladder.svg" width="49%"/> <img src="docs/img/login.svg" width="49%"/>
</div>

## 特性

- **看见即封禁** —— 入向 eBPF 采样,一键封禁。
- **治理式** —— 审批流、角色权限、不可篡改审计、邮件审批链接。
- **阶梯封禁** —— 屡犯者封禁时间逐级加长,直至永久。
- **三种后端** —— XDP/bpfilter(最快)、nftables(默认)、legacy iptables(老内核)。
- **单二进制** —— 纯 Go,无 cgo,无需外部数据库。拷了就跑。

## 快速开始

```bash
CGO_ENABLED=0 go build -ldflags "-s -w" -o xdp-ban ./cmd/xdpban
./xdp-ban          # http://localhost:8080  (默认 admin / admin12345,请立即修改)
```

数据存于单个 `xdpban.db` 文件,备份就是拷贝这个文件。

## 从源码构建

```bash
go mod tidy
CGO_ENABLED=0 go build -o xdp-ban ./cmd/xdpban
go test ./internal/...
```

## 许可证

Apache-2.0,见 [LICENSE](LICENSE)。
