<div align="center">

# XDP-ban

**看见即封禁**

eBPF 流量采样 + 治理式封禁 —— 拷贝二进制即可运行。

[English](README.md) · 中文 · [日本語](README.ja.md) · [한국어](README.ko.md)

</div>

---

大多数工具只能**看**流量,或者只能**封**——从不兼得,而且背后都拖着一套沉重的系统。XDP-ban 两者都做,而且只是几个可以拷了就跑的静态二进制。

它用 eBPF 对镜像流量做包采样,让你看清谁在打你的主机,然后把它封掉——经过真正的审批、四眼原则、角色权限和审计留痕。封禁在**内核 XDP 层**执行,对屡屡来犯的攻击者,封禁时长阶梯式升级。

<div align="center">
<img src="docs/img/dashboard.svg" width="49%"/> <img src="docs/img/bans.svg" width="49%"/>
<img src="docs/img/ladder.svg" width="49%"/> <img src="docs/img/login.svg" width="49%"/>
</div>

## 特性

- **看见即封禁** —— 对镜像流量做 1/N 包采样,一键封禁。
- **治理式** —— 审批流、四眼原则、角色权限、不可篡改审计、一次性邮件审批链接。
- **阶梯封禁** —— 屡犯者封禁时间逐级加长,直至永久。
- **范围封禁** —— 按**国家 / AS 号**选择源地址范围,保护指定的单台目标主机;提交前预览影响面并做配额校验。
- **纯 XDP 执行** —— 不经 nftables,不经 iptables,执行器直接写 eBPF map。
- **单二进制** —— 纯 Go,`CGO_ENABLED=0`,无需外部数据库。拷了就跑。

## 架构

三个二进制,可独立部署:

| 二进制 | 职责 | 需要 root |
|---|---|---|
| `xdp-ban` | 控制面:Web 界面、审批治理、SQLite | 否 |
| `xdp-agent` | 执行面:轮询指令,写 XDP 黑名单 map | 是 |
| `xdp-sampler` | 观测面:在镜像口做 1/N 采样并上报流量 | 是 |

```
交换机镜像 ──▶ [eth1] xdp_sampler.o ──ringbuf──▶ xdp-sampler ──HTTP──▶ xdp-ban
                                                                         │
业务流量 ─────▶ [eth0] xdp_filter.o ◀──eBPF map── xdp-agent ◀──HTTP──────┘
```

采样是**旁路**的:它观测的是流量副本,恒返回 `XDP_PASS`,只看不丢。执行是业务网卡上另一个独立程序。

## 快速开始

```bash
make bpf     # 编译 eBPF 目标文件(需 clang)
make build   # 编译三个二进制

./xdp-ban    # http://localhost:8080  (默认 admin / admin12345,请立即修改)
```

数据存于单个 `xdpban.db` 文件,备份就是拷贝这个文件。

数据面(在实际干活的主机上,需 root):

```bash
sudo ./xdp-sampler -d eth1 -url http://<控制面>:8080/api/v1/samples -n 100 -key <API_KEY>
sudo ./xdp-agent   -server http://<控制面>:8080 -key <API_KEY>
```

## 范围封禁(按国家 / AS)

要实现"封掉 AS4134 打向 10.0.1.100 的全部流量",需要一份 IP 前缀库。它**不打进二进制** —— IPv4 表约 120 万条区间,嵌进去会让"拷一个文件就能跑"变成谎言。

```bash
curl -O https://iptoasn.com/data/ip2asn-v4.tsv.gz
XDPBAN_PREFIX_DB=./ip2asn-v4.tsv.gz ./xdp-ban
```

未配置时其余功能照常,界面会提示该功能不可用。

两条约束是刻意的,且在后端强制:

- **目标必须是单台主机(`/32`)。** 内核用 `LPM_TRIE` 对*源前缀*做最长匹配。若目标也允许前缀,就变成二维最长匹配 —— `LPM_TRIE` 表达不了,只能退化成每包遍历,这在 XDP 里不可接受。
- **提交前必须预览影响面并通过配额校验。** 一个国家可展开成上万条前缀。界面会给出确切的表项开销与覆盖的 IPv4 空间占比;超限的选择直接拒绝,范围异常大的需要显式勾选确认,该确认会写入审计。

## 配置

| 环境变量 | 默认值 | 用途 |
|---|---|---|
| `XDPBAN_DB` | `xdpban.db` | SQLite 文件路径 |
| `XDPBAN_ADDR` | `:8080` | 监听地址 |
| `XDPBAN_API_KEY` | `changeme` | agent / sampler 访问 API 的共享密钥 |
| `XDPBAN_BASE_URL` | `http://localhost:8080` | 邮件审批链接前缀 |
| `XDPBAN_SAMPLER_URL` | `http://localhost:9090` | 采样器控制端点 |
| `XDPBAN_PREFIX_DB` | — | `ip2asn-v4.tsv[.gz]` 路径;启用范围封禁 |
| `XDPBAN_COOKIE_SECURE` | — | 位于 TLS 之后时设为任意值 |
| `XDPBAN_PPROF` | — | 设为任意值以开放 `/debug/pprof`(务必仅绑定内网) |

## 从源码构建

```bash
make bpf      # clang → cmd/*/obj/*.o,由 go:embed 嵌入
make build    # 三个静态二进制
make check    # go vet + go test -race
make dist     # 交叉编译 linux/{amd64,arm64} + SHA256SUMS
```

测试与性能剖析:

```bash
make test       # go test -race ./...
make bench      # 基准测试(含内存分配统计)
make fuzz       # 对信任边界的解析函数做模糊测试
make prof       # 采样热路径的 CPU/内存 profile
make bench-api  # 对运行中的实例施加 HTTP 负载并采 pprof
```

数据面真机测量见 [`scripts/xdp-bench.sh`](scripts/xdp-bench.sh)(用 `bpftool` 读命中率,用 `perf` 看每包开销)。

工程说明 —— 并发模型、错误处理规范、Go/eBPF 边界、实测的 profiling 结果 —— 见 [ENGINEERING.md](ENGINEERING.md)。

## 现状

控制面与两个数据面程序均可编译,通过 `go vet` 与 `go test -race`,并已通过 HTTP 做过端到端验证。XDP 吞吐与每包开销**尚未**在真实网卡上测量 —— 压测脚本已提供,但不声称任何数据。

## 许可证

Apache-2.0,见 [LICENSE](LICENSE)。
