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

下载二进制,直接运行。无依赖、无需编译 —— eBPF 目标文件已经嵌在里面。

```bash
# x86_64
curl -L -o xdp-ban https://github.com/githubflyideas/xdp-ban/releases/download/v0.26/xdp-ban-linux-amd64
# arm64:把上面 URL 里的 amd64 换成 arm64

chmod +x xdp-ban
./xdp-ban    # http://localhost:8080  (默认 admin / admin12345,请立即修改)
```

数据存于单个 `xdpban.db` 文件,备份就是拷贝这个文件。

数据面(在实际干活的主机上,需 root)—— `xdp-sampler` 和 `xdp-agent` 同样方式下载:

```bash
curl -L -o xdp-sampler https://github.com/githubflyideas/xdp-ban/releases/download/v0.26/xdp-sampler-linux-amd64
curl -L -o xdp-agent   https://github.com/githubflyideas/xdp-ban/releases/download/v0.26/xdp-agent-linux-amd64
chmod +x xdp-sampler xdp-agent

sudo ./xdp-sampler -d eth1 -url http://<控制面>:8080/api/v1/samples -n 100 -key <API_KEY>
sudo ./xdp-agent   -server http://<控制面>:8080 -key <API_KEY>
```

全部版本:https://github.com/githubflyideas/xdp-ban/releases

## 流量分析(ElastiFlow)

采样器可在向 xdp-ban 上报的同时,把采样流量以 **NetFlow v5** 导出到 ElastiFlow
做可视化分析。加 `-netflow <collector>:2055` 即可:

```bash
sudo ./xdp-sampler -d eth1 -url http://<控制面>:8080/api/v1/samples \
     -n 100 -key <API_KEY> -netflow 127.0.0.1:2055
```

[`deploy/elastiflow/`](deploy/elastiflow/) 下有一键 compose(Elasticsearch + Kibana
+ ElastiFlow)——`docker compose up -d` 后让采样器指向 `udp/2055` 即可。采样率会写进
每个报文,ElastiFlow 据此自动还原真实流量。为什么选 NetFlow v5 而非 IPFIX,见
[deploy/elastiflow/README.md](deploy/elastiflow/README.md)。

## 范围封禁(按国家 / AS)

```bash
curl -O https://iptoasn.com/data/ip2asn-v4.tsv.gz
XDPBAN_PREFIX_DB=./ip2asn-v4.tsv.gz ./xdp-ban
```

未配置时其余功能照常,界面会提示该功能不可用。

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

仅在你要改代码时需要 —— 发布的二进制已内嵌 eBPF 目标文件。

```bash
make bpf      # 编译 eBPF(需 clang)
make build    # 编译三个二进制
make check    # go vet + go test -race
```

工程说明 —— 并发模型、错误处理规范、Go/eBPF 边界、实测的 profiling 结果 —— 见 [ENGINEERING.md](ENGINEERING.md)。

## 许可证

Apache-2.0,见 [LICENSE](LICENSE)。
