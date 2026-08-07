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

两个二进制,可独立部署:

| 二进制 | 职责 | 需要 root |
|---|---|---|
| `xdp-ban` | 控制面 + 执行面:Web 界面、审批治理、SQLite、写 XDP 封禁 map | 是 |
| `xdp-sampler` | 观测面:在镜像口做 1/N 采样并上报流量 | 是 |

```
交换机镜像 ──▶ [eth1] xdp_sampler.o ──ringbuf──▶ xdp-sampler ──HTTP──▶ xdp-ban
                                                                         │
业务流量 ─────▶ [eth0] xdp_filter.o ◀──eBPF map──────────────────── (进程内直接调用)
```

`xdp-ban` 原本拆成控制面和一个独立的 `xdp-agent` 执行器 —— 后者通过 HTTP
轮询控制面自己的 API 拉取待执行指令。两者已合并:`xdp-ban` 现在自己加载并
挂载 XDP 封禁程序,审批通过后直接对数据库执行,不再有本地 HTTP 回环。
启动时需要 `-iface <网卡名>`(业务口,不是镜像口)告诉它挂在哪张卡上。

采样仍是独立二进制 —— 它跑在镜像口上,只观测不拦截(恒 `XDP_PASS`),
与执行逻辑没有共享状态,没有合并的理由。

## 快速开始

下载二进制,直接运行。无依赖、无需编译 —— eBPF 目标文件已经嵌在里面。

```bash
# x86_64
curl -L -o xdp-ban https://github.com/githubflyideas/xdp-ban/releases/download/v0.28/xdp-ban-linux-amd64
# arm64:把上面 URL 里的 amd64 换成 arm64

chmod +x xdp-ban
sudo ./xdp-ban -iface eth0    # http://localhost:8080 —— 需要 root 来挂载 XDP
```

### 默认账号

首次启动会按角色各建一个账号。**这些密码写在公开的 README 里,请立即修改。**

| 用户名 | 密码 | 角色 | 能做什么 |
|---|---|---|---|
| `admin` | `admin12345` | admin | 全部权限,含用户管理与系统配置 |
| `approver` | `approver12345` | approver | 审批 / 驳回 / 撤销封禁,查看审计 |
| `operator` | `operator12345` | operator | 提交封禁请求,查看审计 |
| `viewer` | `viewer12345` | viewer | 只读 |

为什么是四个而不是一个:**四眼原则**要求提交人与审批人不是同一个人。
一个账号无法审批自己提交的请求,所以至少需要两个可用登录才能完成一次封禁。

在 **用户管理** 页面(仅 admin)可改密码、新增、停用、删除用户 ——
每次变更都写入审计日志。

数据存于单个 `xdpban.db` 文件,备份就是拷贝这个文件。

数据面(在实际干活的主机上,需 root):

```bash
curl -L -o xdp-sampler https://github.com/githubflyideas/xdp-ban/releases/download/v0.28/xdp-sampler-linux-amd64
chmod +x xdp-sampler

sudo ./xdp-sampler -d eth1 -url http://<控制面>:8080/api/v1/samples -n 4096 -key <API_KEY>
```

全部版本:https://github.com/githubflyideas/xdp-ban/releases

## 流量分析(ElastiFlow)

采样器可在向 xdp-ban 上报的同时,把采样流量以 **NetFlow v5** 导出到 ElastiFlow
做可视化分析。加 `-netflow <collector>:2055` 即可:

```bash
sudo ./xdp-sampler -d eth1 -url http://<控制面>:8080/api/v1/samples \
     -n 4096 -key <API_KEY> -netflow 127.0.0.1:2055
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

`xdp-ban` 启动参数:

| 参数 | 默认值 | 用途 |
|---|---|---|
| `-iface` | —(必填) | XDP 封禁程序挂载的业务网卡。没有默认值 —— 静默跳过这一步等于封禁永远停留在审批记录里,从不真正生效。 |
| `-poll-interval` | `5s` | 扫描待执行 dispatch 的间隔 |

`xdp-ban` 环境变量:

| 环境变量 | 默认值 | 用途 |
|---|---|---|
| `XDPBAN_DB` | `xdpban.db` | SQLite 文件路径 |
| `XDPBAN_ADDR` | `:8080` | 监听地址 |
| `XDPBAN_API_KEY` | `changeme` | 采样器上报接口的共享密钥 |
| `XDPBAN_BASE_URL` | `http://localhost:8080` | 邮件审批链接前缀 |
| `XDPBAN_IFACE` | — | `-iface` 的替代写法 |
| `XDPBAN_PREFIX_DB` | — | `ip2asn-v4.tsv[.gz]` 路径;启用范围封禁 |
| `XDPBAN_COOKIE_SECURE` | — | 位于 TLS 之后时设为任意值 |
| `XDPBAN_PPROF` | — | 设为任意值以开放 `/debug/pprof`(务必仅绑定内网) |

`xdp-sampler` 启动参数(固定 5 个,启动后不可再改 —— 采样率不支持运行时
调整,要改就重启进程):

| 参数 | 默认值 | 用途 |
|---|---|---|
| `-d` | `eth1` | 采样网卡(镜像口) |
| `-n` | `100` | 采样率 1/N |
| `-url` | `http://localhost:8080/api/v1/samples` | `xdp-ban` 上报端点 |
| `-key` | `changeme` | 上报到 `xdp-ban` 的 API Key |
| `-netflow` | — | NetFlow v5 collector 地址(`host:port`);为空则不导出 |

## 从源码构建

仅在你要改代码时需要 —— 发布的二进制已内嵌 eBPF 目标文件。
需要 `clang` 与 `libbpf-dev`。

```bash
make bpf      # clang → cmd/{xdpban,xdp-sampler}/obj/*.o(由 go:embed 嵌入)
make build    # 编译 xdp-ban + xdp-sampler;.o 缺失时直接失败
make check    # go vet + go test -race
make release  # bpf + check + 交叉编译 linux/{amd64,arm64}
```

`.o` 是构建产物,不进版本库。`make build` 会断言它们非空,
避免误发出内嵌空 bytecode 的二进制。

工程说明 —— 并发模型、错误处理规范、Go/eBPF 边界、实测的 profiling 结果 —— 见 [ENGINEERING.md](ENGINEERING.md)。

## 许可证

Apache-2.0,见 [LICENSE](LICENSE)。
