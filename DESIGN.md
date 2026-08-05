# xdp-ban 设计文档

版本 v0.25 · 2026-08

---

## 1. 这是什么

一套**把封禁当成需要治理的特权操作**的 DDoS 防护系统。

现有工具的通病:fail2ban 之类只管封,封完就忘,一解封攻击者立刻接着打;
手敲规则则完全不可审计 —— 谁封的、为什么、什么时候到期、误封了谁负责,全都无迹可查。
一条命令就能把自己的网关封掉,没有任何东西拦得住。

xdp-ban 的赌注是:**能证明自己封禁操作合规的能力,比封禁本身更值钱**。
所以它做两件事——用 eBPF 看清谁在打,再让你通过审批流把它封掉,全程留痕。
封禁在内核 XDP 层执行,不经 nftables/iptables。

目标客户假设:需要向测评方**证明**特权操作合规的组织(金融、政企、支付)。
这个假设尚未经真实客户验证。

---

## 2. 整体架构

三个静态二进制,可独立部署。eBPF 目标文件通过 `go:embed` 内嵌,下载即用。

```
                          ┌──────────────────────────────┐
交换机镜像口 ──▶ eth1 ──▶ │ xdp_sampler.o  (1/N 采样)     │
                          │ 恒 XDP_PASS,只观测不丢包      │
                          └───────────┬──────────────────┘
                                      │ ringbuf
                          ┌───────────▼──────────────────┐
                          │ xdp-sampler (root)           │
                          │ 聚合 → 两路上报               │
                          └─────┬──────────────┬─────────┘
                    HTTP JSON   │              │  NetFlow v5 / udp
                                ▼              ▼
                     ┌──────────────────┐   ┌──────────────┐
                     │ xdp-ban          │   │ ElastiFlow   │
                     │ 控制面 + Web UI  │   │ → Kibana     │
                     │ SQLite (WAL)     │   └──────────────┘
                     └────────┬─────────┘
                              │ HTTP 轮询 /api/v1/dispatch/pending
                     ┌────────▼─────────┐
业务流量 ──▶ eth0 ──▶│ xdp-agent (root) │
                     │ 写 eBPF map      │
                     └────────┬─────────┘
                     ┌────────▼──────────────────────────┐
                     │ xdp_filter.o  命中黑名单 XDP_DROP  │
                     └───────────────────────────────────┘
```

| 二进制 | 职责 | 需 root | 大小 |
|---|---|---|---|
| `xdp-ban` | 控制面:Web UI、审批治理、SQLite、报告 | 否 | 16 MB |
| `xdp-agent` | 执行面:轮询指令,写 XDP 黑名单 map | 是 | 6 MB |
| `xdp-sampler` | 观测面:镜像口 1/N 采样,上报流量 | 是 | 6.5 MB |

**采样是旁路的**:它看的是流量副本,恒返回 `XDP_PASS`。执行是业务网卡上另一个独立程序。
两者互不影响 —— 采样器崩了不影响封禁,封禁程序崩了不影响业务转发。

代码量:Go 5,833 行(非测试)+ 2,086 行测试 + 340 行 C(eBPF)。

---

## 3. 控制面设计

### 3.1 治理层次

封禁不是一个动作,是一条有状态的流程:

```
提交 ──▶ pending ──┬─▶ 审批 ──▶ active ──▶ 下发 ──▶ XDP map
                   │     ↑                    │
                   │     └─ 四眼原则拦截       └─▶ TTL 到期 / 撤销
                   └─▶ rejected
                   └─▶ safety_blocked  (保护集否决)
```

每一步都有对应的强制点:

| 关卡 | 实现 | 强制位置 |
|---|---|---|
| 权限 | `internal/policy` 4 角色 × 12 能力矩阵 | `requireCap` 中间件,后端强制 |
| 四眼原则 | 提交人 ≠ 审批人 | handler + 审批事务内二次兜底 |
| 安全兜底 | `internal/safety` 绝对保护集 | 下发前最后否决,无旁路 |
| 裁决优先级 | `internal/resolution` 声明式规则表 | 白名单压黑名单,保护集压一切 |
| 资源配额 | `internal/quota` 三级闸门 | 提交时预占,不是批准时 |
| 审计 | `internal/model.WriteAudit` | 只增,应用层禁 update/delete |

### 3.2 权限矩阵

```
                    admin  approver  operator  viewer
dashboard_view        ✓       ✓         ✓        ✓
ban_request_view      ✓       ✓         ✓        ✓
ban_request_create    ✓       ✗         ✓        ✗
ban_request_approve   ✓       ✓         ✗        ✗
ban_request_reject    ✓       ✓         ✗        ✗
unban_execute         ✓       ✓         ✗        ✗
audit_view            ✓       ✓         ✓        ✓
user_manage           ✓       ✗         ✗        ✗
system_config         ✓       ✗         ✗        ✗
```

前端按能力隐藏按钮只是体验,**真正的墙在 `requireCap`**。

### 3.3 阶梯封禁

治 fail2ban 最痛的病:一解封就接着打。惩罚记住历史,不每次从零开始。

```
level:      0        1       2      3       4
时长:     10分钟 → 1小时 → 1天 → 7天 → 永久
```

解封后进入 1 小时观察期;观察期内再犯则升级,平安度过则降级。
状态存 `BanLadder` 表,按目标 IP 记级别与观察期。

### 3.4 两种封禁入口

**单点封禁** (`/bans`):直接指定 IP/CIDR。

**范围封禁** (`/scoped`):按国家 / AS 号选源地址范围,保护指定的单台目标主机。
这是给"整个 AS 在打我某台服务器"场景准备的。

范围封禁有两条硬约束,都在后端强制:

1. **目标必须是 `/32` 单主机**。内核用 `LPM_TRIE` 对*源前缀*做最长匹配;
   目标也允许前缀就变成二维最长匹配,`LPM_TRIE` 表达不了,只能退化成每包遍历
   —— XDP 里不可接受。把目标限为主机 IP,二维问题降成一维。

2. **提交前必须预览影响面并通过配额校验**。一个国家可展开成上万条前缀。
   界面给出确切的表项开销与 IPv4 空间占比;超限直接拒绝,范围异常大的
   需显式勾选确认,该确认写入审计。

### 3.5 看见即封禁闭环

采样页展示近 5 分钟 Top 流量(按包数降序),每行有「封禁此源」按钮,
点击把源 IP + 原因预填进封禁表单,走正常审批流。

这是**从观测一键发起治理**,不是绕过治理。按钮受 `BanRequestCreate` 权限控制。

### 3.6 合规报告

`/report` 导出 CSV 与可打印 HTML。这是最接近"客户愿意付钱"的功能。

报告以**封禁生命周期**为主体,不是审计事件流 —— 测评人员问的是
"这条封禁谁批的",不是"11:03 发生了什么"。

核心价值是**控制措施执行统计**:四眼原则拦截 N 次、保护集否决 N 次、
大范围二次确认 N 次。数字比"我们有机制"的声明有力得多。

---

## 4. 数据面设计

### 4.1 采样侧 (`bpf/xdp_sampler.c`)

| Map | 类型 | 用途 |
|---|---|---|
| `sampling_rate` | ARRAY[1] | 1/N 的 N,用户态可运行时改 |
| `flow_table` | HASH | 流五元组聚合 |
| `global_stats` | ARRAY[1] | 总包数 / 采样包数 |
| `samples` | RINGBUF 256KB | 采样事件上报 |

采样判定用简单 LCG 伪随机取模。恒 `XDP_PASS`。

### 4.2 执行侧 (`bpf/xdp_filter.c`)

两条查表路径,对应两类封禁:

| Map | 类型 | 容量 | 用途 |
|---|---|---|---|
| `src_ban_global` | **LPM_TRIE** | 65,536 | 源前缀 → ban_value("封这个源,不限目标") |
| `target_hosts` | HASH | 4,096 | 受保护目标主机 → target_id |
| `src_ban` | **LPM_TRIE** | 262,144 | (target_id, src_prefix) → ban_value |
| `counters` | PERCPU_ARRAY | 4 | dropped/passed/expired/not_target |

查表路径:
```
包进来 → 源是否在全局封禁表内(LPM)?  是 → TTL 未过期 → XDP_DROP
                                     否 ↓
       目标是否在 target_hosts?        否 → XDP_PASS(快路径,绝大多数包在此返回)
                                     是 ↓
       源是否落在该目标的封禁前缀内?    否 → XDP_PASS
                                     是 ↓
                          TTL 是否过期?  是 → XDP_PASS + 计数
                                     否 ↓
                                  XDP_DROP
```

全局表放在最前面是刻意的 —— 单点封禁最常用,让它走最短路径。
正常流量的成本是 1 次 LPM miss + 1 次 HASH miss。

**LPM_TRIE 是范围封禁能成立的前提**:一条 `/8` 在 LPM_TRIE 里占 **1** 个表项,
在 HASH 里要 1600 万个。

`target_id` 放在 LPM key 的前 4 字节且 `prefixlen >= 32`,等价于
"target_id 精确匹配 + src_ip 前缀匹配"(Cilium 同样手法)。

### 4.3 Go ↔ eBPF 边界契约

放内核的(每包执行,必须极简且 verifier 可过):查表、TTL 判断、计数、采样判定。
无循环、无动态分配、无浮点。

放用户态的:审批、权限、阶梯 TTL、SafetyGuard、裁决、map 增删、ringbuf 消费。

编码逻辑单独拆到 `internal/banmap`,理由是**能在没有内核、没有 root 的
环境里单测这层契约**。agent 的 `main.go` 只负责轮询与调度,
`executor.go` 负责翻译成 map 写入(依赖抽象的 `mapWriter` 接口而非 `*ebpf.Map`)。

**四条必须守死的契约,全部有测试锁定:**

| 契约 | 违反后果 | 测试 |
|---|---|---|
| map 名一致 | agent 启动即 Fatalf,或规则静默不生效 | `TestMapNamesMatchBPFSource`(解析 C 源码比对) |
| 结构体尺寸 | key 编码错位,写进去的 key 与内核算出的不等 | `TestKeyValueSizesMatchBPFSource` |
| 容量上限一致 | 配额算错余量,下发时收 E2BIG | `TestMaxSrcBansMatchesQuotaCapacity` |
| JSON payload 形状 | 定向封禁被当成单点封禁写进全局表 | `TestPayloadContract_SingleAndScoped` |

另外两条:

- **字节序**。IP 字段是网络字节序,与 `iphdr->saddr/daddr` 原样一致,不做转换。
  prefixlen / target_id 等数值字段是主机字节序。
- **LPM key 必须归一化**。`netip.Prefix.Masked()` —— 超出 prefixlen 的位
  必须为 0,否则内核插入位置与查询时的最长匹配不一致,规则永远匹配不上。
- **TTL 用 ktime 而非 Unix 时间**。XDP 只能拿到 `bpf_ktime_get_ns()`
  (系统 uptime)。用 Unix 纳秒会让所有封禁被判成"未过期"而永久生效。
  agent 从 `/proc/uptime` 读**系统**启动时刻做换算 —— 用进程启动时刻的话,
  在已运行数天的机器上所有封禁会立刻失效。

---

## 5. 关键技术决策与取舍

| 决策 | 选择 | 为什么不选另一个 |
|---|---|---|
| 执行后端 | 纯 XDP,直写 eBPF map | nftables/iptables 多一跳、多一份状态,且 XDP 在驱动层更早 |
| 黑名单结构 | LPM_TRIE | HASH 无法表达前缀,一条 /8 要 1600 万条目 |
| 目标粒度 | 限 /32 | 二维 LPM 表达不了,退化成每包遍历 |
| 采样上报通道 | ringbuf | perf_buffer 每 CPU 独立、需自行合并排序;但见 §7 缺口 |
| 流量分析格式 | NetFlow v5 | IPFIX 要周期发模板,收方没模板前**静默丢数据**;我们的字段正好是 v5 全集,用不上扩展性却要背风险 |
| 数据库 | SQLite + WAL | 单文件、零运维,匹配单二进制形态。WAL 必须开:默认模式下一次审批写阻塞所有仪表板读 |
| PDF 生成 | 浏览器打印 | 纯 Go PDF 库要嵌中文字体:二进制涨几 MB 或缺字体出方块 |
| 前缀库 | 不打进二进制 | IPv4 表约 120 万条区间,嵌进去"拷一个文件就能跑"就是谎言 |
| 会话存储 | 内存 + RWMutex | 见 §7 —— 这是我最想推倒重来的决定 |
| 配额记账 | 提交时预占 | 批准时才扣的话,多人同时提交会各自看到充足余量、合起来超限 |
| 水位线 | 容量 80%,留 20% | 攻击进行中必须能立刻插一条精准封禁,不能被批量导入挤占 |

### 资源保护的五道闸门

按国家/AS 封禁可能一次引入几万条前缀。内核**不会崩**(map 有硬上限),
真正的风险是**静默失效**:满了返回 `E2BIG`,界面显示已封禁而流量照进。

1. LPM_TRIE 而非 HASH(前提)
2. 区间合并 + 最小 CIDR 拆分,避免碎片前缀白占表项
3. 提交前强制预览
4. 三级配额:单规则 32,768 上限 / 全局水位 80% / 覆盖 >25% 需确认
5. 不逐条落库,只存"选择器 + 展开数量"

---

## 6. 数据模型

SQLite,8 张表。

| 表 | 用途 | 要点 |
|---|---|---|
| `User` | 用户与角色 | bcrypt 密码 |
| `BanRequest` | 单点封禁请求 | 审批生命周期 |
| `ScopedBan` | 范围封禁规则 | 只存选择器+数量,不存展开的前缀 |
| `Dispatch` | 下发指令 (WAL) | `ban_id` 幂等键 |
| `AuditLog` | 审计 | 只增,应用层禁改删 |
| `ApprovalToken` | 邮件审批令牌 | 一次性,10 分钟过期 |
| `ProtectedTarget` | 绝对保护集 | SafetyGuard 数据源 |
| `BanLadder` | 阶梯状态 | 按目标记级别与观察期 |

SQLite 配置(每项对应一个具体故障):

```
journal_mode=WAL      不开:一次审批写阻塞所有仪表板读
busy_timeout=5000     不设:并发写直接 SQLITE_BUSY → 随机 500
synchronous=NORMAL    FULL 每事务 fsync,写延迟显著上升
MaxOpenConns=8        嵌入库连接堆高只把争抢从 Go 层挪到文件锁层
PrepareStmt=true      不开:pprof 显示 SQL 反复解析占 CPU 17%
```

`Open()` 会**回读 `PRAGMA journal_mode` 验证 WAL 真生效** ——
pragma 名写错时驱动静默忽略,不验证会以为开了其实没开。

---

## 7. 已知缺口与风险

诚实清单。按严重程度排序。

### 已修复 — agent 与 eBPF 程序不匹配(曾为 P0)

做范围封禁时重构了 `xdp_filter.c`(单级 `ban_list` → 两级 `target_hosts` + `src_ban`),
但没同步更新 agent 的写入逻辑:agent 找已不存在的 `ban_list`,启动即 Fatalf;
key 编码也还是旧的 8 字节格式。**控制面完整可用,执行面实际跑不起来。**

单测没抓到,是因为它们只覆盖纯函数(parseTarget、字节序、结构体布局),
**没有任何测试触及 map 加载与写入**。

修复内容:

- eBPF 侧补上 `src_ban_global`(LPM_TRIE),让单点封禁走全局表 ——
  此前重构只考虑了定向封禁,把最常用的"封这个源不限目标"场景丢了
- 编码逻辑抽到 `internal/banmap`,能在无内核环境单测
- agent 拆出 `executor.go`,依赖抽象 `mapWriter` 接口,用内存 fake 完整测试
  两条执行路径(单点 → 全局表;范围 → target_hosts + src_ban)
- 补上 §4.3 那四条契约测试,其中 map 名与结构体尺寸的测试**直接解析 C 源码比对**
  —— 已验证:把 C 侧 map 改名后测试立即失败
- TTL 换算修正为 ktime 基准并从 `/proc/uptime` 读系统启动时刻
- 控制面补 `CreateScopedDispatch`,范围封禁审批时重新展开前缀并检测漂移

### P1 — 过期表项没有内核侧清理

XDP 只判 TTL 并放行,不删表项(内核删除需额外写权限与复杂度)。
缺少用户态 reaper 定期扫 map 删过期项并释放配额 ——
长期运行后表项会被过期规则占满,最终触发 §5 的静默失效。

**这是当前唯一会随时间累积成事故的缺口。**

### 已修复 — 发布二进制内嵌空 bytecode(曾为 P1)

此前仓库跟踪 `obj/*.o` 的 0 字节占位文件(为了让无 clang 的机器也能编译
Go 部分),但发布流程没有强制先 `make bpf` —— 结果 v0.26 及之前的
agent/sampler 二进制内嵌的是空 bytecode,运行时报
`bytecode 为空`。**错误发生在客户机器上,而不是构建时。**

修复内容:

- `.o` 从版本库移除(它是构建产物,不该有第二份事实源)
- 新增 `make bpf-check` 断言 `.o` 非空,`build`/`dist` 都依赖它 ——
  忘了跑 `make bpf` 时构建直接失败,而不是产出坏二进制
- `make bpf` 补上 `-I/usr/include/$(ARCH_TRIPLET)`:Debian/Ubuntu 把
  `asm/` 放在架构子目录,不加会 `asm/types.h not found`
- 新增 `make release` 串起完整流程:`bpf → check → dist`
- 补 `TestEmbeddedBytecodeHasRequiredMaps`:真正解析内嵌 bytecode,
  断言所需 map 都在且容量正确。这条测试在 `.o` 为空时会 skip 并说明原因

同时修掉编译 sampler 时暴露的两个 eBPF 侧真实缺陷:

- **包长算错**:用了 `ctx->data_meta - data`。`data_meta` 指向元数据区
  (XDP 程序间传递自定义数据用),与包长无关 —— 上报的字节数全是垃圾。
  改为 `data_end - data`。这个错误此前编译不过所以一直没暴露。
- **采样退化成"全采或全不采"**:随机种子只用 `ctx->rx_queue_index`,
  同一队列上每个包算出的随机数完全相同,采样率形同虚设。
  改为混入五元组与 ktime。顺带给 `rate == 0` 加兜底(除零会被 verifier 拒绝)。

### P2 — 会话存内存

重启即全员掉线,无法多副本,无法横向扩展。
应该用签名 cookie(HMAC 自包含,无服务端状态)。
已修的并发崩溃(`concurrent map writes` 导致进程退出)只是打补丁,不是修根。

### P2 — XDP 性能未在真机测量

`scripts/xdp-bench.sh` 已写好(bpftool 读命中率、perf 抓内核侧占比、
tcpreplay 回放验证采样率),但需要 root + 真实网卡。**没有数据,不编。**

### P2 — 状态机散在各处

封禁状态是散落的字符串比较(`state != "pending"`),分布在 handlers、scoped、
dispatch 里。加一个状态要改七八处,漏一处就是"某状态下能做本不该做的操作"
这类难测的漏洞。

### P2 — BanRequest 与 ScopedBan 重复

两套几乎相同的字段和审批逻辑,只因为一个有源范围一个没有。
应该是同一实体,源范围为可选字段。现状意味着**每个治理特性都要写两遍**
—— 这次修 P0 就付了这个代价:`CreateDispatch` 和 `CreateScopedDispatch`
是两份高度相似的代码。

### P3 — 其他

- 未探测 `RLIMIT_MEMLOCK`,map 创建失败时只能看内核报错
- agent 一次写一个 key,上万条前缀应改 `BatchUpdate`(内核 5.6+)
- LDAP/SSO 未实现(企业采购硬门槛)
- 邮件发送是 `log.Printf` 占位,需接真实 SMTP/SendGrid
- 单节点,无多节点集中管控

---

## 8. 工程实践

```
make bpf        clang → cmd/*/obj/*.o,go:embed 内嵌
make build      三个静态二进制
make check      go vet + go test -race
make dist       交叉编译 linux/{amd64,arm64} + SHA256SUMS
make bench      基准测试(含分配统计)
make fuzz       信任边界解析函数模糊测试
make prof       采样热路径 CPU/内存 profile
make bench-api  HTTP 负载 + pprof
```

**测试**:`go test -race` 全绿。fuzz 覆盖 `parseTarget`(执行器信任边界)
与 `parseRate`(Web 输入)。

**pprof 定位并修掉的两处**:
- SQL 反复解析 → 开 `PrepareStmt`:审计写 122,706 → 109,783 ns/op,分配 −26%
- 采样聚合字符串 key → 定长 struct key:延迟 −61%,分配次数 32,270 → 262

**已实测的延迟归属**:审计写 ~110 µs、仪表板 3×count ~173 µs、
TopFlows 满载 ~1.4 ms、Gin 端到端 9–13 ms(含 curl 开销)。
**控制面瓶颈在 SQLite,不在 Gin。**

详见 [ENGINEERING.md](ENGINEERING.md)。

---

## 9. 后续路线

按"能否直接支撑收费"排序:

1. **过期表项 reaper** —— 唯一会随时间累积成事故的缺口
2. **LDAP / SSO** —— 企业采购硬门槛
3. **多节点集中管控** —— 单机免费引流、多节点收费,最自然的开源/商业分界
4. **告警集成**(邮件/Webhook/钉钉)—— 运维日常黏性
5. **威胁情报源接入** —— 从人工封禁变成自动响应

**不该优先做**:更快的 XDP、更多协议。性能不是购买决策点 ——
客户不会因为你从 10 Mpps 到 20 Mpps 付钱,但会因为测评过不了而付钱。

### 透明网桥形态(评估中,未立项)

四网卡:管理 / 采样 / 桥入口 / 桥出口。封禁做在桥入口 ingress,
命中即 `XDP_DROP`,否则 `XDP_TX`/redirect 到出口。

价值:受保护主机**不用装 agent**,对"生产服务器不能装东西"的客户是刚需;
形态上就是一台流量清洗盒子。

难点:XDP 二层转发比 DROP 复杂一个数量级(MAC 学习、VLAN 透传、
ARP/STP 必须放行否则桥断);必须做 bypass(软件桥崩了链路就断,
客户不敢串进生产);性能必须真机验证(在途流量,线速不达标就丢业务包)。

结论:数量级的工作量,且做错就是整段网络断。值得单独立项,先出设计再动手。

---

## 10. 一句话总结

代码本身不难,难的是这些"为什么这样做"的判断 ——
为什么四眼要在事务里兜底、为什么保护集要独立于业务逻辑、
为什么配额要留 20% 余量、为什么目标只能是 /32。

这些都是想清楚"哪里会出事故"之后的选择。而 §7 那份缺口清单,
是我目前还没想清楚或还没做完的部分。
