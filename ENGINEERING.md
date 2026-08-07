# 工程质量说明 (ENGINEERING.md)

本文件如实记录测试策略、错误处理规范、性能剖析结果,以及 Go/eBPF 边界设计。
凡是"沙箱内无法验证"的部分,明确标注,不含糊。

---

## 1. 测试:race / benchmark / fuzz

### 已系统化的部分

| 类型 | 命令 | 现状 |
|------|------|------|
| 竞态检测 | `make test`(`CGO_ENABLED=1 go test -race ./...`) | 全绿 |
| 基准 | `make bench` | TopFlows / SampleBufferPut / key 编码 |
| 模糊 | `make fuzz` | parseTarget(执行器)、parseRate(Web) |
| CPU/内存剖析 | `make prof` | TopFlows 热路径 |

### race 暴露 & 验证的并发点

采样链路是唯一真正的并发热点:**HTTP handler 改采样率**、**上报接口写环形缓冲**、
**仪表板读缓冲聚合** 三者并发。

- `internal/web/samples.go` 的 `sampleBuffer` 用 `RWMutex`;
  `TestSampleBuffer_ConcurrentReadWrite` 用 4 写 + 4 读 goroutine 持续打,`-race` 下干净。
- `cmd/xdp-sampler` 的采样率是 handler 与上报循环共享状态,改用 `sync.RWMutex`
  包了 `samplingRate()` / `setSamplingRate()`,eBPF map 是唯一事实源,本地副本仅供上报标注。
- ringbuf 读取改为独立 goroutine + 带缓冲 channel,背压时**主动丢样本**而非阻塞内核侧
  ——采样本就是有损统计,不能因用户态跟不上而拖慢 XDP。

### fuzz 暴露的边界条件

`FuzzParseTarget` 跑 ~10 万 execs,锁死执行器信任边界的契约:
要么返回**恰好 4 字节**的 IPv4,要么返回错误,绝不 panic、绝不返回错长 slice。
CIDR / IPv6 显式拒绝(当前 HASH map 无法表达 LPM),而不是被静默当成主机地址。
`FuzzParseRate` 确保采样率越界(0 会让 BPF 取模除零、超大值让采样失效)一律被拒。

### 已知未覆盖

- **数据面 e2e**:挂真实 XDP、真机丢包/命中率,需 root + 网卡,当前 CI 沙箱做不了。
  逻辑用单测覆盖(字节序、结构体尺寸、TTL 编码),真机验收步骤见 `dist/README.md`。

---

## 2. 错误处理规范

分三档,按"谁该为这个错误负责"来定:

**a. 包装后上抛(`fmt.Errorf(... %w ...)`)** —— 库/服务层。
调用方需要判别或链式定位时用 `%w` 保留链。例:`dispatch.CreateDispatch` 的
`marshal payload: %w`、`create dispatch: %w`;`xdp-ban` 执行器(原 `xdp-agent`,已合并)的 `ban_list update: %w`。

**b. 哨兵错误 + `errors.Is`** —— 需要分支处理的预期失败。
`internal/web` 定义 `errSelfApproval` / `errStateConflict`,审批事务内返回,
外层用 `==`/`errors.Is` 映射到不同 HTTP 状态(403 vs 409 vs 404),
而不是把内部原因泄露给终端用户。
`xdp-sampler` 用 `errors.Is(err, ringbuf.ErrClosed)` 区分"正常关闭"与"真错误";
`errors.Is(err, http.ErrServerClosed)` 同理。

**c. 记录日志后继续 / 终止**:
- **启动期不可恢复**(打不开 DB、加载不了 eBPF、map 不存在)→ `log.Fatalf`,快速失败。
- **运行期可容忍**(单次上报失败、单封审批邮件发送失败)→ `log.Printf` + 继续。
  邮件失败**不回滚**审批令牌:审批人仍可在界面处理,链接仍有效,失败记入审计。

**审计是一等公民**:所有状态变更经 `model.WriteAudit`(只增、应用层禁改删)。
审计写入失败用 `_ =` 显式忽略——审计尽力而为,不因它阻断主流程,但绝不静默 nil-check 漏掉主逻辑。

`errors.Join` 目前未用到:尚无"需要合并多个独立错误一起上报"的场景,不为用而用。

---

## 3. 性能热点 & pprof 结果

**唯一被 profile 证实的用户态热点:`sampleBuffer.TopFlows`**(仪表板每次打开都全量重聚合)。

`make prof` → `go tool pprof` 结果(flows=500/report × 64 reports):

初版(`map[string]` + 字符串拼 key):

```
BenchmarkTopFlows/flows=500   3,544,562 ns/op   1,093,567 B/op   32,270 allocs/op
```

CPU profile 显示 `aeshashbody` + `mapaccess2` 占 ~61%,瓶颈是**字符串 key 的哈希**;
mem profile 显示 87% 分配来自每条流一次 `f.SrcIP+"|"+...` 的字符串拼接。

优化:key 改为定长 `struct{src,dst,proto string}`(免拼接),按索引取址免拷贝,预分配 map:

```
BenchmarkTopFlows/flows=500   1,396,462 ns/op      82,112 B/op      262 allocs/op
```

**效果:延迟 −61%,分配字节 −92%,分配次数 −99%(32270 → 262)。**

`BenchmarkSampleBufferPut`:99 ns/op、0 allocs——写路径本就不是问题,保持。

> XDP 侧的每包开销、命中率不在 Go pprof 范围内(见第 5 节),需 bpftool/内核工具。

---

## 4. Go ↔ eBPF 边界

**放 XDP(内核,每包执行,必须极简且 verifier 可过):**
- `bpf/xdp_filter.c`:查黑名单 HASH map,命中即 `XDP_DROP`,含 TTL 过期判断与命中计数。
- `bpf/xdp_sampler.c`:1/N 采样判定、流五元组聚合、命中包推 ringbuf;旁路恒 `XDP_PASS`。
- 原则:无循环、无动态分配、无浮点;策略/审批/裁决一律**不进内核**。

**放 Go(用户态,策略与生命周期):**
- 审批、权限、阶梯 TTL、SafetyGuard 否决、裁决优先级——全部在 Go。
- eBPF map 的增删、ringbuf 消费、采样率调整。

**Map 生命周期与一致性:**
- map 由 `.o` 声明,`ebpf.NewCollection` 加载时创建,进程持有,`coll.Close()` 释放。
  (生产若需跨进程存活应 pin 到 `/sys/fs/bpf`;当前单进程持有,重启即重建,已在文档标注。)
- **字节序是关键契约**:`ban_entry.dst_ip` 直接取自 `iphdr->daddr`(网络字节序)。
  用户态若按主机序拼 key,写进去的 key 与 XDP 侧算出的永不相等——黑名单静态失效。
  这是真实修过的 bug,现由 `TestBuildKey_UsesNetworkByteOrder` 锁死。
- **结构体布局对齐**:`SampleEvent`(Go)与 `struct sample_event`(C)必须同尺寸,
  否则 `binary.Read` 错位;由 `TestSampleEventSize`(28 字节)守护。
- **并发写 map**:HASH map 的单键更新在内核侧原子;C 侧计数用 `__sync_fetch_and_add`。
  用户态并发下发时,`banListMap.Put` 各键独立,无需额外锁。
- **采样率同步**:eBPF `sampling_rate` ARRAY map 是唯一事实源;Go 侧副本仅用于上报标注,
  改值必先写 map 成功才更新副本(`setSamplingRate`)。

---

## 5. 性能验证手段(超出 go test)

**已在本环境做:** `go test -race`、`go test -bench -benchmem`、`go test -fuzz`、
`go tool pprof`(CPU + alloc_space),结果见第 3 节,优化有据可查。

**需真机 / root(已写入 `dist/README.md` 验收清单,当前沙箱无法执行):**
- `bpftool prog show` / `bpftool map dump name ban_list` —— 确认 map 内容与命中计数。
- `bpftool map dump name counters` —— XDP drop/pass 计数,算命中率。
- XDP 每包开销:`xdp-bench` 或 `pktgen` 打流,看线速下 pps 与 CPU。
- 流量回放:`tcpreplay` 灌镜像流量到采样网卡,验证 1/N 采样比与上报聚合准确性。

## 6. 并发安全:Gin × SQLite × eBPF

三条并发路径,各自的保护手段不同。

### Gin handler 之间的共享状态

**修复过的真实缺陷**:会话表原本是裸 `map[string]uint`。Gin 每请求一个 goroutine,
并发登录会触发 `fatal error: concurrent map writes` ——**这个 panic 无法 recover,
进程直接退出**,等于一个可远程触发的拒绝服务(多人同时点登录即可)。

`TestSessionStore_ConcurrentLoginAndAccess` 在 `-race` 下确认过这个竞争(修复前报
DATA RACE,修复后干净)。现在是 `internal/web/session.go` 的 `sessionStore`:
`RWMutex` + 过期时间 + 后台 reaper 清理僵尸会话。顺带补上两个安全缺口:
登出真正吊销 token(并清 cookie)、改密码吊销该用户全部会话。

### SQLite

`internal/model/model.go` 的 `Open()` 做了四件事,每一件都对应一个具体故障:

| 设置 | 不做会怎样 |
|------|-----------|
| `journal_mode=WAL` | 默认模式下写事务阻塞所有读:一次审批写卡住全部仪表板查询 |
| `busy_timeout=5000` | 并发写直接返回 `SQLITE_BUSY`,表现为随机 "database is locked" 500 |
| `synchronous=NORMAL` | FULL 每事务 fsync,写延迟显著上升;NORMAL 是 WAL 下的常规折中 |
| 连接池 `MaxOpen=8` | SQLite 是单文件嵌入库,连接堆高只把争抢从 Go 层挪到文件锁层 |

`Open()` 会**回读 `PRAGMA journal_mode` 校验 WAL 真的生效** —— DSN pragma 名写错时
驱动静默忽略,不验证就会以为开了其实没开,问题拖到生产才炸。
`TestOpen_ConcurrentReadWriteNoLockError` 用 8 写 + 8 读混合负载守住这条。

**事务**:只在需要原子性的地方显式用 `db.Transaction` —— 审批令牌的
"标记已用 + 推进状态"必须同生共死,否则重放窗口打开。
其余单条写用 `SkipDefaultTransaction` 免掉 GORM 默认的多余 BEGIN/COMMIT。

### eBPF Map

内核侧 HASH map 的单键更新本身原子,C 侧计数用 `__sync_fetch_and_add`,
用户态各键独立 `Put` 无需额外锁。采样率的 Go 侧副本用 `RWMutex` 保护,
且**以 eBPF map 为唯一事实源**:先写 map 成功才更新副本。

---

## 7. 全链路 Profiling 与优化结果

`scripts/api-bench.sh` 打真实 HTTP 负载并**在负载期间**采 pprof
(踩过的坑:先后串行采集会得到全零 profile)。pprof 端点默认关闭,
需 `XDPBAN_PPROF=1`,因为它会暴露内存布局与 goroutine 栈。

### pprof 定位并修掉的两处

**① SQL 反复解析(GORM/SQLite 层)**

初次 CPU profile 显示 `modernc.org/sqlite/lib.yy_reduce` 占 ~17%,
`gorm.(*processor).Execute` 累计 42% —— 每次查询都在重新解析同样的 SQL。
开启 `PrepareStmt: true` 后语句只解析一次,`yy_reduce` 从 Top10 消失。

`BenchmarkWriteAudit`(最高频写路径):`122,706 ns/op / 109 allocs`
→ `109,783 ns/op / 81 allocs`,**延迟 −11%,分配 −26%**。

**② 采样聚合的字符串 key(见第 3 节)**

`TopFlows` 延迟 −61%、分配次数 −99%。

### 各阶段延迟归属(本机实测)

| 阶段 | 量级 | 依据 |
|------|------|------|
| XDP 收包 → DROP | 亚微秒(未真机实测) | 无循环无分配,单次 map 查表 |
| eBPF map 更新(agent) | 常驻进程 fd 复用,µs 级 | `bpftool` 单次往返是上界,见压测脚本 |
| SQLite 单写(审计) | ~110 µs | `BenchmarkWriteAudit` |
| 仪表板 3× count | ~173 µs | `BenchmarkDashboardCounts` |
| 采样聚合 TopFlows | ~1.4 ms(64×500 流满载) | `BenchmarkTopFlows` |
| Gin 端到端 | 9–13 ms | `api-bench.sh`(含 curl 进程启动开销,非纯服务端) |

**结论:控制面瓶颈在 SQLite,不在 Gin。** Mutex profile 未见 `sessionStore` 或
`sqlite` 相关争用条目(只有 runtime 内部锁),说明当前锁粒度不是瓶颈。
Block profile 中 `internal/poll.(*fdMutex).rwlock` 占比高,来源是 `gin.Logger()`
往同一 stdout 写日志 —— 生产环境应关掉访问日志或改异步写。

### 还没做的

XDP 侧每包开销与命中率需真机(见下)。`scripts/xdp-bench.sh` 已写好,
在有网卡的机器上 `sudo ./scripts/xdp-bench.sh --iface eth0` 即可采数:
`bpftool` 读 map/counters 算命中率、`perf record` 抓内核侧 `bpf_prog_run` 占比、
`tcpreplay` 回放验证 1/N 采样准确性。**这部分我没有数据,不编。**

---

## 8. 大规模封禁的资源边界

按国家 / AS 封禁会一次引入成千上万条前缀。这里逐一说明"会打爆什么"和"怎么防"。

### 会先炸的三个地方

| 资源 | 失败方式 | 严重程度 |
|------|----------|----------|
| eBPF LPM_TRIE 满 | `bpf_map_update_elem` 返 `E2BIG`,**规则静默不生效** | 最危险:界面显示已封禁而流量照进 |
| 内核 locked memory | map 创建/扩容失败 | 明确报错,但可能连带影响其他 BPF 程序 |
| 用户态内存 | 前缀库常驻约 80 MB;逐条落库会让单次操作产生上万行 | DB 膨胀、界面不可读、下发变慢 |

内核**不会崩**,系统也不会死机 —— eBPF map 有硬容量上限,满了就是插入失败。
真正的风险不是崩溃,而是**静默失效**:运维以为封住了,实际没封。

### 五道闸门

**① 用 LPM_TRIE 而不是 HASH。** 这是前提。一条 `/8` 在 LPM_TRIE 里占 1 个表项,
在 HASH 里要 1600 万个。按国家封禁能成立完全依赖这一点。

**② 区间合并 + 最小 CIDR 拆分。** 数据源给的是任意起止区间(如 `1.0.0.0–1.0.3.255`),
不合并就逐个转 CIDR 会产生大量本可合并的碎片。`prefixdb.Resolve` 先按起点排序合并
重叠/相邻区间,再拆成最少数量的 CIDR。`TestRangeToCIDRs` 验证覆盖精确:
总地址数必须等于区间长度,不多一个(多封)也不少一个(漏封)。

**③ 提交前预览。** 界面强制先点"预览影响",返回确切的表项数、覆盖地址数、
IPv4 空间占比、剩余余量。用户在决定前就看到代价,而不是提交后收到错误。

**④ 三级配额(`internal/quota`)。**

- 单规则上限 32768 条前缀 —— 超过硬拒绝并建议缩小范围
- 全局水位线 = 容量的 80% —— **刻意留 20%**:攻击进行中时运维必须能立刻
  插一条精准封禁,不能因为之前批量导入了几个国家就无法操作
- 覆盖占比 > 25% 需显式勾选确认,该确认写入审计(可追溯到人)

配额是**预占式**的:提交(pending)时就扣额度,不是批准时。
否则多人同时提交会各自看到充足余量、合起来超限。
`TestTracker_ConcurrentReserveRespectsLimit` 用 500 并发验证
(实测 209/500 通过,占用 209000/209715,精确停在水位线)。

**⑤ 不逐条存储展开结果。** `ScopedBan` 只存"选择器 + 展开数量",
前缀在下发时重新展开。代价是前缀库更新后同一规则的展开结果可能漂移 ——
这是想要的行为(封禁跟随 BGP 现实),但记录了 `ResolvedAt` 与 `PrefixCount` 以便发现。

### 启动时恢复配额

重启后 Tracker 归零会让用户看到"表项全空"的假象,继续导入直到内核 map 真满。
`restoreQuota()` 从 DB 恢复 `pending + active` 的占用总量 ——
统计范围必须与 `Reserve` 的时机一致,否则待审批规则会凭空释放额度导致超额批准。

### 为什么目标限 /32

内核用 `LPM_TRIE` 对**源前缀**做最长匹配。key 的前 4 字节放 `target_id` 且
`prefixlen >= 32`,等价于"target_id 精确匹配 + src_ip 前缀匹配"(Cilium 同样手法)。
若目标也允许前缀,就需要对 `(dst_prefix, src_prefix)` 做二维最长匹配 ——
`LPM_TRIE` 表达不了,只能退化成逐条遍历,每包遍历在 XDP 里不可接受。
把目标限为主机 IP,二维问题降成一维。

### 还没做的

- **过期规则的内核侧清理**:XDP 侧只判 TTL 并放行,不删表项(内核删除需额外
  写权限与复杂度)。需要一个用户态 reaper 定期扫 map 删过期项并释放配额,
  否则长期运行后表项会被过期规则占满。**这是已知缺口。**
- **RLIMIT_MEMLOCK 探测**:目前不检查系统 locked memory 限额,map 创建
  失败时只能看到内核报错。应在启动时读 `/proc/self/limits` 并预警。
- **agent 侧的批量下发**:`executeXDP` 目前一次写一个 key。上万条前缀应改用
  `BatchUpdate`(内核 5.6+)减少 syscall 次数,否则单条规则下发会有可观延迟。

