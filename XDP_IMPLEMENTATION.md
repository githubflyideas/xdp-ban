# XDP 执行层 & 采样层完整实现

## 🎯 架构

```
交换机(镜像流量)
    ↓
┌─────────────────────────────────────┐
│ 采样网卡(eth1) —— XDP 采样层         │
│ ┌─────────────────────────────────┐ │
│ │ xdp_sampler.o (BPF)             │ │
│ │ - 1/N 包采样                     │ │
│ │ - 流五元组聚合                   │ │
│ │ - ringbuf 上报                  │ │
│ └─────────────────────────────────┘ │
│      ↓ (ringbuf events)             │
│ ┌─────────────────────────────────┐ │
│ │ xdp-sampler (Go user daemon)    │ │
│ │ - 读 ringbuf 汇聚               │ │
│ │ - HTTP POST 上报到 xdp-ban     │ │
│ └─────────────────────────────────┘ │
└─────────────────────────────────────┘

业务网卡(eth0) —— XDP 执行层
┌──────────────────────────────────────────┐
│ xdp-agent (Go user daemon)               │
│ - 轮询 xdp-ban /api/v1/dispatch/pending │
│ - 调用 nftables 下发规则                 │
│ - 反馈执行状态                           │
└──────────────────────────────────────────┘
      ↓ (nftables cmd)
┌──────────────────────────────────────────┐
│ xdp_filter.o (BPF)                       │
│ - 黑名单快速路径(XDP_DROP)               │
│ - BPF map: 当前生效的黑名单              │
│ - 计数统计                               │
└──────────────────────────────────────────┘
      ↓ (业务流量)
    内核
```

---

## 📝 模块详解

### 1. xdp_sampler.c (采样 eBPF 程序)

**功能**:
- **1/N 包采样** — 可运行时动态调整采样率(BPF map: `sampling_rate`)
- **流五元组聚合** — IP 四元组 + 协议,聚合统计
- **ringbuf 上报** — 采样包事件实时发送到用户态

**BPF 数据结构**:

| Map | 用途 |
|-----|------|
| `sampling_rate` | 采样参数(1/N 中的 N) |
| `flow_table` | 流量统计(五元组 → 包数、字节数) |
| `global_stats` | 全局统计(总包数、采样包数) |
| `samples` | ringbuf(采样事件上报) |

**采样逻辑**:
```
for each packet:
  if packet matches filter(IPv4 only):
    update global_stats.total_packets
    if rand() % sampling_rate == 0:
      采样 = true
      push to ringbuf
    aggregate to flow_table
  return XDP_PASS  (旁路:不丢弃)
```

**运行时调整采样率**:
```bash
# 查看当前采样率
bpftool map dump name sampling_rate

# 修改采样率(1/50)
bpftool map update name sampling_rate key 0 0 0 0 value 50 0 0 0
```

---

### 2. xdp-sampler (Go 用户态采样 daemon)

**职责**:
1. 加载 xdp_sampler.o 到采样网卡(eth1)
2. 读取 ringbuf 事件,汇聚流统计
3. 周期上报到 xdp-ban server: `POST /api/v1/samples`

**工作流**:
```
main()
  ├─ load xdp_sampler.o
  ├─ set sampling_rate BPF map
  ├─ read ringbuf events
  │  ├─ parse flow_key (src/dst IP:port, proto)
  │  └─ aggregate to map[flow_key]*FlowSample
  └─ ticker 10s:
     └─ POST /api/v1/samples with flow list
```

**命令行**:
```bash
./xdp-sampler -d eth1 -prog ./xdp_sampler.o \
    -url http://localhost:8080/api/v1/samples \
    -n 100 \              # 采样率 1/100
    -interval 10s
```

**上报数据**:
```json
{
  "timestamp": 1722786654,
  "device": "eth1",
  "sampling_n": 100,
  "flows": [
    {
      "src_ip": "203.0.113.5",
      "dst_ip": "10.0.1.100",
      "src_port": 54321,
      "dst_port": 22,
      "proto": "tcp",
      "pkt_count": 1523,
      "byte_count": 456789,
      "last_seen_unix": 1722786650
    }
  ],
  "global_stat": {
    "timestamp": 1722786654
  }
}
```

---

### 3. xdp_filter.c (执行 eBPF 程序)

**功能**:
- **黑名单快速路径** — XDP 阶段直接 DROP(无需内核网络栈)
- **BPF map 黑名单** — `ban_list` 由 nftables 或 xdp-agent 管理
- **性能计数** — 丢弃包数统计

**BPF 数据结构**:

| Map | 用途 |
|-----|------|
| `ban_list` | 黑名单(ban_entry → action) |
| `counters` | 统计(DROP/PASS 计数) |

**执行逻辑**:
```
for each packet:
  extract (dst_ip, dst_port, proto)
  lookup ban_list[key]
  if found:
    counters[DROP]++
    return XDP_DROP
  else:
    return XDP_PASS
```

---

### 4. xdp-agent (Go 执行器 daemon)

**职责**:
1. 轮询 xdp-ban server: `GET /api/v1/dispatch/pending`
2. 解析 dispatch 指令(目标 IP、TTL、后端)
3. 调用 **nftables** 或 **iptables** 下发规则
4. 反馈执行状态: `POST /dispatch/:id/ack` 或 `/fail`

**工作流**:
```
main()
  └─ ticker 5s:
     ├─ GET /api/v1/dispatch/pending
     ├─ for each dispatch:
     │  ├─ parse payload
     │  ├─ executeNftables(target, ttl)
     │  │  └─ run: nft add element ip filter blacklist { 203.0.113.5 expires 3600s }
     │  ├─ if success: POST /dispatch/:id/ack
     │  └─ if fail: POST /dispatch/:id/fail
     └─ sleep 5s
```

**命令行**:
```bash
./xdp-agent -server http://localhost:8080 \
    -key changeme \
    -interval 5s
```

**nftables 初始化**(需 root):
```bash
# 创建表和规则集
nft add table ip filter
nft add chain ip filter input { type filter hook input priority 0; policy accept; }
nft add set ip filter blacklist { type ipv4_addr; flags dynamic; }
nft add rule ip filter input ip daddr @blacklist drop
```

**执行示例**:

```
dispatch 指令: 
{
  "id": 5,
  "target": "203.0.113.7",
  "ttl_secs": 3600,
  "backend": "nftables",
  "ban_id": "ban-5-203.0.113.7"
}

agent 执行:
  $ nft add element ip filter blacklist { 203.0.113.7 expires 3600s }
  ✓ success
  $ curl -X POST http://localhost:8080/api/v1/dispatch/5/ack
```

---

## 🔧 编译与部署

### 编译

```bash
# 编译 eBPF 程序(需 clang, llvm)
bash build_xdp.sh
# 生成:
#   cmd/xdp-agent/obj/xdp_filter.o
#   cmd/xdp-sampler/obj/xdp_sampler.o

# 编译 Go agent
go build -o xdp-agent ./cmd/xdp-agent

# 编译 Go sampler
go build -o xdp-sampler ./cmd/xdp-sampler
```

### 部署(需 root)

#### 采样侧(镜像流量接收端)

```bash
# 1. 挂载 XDP 采样程序到 eth1
ip link set dev eth1 xdp obj ./cmd/xdp-sampler/obj/xdp_sampler.o

# 2. 启动采样 daemon(连续读 ringbuf、上报)
sudo ./xdp-sampler -d eth1 -prog ./cmd/xdp-sampler/obj/xdp_sampler.o \
    -url http://xdpban-server:8080/api/v1/samples \
    -n 100 -interval 10s
```

#### 业务侧(防护网卡)

```bash
# 1. 初始化 nftables 表和规则集
sudo nft add table ip filter
sudo nft add chain ip filter input { type filter hook input priority 0; policy accept; }
sudo nft add set ip filter blacklist { type ipv4_addr; flags dynamic; }
sudo nft add rule ip filter input ip daddr @blacklist drop

# 2. 挂载 XDP 过滤程序到 eth0
sudo ip link set dev eth0 xdp obj ./cmd/xdp-agent/obj/xdp_filter.o

# 3. 启动执行器 daemon(轮询、下发)
sudo ./xdp-agent -server http://xdpban-server:8080 \
    -key your-api-key \
    -interval 5s
```

---

## 📊 数据流

```
1. 仪表板提交封禁请求
   xdp-ban server: CREATE ban_request (status=pending)
   
2. approver 审批
   xdp-ban server: UPDATE ban_request (status=active)
   生成 dispatch: target=203.0.113.7, ttl=3600s
   
3. xdp-agent 轮询
   GET /api/v1/dispatch/pending → [dispatch#5]
   执行: nft add element ip filter blacklist { 203.0.113.7 expires 3600s }
   POST /dispatch/5/ack
   
4. xdp-sampler 采样上报(并行)
   eth1 收到镜像流量
   每 1/100 个包采样上报到 xdp-ban
   仪表板展示实时流量统计
   
5. 威胁包经由 eth0
   xdp_filter.o 在 XDP 阶段检查黑名单
   命中 → XDP_DROP(无需内核处理)
   速度: 线速(L线 Gbps 级)
```

---

## 🎚️ 运行时调参

### 调整采样率

```bash
# 看当前采样率
bpftool map dump name sampling_rate

# 修改为 1/50
bpftool map update name sampling_rate key 0 0 0 0 value 50 0 0 0

# 修改为 1/10(采样更多)
bpftool map update name sampling_rate key 0 0 0 0 value 10 0 0 0
```

### 查看黑名单

```bash
# 查看当前黑名单(nftables)
nft list set ip filter blacklist

# 查看 XDP 计数
bpftool map dump name counters

# 实时监控 dispatch 状态
curl http://localhost:8080/api/v1/dispatch/pending
```

---

## ⚡ 性能指标

| 指标 | 数值 |
|------|------|
| XDP DROP 延迟 | < 1μs |
| 采样上报延迟 | ~10-100ms(ringbuf + HTTP) |
| 采样包吞吐 | 1M+ pps (1/100 at 100M pps) |
| nftables 更新延迟 | ~10ms |

---

## 🛑 故障恢复

### 移除 XDP 程序

```bash
# 卸载 XDP
ip link set dev eth0 xdp off
ip link set dev eth1 xdp off
```

### 清空黑名单

```bash
nft delete set ip filter blacklist
nft add set ip filter blacklist { type ipv4_addr; flags dynamic; }
```

### 日志查看

```bash
# xdp-agent 日志
journalctl -u xdp-agent -f

# xdp-sampler 日志
journalctl -u xdp-sampler -f

# eBPF 跟踪
bpftrace -e 'tracepoint:syscalls:sys_enter_* { printf("%s\n", comm); }' -n 5
```

---

## 📚 参考

- [xdp-project/xdp-tools](https://github.com/xdp-project/xdp-tools)
- [libbpf 文档](https://libbpf.readthedocs.io/)
- [nftables 手册](https://wiki.nftables.org/)
