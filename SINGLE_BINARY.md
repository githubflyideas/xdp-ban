## 纯 Go 单二进制部署(NO 外部文件)

### 快速开始

```bash
# 1. 编译 eBPF bytecode 并嵌入 Go
bash gen_ebpf_bytes.sh

# 2. 编译两个纯 Go 单二进制
go build -o xdp-agent ./cmd/xdp-agent
go build -o xdp-sampler ./cmd/xdp-sampler

# 3. 部署:只需拷贝二进制(需 root)
sudo cp xdp-agent /usr/local/bin/
sudo cp xdp-sampler /usr/local/bin/

# 4. 挂载 XDP(自动完成)
sudo xdp-agent -server http://localhost:8080 -key changeme &
sudo xdp-sampler -d eth1 -url http://localhost:8080/api/v1/samples &
```

### 部署架构

```
┌─────────────────────────────────┐
│ 单个 Go 二进制(xdp-sampler)    │
│ - 嵌入 xdp_sampler.o bytecode   │
│ - 加载 → ringbuf → 上报         │
│ - 参数: -d eth1 -n 100 -url ... │
└─────────────────────────────────┘

┌─────────────────────────────────┐
│ 单个 Go 二进制(xdp-agent)      │
│ - 嵌入 xdp_filter.o bytecode    │
│ - 加载 → 轮询 → 更新 eBPF map  │
│ - 参数: -server ... -key ...    │
└─────────────────────────────────┘
```

### 运行时调参(采样率)

```bash
# 修改采样率为 1/50
bpftool map update name sampling_rate key 0 0 0 0 value 50 0 0 0

# 修改为 1/10
bpftool map update name sampling_rate key 0 0 0 0 value 10 0 0 0
```

### 文件大小(预估)

```
xdp-agent:    ~15 MB (包含 eBPF bytecode)
xdp-sampler:  ~15 MB (包含 eBPF bytecode)
```

### 完整生命周期

```
1. 编译阶段:
   gen_ebpf_bytes.sh
   ├─ clang 编译 xdp_sampler.c → xdp_sampler.o
   ├─ clang 编译 xdp_filter.c → xdp_filter.o
   ├─ od 转换为 Go byte array
   └─ 生成 ebpf_sampler.go, ebpf_filter.go

2. 编译时:
   go build ./cmd/xdp-agent
   └─ 编译 main_ebpf.go + ebpf_filter.go → xdp-agent(单二进制)
   
   go build ./cmd/xdp-sampler
   └─ 编译 main_ebpf.go + ebpf_sampler.go → xdp-sampler(单二进制)

3. 运行时:
   xdp-agent
   ├─ 读 xdp-agent 二进制中的 xdpFilterBytecode
   ├─ ebpf.LoadCollectionSpec(bytes.Reader)
   ├─ 加载 → eBPF map 操作 → 执行
   └─ 轮询 xdp-ban server
   
   xdp-sampler
   ├─ 读 xdp-sampler 二进制中的 xdpSamplerBytecode
   ├─ ebpf.LoadCollectionSpec(bytes.Reader)
   ├─ 加载 → ringbuf 读取 → 聚合 → 上报
   └─ 周期上报采样数据
```

### 验证部署

```bash
# 查看 eBPF map
bpftool map list
bpftool map dump name ban_list
bpftool map dump name sampling_rate

# 查看 XDP program
bpftool prog list
ip link show dev eth0

# 查看日志
journalctl -u xdp-agent -f
journalctl -u xdp-sampler -f
```

### 优势

✅ **单二进制部署** — 一个文件,拷贝即用
✅ **零外部依赖** — 内嵌 eBPF bytecode,无需 .o 文件
✅ **即插即用** — `xdp-agent` 和 `xdp-sampler` 独立运行
✅ **运行时调参** — 采样率可动态修改,无需重启
✅ **生产级** — 正式发行版本可静态编译 `CGO_ENABLED=0`
