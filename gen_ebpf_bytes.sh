#!/bin/bash
# gen_ebpf_bytes.sh — 生成 eBPF bytecode 的 Go 常量

set -e

CLANG=${CLANG:=clang}
LLVM_OBJCOPY=${LLVM_OBJCOPY:=llvm-objcopy}

echo "编译 eBPF 程序为 Go bytecode..."

# 1. 编译 xdp_sampler.c
echo "  编译 xdp_sampler.c..."
mkdir -p cmd/xdp-sampler/obj
$CLANG -O2 -target bpf -c cmd/xdp-sampler/xdp_sampler.c -o cmd/xdp-sampler/obj/xdp_sampler.o

# 2. 编译 xdp_filter.c
echo "  编译 xdp_filter.c..."
mkdir -p cmd/xdp-agent/obj
$CLANG -O2 -target bpf -c cmd/xdp-agent/xdp_filter.c -o cmd/xdp-agent/obj/xdp_filter.o

# 3. 转换为 Go 常量
echo "  生成 Go 常量..."

# xdp_sampler.go
cat > cmd/xdp-sampler/ebpf_sampler.go << 'EOF'
package main

// xdpSamplerBytecode — 嵌入的 XDP 采样 eBPF 程序(bytecode)
// 由 gen_ebpf_bytes.sh 自动生成,勿手动编辑
var xdpSamplerBytecode = []byte{
EOF

# 读取 .o 文件转为 hex byte array
od -An -tx1 -v cmd/xdp-sampler/obj/xdp_sampler.o | sed 's/ /0x/g;s/^/\t/;s/ /, 0x/g' >> cmd/xdp-sampler/ebpf_sampler.go

cat >> cmd/xdp-sampler/ebpf_sampler.go << 'EOF'
}
EOF

# xdp_filter.go
cat > cmd/xdp-agent/ebpf_filter.go << 'EOF'
package main

// xdpFilterBytecode — 嵌入的 XDP 过滤 eBPF 程序(bytecode)
// 由 gen_ebpf_bytes.sh 自动生成,勿手动编辑
var xdpFilterBytecode = []byte{
EOF

od -An -tx1 -v cmd/xdp-agent/obj/xdp_filter.o | sed 's/ /0x/g;s/^/\t/;s/ /, 0x/g' >> cmd/xdp-agent/ebpf_filter.go

cat >> cmd/xdp-agent/ebpf_filter.go << 'EOF'
}
EOF

echo "✓ eBPF bytecode 已生成:"
echo "  - cmd/xdp-sampler/ebpf_sampler.go"
echo "  - cmd/xdp-agent/ebpf_filter.go"
echo ""
echo "文件大小:"
ls -lh cmd/xdp-sampler/ebpf_sampler.go cmd/xdp-agent/ebpf_filter.go
