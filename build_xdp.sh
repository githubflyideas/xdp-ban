#!/bin/bash
# build_xdp.sh — 编译 XDP 程序

set -e

BPF_DIR="./cmd/xdp-agent"
SAMPLER_DIR="./cmd/xdp-sampler"
CLANG=${CLANG:=clang}
VMLINUX_BTF=${VMLINUX_BTF:=/sys/kernel/btf/vmlinux}

echo "=== 编译 XDP eBPF 程序 ==="

# 1. 编译 xdp_filter (执行层)
echo "编译 xdp_filter.c ..."
mkdir -p "$BPF_DIR/obj"
$CLANG -O2 -target bpf \
    -c "$BPF_DIR/xdp_filter.c" \
    -o "$BPF_DIR/obj/xdp_filter.o"
echo "✓ $BPF_DIR/obj/xdp_filter.o"

# 2. 编译 xdp_sampler (采样层)
echo "编译 xdp_sampler.c ..."
mkdir -p "$SAMPLER_DIR/obj"
$CLANG -O2 -target bpf \
    -c "$SAMPLER_DIR/xdp_sampler.c" \
    -o "$SAMPLER_DIR/obj/xdp_sampler.o"
echo "✓ $SAMPLER_DIR/obj/xdp_sampler.o"

echo ""
echo "=== XDP 程序编译完成 ==="
echo ""
echo "部署方法:"
echo "  采样网卡(eth1): ip link set dev eth1 xdp obj $SAMPLER_DIR/obj/xdp_sampler.o"
echo "  过滤网卡(eth0): ip link set dev eth0 xdp obj $BPF_DIR/obj/xdp_filter.o"
echo ""
echo "编译 Go agent: go build -o xdp-agent ./cmd/xdp-agent"
echo "编译 Go sampler: go build -o xdp-sampler ./cmd/xdp-sampler"
