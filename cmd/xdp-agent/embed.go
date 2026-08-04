package main

import _ "embed"

// xdpFilterBytecode 嵌入编译好的 XDP 过滤 eBPF 目标文件。
//
// obj/xdp_filter.o 由 `make bpf` (clang -target bpf) 生成。
// 仓库中保留一个占位空文件，使得在没有 clang 的机器上仍可编译
// 主程序；运行时若发现 bytecode 为空会明确报错。
//
//go:embed obj/xdp_filter.o
var xdpFilterBytecode []byte
