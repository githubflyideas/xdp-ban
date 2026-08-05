package main

import _ "embed"

// xdpSamplerBytecode 嵌入编译好的 XDP 采样 eBPF 目标文件。
//
// obj/xdp_sampler.o 由 `make bpf` (clang -target bpf) 生成,不进版本库
// —— 它是构建产物,且必须与 bpf/xdp_sampler.c 同步,不该有第二份事实源。
//
// 首次克隆后需先 `make bpf`;`make build` 会断言 .o 非空,
// 避免产出内嵌空 bytecode 的二进制。
//
//go:embed obj/xdp_sampler.o
var xdpSamplerBytecode []byte
