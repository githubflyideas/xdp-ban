package main

import _ "embed"

// xdpFilterBytecode 嵌入编译好的 XDP 过滤 eBPF 目标文件。
//
// obj/xdp_filter.o 由 `make bpf` (clang -target bpf) 生成,不进版本库
// —— 它是构建产物,且必须与 bpf/xdp_filter.c 同步,不该有第二份事实源。
//
// go:embed 要求文件存在才能编译,所以 obj/ 下有一个 .gitkeep;
// 首次克隆后需先 `make bpf`。`make build` 会先跑 bpf-check 断言 .o 非空,
// 避免产出内嵌空 bytecode 的二进制(那种二进制启动即报错,
// 但错误发生在客户机器上而不是构建时)。
//
//go:embed obj/xdp_filter.o
var xdpFilterBytecode []byte
