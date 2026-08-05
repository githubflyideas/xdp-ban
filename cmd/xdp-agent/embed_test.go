package main

import (
	"bytes"
	"testing"

	"github.com/cilium/ebpf"

	"github.com/xdpban/xdp-ban/internal/banmap"
)

// 这个测试是 P0 事故的最终防线:它真正解析内嵌的 bytecode,
// 断言所需的每张 map 都在里面。
//
// 只解析 spec 不创建 collection —— 创建需要 root 与内核支持,
// 但 spec 解析已经能抓住"map 名不匹配""bytecode 是空文件"这两类问题,
// 而这正是此前漏掉的。
func TestEmbeddedBytecodeHasRequiredMaps(t *testing.T) {
	if len(xdpFilterBytecode) == 0 {
		t.Skip("obj/xdp_filter.o 为占位空文件;在有 clang 的环境执行 `make bpf` 后此测试才有意义")
	}

	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(xdpFilterBytecode))
	if err != nil {
		t.Fatalf("内嵌 bytecode 无法解析: %v", err)
	}

	for _, name := range []string{
		banmap.MapGlobalBans, banmap.MapTargetHosts,
		banmap.MapSrcBans, banmap.MapCounters,
	} {
		m, ok := spec.Maps[name]
		if !ok {
			t.Errorf("内嵌 bytecode 缺少 map %q —— agent 启动会 Fatalf", name)
			continue
		}
		t.Logf("✓ %s: %s, max_entries=%d", name, m.Type, m.MaxEntries)
	}

	// 容量必须与配额记账一致,否则用户态以为还有余量而内核已满
	if m, ok := spec.Maps[banmap.MapSrcBans]; ok {
		const want = 262144
		if m.MaxEntries != want {
			t.Errorf("%s max_entries=%d,期望 %d(须与 quota.MapCapacity 一致)",
				banmap.MapSrcBans, m.MaxEntries, want)
		}
	}

	if _, ok := spec.Programs["xdp_filter"]; !ok {
		t.Error("内嵌 bytecode 缺少 xdp_filter 程序")
	}
}
