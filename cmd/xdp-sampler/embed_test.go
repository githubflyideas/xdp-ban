package main

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/cilium/ebpf"
)

// 同 agent:验证内嵌 bytecode 真的可解析且含所需 map。
func TestEmbeddedBytecodeHasRequiredMaps(t *testing.T) {
	if len(xdpSamplerBytecode) == 0 {
		t.Skip("obj/xdp_sampler.o 为占位空文件;`make bpf` 后此测试才有意义")
	}

	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(xdpSamplerBytecode))
	if err != nil {
		t.Fatalf("内嵌 bytecode 无法解析: %v", err)
	}

	for _, name := range []string{"sampling_rate", "flow_table", "global_stats", "samples"} {
		m, ok := spec.Maps[name]
		if !ok {
			t.Errorf("缺少 map %q", name)
			continue
		}
		t.Logf("✓ %s: %s, max_entries=%d", name, m.Type, m.MaxEntries)
	}

	if _, ok := spec.Programs["xdp_sample"]; !ok {
		t.Error("缺少 xdp_sample 程序")
	}

	// ringbuf 必须是 RingBuf 类型 —— 用户态 ringbuf.NewReader 只认这个
	if m, ok := spec.Maps["samples"]; ok && m.Type != ebpf.RingBuf {
		t.Errorf("samples 类型 = %s,期望 RingBuf", m.Type)
	}
}

// SampleEvent 的 Go 结构体必须与 C 侧 struct sample_event 同尺寸。
// 不同则 binary.Read 错位,上报的 IP、端口、包长全是垃圾。
func TestSampleEventSizeMatchesBTF(t *testing.T) {
	const want = 28 // ts(8)+src_ip(4)+dst_ip(4)+ports(4)+proto(1)+pad(3)+len(2)+sampled(1)+pad(1)
	if got := binary.Size(SampleEvent{}); got != want {
		t.Errorf("SampleEvent = %d 字节,期望 %d(须与 C struct sample_event 一致)", got, want)
	}
}
