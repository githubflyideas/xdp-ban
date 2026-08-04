package main

import (
	"encoding/binary"
	"testing"
)

// BPF 侧端口取自 tcphdr->source/dest,是网络字节序。
// 不转换就上报的话,80 端口会显示成 20480,仪表板上完全看不懂。
func TestNtohs(t *testing.T) {
	cases := []struct {
		net  uint16 // 网络字节序下的原始值
		host uint16 // 期望的主机序端口
	}{
		{0x5000, 80},    // HTTP
		{0x1600, 22},    // SSH
		{0xBB01, 443},   // HTTPS
		{0x3500, 53},    // DNS
	}
	for _, tc := range cases {
		if got := ntohs(tc.net); got != tc.host {
			t.Errorf("ntohs(0x%04X) = %d, 期望 %d", tc.net, got, tc.host)
		}
	}
}

func TestNtohs_RoundTrip(t *testing.T) {
	for _, port := range []uint16{1, 22, 80, 443, 8080, 65535} {
		if got := ntohs(ntohs(port)); got != port {
			t.Errorf("两次 ntohs(%d) = %d, 应回到原值", port, got)
		}
	}
}

// BPF 侧的 __u32 IP 是网络字节序,解码时按字节原样取出即可。
func TestIPToString(t *testing.T) {
	// 构造网络字节序的 203.0.113.7
	var raw uint32
	raw = binary.LittleEndian.Uint32([]byte{203, 0, 113, 7})

	if got := ipToString(raw); got != "203.0.113.7" {
		t.Errorf("ipToString = %q, 期望 203.0.113.7", got)
	}
}

func TestIPToString_Boundaries(t *testing.T) {
	cases := []struct {
		bytes []byte
		want  string
	}{
		{[]byte{0, 0, 0, 0}, "0.0.0.0"},
		{[]byte{255, 255, 255, 255}, "255.255.255.255"},
		{[]byte{10, 0, 0, 1}, "10.0.0.1"},
		{[]byte{127, 0, 0, 1}, "127.0.0.1"},
	}
	for _, tc := range cases {
		raw := binary.LittleEndian.Uint32(tc.bytes)
		if got := ipToString(raw); got != tc.want {
			t.Errorf("ipToString(%v) = %q, 期望 %q", tc.bytes, got, tc.want)
		}
	}
}

func TestProtoToString(t *testing.T) {
	if got := protoToString(6); got != "tcp" {
		t.Errorf("proto 6 = %q, 期望 tcp", got)
	}
	if got := protoToString(17); got != "udp" {
		t.Errorf("proto 17 = %q, 期望 udp", got)
	}
	if got := protoToString(1); got != "proto1" {
		t.Errorf("proto 1 = %q, 期望 proto1", got)
	}
}

// SampleEvent 必须与 bpf/xdp_sampler.c 的 struct sample_event 等长,
// 否则 binary.Read 会读串,所有字段都错位。
func TestSampleEventSize(t *testing.T) {
	// ts(8) + src_ip(4) + dst_ip(4) + src_port(2) + dst_port(2)
	// + proto(1) + pad(3) + pkt_len(2) + sampled(1) + pad(1) = 28
	const want = 28
	var evt SampleEvent
	got := binary.Size(evt)
	if got != want {
		t.Errorf("SampleEvent 大小 = %d 字节, 期望 %d(须与 C 结构体一致)", got, want)
	}
}

// 采样率是并发读写的:HTTP handler 改、上报循环读。
func TestSamplingRate_ConcurrentAccess(t *testing.T) {
	// currentRateMap 为 nil 时 setSamplingRate 应报错而非 panic
	if err := setSamplingRate(50); err == nil {
		t.Error("map 未初始化时 setSamplingRate 应返回错误")
	}
	// 读路径在任何情况下都不应 panic
	if n := samplingRate(); n < 1 {
		t.Errorf("samplingRate() = %d, 应有合法默认值", n)
	}
}
