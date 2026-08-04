package main

import (
	"encoding/binary"
	"net"
	"testing"
	"time"
)

// NetFlow v5 是固定二进制格式,一个字节错位 ElastiFlow 就整包丢弃。
// 这个测试逐字段解回来核对,是与 collector 兼容性的唯一保证 ——
// 没有真机时,报文结构正确就是能被解析的充分条件(v5 无模板协商)。
func TestNetflowV5_WireFormat(t *testing.T) {
	e := &netflowExporter{bootTime: time.Now().Add(-5 * time.Second), enabled: true}

	flows := []nfFlow{
		{
			srcIP:   binary.BigEndian.Uint32([]byte{203, 0, 113, 5}),
			dstIP:   binary.BigEndian.Uint32([]byte{10, 0, 0, 1}),
			srcPort: 54321, dstPort: 443, proto: 6,
			pkts: 100, bytes: 64000, first: 1000, last: 4000,
		},
	}
	pkt := e.encode(flows, 100)

	if len(pkt) != netflowV5HeaderLen+netflowV5RecordLen {
		t.Fatalf("报文长度 = %d, 期望 %d", len(pkt), netflowV5HeaderLen+netflowV5RecordLen)
	}

	// ---- 头 ----
	if v := binary.BigEndian.Uint16(pkt[0:2]); v != 5 {
		t.Errorf("version = %d, 期望 5", v)
	}
	if c := binary.BigEndian.Uint16(pkt[2:4]); c != 1 {
		t.Errorf("count = %d, 期望 1", c)
	}
	// sampling_interval:高 2 位 = 模式 01(确定性),低 14 位 = 采样率 100
	si := binary.BigEndian.Uint16(pkt[22:24])
	if si>>14 != 0b01 {
		t.Errorf("采样模式位 = %b, 期望 01(确定性采样)", si>>14)
	}
	if si&0x3FFF != 100 {
		t.Errorf("采样率字段 = %d, 期望 100 —— 填错会让 ElastiFlow 还原出错误的流量", si&0x3FFF)
	}

	// ---- 记录 ----
	rec := pkt[netflowV5HeaderLen:]
	if got := net.IP(rec[0:4]).String(); got != "203.0.113.5" {
		t.Errorf("srcaddr = %s, 期望 203.0.113.5", got)
	}
	if got := net.IP(rec[4:8]).String(); got != "10.0.0.1" {
		t.Errorf("dstaddr = %s, 期望 10.0.0.1", got)
	}
	if p := binary.BigEndian.Uint32(rec[16:20]); p != 100 {
		t.Errorf("dPkts = %d, 期望 100", p)
	}
	if b := binary.BigEndian.Uint32(rec[20:24]); b != 64000 {
		t.Errorf("dOctets = %d, 期望 64000", b)
	}
	if sp := binary.BigEndian.Uint16(rec[32:34]); sp != 54321 {
		t.Errorf("srcport = %d, 期望 54321", sp)
	}
	if dp := binary.BigEndian.Uint16(rec[34:36]); dp != 443 {
		t.Errorf("dstport = %d, 期望 443", dp)
	}
	if proto := rec[38]; proto != 6 {
		t.Errorf("prot = %d, 期望 6(TCP)", proto)
	}
}

// 超过 30 条必须分包 —— v5 头的 count 是无符号但 Cisco 约定单包上限 30,
// ElastiFlow 也按此校验,超了会拒收。
func TestNetflowV5_SplitsOversizedBatch(t *testing.T) {
	var sent [][]byte
	e := &netflowExporter{
		bootTime: time.Now(), enabled: true,
		conn: &capturingConn{onWrite: func(b []byte) { sent = append(sent, append([]byte(nil), b...)) }},
	}

	flows := make([]nfFlow, 70) // 应分成 30 + 30 + 10
	e.export(flows, 100)

	if len(sent) != 3 {
		t.Fatalf("70 条应分 3 个包,实际 %d 个", len(sent))
	}
	counts := []uint16{30, 30, 10}
	for i, pkt := range sent {
		if c := binary.BigEndian.Uint16(pkt[2:4]); c != counts[i] {
			t.Errorf("第 %d 包 count = %d, 期望 %d", i, c, counts[i])
		}
	}
}

// flow_sequence 必须单调递增且连续 —— collector 用它算丢包率,
// 回退或跳变会让 ElastiFlow 误报网络异常。
func TestNetflowV5_SequenceMonotonic(t *testing.T) {
	var seqs []uint32
	e := &netflowExporter{
		bootTime: time.Now(), enabled: true,
		conn: &capturingConn{onWrite: func(b []byte) {
			seqs = append(seqs, binary.BigEndian.Uint32(b[16:20]))
		}},
	}

	e.export(make([]nfFlow, 10), 100) // seq 0
	e.export(make([]nfFlow, 5), 100)  // seq 10
	e.export(make([]nfFlow, 3), 100)  // seq 15

	want := []uint32{0, 10, 15}
	for i := range want {
		if seqs[i] != want[i] {
			t.Errorf("第 %d 次导出 flow_sequence = %d, 期望 %d", i, seqs[i], want[i])
		}
	}
}

// 未配置 collector 时导出应是彻底的空操作,不 panic、不建连接
func TestNetflowV5_DisabledIsNoop(t *testing.T) {
	e, err := newNetflowExporter("")
	if err != nil {
		t.Fatalf("newNetflowExporter(\"\") 报错: %v", err)
	}
	if e.enabled {
		t.Error("空地址应表示未启用")
	}
	e.export([]nfFlow{{srcIP: 1}}, 100) // 不应 panic
}

func TestSat32(t *testing.T) {
	cases := []struct {
		in   int64
		want uint32
	}{
		{0, 0}, {100, 100},
		{-5, 0},                           // 负数饱和到 0
		{int64(^uint32(0)), ^uint32(0)},   // 恰好上限
		{int64(^uint32(0)) + 1, ^uint32(0)}, // 溢出饱和,不回绕
	}
	for _, tc := range cases {
		if got := sat32(tc.in); got != tc.want {
			t.Errorf("sat32(%d) = %d, 期望 %d", tc.in, got, tc.want)
		}
	}
}

// capturingConn 是测试用的假 net.Conn,只捕获写入的字节
type capturingConn struct {
	onWrite func([]byte)
}

func (c *capturingConn) Write(b []byte) (int, error) { c.onWrite(b); return len(b), nil }
func (c *capturingConn) Read([]byte) (int, error)    { return 0, nil }
func (c *capturingConn) Close() error                { return nil }
func (c *capturingConn) LocalAddr() net.Addr         { return nil }
func (c *capturingConn) RemoteAddr() net.Addr        { return nil }
func (c *capturingConn) SetDeadline(time.Time) error { return nil }
func (c *capturingConn) SetReadDeadline(time.Time) error  { return nil }
func (c *capturingConn) SetWriteDeadline(time.Time) error { return nil }
