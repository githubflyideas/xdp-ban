// netflow.go — NetFlow v5 导出。
//
// 为什么是 NetFlow v5 而不是 IPFIX/v9:
//
// 我们的 XDP 采样只产生 IPv4 五元组 + 包数/字节数,这恰好是 NetFlow v5
// 固定记录字段的全集。v5 无模板、无状态 —— 编码一次调对就永远对;
// IPFIX 要周期性发模板,收方没收到模板前会静默丢弃数据流,是一类
// "看起来在跑其实没数据"的隐性故障。灵活性我们用不上,复杂度和这个
// 稳定性风险却要全背。故选 v5。
//
// v5 的真实限制:32 位计数器、IPv4-only。对抽样统计场景无所谓 ——
// 采样本就是有损的,不是精确计费。
//
// 参考:Cisco NetFlow v5 报文格式(24 字节头 + 每条 48 字节,最多 30 条/包)。
package main

import (
	"bytes"
	"encoding/binary"
	"log"
	"net"
	"sync/atomic"
	"time"
)

const (
	netflowV5MaxRecords = 30 // 每个 UDP 包最多 30 条,超过要分包
	netflowV5HeaderLen  = 24
	netflowV5RecordLen  = 48
)

// netflowExporter 向一个 collector(ElastiFlow)发送 NetFlow v5。
//
// sysUptime 与 unixSecs 是 v5 头的必填项。flowSeq 必须单调递增 ——
// collector 用它检测丢包;发重或回退会让 ElastiFlow 误报异常。
type netflowExporter struct {
	conn     net.Conn
	bootTime time.Time
	flowSeq  atomic.Uint32
	enabled  bool
}

// newNetflowExporter 建立到 collector 的 UDP "连接"(UDP 无连接,
// 这里只是绑定目的地址,避免每次 send 都做地址解析)。
// addr 为空表示不启用导出。
func newNetflowExporter(addr string) (*netflowExporter, error) {
	if addr == "" {
		return &netflowExporter{enabled: false}, nil
	}
	conn, err := net.Dial("udp", addr)
	if err != nil {
		return nil, err
	}
	return &netflowExporter{
		conn:     conn,
		bootTime: time.Now(),
		enabled:  true,
	}, nil
}

// nfFlow 是导出所需的最小流信息。
// 与 FlowSample 分开:FlowSample 面向 JSON/人读,这里面向二进制线格式,
// 需要数值型的 IP、端口、协议号,而不是字符串。
type nfFlow struct {
	srcIP   uint32 // 网络字节序
	dstIP   uint32
	srcPort uint16
	dstPort uint16
	proto   uint8
	tos     uint8
	pkts    uint32
	bytes   uint32
	first   uint32 // 流首包相对 boot 的毫秒
	last    uint32 // 流末包相对 boot 的毫秒
}

// export 把一批流编码成 NetFlow v5 报文并发出。超过 30 条自动分包。
func (e *netflowExporter) export(flows []nfFlow, samplingN int) {
	if !e.enabled || len(flows) == 0 {
		return
	}
	for i := 0; i < len(flows); i += netflowV5MaxRecords {
		end := i + netflowV5MaxRecords
		if end > len(flows) {
			end = len(flows)
		}
		pkt := e.encode(flows[i:end], samplingN)
		if _, err := e.conn.Write(pkt); err != nil {
			log.Printf("netflow 导出失败: %v", err)
			return // 一个包失败,后续大概率也失败,不刷屏
		}
	}
}

func (e *netflowExporter) encode(flows []nfFlow, samplingN int) []byte {
	now := time.Now()
	uptime := uint32(now.Sub(e.bootTime).Milliseconds())

	buf := bytes.NewBuffer(make([]byte, 0, netflowV5HeaderLen+len(flows)*netflowV5RecordLen))

	// ---- v5 头(24 字节)----
	binary.Write(buf, binary.BigEndian, uint16(5))            // version
	binary.Write(buf, binary.BigEndian, uint16(len(flows)))   // count
	binary.Write(buf, binary.BigEndian, uptime)               // sys_uptime (ms)
	binary.Write(buf, binary.BigEndian, uint32(now.Unix()))   // unix_secs
	binary.Write(buf, binary.BigEndian, uint32(now.Nanosecond())) // unix_nsecs
	// flow_sequence:本包首条记录的序号,单调递增
	seq := e.flowSeq.Add(uint32(len(flows))) - uint32(len(flows))
	binary.Write(buf, binary.BigEndian, seq)
	buf.WriteByte(0) // engine_type
	buf.WriteByte(0) // engine_id
	// sampling_interval:高 2 位为采样模式,低 14 位为采样率。
	// 模式 0b01 = 确定性采样(每 N 个包取 1)。ElastiFlow 读这个字段
	// 后会把计数乘以 N 还原真实流量,所以这里必须如实填 N。
	sampInterval := uint16(0x4000) | (uint16(samplingN) & 0x3FFF)
	binary.Write(buf, binary.BigEndian, sampInterval)

	// ---- 流记录(每条 48 字节)----
	for _, f := range flows {
		binary.Write(buf, binary.BigEndian, f.srcIP)   // srcaddr
		binary.Write(buf, binary.BigEndian, f.dstIP)   // dstaddr
		binary.Write(buf, binary.BigEndian, uint32(0)) // nexthop
		binary.Write(buf, binary.BigEndian, uint16(0)) // input snmp
		binary.Write(buf, binary.BigEndian, uint16(0)) // output snmp
		binary.Write(buf, binary.BigEndian, f.pkts)    // dPkts
		binary.Write(buf, binary.BigEndian, f.bytes)   // dOctets
		binary.Write(buf, binary.BigEndian, f.first)   // first (uptime ms)
		binary.Write(buf, binary.BigEndian, f.last)    // last  (uptime ms)
		binary.Write(buf, binary.BigEndian, f.srcPort) // srcport
		binary.Write(buf, binary.BigEndian, f.dstPort) // dstport
		buf.WriteByte(0)                               // pad1
		buf.WriteByte(0)                               // tcp_flags(采样拿不全,置 0)
		buf.WriteByte(f.proto)                         // prot
		buf.WriteByte(f.tos)                           // tos
		binary.Write(buf, binary.BigEndian, uint16(0)) // src_as
		binary.Write(buf, binary.BigEndian, uint16(0)) // dst_as
		buf.WriteByte(0)                               // src_mask
		buf.WriteByte(0)                               // dst_mask
		binary.Write(buf, binary.BigEndian, uint16(0)) // pad2
	}
	return buf.Bytes()
}

func (e *netflowExporter) Close() error {
	if e.conn != nil {
		return e.conn.Close()
	}
	return nil
}
