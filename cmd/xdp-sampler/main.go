// Package main — xdp-sampler: 纯 Go 单二进制
//
// 职责:
// 1. 加载嵌入的 eBPF bytecode,attach 到采样网卡(XDP_PASS 旁路,只观测不拦截)
// 2. 读 ringbuf 事件 → 聚合 → 上报给 xdp-ban
// 3. 可选:把同一批聚合结果以 NetFlow v5 导出给 ElastiFlow
//
// 启动参数只有 5 个,且启动后不可再变(见下方 main 的 flag 定义):
// 采样率是"看见即封禁"链路里的观测配置,不该在运行时被网页悄悄改掉——
// 改动过一次采样率却没人记得,复现问题时会怀疑错方向。要改就重启,
// systemd/进程管理器的重启记录本身就是变更记录。
//
// 部署: 拷贝单个二进制即可运行(需 root/CAP_NET_ADMIN,因为要 attach XDP)
package main

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
)

// apiKey 上报时携带的 API Key,由 -key 参数注入
var apiKey = "changeme"

// SampleEvent 采样事件
type SampleEvent struct {
	Ts      uint64
	SrcIP   uint32
	DstIP   uint32
	SrcPort uint16
	DstPort uint16
	Proto   uint8
	_       [3]uint8
	PktLen  uint16
	Sampled uint8
	_       uint8
}

// FlowSample 上报数据
type FlowSample struct {
	SrcIP     string `json:"src_ip"`
	DstIP     string `json:"dst_ip"`
	SrcPort   int    `json:"src_port"`
	DstPort   int    `json:"dst_port"`
	Proto     string `json:"proto"`
	PktCount  int64  `json:"pkt_count"`
	ByteCount int64  `json:"byte_count"`
	LastSeen  int64  `json:"last_seen_unix"`

	// 以下为数值型原始字段,仅供 NetFlow v5 二进制编码使用,不进 JSON。
	// 保留在这里避免为 NetFlow 单独维护第二张聚合表。
	rawSrcIP    uint32 // 网络字节序
	rawDstIP    uint32
	rawSrcPort  uint16
	rawDstPort  uint16
	rawProto    uint8
	firstUptime uint32 // 流首包相对采样器启动的毫秒
	lastUptime  uint32
}

// ReportPayload 上报载荷。
//
// Interface / NetflowTarget 是新增字段:xdp-ban 的「采样与流量」页要展示
// 当前采样器的启动参数(只读),不新开接口去反向查询采样器 —— 复用这条
// 已有的周期上报,把这两个字段捎带过去即可。
type ReportPayload struct {
	Timestamp     int64                  `json:"timestamp"`
	Device        string                 `json:"device"`
	SamplingN     int                    `json:"sampling_n"`
	NetflowTarget string                 `json:"netflow_target,omitempty"`
	Flows         []FlowSample           `json:"flows"`
	GlobalStat    map[string]interface{} `json:"global_stat"`
}

// bootTime 采样器启动时刻。NetFlow v5 的 first/last 是相对启动的毫秒数,
// 需要一个进程级基准。
var bootTime = time.Now()

func main() {
	device := flag.String("d", "eth1", "采样网卡")
	xdpbanURL := flag.String("url", "http://localhost:8080/api/v1/samples", "xdp-ban 上报端点")
	samplingN := flag.Int("n", 100, "采样率 1/N")
	key := flag.String("key", "changeme", "上报到 xdp-ban 时使用的 API Key")
	netflowAddr := flag.String("netflow", "", "NetFlow v5 collector 地址(host:port,如 elastiflow:2055);为空则不导出")
	flag.Parse()
	apiKey = *key

	const reportInterval = 10 * time.Second

	log.Printf("XDP 采样器启动(纯 Go 单二进制): device=%s, sampling_rate=1/%d\n", *device, *samplingN)

	// NetFlow v5 导出器(可选)。启动即建 UDP 目的地绑定,失败快速退出 ——
	// 配了 collector 却连不上,应该让用户立刻知道,而不是静默不发。
	nfExporter, err := newNetflowExporter(*netflowAddr)
	if err != nil {
		log.Fatalf("初始化 NetFlow 导出器 (%s): %v", *netflowAddr, err)
	}
	defer nfExporter.Close()
	if nfExporter.enabled {
		log.Printf("✓ NetFlow v5 导出已启用 → %s(采样率 1/%d 会写入报文供 collector 还原)", *netflowAddr, *samplingN)
	}

	// 1. 加载嵌入的 eBPF bytecode
	if len(xdpSamplerBytecode) == 0 {
		log.Fatalf("嵌入的 eBPF bytecode 为空:请先运行 `make bpf` 编译 bpf/xdp_sampler.c,再重新构建本程序")
	}
	reader := bytes.NewReader(xdpSamplerBytecode)
	spec, err := ebpf.LoadCollectionSpecFromReader(reader)
	if err != nil {
		log.Fatalf("load ebpf spec: %v", err)
	}

	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		log.Fatalf("create ebpf collection: %v", err)
	}
	defer coll.Close()

	// 2. 设置采样率(启动时一次性写入,运行期不再变更)
	rateMap := coll.Maps["sampling_rate"]
	if rateMap == nil {
		log.Fatalf("sampling_rate map 不存在:bytecode 与预期不符")
	}
	idx := uint32(0)
	if err := rateMap.Put(idx, uint32(*samplingN)); err != nil {
		log.Fatalf("set sampling rate: %v", err)
	}
	log.Printf("✓ 采样率已设置: 1/%d(启动参数,运行期不可调整)", *samplingN)

	// 3. attach XDP 程序到采样网卡。这一步此前缺失 —— eBPF collection 加载
	// 成功只代表程序在内核里"存在",不代表它在处理任何流量;没有这一步,
	// 采样器会正常启动、正常打日志,却永远收不到一个采样事件。
	prog := coll.Programs["xdp_sample"]
	if prog == nil {
		log.Fatalf("内嵌 bytecode 缺少 xdp_sample 程序 —— bytecode 与本程序版本不匹配")
	}
	ifc, err := net.InterfaceByName(*device)
	if err != nil {
		log.Fatalf("查找网卡 %q 失败: %v", *device, err)
	}
	xdpLink, err := link.AttachXDP(link.XDPOptions{
		Program:   prog,
		Interface: ifc.Index,
	})
	if err != nil {
		log.Fatalf("attach XDP 程序到 %s 失败: %v ——"+
			"常见原因:权限不足(需 root/CAP_NET_ADMIN)、网卡不支持 XDP、"+
			"或已有另一个 XDP 程序占用该网卡", *device, err)
	}
	defer xdpLink.Close()
	log.Printf("✓ XDP 采样程序已挂载到 %s", *device)

	// 4. 读 ringbuf → 上报
	rd, err := ringbuf.NewReader(coll.Maps["samples"])
	if err != nil {
		log.Fatalf("create ringbuf reader: %v", err)
	}
	defer rd.Close()

	// ringbuf.Reader.Read 是阻塞调用,放到独立 goroutine,
	// 通过 channel 与上报 ticker 汇合,避免读事件阻塞上报周期。
	events := make(chan SampleEvent, 4096)
	go func() {
		defer close(events)
		for {
			record, err := rd.Read()
			if err != nil {
				if errors.Is(err, ringbuf.ErrClosed) {
					return
				}
				log.Printf("read ringbuf: %v", err)
				continue
			}
			var evt SampleEvent
			if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &evt); err != nil {
				log.Printf("parse sample event: %v", err)
				continue
			}
			select {
			case events <- evt:
			default:
				// 上报侧跟不上时丢弃,采样本身已是有损统计,不因背压阻塞内核侧
			}
		}
	}()

	// 流量聚合缓冲
	flowStats := make(map[string]*FlowSample)
	ticker := time.NewTicker(reportInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			// 上报周期到
			if len(flowStats) > 0 {
				reportSamples(*xdpbanURL, *device, *samplingN, *netflowAddr, flowStats)
				// 同一批聚合结果同时喂给 NetFlow collector(ElastiFlow)。
				// 复用同一张表,不为 NetFlow 单独再聚合一遍。
				nfExporter.export(toNetflowFlows(flowStats), *samplingN)
				flowStats = make(map[string]*FlowSample) // 清空
			}

		case evt, ok := <-events:
			if !ok {
				return
			}

			// BPF 侧端口为网络字节序,这里转主机序
			srcPort := ntohs(evt.SrcPort)
			dstPort := ntohs(evt.DstPort)
			srcIP := ipToString(evt.SrcIP)
			dstIP := ipToString(evt.DstIP)
			nowMs := uint32(time.Since(bootTime).Milliseconds())

			// 聚合流统计
			key := fmt.Sprintf("%s:%d-%s:%d/%s", srcIP, srcPort, dstIP, dstPort, protoToString(evt.Proto))

			if fs, exists := flowStats[key]; exists {
				fs.PktCount++
				fs.ByteCount += int64(evt.PktLen)
				fs.LastSeen = time.Now().Unix()
				fs.lastUptime = nowMs
			} else {
				flowStats[key] = &FlowSample{
					SrcIP:     srcIP,
					DstIP:     dstIP,
					SrcPort:   int(srcPort),
					DstPort:   int(dstPort),
					Proto:     protoToString(evt.Proto),
					PktCount:  1,
					ByteCount: int64(evt.PktLen),
					LastSeen:  time.Now().Unix(),

					rawSrcIP:    evt.SrcIP,
					rawDstIP:    evt.DstIP,
					rawSrcPort:  srcPort,
					rawDstPort:  dstPort,
					rawProto:    evt.Proto,
					firstUptime: nowMs,
					lastUptime:  nowMs,
				}
			}
		}
	}
}

// toNetflowFlows 把聚合表转成 NetFlow v5 记录。
// 32 位计数器溢出用饱和处理:采样统计不做精确计费,封顶比回绕更符合直觉。
func toNetflowFlows(flows map[string]*FlowSample) []nfFlow {
	out := make([]nfFlow, 0, len(flows))
	for _, fs := range flows {
		out = append(out, nfFlow{
			srcIP:   fs.rawSrcIP,
			dstIP:   fs.rawDstIP,
			srcPort: fs.rawSrcPort,
			dstPort: fs.rawDstPort,
			proto:   fs.rawProto,
			pkts:    sat32(fs.PktCount),
			bytes:   sat32(fs.ByteCount),
			first:   fs.firstUptime,
			last:    fs.lastUptime,
		})
	}
	return out
}

func sat32(v int64) uint32 {
	if v < 0 {
		return 0
	}
	if v > int64(^uint32(0)) {
		return ^uint32(0)
	}
	return uint32(v)
}

func reportSamples(url, device string, samplingN int, netflowTarget string, flows map[string]*FlowSample) {
	flowList := make([]FlowSample, 0, len(flows))
	for _, fs := range flows {
		flowList = append(flowList, *fs)
	}

	payload := ReportPayload{
		Timestamp:     time.Now().Unix(),
		Device:        device,
		SamplingN:     samplingN,
		NetflowTarget: netflowTarget,
		Flows:         flowList,
		GlobalStat: map[string]any{
			"timestamp": time.Now().Unix(),
		},
	}

	data, err := json.Marshal(payload)
	if err != nil {
		log.Printf("序列化上报载荷: %v", err)
		return
	}

	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(data))
	if err != nil {
		log.Printf("构造上报请求: %v", err)
		return
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", apiKey)

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("上报失败: %v", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		log.Printf("上报返回非 200: %d", resp.StatusCode)
		return
	}

	log.Printf("✓ 上报 %d 条流统计(采样率 1/%d)", len(flowList), samplingN)
}

// ipToString 把 BPF 侧的 __u32 IPv4(网络字节序)转为点分十进制
func ipToString(ip uint32) string {
	var b [4]byte
	binary.LittleEndian.PutUint32(b[:], ip)
	return net.IPv4(b[0], b[1], b[2], b[3]).String()
}

// ntohs 网络字节序 uint16 转主机序
func ntohs(v uint16) uint16 {
	return (v >> 8) | (v << 8)
}

func protoToString(proto uint8) string {
	switch proto {
	case 6:
		return "tcp"
	case 17:
		return "udp"
	default:
		return fmt.Sprintf("proto%d", proto)
	}
}
