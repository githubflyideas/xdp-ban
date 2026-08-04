// Package main — xdp-sampler: 纯 Go 单二进制
//
// 职责:
// 1. 加载嵌入的 eBPF bytecode 到采样网卡
// 2. 管理采样率(用户态可修改 BPF map)
// 3. 读 ringbuf 事件 → 聚合 → 上报
//
// 部署: 拷贝单个二进制即可运行(需 root)
package main

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/ringbuf"
)

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
}

// ReportPayload 上报载荷
type ReportPayload struct {
	Timestamp  int64                  `json:"timestamp"`
	Device     string                 `json:"device"`
	SamplingN  int                    `json:"sampling_n"`
	Flows      []FlowSample           `json:"flows"`
	GlobalStat map[string]interface{} `json:"global_stat"`
}

func main() {
	device := flag.String("d", "eth1", "采样网卡")
	xdpbanURL := flag.String("url", "http://localhost:8080/api/v1/samples", "xdp-ban 上报端点")
	samplingN := flag.Int("n", 100, "采样率 1/N")
	reportInterval := flag.Duration("interval", 10*time.Second, "上报间隔")
	flag.Parse()

	log.Printf("XDP 采样器启动(纯 Go 单二进制): device=%s, sampling_rate=1/%d\n", *device, *samplingN)

	// 1. 加载嵌入的 eBPF bytecode
	reader := bytes.NewReader(xdpSamplerBytecode)
	spec, err := ebpf.LoadCollectionSpec(reader)
	if err != nil {
		log.Fatalf("load ebpf spec: %v", err)
	}

	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		log.Fatalf("create ebpf collection: %v", err)
	}
	defer coll.Close()

	// 2. 修改采样率(运行时配置)
	rateMap := coll.Maps["sampling_rate"]
	if rateMap != nil {
		idx := uint32(0)
		if err := rateMap.Put(idx, uint32(*samplingN)); err != nil {
			log.Fatalf("set sampling rate: %v", err)
		}
		log.Printf("✓ 采样率已设置: 1/%d (可运行时修改)", *samplingN)
		log.Printf("  修改采样率: bpftool map update name sampling_rate key 0 0 0 0 value <N> 0 0 0")
	}

	// 3. 挂载 XDP prog
	log.Printf("XDP prog 已加载(需 root 权限挂载到 %s):", *device)
	log.Printf("  ip link set dev %s xdp obj <path> section xdp", *device)
	log.Printf("")

	// 4. 读 ringbuf → 上报
	rd, err := ringbuf.NewReader(coll.Maps["samples"])
	if err != nil {
		log.Fatalf("create ringbuf reader: %v", err)
	}
	defer rd.Close()

	// 流量聚合缓冲
	flowStats := make(map[string]*FlowSample)
	ticker := time.NewTicker(*reportInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			// 上报周期到
			if len(flowStats) > 0 {
				reportSamples(*xdpbanURL, *device, *samplingN, flowStats)
				flowStats = make(map[string]*FlowSample) // 清空
			}

		case record := <-rd.Records:
			// 读取 ringbuf 事件
			if record.RawSample == nil {
				continue
			}

			var evt SampleEvent
			if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &evt); err != nil {
				log.Printf("parse sample event: %v", err)
				continue
			}

			// 聚合流统计
			key := fmt.Sprintf("%s:%d-%s:%d/%s",
				ipUint32ToString(evt.SrcIP), evt.SrcPort,
				ipUint32ToString(evt.DstIP), evt.DstPort,
				protoToString(evt.Proto),
			)

			if fs, exists := flowStats[key]; exists {
				fs.PktCount++
				fs.ByteCount += int64(evt.PktLen)
			} else {
				flowStats[key] = &FlowSample{
					SrcIP:     ipUint32ToString(evt.SrcIP),
					DstIP:     ipUint32ToString(evt.DstIP),
					SrcPort:   int(evt.SrcPort),
					DstPort:   int(evt.DstPort),
					Proto:     protoToString(evt.Proto),
					PktCount:  1,
					ByteCount: int64(evt.PktLen),
					LastSeen:  time.Now().Unix(),
				}
			}
		}
	}
}

func reportSamples(url, device string, samplingN int, flows map[string]*FlowSample) {
	flowList := make([]FlowSample, 0, len(flows))
	for _, fs := range flows {
		flowList = append(flowList, *fs)
	}

	payload := ReportPayload{
		Timestamp: time.Now().Unix(),
		Device:    device,
		SamplingN: samplingN,
		Flows:     flowList,
		GlobalStat: map[string]interface{}{
			"timestamp": time.Now().Unix(),
		},
	}

	data, _ := json.Marshal(payload)
	resp, err := http.Post(url, "application/json", bytes.NewBuffer(data))
	if err != nil {
		log.Printf("上报失败: %v", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		log.Printf("上报返回: %d", resp.StatusCode)
		return
	}

	log.Printf("✓ 上报 %d 条流统计(采样率 1/%d)", len(flowList), samplingN)
}

func ipUint32ToString(ip uint32) string {
	return net.IPv4(byte(ip), byte(ip>>8), byte(ip>>16), byte(ip>>24)).String()
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
