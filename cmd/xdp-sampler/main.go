// Package main — xdp-sampler: 纯 Go 单二进制
//
// 职责:
// 1. 加载嵌入的 eBPF bytecode 到采样网卡
// 2. 管理采样率(用户态可修改 BPF map)
// 3. 读 ringbuf 事件 → 聚合 → 上报
// 4. 提供 HTTP API 供 xdp-ban 控制采样率
//
// 部署: 拷贝单个二进制即可运行(需 root)
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
	"strconv"
	"sync"
	"time"

	"github.com/cilium/ebpf"
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
}

// ReportPayload 上报载荷
type ReportPayload struct {
	Timestamp  int64                  `json:"timestamp"`
	Device     string                 `json:"device"`
	SamplingN  int                    `json:"sampling_n"`
	Flows      []FlowSample           `json:"flows"`
	GlobalStat map[string]interface{} `json:"global_stat"`
}

// 采样率的运行时状态。HTTP handler 与主循环并发访问,故用锁保护;
// eBPF map 是唯一事实源,这里的副本只用于上报时标注当前比率。
var (
	rateMu         sync.RWMutex
	currentRateMap *ebpf.Map
	currentRate    = 100
)

// samplingRate 返回当前采样率 N(1/N)
func samplingRate() int {
	rateMu.RLock()
	defer rateMu.RUnlock()
	return currentRate
}

// setSamplingRate 更新 eBPF map 与本地副本
func setSamplingRate(n int) error {
	rateMu.Lock()
	defer rateMu.Unlock()
	if currentRateMap == nil {
		return fmt.Errorf("sampling_rate map 未初始化")
	}
	idx := uint32(0)
	if err := currentRateMap.Put(idx, uint32(n)); err != nil {
		return fmt.Errorf("更新 sampling_rate map: %w", err)
	}
	currentRate = n
	return nil
}

func main() {
	device := flag.String("d", "eth1", "采样网卡")
	xdpbanURL := flag.String("url", "http://localhost:8080/api/v1/samples", "xdp-ban 上报端点")
	samplingN := flag.Int("n", 100, "采样率 1/N")
	reportInterval := flag.Duration("interval", 10*time.Second, "上报间隔")
	httpPort := flag.String("p", ":9090", "HTTP API 监听端口")
	key := flag.String("key", "changeme", "上报到 xdp-ban 时使用的 API Key")
	flag.Parse()
	apiKey = *key

	log.Printf("XDP 采样器启动(纯 Go 单二进制): device=%s, sampling_rate=1/%d, http_port=%s\n", *device, *samplingN, *httpPort)

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

	// 2. 修改采样率(运行时配置)
	rateMap := coll.Maps["sampling_rate"]
	if rateMap == nil {
		log.Fatalf("sampling_rate map 不存在:bytecode 与预期不符")
	}
	currentRateMap = rateMap
	if err := setSamplingRate(*samplingN); err != nil {
		log.Fatalf("set sampling rate: %v", err)
	}
	log.Printf("✓ 采样率已设置: 1/%d (可通过 HTTP API 运行时修改)", *samplingN)

	// 3. 启动 HTTP API 服务(用于 xdp-ban 控制)
	mux := http.NewServeMux()
	mux.HandleFunc("/api/sampling/rate", handleSamplingRate)
	srv := &http.Server{
		Addr:              *httpPort,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}
	go func() {
		log.Printf("HTTP API 监听: %s", *httpPort)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("http listen: %v", err)
		}
	}()

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
	ticker := time.NewTicker(*reportInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			// 上报周期到
			if len(flowStats) > 0 {
				reportSamples(*xdpbanURL, *device, samplingRate(), flowStats)
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

			// 聚合流统计
			key := fmt.Sprintf("%s:%d-%s:%d/%s", srcIP, srcPort, dstIP, dstPort, protoToString(evt.Proto))

			if fs, exists := flowStats[key]; exists {
				fs.PktCount++
				fs.ByteCount += int64(evt.PktLen)
				fs.LastSeen = time.Now().Unix()
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
				}
			}
		}
	}
}

// handleSamplingRate HTTP API: 修改采样率
func handleSamplingRate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	rateStr := r.FormValue("rate")
	if rateStr == "" {
		http.Error(w, "rate required", http.StatusBadRequest)
		return
	}

	rate, err := strconv.Atoi(rateStr)
	if err != nil || rate < 1 || rate > 1000000 {
		http.Error(w, "invalid rate: 需为 1..1000000 的整数", http.StatusBadRequest)
		return
	}

	if err := setSamplingRate(rate); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	log.Printf("✓ 采样率已更新: 1/%d", rate)

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "rate": rate})
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
	return (v>>8) | (v<<8)
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
