// Package main — xdp-agent: 纯 Go 单二进制
//
// 职责:
// 1. 轮询 xdp-ban 服务器 GET /api/v1/dispatch/pending
// 2. 执行 dispatch 指令(直接操作嵌入的 eBPF map,NO nftables)
// 3. 反馈执行状态 POST /api/v1/dispatch/:id/ack 或 /fail
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
	"strings"
	"time"

	"github.com/cilium/ebpf"
)

// Dispatch 下发指令
type Dispatch struct {
	ID           uint   `json:"id"`
	BanRequestID uint   `json:"ban_request_id"`
	BanID        string `json:"ban_id"`
	NodeID       string `json:"node_id"`
	Payload      string `json:"payload"`
	State        string `json:"state"`
}

// BanPayload 指令内容
type BanPayload struct {
	Target   string `json:"target"`
	TTLSecs  int64  `json:"ttl_secs"`
	NodeID   string `json:"node_id"`
	ReqID    uint   `json:"req_id"`
	BanID    string `json:"ban_id"`
	Backend  string `json:"backend"`
	Reason   string `json:"reason"`
}

// BanEntry 对应 bpf/xdp_filter.c 的 ban_entry(仅作文档参照,写 map 时手工编码)
type BanEntry struct {
	DstIP   uint32
	DstPort uint16
	Proto   uint8
	_       uint8
}

// BanValue 对应 xdp_filter.c 的 ban_value
type BanValue struct {
	ExpiresAt uint64
	Hits      uint32
}

type Config struct {
	ServerURL string
	APIKey    string
	Interval  time.Duration
}

func main() {
	serverURL := flag.String("server", "http://localhost:8080", "xdp-ban 服务器地址")
	apiKey := flag.String("key", "changeme", "API Key")
	interval := flag.Duration("interval", 5*time.Second, "轮询间隔")
	flag.Parse()

	cfg := Config{
		ServerURL: *serverURL,
		APIKey:    *apiKey,
		Interval:  *interval,
	}

	log.Printf("XDP 执行器启动(纯 Go 单二进制): server=%s\n", cfg.ServerURL)

	// 1. 加载嵌入的 eBPF bytecode
	if len(xdpFilterBytecode) == 0 {
		log.Fatalf("嵌入的 eBPF bytecode 为空:请先运行 `make bpf` 编译 bpf/xdp_filter.c,再重新构建本程序")
	}
	reader := bytes.NewReader(xdpFilterBytecode)
	spec, err := ebpf.LoadCollectionSpecFromReader(reader)
	if err != nil {
		log.Fatalf("load ebpf spec: %v", err)
	}

	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		log.Fatalf("create ebpf collection: %v", err)
	}
	defer coll.Close()

	banListMap := coll.Maps["ban_list"]
	if banListMap == nil {
		log.Fatalf("ban_list map not found")
	}

	log.Printf("✓ eBPF 黑名单 map 已加载(纯 XDP 执行)\n")

	ticker := time.NewTicker(cfg.Interval)
	defer ticker.Stop()

	for range ticker.C {
		pollAndExecute(&cfg, banListMap)
	}
}

func pollAndExecute(cfg *Config, banListMap *ebpf.Map) {
	// 1. 轮询待执行指令
	dispatches, err := fetchPending(cfg)
	if err != nil {
		log.Printf("fetch pending: %v", err)
		return
	}

	if len(dispatches) == 0 {
		return
	}

	log.Printf("获取 %d 条待执行指令", len(dispatches))

	// 2. 逐条执行
	for _, d := range dispatches {
		var payload BanPayload
		if err := json.Unmarshal([]byte(d.Payload), &payload); err != nil {
			log.Printf("parse payload: %v", err)
			markFailed(cfg, d.ID, fmt.Sprintf("parse error: %v", err))
			continue
		}

		log.Printf("执行指令 #%d: %s (TTL=%ds)", d.ID, payload.Target, payload.TTLSecs)

		// 3. 直接写 eBPF map(XDP 执行)
		if err := executeXDP(banListMap, &payload); err != nil {
			log.Printf("execute XDP: %v", err)
			markFailed(cfg, d.ID, fmt.Sprintf("exec error: %v", err))
			continue
		}

		// 4. 标记成功
		markAck(cfg, d.ID)
		log.Printf("指令 #%d 执行成功", d.ID)
	}
}

func fetchPending(cfg *Config) ([]Dispatch, error) {
	url := cfg.ServerURL + "/api/v1/dispatch/pending"
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("X-API-Key", cfg.APIKey)

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("status %d", resp.StatusCode)
	}

	var dispatches []Dispatch
	if err := json.NewDecoder(resp.Body).Decode(&dispatches); err != nil {
		return nil, err
	}
	return dispatches, nil
}

// executeXDP 直接写 eBPF map。
//
// 键的内存布局必须与 bpf/xdp_filter.c 的 struct ban_entry 一致:
//
//	__u32 dst_ip    // 网络字节序,与 iphdr->daddr 原样一致
//	__u16 dst_port  // 网络字节序,0 = 任意
//	__u8  proto     // 0 = 任意
//	__u8  _pad
func executeXDP(banListMap *ebpf.Map, payload *BanPayload) error {
	ip, err := parseTarget(payload.Target)
	if err != nil {
		return err
	}

	// dst_ip: 原样 4 字节(网络字节序),不做端序转换
	key := make([]byte, 8)
	copy(key[0:4], ip)
	// key[4:6] dst_port = 0(任意), key[6] proto = 0(任意), key[7] 填充

	expiresAt := uint64(0)
	if payload.TTLSecs > 0 {
		expiresAt = uint64(time.Now().UnixNano()) + uint64(payload.TTLSecs)*uint64(time.Second)
	}

	// 值布局: __u64 expires_at; __u32 hits; (+4 字节尾部对齐)
	val := make([]byte, 16)
	binary.LittleEndian.PutUint64(val[0:8], expiresAt)
	binary.LittleEndian.PutUint32(val[8:12], 0)

	if err := banListMap.Put(key, val); err != nil {
		return fmt.Errorf("ban_list update: %w", err)
	}

	log.Printf("  ✓ 写入 eBPF map: %s (TTL=%ds)", payload.Target, payload.TTLSecs)
	return nil
}

// parseTarget 解析目标为 4 字节 IPv4。当前只支持单个 IPv4 地址;
// CIDR 需要 LPM_TRIE 类型的 map,属于后续工作,这里显式拒绝而不是静默按主机处理。
func parseTarget(target string) ([]byte, error) {
	if strings.Contains(target, "/") {
		return nil, fmt.Errorf("暂不支持 CIDR 目标 %q:XDP 侧需要 LPM_TRIE map", target)
	}
	ip := net.ParseIP(target)
	if ip == nil {
		return nil, fmt.Errorf("非法目标地址: %q", target)
	}
	v4 := ip.To4()
	if v4 == nil {
		return nil, fmt.Errorf("暂不支持 IPv6 目标: %q", target)
	}
	return v4, nil
}

func markAck(cfg *Config, dispatchID uint) {
	url := fmt.Sprintf("%s/api/v1/dispatch/%d/ack", cfg.ServerURL, dispatchID)
	req, _ := http.NewRequest("POST", url, nil)
	req.Header.Set("X-API-Key", cfg.APIKey)

	client := &http.Client{Timeout: 5 * time.Second}
	resp, _ := client.Do(req)
	if resp != nil {
		resp.Body.Close()
	}
}

func markFailed(cfg *Config, dispatchID uint, errMsg string) {
	url := fmt.Sprintf("%s/api/v1/dispatch/%d/fail", cfg.ServerURL, dispatchID)
	payload := map[string]string{"error": errMsg}
	data, _ := json.Marshal(payload)

	req, _ := http.NewRequest("POST", url, bytes.NewBuffer(data))
	req.Header.Set("X-API-Key", cfg.APIKey)
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 5 * time.Second}
	resp, _ := client.Do(req)
	if resp != nil {
		resp.Body.Close()
	}
}
