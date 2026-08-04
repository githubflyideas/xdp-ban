// Package main — xdp-agent: 执行器
//
// 职责:
// 1. 轮询 xdp-ban 服务器 GET /api/v1/dispatch/pending
// 2. 执行 dispatch 指令(调用 nftables)
// 3. 反馈执行状态 POST /api/v1/dispatch/:id/ack 或 /fail
package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/exec"
	"time"
)

// Dispatch 下发指令(从 xdp-ban 服务器)
type Dispatch struct {
	ID           uint   `json:"id"`
	BanRequestID uint   `json:"ban_request_id"`
	BanID        string `json:"ban_id"`
	NodeID       string `json:"node_id"`
	Payload      string `json:"payload"`
	State        string `json:"state"`
}

// BanPayload 解析的指令内容
type BanPayload struct {
	Target   string `json:"target"`
	TTLSecs  int64  `json:"ttl_secs"`
	NodeID   string `json:"node_id"`
	ReqID    uint   `json:"req_id"`
	BanID    string `json:"ban_id"`
	Backend  string `json:"backend"`
	Reason   string `json:"reason"`
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

	log.Printf("xdp-agent 启动: server=%s, interval=%v\n", cfg.ServerURL, cfg.Interval)

	ticker := time.NewTicker(cfg.Interval)
	defer ticker.Stop()

	for range ticker.C {
		pollAndExecute(&cfg)
	}
}

func pollAndExecute(cfg *Config) {
	// 1. 轮询待执行指令
	dispatches, err := fetchPending(cfg)
	if err != nil {
		log.Printf("fetch pending: %v", err)
		return
	}

	if len(dispatches) == 0 {
		// log.Printf("no pending dispatch")
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

		log.Printf("执行指令 #%d: %s (TTL=%ds, backend=%s)", d.ID, payload.Target, payload.TTLSecs, payload.Backend)

		// 3. 下发到 nftables/iptables
		if err := executeDispatch(&payload); err != nil {
			log.Printf("execute dispatch: %v", err)
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

func executeDispatch(payload *BanPayload) error {
	if payload.Backend == "" {
		payload.Backend = "nftables"
	}

	switch payload.Backend {
	case "nftables":
		return executeNftables(payload)
	case "iptables":
		return executeIptables(payload)
	default:
		return fmt.Errorf("unknown backend: %s", payload.Backend)
	}
}

// executeNftables 调用 nftables 下发规则
func executeNftables(payload *BanPayload) error {
	// 设定(需提前创建 nftables 表)
	// nft add table ip filter
	// nft add chain ip filter input { type filter hook input priority 0; }
	// nft add set ip filter blacklist { type ipv4_addr; flags dynamic; }

	ttl := ""
	if payload.TTLSecs > 0 {
		ttl = fmt.Sprintf("expires %ds", payload.TTLSecs)
	} else {
		ttl = ""  // 永久
	}

	cmd := fmt.Sprintf(`nft add element ip filter blacklist { %s %s }`, payload.Target, ttl)
	log.Printf("执行 nftables: %s", cmd)

	out, err := exec.Command("sh", "-c", cmd).CombinedOutput()
	if err != nil {
		return fmt.Errorf("nftables: %v (%s)", err, string(out))
	}
	return nil
}

// executeIptables 调用 iptables 下发规则(备选)
func executeIptables(payload *BanPayload) error {
	// iptables -I INPUT -d <target> -j DROP
	cmd := fmt.Sprintf(`iptables -I INPUT -d %s -j DROP`, payload.Target)
	log.Printf("执行 iptables: %s", cmd)

	out, err := exec.Command("sh", "-c", cmd).CombinedOutput()
	if err != nil {
		return fmt.Errorf("iptables: %v (%s)", err, string(out))
	}
	return nil
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
