// Package main — xdp-agent: 纯 Go 单二进制执行器。
//
// 职责:
//  1. 加载嵌入的 eBPF bytecode,取得三张封禁 map
//  2. 轮询 xdp-ban GET /api/v1/dispatch/pending
//  3. 把指令翻译成 map 写入(编码逻辑在 internal/banmap,执行在 executor.go)
//  4. 回执 POST /api/v1/dispatch/:id/ack 或 /fail
//
// 部署: 拷贝单个二进制即可运行(需 root)
package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/cilium/ebpf"

	"github.com/xdpban/xdp-ban/internal/banmap"
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

// BanPayload 指令内容。
//
// 两种形态由字段组合区分:
//   - 单点封禁:Target 有值,ScopedTarget 为空 → 写全局表
//   - 范围封禁:ScopedTarget + Prefixes 有值   → 写 target_hosts + src_ban
type BanPayload struct {
	Target  string `json:"target"`
	TTLSecs int64  `json:"ttl_secs"`
	NodeID  string `json:"node_id"`
	ReqID   uint   `json:"req_id"`
	BanID   string `json:"ban_id"`
	Backend string `json:"backend"`
	Reason  string `json:"reason"`

	// 范围封禁专用
	ScopedTarget string   `json:"scoped_target,omitempty"`
	Prefixes     []string `json:"prefixes,omitempty"`
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

	log.Printf("XDP 执行器启动: server=%s interval=%v", cfg.ServerURL, cfg.Interval)

	// 1. 加载嵌入的 eBPF bytecode
	if len(xdpFilterBytecode) == 0 {
		log.Fatalf("嵌入的 eBPF bytecode 为空:请先运行 `make bpf` 编译 bpf/xdp_filter.c,再重新构建本程序")
	}
	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(xdpFilterBytecode))
	if err != nil {
		log.Fatalf("load ebpf spec: %v", err)
	}
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		log.Fatalf("create ebpf collection: %v", err)
	}
	defer coll.Close()

	// 2. 取出三张 map。缺任何一张都是致命的 —— bytecode 与本程序版本不匹配,
	//    继续跑只会静默不生效。宁可启动失败。
	maps, err := resolveMaps(coll)
	if err != nil {
		log.Fatalf("%v", err)
	}
	log.Printf("✓ eBPF map 就绪: %s / %s / %s",
		banmap.MapGlobalBans, banmap.MapTargetHosts, banmap.MapSrcBans)

	boot, err := systemBootTime()
	if err != nil {
		log.Fatalf("读取系统启动时刻(TTL 换算依赖它): %v", err)
	}
	log.Printf("✓ 系统启动于 %s,TTL 将换算为 ktime 基准", boot.Format(time.RFC3339))

	bm := newBanMaps(
		maps[banmap.MapGlobalBans],
		maps[banmap.MapTargetHosts],
		maps[banmap.MapSrcBans],
		boot,
	)

	ticker := time.NewTicker(cfg.Interval)
	defer ticker.Stop()
	for range ticker.C {
		pollAndExecute(&cfg, bm)
	}
}

// resolveMaps 按名字取出所需的 map,任一缺失即报错。
//
// map 名是字符串查找,编译器抓不到不一致 —— 所以这里一次性全部校验,
// 并把名字集中在 internal/banmap 的常量里。
func resolveMaps(coll *ebpf.Collection) (map[string]*ebpf.Map, error) {
	want := []string{banmap.MapGlobalBans, banmap.MapTargetHosts, banmap.MapSrcBans}
	out := make(map[string]*ebpf.Map, len(want))
	var missing []string
	for _, name := range want {
		m := coll.Maps[name]
		if m == nil {
			missing = append(missing, name)
			continue
		}
		out[name] = m
	}
	if len(missing) > 0 {
		return nil, fmt.Errorf("eBPF bytecode 中缺少 map: %s —— "+
			"bytecode 与本程序版本不匹配,请重新 `make bpf && make build`",
			strings.Join(missing, ", "))
	}
	return out, nil
}

// systemBootTime 从 /proc/uptime 推算系统启动时刻。
//
// 为什么必须是**系统**启动时刻而非进程启动时刻:XDP 侧的
// bpf_ktime_get_ns() 返回系统 uptime。用进程启动时刻算 deadline,
// 在一台已运行数天的机器上会让所有封禁立刻被判成过期。
func systemBootTime() (time.Time, error) {
	b, err := os.ReadFile("/proc/uptime")
	if err != nil {
		return time.Time{}, err
	}
	fields := strings.Fields(string(b))
	if len(fields) == 0 {
		return time.Time{}, fmt.Errorf("/proc/uptime 格式异常: %q", string(b))
	}
	secs, err := strconv.ParseFloat(fields[0], 64)
	if err != nil {
		return time.Time{}, fmt.Errorf("解析 uptime %q: %w", fields[0], err)
	}
	return time.Now().Add(-time.Duration(secs * float64(time.Second))), nil
}

func pollAndExecute(cfg *Config, bm *banMaps) {
	dispatches, err := fetchPending(cfg)
	if err != nil {
		log.Printf("fetch pending: %v", err)
		return
	}
	if len(dispatches) == 0 {
		return
	}
	log.Printf("获取 %d 条待执行指令", len(dispatches))

	for _, d := range dispatches {
		var payload BanPayload
		if err := json.Unmarshal([]byte(d.Payload), &payload); err != nil {
			log.Printf("指令 #%d payload 解析失败: %v", d.ID, err)
			markFailed(cfg, d.ID, fmt.Sprintf("parse error: %v", err))
			continue
		}

		log.Printf("执行指令 #%d: %s", d.ID, describePayload(&payload))

		if err := bm.Apply(&payload); err != nil {
			log.Printf("指令 #%d 执行失败: %v", d.ID, err)
			markFailed(cfg, d.ID, err.Error())
			continue
		}

		markAck(cfg, d.ID)
		log.Printf("指令 #%d 执行成功", d.ID)
	}
}

func describePayload(p *BanPayload) string {
	if p.ScopedTarget != "" {
		return fmt.Sprintf("范围封禁 %d 条源前缀 → %s (TTL=%ds)",
			len(p.Prefixes), p.ScopedTarget, p.TTLSecs)
	}
	return fmt.Sprintf("全局封禁 %s (TTL=%ds)", p.Target, p.TTLSecs)
}

func fetchPending(cfg *Config) ([]Dispatch, error) {
	req, err := http.NewRequest(http.MethodGet, cfg.ServerURL+"/api/v1/dispatch/pending", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-API-Key", cfg.APIKey)

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("status %d", resp.StatusCode)
	}
	var dispatches []Dispatch
	if err := json.NewDecoder(resp.Body).Decode(&dispatches); err != nil {
		return nil, err
	}
	return dispatches, nil
}

func markAck(cfg *Config, dispatchID uint) {
	postStatus(cfg, fmt.Sprintf("/api/v1/dispatch/%d/ack", dispatchID), nil)
}

func markFailed(cfg *Config, dispatchID uint, errMsg string) {
	body, _ := json.Marshal(map[string]string{"error": errMsg})
	postStatus(cfg, fmt.Sprintf("/api/v1/dispatch/%d/fail", dispatchID), body)
}

// postStatus 回执。失败只记日志:控制面会因为指令长期 pending 而暴露问题,
// 在这里重试反而可能把一次失败放大成风暴。
func postStatus(cfg *Config, path string, body []byte) {
	var r *bytes.Reader
	if body != nil {
		r = bytes.NewReader(body)
	} else {
		r = bytes.NewReader(nil)
	}
	req, err := http.NewRequest(http.MethodPost, cfg.ServerURL+path, r)
	if err != nil {
		log.Printf("构造回执请求 %s: %v", path, err)
		return
	}
	req.Header.Set("X-API-Key", cfg.APIKey)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("回执 %s 失败: %v", path, err)
		return
	}
	resp.Body.Close()
}
