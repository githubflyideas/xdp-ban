package main

import (
	"encoding/json"
	"testing"
	"time"
)

// 跨进程 JSON 契约:控制面 internal/dispatch.BanPayload 序列化出的 JSON,
// 必须能被本进程的 BanPayload 解出,且字段组合能正确分流到两条执行路径。
// 这两个结构体在不同包里,编译器不会检查它们一致 —— 只能靠测试锁定。
func TestPayloadContract_SingleAndScoped(t *testing.T) {
	// 控制面单点封禁产出的形状
	singleJSON := `{"target":"203.0.113.7","ttl_secs":600,"node_id":"local","req_id":1,"ban_id":"ban-1-203.0.113.7","backend":"xdp","reason":"ssh"}`
	// 控制面范围封禁产出的形状
	scopedJSON := `{"ttl_secs":3600,"node_id":"local","req_id":2,"ban_id":"scoped-2-10.0.1.100","backend":"xdp","reason":"as flood","scoped_target":"10.0.1.100","prefixes":["203.0.113.0/24","198.51.100.0/24"]}`

	var single, scoped BanPayload
	if err := json.Unmarshal([]byte(singleJSON), &single); err != nil {
		t.Fatalf("单点 payload 解析失败: %v", err)
	}
	if err := json.Unmarshal([]byte(scopedJSON), &scoped); err != nil {
		t.Fatalf("范围 payload 解析失败: %v", err)
	}

	bm, global, targets, src := newTestMaps()

	if err := bm.Apply(&single); err != nil {
		t.Fatalf("apply single: %v", err)
	}
	if global.puts != 1 || src.puts != 0 {
		t.Errorf("单点封禁应只写全局表: global=%d src=%d", global.puts, src.puts)
	}

	if err := bm.Apply(&scoped); err != nil {
		t.Fatalf("apply scoped: %v", err)
	}
	if targets.puts != 1 || src.puts != 2 {
		t.Errorf("范围封禁应写 1 目标 + 2 前缀: targets=%d src=%d", targets.puts, src.puts)
	}
	if global.puts != 1 {
		t.Errorf("范围封禁不应再写全局表,global 从 1 变成 %d", global.puts)
	}
	_ = time.Now
}
