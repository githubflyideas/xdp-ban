package main

import (
	"encoding/json"
	"testing"
)

// 跨包 JSON 契约:internal/dispatch.BanPayload 序列化出的 JSON,
// 必须能被本包的 BanPayload 解出,且字段组合能正确分流到两条执行路径。
//
// 合并前,这个契约跨越了两个独立进程(xdp-ban 通过 HTTP 下发,xdp-agent
// 通过 HTTP 拉取并反序列化)。合并后不再有网络往返,但契约本身没有消失:
// dispatch.BanPayload 和 main.BanPayload 仍是两个包里独立定义的结构体,
// 编译器不会检查它们的 JSON 形状一致 —— 只能靠测试锁定。
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
}
