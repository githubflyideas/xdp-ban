package main

import (
	"encoding/binary"
	"fmt"
	"net/netip"
	"testing"
	"time"

	"github.com/xdpban/xdp-ban/internal/banmap"
)

// fakeMap 是 mapWriter 的内存实现,让 map 写入路径能在无内核、
// 无 root 的环境里被完整测试。
//
// 这正是此前那次事故的根源:agent 的测试只覆盖纯函数,
// 没有任何测试触及 map 加载与写入,所以 map 改名后编译通过、测试全绿,
// 而执行面实际启动即挂。
type fakeMap struct {
	name    string
	entries map[string][]byte
	putErr  error // 注入错误,模拟 map 满(E2BIG)
	puts    int
}

func newFakeMap(name string) *fakeMap {
	return &fakeMap{name: name, entries: make(map[string][]byte)}
}

func (m *fakeMap) Put(key, value any) error {
	if m.putErr != nil {
		return m.putErr
	}
	kb, ok := key.([]byte)
	if !ok {
		return fmt.Errorf("%s: key 类型应为 []byte,实际 %T", m.name, key)
	}
	vb, ok := value.([]byte)
	if !ok {
		return fmt.Errorf("%s: value 类型应为 []byte,实际 %T", m.name, value)
	}
	m.entries[string(kb)] = vb
	m.puts++
	return nil
}

func (m *fakeMap) Delete(key any) error {
	kb, ok := key.([]byte)
	if !ok {
		return fmt.Errorf("%s: key 类型应为 []byte", m.name)
	}
	delete(m.entries, string(kb))
	return nil
}

func newTestMaps() (*banMaps, *fakeMap, *fakeMap, *fakeMap) {
	g := newFakeMap(banmap.MapGlobalBans)
	t := newFakeMap(banmap.MapTargetHosts)
	s := newFakeMap(banmap.MapSrcBans)
	// 固定 bootTime,让 TTL 换算可预测
	boot := time.Now().Add(-time.Hour)
	return newBanMaps(g, t, s, boot), g, t, s
}

// 单点封禁必须写入全局表,而不是定向表。
// 写错表的后果:规则只在"该源打向某个已注册目标"时生效,
// 打向其他主机照样通过 —— 用户以为封了,实际没封。
func TestApply_SingleHostGoesToGlobalMap(t *testing.T) {
	bm, global, targets, src := newTestMaps()

	err := bm.Apply(&BanPayload{Target: "203.0.113.7", TTLSecs: 600, ReqID: 42})
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}

	if global.puts != 1 {
		t.Errorf("全局表写入 %d 次,期望 1", global.puts)
	}
	if targets.puts != 0 || src.puts != 0 {
		t.Errorf("单点封禁不应碰定向表(targets=%d src=%d)", targets.puts, src.puts)
	}

	// key 必须是 /32 且字节序正确
	wantKey, _ := banmap.EncodeGlobalKey(netip.MustParsePrefix("203.0.113.7/32"))
	if _, ok := global.entries[string(wantKey)]; !ok {
		t.Errorf("未找到期望的 key %v;实际键集合 %v", wantKey, keysOf(global))
	}
}

// 全局封禁支持网段 —— 这是相对旧实现的行为变化,必须固定住。
func TestApply_GlobalBanSupportsCIDR(t *testing.T) {
	bm, global, _, _ := newTestMaps()

	if err := bm.Apply(&BanPayload{Target: "203.0.113.0/24", TTLSecs: 0}); err != nil {
		t.Fatalf("Apply CIDR: %v", err)
	}

	wantKey, _ := banmap.EncodeGlobalKey(netip.MustParsePrefix("203.0.113.0/24"))
	if _, ok := global.entries[string(wantKey)]; !ok {
		t.Errorf("网段封禁未写入正确的 key")
	}
	// prefixlen 字段应为 24
	if got := binary.LittleEndian.Uint32(wantKey[0:4]); got != 24 {
		t.Errorf("prefixlen = %d,期望 24", got)
	}
}

// 范围封禁必须写 target_hosts + src_ban 两张表。
func TestApply_ScopedWritesBothMaps(t *testing.T) {
	bm, global, targets, src := newTestMaps()

	err := bm.Apply(&BanPayload{
		ScopedTarget: "10.0.1.100",
		Prefixes:     []string{"203.0.113.0/24", "198.51.100.0/24", "1.2.3.4"},
		TTLSecs:      3600,
		ReqID:        7,
	})
	if err != nil {
		t.Fatalf("Apply scoped: %v", err)
	}

	if targets.puts != 1 {
		t.Errorf("target_hosts 写入 %d 次,期望 1", targets.puts)
	}
	if src.puts != 3 {
		t.Errorf("src_ban 写入 %d 次,期望 3(每条源前缀一次)", src.puts)
	}
	if global.puts != 0 {
		t.Errorf("范围封禁不应写全局表")
	}

	// src_ban 的 key 必须包含 target_id,且 prefixlen >= 32
	for k := range src.entries {
		kb := []byte(k)
		if len(kb) != banmap.SrcKeySize {
			t.Fatalf("src key 长度 %d,期望 %d", len(kb), banmap.SrcKeySize)
		}
		pl := binary.LittleEndian.Uint32(kb[0:4])
		if pl < 32 {
			t.Errorf("prefixlen = %d < 32,target_id 不再是精确匹配", pl)
		}
		tid := binary.LittleEndian.Uint32(kb[4:8])
		if tid == 0 {
			t.Errorf("target_id 为 0 —— 0 应保留不用,以区分'未分配'")
		}
	}
}

// 同一目标主机的多条规则必须复用同一个 target_id。
// 不复用的话,同一主机的规则会分散到不同 id 下,只有最后一个生效。
func TestEnsureTarget_ReusesID(t *testing.T) {
	bm, _, targets, _ := newTestMaps()

	addr := netip.MustParseAddr("10.0.1.100")
	id1, err := bm.ensureTarget(addr)
	if err != nil {
		t.Fatalf("ensureTarget: %v", err)
	}
	id2, err := bm.ensureTarget(addr)
	if err != nil {
		t.Fatalf("ensureTarget 二次: %v", err)
	}

	if id1 != id2 {
		t.Errorf("同一目标分配了不同 id: %d vs %d", id1, id2)
	}
	if targets.puts != 1 {
		t.Errorf("target_hosts 被重复写入 %d 次", targets.puts)
	}

	// 不同目标必须拿到不同 id
	id3, _ := bm.ensureTarget(netip.MustParseAddr("10.0.1.200"))
	if id3 == id1 {
		t.Errorf("不同目标复用了同一 id %d", id1)
	}
}

// map 满(E2BIG)必须明确报错,绝不能静默丢规则。
// 静默失败是最危险的模式:界面显示已封禁而流量照进。
func TestApply_MapFullReturnsError(t *testing.T) {
	bm, global, _, src := newTestMaps()
	global.putErr = fmt.Errorf("argument list too long") // E2BIG 的典型表现

	err := bm.Apply(&BanPayload{Target: "203.0.113.7", TTLSecs: 600})
	if err == nil {
		t.Fatal("map 满时必须返回错误")
	}

	// 定向表同理,且错误信息要说明已写入多少条,便于运维判断
	src.putErr = fmt.Errorf("argument list too long")
	err = bm.Apply(&BanPayload{
		ScopedTarget: "10.0.1.100",
		Prefixes:     []string{"1.0.0.0/8", "2.0.0.0/8"},
	})
	if err == nil {
		t.Fatal("src_ban 满时必须返回错误")
	}
	if !contains(err.Error(), "已写入") {
		t.Errorf("错误信息应说明已写入条数,便于判断部分生效范围,实际: %v", err)
	}
}

// TTL 必须换算成 ktime 基准,不是 Unix 时间。
// 用 Unix 纳秒的话:它远大于任何 uptime,所有封禁都会被判成"未过期"
// 而变成永久生效 —— 一条 10 分钟的临时封禁会永远留在 map 里。
func TestKtimeDeadline_UsesUptimeNotUnix(t *testing.T) {
	boot := time.Now().Add(-2 * time.Hour)
	now := time.Now()

	got := banmap.KtimeDeadline(boot, now, 600) // 10 分钟

	// 期望约等于 2 小时 uptime + 600 秒
	wantLow := uint64((2*time.Hour + 590*time.Second).Nanoseconds())
	wantHigh := uint64((2*time.Hour + 610*time.Second).Nanoseconds())
	if got < wantLow || got > wantHigh {
		t.Errorf("deadline = %d ns,期望约 %d..%d(uptime + TTL)", got, wantLow, wantHigh)
	}

	// 绝不能是 Unix 纳秒量级(2026 年约 1.78e18)
	if got > uint64(1e17) {
		t.Errorf("deadline = %d 看起来是 Unix 时间而非 ktime,所有 TTL 判断都会错", got)
	}
}

func TestKtimeDeadline_ZeroTTLMeansPermanent(t *testing.T) {
	boot := time.Now().Add(-time.Hour)
	for _, ttl := range []int64{0, -1, -3600} {
		if got := banmap.KtimeDeadline(boot, time.Now(), ttl); got != 0 {
			t.Errorf("TTL=%d 应表示永久(deadline=0),实际 %d", ttl, got)
		}
	}
}

// 非法输入必须在写 map 之前就被拒绝,不能留下半个状态。
func TestApply_RejectsBadInput(t *testing.T) {
	cases := []struct {
		name    string
		payload BanPayload
	}{
		{"空目标", BanPayload{Target: ""}},
		{"非法目标", BanPayload{Target: "not-an-ip"}},
		{"IPv6 目标", BanPayload{Target: "2001:db8::1"}},
		{"范围封禁目标非法", BanPayload{ScopedTarget: "bad", Prefixes: []string{"1.0.0.0/8"}}},
		{"范围封禁目标为网段", BanPayload{ScopedTarget: "10.0.0.0/8", Prefixes: []string{"1.0.0.0/8"}}},
		{"范围封禁前缀非法", BanPayload{ScopedTarget: "10.0.1.1", Prefixes: []string{"garbage"}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			bm, _, _, _ := newTestMaps()
			if err := bm.Apply(&tc.payload); err == nil {
				t.Errorf("应拒绝: %+v", tc.payload)
			}
		})
	}
}

// value 布局必须与 C 结构体一致,否则 XDP 侧读到的 expires_at 是垃圾。
func TestValueLayout_MatchesKernelStruct(t *testing.T) {
	v := banmap.Value{ExpiresAt: 0x1122334455667788, Hits: 42, RuleID: 7}
	b := banmap.EncodeValue(v)

	if len(b) != banmap.ValueSize {
		t.Fatalf("value 长度 %d,期望 %d(u64+u64+u32+pad)", len(b), banmap.ValueSize)
	}
	back, err := banmap.DecodeValue(b)
	if err != nil {
		t.Fatalf("DecodeValue: %v", err)
	}
	if back != v {
		t.Errorf("编解码不一致: %+v → %+v", v, back)
	}
}

func keysOf(m *fakeMap) [][]byte {
	out := make([][]byte, 0, len(m.entries))
	for k := range m.entries {
		out = append(out, []byte(k))
	}
	return out
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
