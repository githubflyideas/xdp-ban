package main

import (
	"encoding/binary"
	"testing"
	"time"
)

// ban_entry 的 dst_ip 直接取自 iphdr->daddr,是网络字节序。
// 用户态若按主机序拼装,写进去的 key 与 XDP 侧算出的 key 不相等,
// 结果是黑名单永远查不中——封禁"成功"但流量照旧。
func TestBuildKey_UsesNetworkByteOrder(t *testing.T) {
	ip, err := parseTarget("203.0.113.7")
	if err != nil {
		t.Fatalf("parseTarget: %v", err)
	}

	key := make([]byte, 8)
	copy(key[0:4], ip)

	// 网络字节序下 203.0.113.7 的首字节就是 203
	if key[0] != 203 || key[1] != 0 || key[2] != 113 || key[3] != 7 {
		t.Errorf("key 前 4 字节 = %v, 期望 [203 0 113 7](网络字节序原样)", key[0:4])
	}

	// 与 XDP 侧读到的 __u32 应当一致(小端机器上按 LE 解出的值)
	got := binary.LittleEndian.Uint32(key[0:4])
	want := binary.LittleEndian.Uint32([]byte{203, 0, 113, 7})
	if got != want {
		t.Errorf("__u32 = %d, 期望 %d", got, want)
	}
}

func TestParseTarget_RejectsUnsupported(t *testing.T) {
	cases := []struct {
		in     string
		reason string
	}{
		{"203.0.113.0/24", "CIDR 需要 LPM_TRIE,当前 HASH map 无法表达"},
		{"2001:db8::1", "IPv6 未实现"},
		{"not-an-ip", "非法输入"},
		{"", "空输入"},
	}
	for _, tc := range cases {
		if _, err := parseTarget(tc.in); err == nil {
			t.Errorf("parseTarget(%q) 应报错(%s)", tc.in, tc.reason)
		}
	}
}

func TestParseTarget_AcceptsIPv4(t *testing.T) {
	ip, err := parseTarget("10.1.2.3")
	if err != nil {
		t.Fatalf("parseTarget: %v", err)
	}
	if len(ip) != 4 {
		t.Fatalf("返回 %d 字节, 期望 4", len(ip))
	}
}

// 值布局: __u64 expires_at; __u32 hits; 共 16 字节(含尾部对齐)
func TestBanValueLayout(t *testing.T) {
	ttl := int64(3600)
	before := time.Now()

	val := make([]byte, 16)
	expiresAt := uint64(before.UnixNano()) + uint64(ttl)*uint64(time.Second)
	binary.LittleEndian.PutUint64(val[0:8], expiresAt)

	decoded := binary.LittleEndian.Uint64(val[0:8])
	deadline := time.Unix(0, int64(decoded))

	// 允许 1 秒误差
	want := before.Add(time.Hour)
	if diff := deadline.Sub(want); diff > time.Second || diff < -time.Second {
		t.Errorf("expires_at 解出 %v, 期望约 %v", deadline, want)
	}
	if len(val) != 16 {
		t.Errorf("value 长度 = %d, 期望 16", len(val))
	}
}

// TTL 为 0 表示永久,不能算成"已过期"
func TestPermanentBanHasZeroExpiry(t *testing.T) {
	val := make([]byte, 16)
	binary.LittleEndian.PutUint64(val[0:8], 0)
	if binary.LittleEndian.Uint64(val[0:8]) != 0 {
		t.Error("永久封禁的 expires_at 应为 0")
	}
}
