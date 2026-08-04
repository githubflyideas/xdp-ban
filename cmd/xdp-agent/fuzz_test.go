package main

import (
	"net"
	"strings"
	"testing"
)

// FuzzParseTarget 喂随机字符串给目标解析——这是执行器信任边界上
// 唯一把外部字符串(来自 dispatch payload)变成 map key 的地方。
// 约定:要么返回 4 字节合法 IPv4,要么返回错误;绝不 panic,绝不返回
// 长度不为 4 的 slice(否则后续 copy 到固定 8 字节 key 会静默截断/错位)。
func FuzzParseTarget(f *testing.F) {
	seeds := []string{
		"203.0.113.7", "10.0.0.1", "255.255.255.255", "0.0.0.0",
		"203.0.113.0/24", "2001:db8::1", "::1",
		"", "   ", "999.999.999.999", "1.2.3", "1.2.3.4.5",
		"1.2.3.-1", "0x7f.0.0.1", "010.0.0.1",
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, target string) {
		ip, err := parseTarget(target)
		if err != nil {
			return // 拒绝非法输入是合法结果
		}
		// 接受了 → 必须是恰好 4 字节的 IPv4
		if len(ip) != 4 {
			t.Fatalf("parseTarget(%q) 接受但返回 %d 字节(应为 4)", target, len(ip))
		}
		// CIDR 必须被拒,不能被当成主机地址悄悄接受
		if strings.Contains(target, "/") {
			t.Fatalf("parseTarget(%q) 不应接受 CIDR", target)
		}
		// 返回值必须能被 net 解析回同一个 IPv4
		if net.IP(ip).To4() == nil {
			t.Fatalf("parseTarget(%q) 返回的不是合法 IPv4: %v", target, ip)
		}
	})
}

// BenchmarkExecuteXDPKeyEncode 执行器写 map 的键/值编码开销。
// 单条封禁不算热点,但 dispatch 批量下发(如威胁情报导入上万条)时
// 这段会被反复调用,值得盯住分配次数。
func BenchmarkExecuteXDPKeyEncode(b *testing.B) {
	ip, _ := parseTarget("203.0.113.7")
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		key := make([]byte, 8)
		copy(key[0:4], ip)
	}
}
