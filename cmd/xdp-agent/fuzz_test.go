package main

import (
	"net/netip"
	"strings"
	"testing"

	"github.com/xdpban/xdp-ban/internal/banmap"
)

// FuzzParseIPv4Prefix 喂随机字符串给前缀解析 —— 这是执行器信任边界上
// 唯一把外部字符串(来自 dispatch payload)变成 map key 的地方。
//
// 约定:要么返回合法的 IPv4 前缀,要么返回错误;绝不 panic,
// 绝不返回未归一化的前缀(LPM_TRIE 要求 key 中超出 prefixlen 的位为 0,
// 否则写进去的位置与查询时的最长匹配不一致 —— 规则永远匹配不上)。
func FuzzParseIPv4Prefix(f *testing.F) {
	seeds := []string{
		"203.0.113.7", "10.0.0.1", "255.255.255.255", "0.0.0.0",
		"203.0.113.0/24", "10.0.0.0/8", "1.2.3.4/32", "0.0.0.0/0",
		"203.0.113.5/24", // 未归一化:主机位非零
		"2001:db8::1", "::1", "2001:db8::/32",
		"", "   ", "999.999.999.999", "1.2.3", "1.2.3.4.5",
		"1.2.3.4/33", "1.2.3.4/-1", "0x7f.0.0.1", "010.0.0.1",
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, in string) {
		p, err := banmap.ParseIPv4Prefix(in)
		if err != nil {
			return // 拒绝非法输入是合法结果
		}

		if !p.Addr().Is4() {
			t.Fatalf("ParseIPv4Prefix(%q) 接受了非 IPv4: %s", in, p)
		}
		if p.Bits() < 0 || p.Bits() > 32 {
			t.Fatalf("ParseIPv4Prefix(%q) 前缀长度越界: %d", in, p.Bits())
		}
		// 必须已归一化 —— 未归一化的 key 会让 LPM 匹配失效
		if p != p.Masked() {
			t.Fatalf("ParseIPv4Prefix(%q) 返回未归一化前缀 %s(应为 %s)", in, p, p.Masked())
		}
		// 编码不得 panic,且长度必须符合内核契约
		key, err := banmap.EncodeGlobalKey(p)
		if err != nil {
			t.Fatalf("EncodeGlobalKey(%s) 报错: %v", p, err)
		}
		if len(key) != banmap.GlobalKeySize {
			t.Fatalf("global key 长度 %d,期望 %d", len(key), banmap.GlobalKeySize)
		}
	})
}

// FuzzEncodeSrcKey 定向封禁 key 的编码不得因任意 target_id / 前缀组合而崩。
func FuzzEncodeSrcKey(f *testing.F) {
	f.Add(uint32(1), "203.0.113.0/24")
	f.Add(uint32(0), "0.0.0.0/0")
	f.Add(^uint32(0), "255.255.255.255/32")

	f.Fuzz(func(t *testing.T, tid uint32, prefixStr string) {
		p, err := banmap.ParseIPv4Prefix(prefixStr)
		if err != nil {
			return
		}
		key, err := banmap.EncodeSrcKey(tid, p)
		if err != nil {
			t.Fatalf("EncodeSrcKey(%d, %s) 报错: %v", tid, p, err)
		}
		if len(key) != banmap.SrcKeySize {
			t.Fatalf("src key 长度 %d,期望 %d", len(key), banmap.SrcKeySize)
		}
		// prefixlen 必须 >= 32:前 32 位是 target_id,必须全部参与匹配
		gotPrefixLen := uint32(key[0]) | uint32(key[1])<<8 | uint32(key[2])<<16 | uint32(key[3])<<24
		if gotPrefixLen < 32 || gotPrefixLen > 64 {
			t.Fatalf("prefixlen = %d,必须在 32..64(否则 target_id 不是精确匹配)", gotPrefixLen)
		}
	})
}

// 拒绝 CIDR 的旧行为已经改变:全局封禁现在支持网段。
// 这个测试固定住新契约,防止有人"修回"旧行为。
func TestParseIPv4Prefix_AcceptsCIDRForGlobalBan(t *testing.T) {
	p, err := banmap.ParseIPv4Prefix("203.0.113.0/24")
	if err != nil {
		t.Fatalf("全局封禁应支持网段: %v", err)
	}
	if p.Bits() != 24 {
		t.Errorf("前缀长度 = %d,期望 24", p.Bits())
	}
}

func TestParseIPv4Prefix_RejectsIPv6(t *testing.T) {
	for _, in := range []string{"2001:db8::1", "2001:db8::/32", "::1"} {
		_, err := banmap.ParseIPv4Prefix(in)
		if err == nil {
			t.Errorf("ParseIPv4Prefix(%q) 应拒绝 IPv6", in)
		}
		if err != nil && !strings.Contains(err.Error(), "IPv6") {
			t.Errorf("拒绝 IPv6 时错误信息应说明原因,实际: %v", err)
		}
	}
}

func TestParseIPv4Prefix_NormalizesHostBits(t *testing.T) {
	// 203.0.113.5/24 的主机位非零,必须被归一化成 203.0.113.0/24
	p, err := banmap.ParseIPv4Prefix("203.0.113.5/24")
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	want := netip.MustParsePrefix("203.0.113.0/24")
	if p != want {
		t.Errorf("未归一化: 得到 %s,期望 %s —— 未归一化的 LPM key 永远匹配不上", p, want)
	}
}
