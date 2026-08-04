package web

import (
	"testing"
)

// 目标必须是单主机。这不是界面偏好而是 XDP 侧硬约束:
// 目标带前缀需要二维最长匹配,LPM_TRIE 表达不了。
// 静默把 10.0.1.0/24 当成 10.0.1.0 处理会造成"以为封了一个网段"的误解,
// 所以必须显式拒绝。
func TestParseHostTarget(t *testing.T) {
	ok := []struct{ in, want string }{
		{"10.0.1.100", "10.0.1.100"},
		{" 10.0.1.100 ", "10.0.1.100"},
		{"10.0.1.100/32", "10.0.1.100"}, // /32 是允许的写法
	}
	for _, tc := range ok {
		got, err := parseHostTarget(tc.in)
		if err != nil {
			t.Errorf("parseHostTarget(%q) 报错: %v", tc.in, err)
			continue
		}
		if got != tc.want {
			t.Errorf("parseHostTarget(%q) = %q, 期望 %q", tc.in, got, tc.want)
		}
	}

	bad := []struct{ in, why string }{
		{"", "空输入"},
		{"10.0.1.0/24", "网段目标必须拒绝"},
		{"10.0.0.0/8", "大网段更要拒绝"},
		{"10.0.1.100/31", "非 /32 前缀"},
		{"2001:db8::1", "IPv6 未支持"},
		{"not-an-ip", "非法格式"},
		{"999.1.1.1", "越界八位组"},
	}
	for _, tc := range bad {
		if _, err := parseHostTarget(tc.in); err == nil {
			t.Errorf("parseHostTarget(%q) 应报错(%s)", tc.in, tc.why)
		}
	}
}

// 拒绝网段时,错误信息必须解释原因 —— 用户否则不理解为什么
// "封一个网段的来源"可以而"保护一个网段"不行。
func TestParseHostTarget_ErrorExplainsWhy(t *testing.T) {
	_, err := parseHostTarget("10.0.1.0/24")
	if err == nil {
		t.Fatal("应报错")
	}
	msg := err.Error()
	for _, kw := range []string{"/32", "LPM"} {
		if !contains(msg, kw) {
			t.Errorf("错误信息应提及 %q,实际: %s", kw, msg)
		}
	}
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && (func() bool {
		for i := 0; i+len(sub) <= len(s); i++ {
			if s[i:i+len(sub)] == sub {
				return true
			}
		}
		return false
	})()
}
