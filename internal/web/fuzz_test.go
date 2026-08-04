package web

import (
	"testing"
)

// FuzzParseRate 采样率来自 Web 表单,是纯用户输入。
// 约定:接受的值必在 [1, 1000000];返回 error 时绝不返回可用的正数。
// 重点防两类事故:0 传到 BPF 侧取模会除零;超大值让采样实际失效。
func FuzzParseRate(f *testing.F) {
	for _, s := range []string{"1", "100", "1000000", "0", "-1", "abc", "", " 50 ", "99999999", "1e3"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		n, err := parseRate(raw)
		if err != nil {
			return
		}
		if n < 1 || n > 1000000 {
			t.Fatalf("parseRate(%q) 接受了越界值 %d", raw, n)
		}
	})
}
