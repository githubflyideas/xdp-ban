package prefixdb

import (
	"net/netip"
	"testing"
)

// rangeToCIDRs 是把"国家/AS 的任意起止区间"变成 LPM 表项的唯一路径。
// 算错会有两种后果:多封(覆盖了不该封的地址)或少封(漏掉攻击源),
// 前者是生产事故。这里逐个验证边界。
func TestRangeToCIDRs(t *testing.T) {
	cases := []struct {
		name       string
		start, end string
		want       []string
	}{
		{"单个地址", "1.2.3.4", "1.2.3.4", []string{"1.2.3.4/32"}},
		{"整齐的 /24", "1.2.3.0", "1.2.3.255", []string{"1.2.3.0/24"}},
		{"整齐的 /8", "10.0.0.0", "10.255.255.255", []string{"10.0.0.0/8"}},
		{"跨两个 /24", "1.2.3.0", "1.2.4.255", []string{"1.2.3.0/24", "1.2.4.0/24"}},
		{
			"非对齐区间需多个 CIDR",
			"1.2.3.1", "1.2.3.6",
			[]string{"1.2.3.1/32", "1.2.3.2/31", "1.2.3.4/31", "1.2.3.6/32"},
		},
		{"地址空间末尾不回绕", "255.255.255.254", "255.255.255.255", []string{"255.255.255.254/31"}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := mustAddr(t, tc.start)
			e := mustAddr(t, tc.end)
			got := rangeToCIDRs(addrToU32(s), addrToU32(e))

			if len(got) != len(tc.want) {
				t.Fatalf("CIDR 数量 = %d %v, 期望 %d %v", len(got), got, len(tc.want), tc.want)
			}
			for i := range got {
				if got[i].String() != tc.want[i] {
					t.Errorf("第 %d 个 = %s, 期望 %s", i, got[i], tc.want[i])
				}
			}

			// 覆盖必须精确:总地址数等于区间长度,不多一个不少一个
			var covered uint64
			for _, p := range got {
				covered += uint64(1) << (32 - p.Bits())
			}
			want := uint64(addrToU32(e)) - uint64(addrToU32(s)) + 1
			if covered != want {
				t.Errorf("覆盖地址数 = %d, 期望 %d(多封或漏封)", covered, want)
			}
		})
	}
}

// 全 IPv4 空间是最容易触发回绕死循环的输入
func TestRangeToCIDRs_FullSpace(t *testing.T) {
	got := rangeToCIDRs(0, ^uint32(0))
	if len(got) != 1 || got[0].String() != "0.0.0.0/0" {
		t.Errorf("全空间应为单条 0.0.0.0/0, 实际 %v", got)
	}
}

func TestResolve_MergesAdjacentRanges(t *testing.T) {
	// 两个相邻区间应被合并成一条 /23,而不是两条 /24 ——
	// 不合并会白白多占 LPM 表项
	db := &DB{
		entries: []Entry{
			{Start: addrToU32(mustAddr(t, "1.2.2.0")), End: addrToU32(mustAddr(t, "1.2.2.255")), Country: "XX", ASN: 100},
			{Start: addrToU32(mustAddr(t, "1.2.3.0")), End: addrToU32(mustAddr(t, "1.2.3.255")), Country: "XX", ASN: 100},
		},
		byCountry: map[string][]int{"XX": {0, 1}},
		byASN:     map[uint32][]int{100: {0, 1}},
	}

	got, err := db.Resolve(Selector{Country: "XX"})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if len(got) != 1 || got[0].String() != "1.2.2.0/23" {
		t.Errorf("相邻区间未合并: %v(期望 [1.2.2.0/23])", got)
	}
}

func TestResolve_RequiresSelector(t *testing.T) {
	db := &DB{byCountry: map[string][]int{}, byASN: map[uint32][]int{}}
	if _, err := db.Resolve(Selector{}); err == nil {
		t.Error("既无国家也无 ASN 时应报错")
	}
}

func TestResolve_CountryAndASNIntersect(t *testing.T) {
	db := &DB{
		entries: []Entry{
			{Start: 100, End: 200, Country: "CN", ASN: 4134},
			{Start: 300, End: 400, Country: "CN", ASN: 4809}, // 同国不同 AS
			{Start: 500, End: 600, Country: "US", ASN: 4134}, // 同 AS 不同国
		},
		byCountry: map[string][]int{"CN": {0, 1}, "US": {2}},
		byASN:     map[uint32][]int{4134: {0, 2}, 4809: {1}},
	}

	idxs, err := db.candidates(Selector{Country: "CN", ASN: 4134})
	if err != nil {
		t.Fatalf("candidates: %v", err)
	}
	if len(idxs) != 1 || idxs[0] != 0 {
		t.Errorf("CN+AS4134 交集 = %v, 期望 [0]", idxs)
	}
}

func TestPreview_CountsAddressesAndBlocks(t *testing.T) {
	db := &DB{
		entries: []Entry{
			{Start: addrToU32(mustAddr(t, "10.0.0.0")), End: addrToU32(mustAddr(t, "10.255.255.255")), Country: "XX"},
		},
		byCountry: map[string][]int{"XX": {0}},
		byASN:     map[uint32][]int{},
	}

	p, err := db.Preview(Selector{Country: "XX"}, 10)
	if err != nil {
		t.Fatalf("Preview: %v", err)
	}
	if p.CIDRCount != 1 {
		t.Errorf("CIDRCount = %d, 期望 1(一个 /8 只占一个 LPM 表项)", p.CIDRCount)
	}
	if p.AddrCount != 1<<24 {
		t.Errorf("AddrCount = %d, 期望 %d", p.AddrCount, 1<<24)
	}
}

func TestNormalizeASNQuery(t *testing.T) {
	cases := []struct {
		in      string
		wantASN uint32
		wantKw  string
	}{
		{"4134", 4134, ""},
		{"AS4134", 4134, ""},
		{"as4134", 4134, ""},
		{" 4134 ", 4134, ""},
		{"CHINANET", 0, "CHINANET"},
		{"", 0, ""},
	}
	for _, tc := range cases {
		q := normalizeASNQuery(tc.in)
		if q.asn != tc.wantASN || q.keyword != tc.wantKw {
			t.Errorf("normalizeASNQuery(%q) = {asn:%d kw:%q}, 期望 {asn:%d kw:%q}",
				tc.in, q.asn, q.keyword, tc.wantASN, tc.wantKw)
		}
	}
}

// BenchmarkResolve 单个大国可能有数万条区间,合并+拆 CIDR 的开销
// 直接决定"预览"按钮的响应速度。
func BenchmarkResolve(b *testing.B) {
	const n = 20000
	db := &DB{
		entries:   make([]Entry, n),
		byCountry: map[string][]int{"XX": make([]int, n)},
		byASN:     map[uint32][]int{},
	}
	for i := 0; i < n; i++ {
		base := uint32(i) * 512 // 留空隙,避免全部合并成一条
		db.entries[i] = Entry{Start: base, End: base + 255, Country: "XX"}
		db.byCountry["XX"][i] = i
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := db.Resolve(Selector{Country: "XX"}); err != nil {
			b.Fatal(err)
		}
	}
}

func mustAddr(t *testing.T, s string) netip.Addr {
	t.Helper()
	a, err := netip.ParseAddr(s)
	if err != nil {
		t.Fatalf("ParseAddr(%q): %v", s, err)
	}
	return a
}

func addrToU32(a netip.Addr) uint32 {
	b := a.As4()
	return uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
}
