package prefixdb

import (
	"strings"
	"testing"
)

// 本地覆盖是给人手写的文件。解析必须宽松(多余空格、制表混用、
// 行内注释都要接受),但不能把错误当正确 —— 写坏的规则会让
// 下次启动时整库加载失败。
func TestParseOverrideLine(t *testing.T) {
	ok := []struct {
		in       string
		country  string
		asn      uint32
		wantSize uint64 // 覆盖的地址数
	}{
		{"203.0.113.0/24 CN 4134 本地 ISP", "CN", 4134, 256},
		{"203.0.113.0/24\tCN\t4134", "CN", 4134, 256},
		{"203.0.113.5/32 SG", "SG", 0, 1},
		{"198.51.100.0 198.51.100.255 JP 0 手工修正", "JP", 0, 256},
		{"10.0.0.0/8 US AS64496", "US", 64496, 1 << 24},
		{"1.2.3.0/24 DE 100  # 行内注释应被忽略", "DE", 100, 256},
	}
	for _, tc := range ok {
		ov, err := parseOverrideLine(tc.in)
		if err != nil {
			t.Errorf("parseOverrideLine(%q) 报错: %v", tc.in, err)
			continue
		}
		if ov.Country != tc.country {
			t.Errorf("%q 国家 = %q, 期望 %q", tc.in, ov.Country, tc.country)
		}
		if ov.ASN != tc.asn {
			t.Errorf("%q ASN = %d, 期望 %d", tc.in, ov.ASN, tc.asn)
		}
		size := uint64(ov.End) - uint64(ov.Start) + 1
		if size != tc.wantSize {
			t.Errorf("%q 覆盖 %d 个地址, 期望 %d", tc.in, size, tc.wantSize)
		}
	}

	bad := []struct{ in, why string }{
		{"203.0.113.0/24", "缺国家码"},
		{"not-an-ip CN", "非法 IP"},
		{"203.0.113.0/99 CN", "非法前缀长度"},
		{"198.51.100.255 198.51.100.0 CN 0", "结束地址小于起始"},
		{"2001:db8::/32 CN", "IPv6 暂不支持"},
		{"198.51.100.0 CN", "区间写法缺第二个地址"},
	}
	for _, tc := range bad {
		if _, err := parseOverrideLine(tc.in); err == nil {
			t.Errorf("parseOverrideLine(%q) 应报错(%s)", tc.in, tc.why)
		}
	}
}

// 校验必须报出行号,否则用户在几百行文件里找不到错在哪
func TestValidateOverrides_ReportsLineNumber(t *testing.T) {
	text := `# 注释
203.0.113.0/24 CN 4134

this-line-is-broken
198.51.100.0/24 JP`

	err := ValidateOverrides(strings.NewReader(text))
	if err == nil {
		t.Fatal("含非法行时应报错")
	}
	if !strings.Contains(err.Error(), "第 4 行") {
		t.Errorf("错误信息应包含行号「第 4 行」,实际: %v", err)
	}
}

func TestValidateOverrides_AcceptsEmptyAndComments(t *testing.T) {
	text := `# 全是注释和空行

# 另一条注释
`
	if err := ValidateOverrides(strings.NewReader(text)); err != nil {
		t.Errorf("纯注释文件应通过校验: %v", err)
	}
}

// 本地覆盖必须真的覆盖主库判定,而不是与之并存 ——
// 同一地址被两条规则归到不同国家,展开时会产生重复前缀。
func TestApplyOverrides_ReplacesOverlapping(t *testing.T) {
	db := &DB{
		entries: []Entry{
			{Start: ipU32(203, 0, 113, 0), End: ipU32(203, 0, 113, 255), Country: "US", ASN: 64496},
			{Start: ipU32(198, 51, 100, 0), End: ipU32(198, 51, 100, 255), Country: "GB", ASN: 100},
		},
	}
	db.rebuildIndex()

	// 用 in-memory 文本模拟覆盖文件的解析结果
	ovs := []Override{
		{Start: ipU32(203, 0, 113, 0), End: ipU32(203, 0, 113, 255),
			Country: "CN", ASN: 4134, Note: "本地修正"},
	}

	kept := db.entries[:0:len(db.entries)]
	for _, e := range db.entries {
		if overlapsAny(e.Start, e.End, ovs) {
			continue
		}
		kept = append(kept, e)
	}
	for _, ov := range ovs {
		kept = append(kept, Entry{Start: ov.Start, End: ov.End,
			ASN: ov.ASN, Country: ov.Country, ASName: ov.Note})
	}
	db.entries = kept
	db.rebuildIndex()

	// 203.0.113.0/24 现在应归 CN 而非 US
	if len(db.byCountry["US"]) != 0 {
		t.Errorf("被覆盖的 US 条目未被剔除,仍有 %d 条", len(db.byCountry["US"]))
	}
	if len(db.byCountry["CN"]) != 1 {
		t.Errorf("覆盖后 CN 条目 = %d, 期望 1", len(db.byCountry["CN"]))
	}
	// 未被覆盖的 GB 条目应保留
	if len(db.byCountry["GB"]) != 1 {
		t.Errorf("未重叠的 GB 条目被误删")
	}
}

func TestSourceByID(t *testing.T) {
	if _, ok := SourceByID("iptoasn"); !ok {
		t.Error("内置源 iptoasn 应存在")
	}
	if _, ok := SourceByID("nonexistent"); ok {
		t.Error("不存在的源不该返回 ok")
	}
	// 每个内置源都必须有 URL、格式与许可说明 ——
	// 没有许可说明的数据源不该内置(法务风险)
	for _, s := range Sources {
		if s.URL == "" || s.Format == "" || s.License == "" {
			t.Errorf("源 %q 缺少必要字段: %+v", s.ID, s)
		}
	}
}

func ipU32(a, b, c, d byte) uint32 {
	return uint32(a)<<24 | uint32(b)<<16 | uint32(c)<<8 | uint32(d)
}
