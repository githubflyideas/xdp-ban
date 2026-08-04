package prefixdb

import (
	"fmt"
	"net/netip"
	"sort"
)

// Selector 描述一次"按国家/AS 选源范围"的查询。
// 二者可同时给出,语义为交集(例:中国境内的 AS4134)。
type Selector struct {
	Country string // ISO alpha-2,空表示不限
	ASN     uint32 // 0 表示不限
}

func (s Selector) String() string {
	switch {
	case s.Country != "" && s.ASN != 0:
		return fmt.Sprintf("%s+AS%d", s.Country, s.ASN)
	case s.Country != "":
		return s.Country
	case s.ASN != 0:
		return fmt.Sprintf("AS%d", s.ASN)
	}
	return "(空)"
}

// Resolve 把选择条件展开为最小 CIDR 集合。
//
// 为什么要"最小化":iptoasn 给的是任意起止区间(如 1.0.0.0–1.0.3.255),
// 不是 CIDR。一个区间可能需要多个 CIDR 表达。若不做区间合并就逐个转换,
// 相邻区间会产生大量本可合并的碎片前缀,直接放大 LPM_TRIE 表项数。
//
// 步骤:① 收集命中区间 → ② 按起点排序并合并重叠/相邻 → ③ 拆成最小 CIDR。
// 实测对单个大国,合并能把表项数降低一到两成。
func (db *DB) Resolve(sel Selector) ([]netip.Prefix, error) {
	idxs, err := db.candidates(sel)
	if err != nil {
		return nil, err
	}
	if len(idxs) == 0 {
		return nil, nil
	}

	// 收集区间
	type rng struct{ start, end uint32 }
	ranges := make([]rng, 0, len(idxs))
	for _, i := range idxs {
		e := &db.entries[i]
		ranges = append(ranges, rng{e.Start, e.End})
	}
	sort.Slice(ranges, func(i, j int) bool { return ranges[i].start < ranges[j].start })

	// 合并重叠与相邻区间
	merged := make([]rng, 0, len(ranges))
	cur := ranges[0]
	for _, r := range ranges[1:] {
		// r.start <= cur.end+1 时可合并;注意 cur.end 可能是 0xffffffff,
		// +1 会溢出,故用减法比较避免回绕
		if r.start <= cur.end || (cur.end != ^uint32(0) && r.start == cur.end+1) {
			if r.end > cur.end {
				cur.end = r.end
			}
			continue
		}
		merged = append(merged, cur)
		cur = r
	}
	merged = append(merged, cur)

	// 区间 → 最小 CIDR
	var out []netip.Prefix
	for _, r := range merged {
		out = append(out, rangeToCIDRs(r.start, r.end)...)
	}
	return out, nil
}

// candidates 取满足条件的 entry 下标
func (db *DB) candidates(sel Selector) ([]int, error) {
	switch {
	case sel.Country == "" && sel.ASN == 0:
		return nil, fmt.Errorf("必须指定国家或 AS 号")

	case sel.Country != "" && sel.ASN != 0:
		// 交集:以较小的一侧为基准过滤
		byC := db.byCountry[sel.Country]
		byA := db.byASN[sel.ASN]
		if len(byC) == 0 || len(byA) == 0 {
			return nil, nil
		}
		base, other := byC, sel.ASN
		if len(byA) < len(byC) {
			// 以 ASN 列表为基准,按国家过滤
			out := make([]int, 0, len(byA))
			for _, i := range byA {
				if db.entries[i].Country == sel.Country {
					out = append(out, i)
				}
			}
			return out, nil
		}
		out := make([]int, 0, len(base))
		for _, i := range base {
			if db.entries[i].ASN == other {
				out = append(out, i)
			}
		}
		return out, nil

	case sel.Country != "":
		return db.byCountry[sel.Country], nil

	default:
		return db.byASN[sel.ASN], nil
	}
}

// rangeToCIDRs 将闭区间 [start, end] 拆成最少数量的 CIDR。
//
// 标准贪心算法:每步取当前起点能对齐的最大块,且不越过终点。
func rangeToCIDRs(start, end uint32) []netip.Prefix {
	var out []netip.Prefix
	for start <= end {
		// 当前起点的对齐能力:最低置位比特决定最大块
		maxSize := uint32(32)
		for maxSize > 0 {
			mask := ^uint32(0) << (32 - (maxSize - 1))
			if start&^mask != 0 {
				break
			}
			maxSize--
		}
		// 不能超出 end
		remaining := uint64(end) - uint64(start) + 1
		for maxSize < 32 {
			if uint64(1)<<(32-maxSize) <= remaining {
				break
			}
			maxSize++
		}

		out = append(out, netip.PrefixFrom(u32ToAddr(start), int(maxSize)))

		blockSize := uint64(1) << (32 - maxSize)
		next := uint64(start) + blockSize
		if next > uint64(^uint32(0)) {
			break // 到达地址空间末尾,避免回绕成死循环
		}
		start = uint32(next)
	}
	return out
}

func u32ToAddr(v uint32) netip.Addr {
	return netip.AddrFrom4([4]byte{
		byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v),
	})
}

// Preview 是下发前给用户看的影响面预估。
//
// 这是资源保护的第一道闸:让人在点"提交"之前就看到
// "这一条规则会占用多少表项、覆盖多少地址"。
type Preview struct {
	Selector  Selector
	CIDRCount int    // 需要占用的 LPM_TRIE 表项数
	AddrCount uint64 // 覆盖的地址总数
	Samples   []string
	Truncated bool
}

// Preview 计算影响面。limitSamples 控制回显的示例数量。
func (db *DB) Preview(sel Selector, limitSamples int) (*Preview, error) {
	cidrs, err := db.Resolve(sel)
	if err != nil {
		return nil, err
	}
	p := &Preview{Selector: sel, CIDRCount: len(cidrs)}
	for _, c := range cidrs {
		p.AddrCount += uint64(1) << (32 - c.Bits())
	}
	for i, c := range cidrs {
		if i >= limitSamples {
			p.Truncated = true
			break
		}
		p.Samples = append(p.Samples, c.String())
	}
	return p, nil
}

// CountryOption / ASNOption 供界面下拉框使用
type CountryOption struct {
	Code       string
	CIDRBlocks int
}

type ASNOption struct {
	ASN        uint32
	Name       string
	Country    string
	CIDRBlocks int
}

// Countries 返回可选国家列表,按前缀数降序(常用的在前)
func (db *DB) Countries() []CountryOption {
	out := make([]CountryOption, 0, len(db.byCountry))
	for code, idxs := range db.byCountry {
		out = append(out, CountryOption{Code: code, CIDRBlocks: len(idxs)})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CIDRBlocks > out[j].CIDRBlocks })
	return out
}

// SearchASN 按 AS 号或名称片段搜索,limit 限制返回条数。
// 界面用搜索而非全量下拉:全球有十万级 AS,下拉框装不下。
func (db *DB) SearchASN(query string, limit int) []ASNOption {
	q := normalizeASNQuery(query)
	var out []ASNOption
	seen := make(map[uint32]bool)

	for asn, idxs := range db.byASN {
		if len(out) >= limit {
			break
		}
		if seen[asn] {
			continue
		}
		e := &db.entries[idxs[0]]
		if !matchASN(asn, e.ASName, q) {
			continue
		}
		seen[asn] = true
		out = append(out, ASNOption{
			ASN: asn, Name: e.ASName, Country: e.Country, CIDRBlocks: len(idxs),
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CIDRBlocks > out[j].CIDRBlocks })
	return out
}
