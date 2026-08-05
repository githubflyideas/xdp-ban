// Package banmap —— eBPF map 的键值编码。
//
// 这个包存在的唯一理由:**内核结构体布局是一份跨语言契约**。
// bpf/xdp_filter.c 定义了 map 的 key/value 内存布局,Go 侧必须逐字节对齐。
// 一旦不一致,写进去的 key 与 XDP 侧算出的永不相等 —— 黑名单静默失效,
// 界面显示"已封禁"而流量照进。这是最危险的失败模式:没有任何报错。
//
// 把编码单独拆包而不是散在 agent 的 main.go 里,是为了能在没有 root、
// 没有内核的环境里单测这层契约。agent 的 main 只负责轮询与调度。
//
// 布局定义(与 xdp_filter.c 逐行对应):
//
//	struct global_ban_key { __u32 prefixlen; __u32 src_ip; }              // 8B
//	struct src_ban_key    { __u32 prefixlen; __u32 target_id; __u32 src_ip; } // 12B
//	struct target_key     { __u32 dst_ip; }                                // 4B
//	struct ban_value      { __u64 expires_at; __u64 hits; __u32 rule_id; __u32 _pad; } // 24B
//
// 字节序约定:
//   - IP 地址字段是**网络字节序**,与 iphdr->saddr/daddr 原样一致,不做转换
//   - prefixlen / target_id / rule_id 等数值字段是**主机字节序**(内核按
//     本机序解释这些结构体成员)
package banmap

import (
	"encoding/binary"
	"fmt"
	"net/netip"
	"time"
)

// Map 名称。必须与 bpf/xdp_filter.c 中 SEC(".maps") 的变量名完全一致。
// 用常量而不是散落的字面量:改名时编译器帮不上忙,但至少只有一处要改。
const (
	MapGlobalBans  = "src_ban_global"
	MapTargetHosts = "target_hosts"
	MapSrcBans     = "src_ban"
	MapCounters    = "counters"
)

// 结构体尺寸。测试会断言这些值 —— 它们变了意味着内核契约变了。
const (
	GlobalKeySize = 8
	SrcKeySize    = 12
	TargetKeySize = 4
	ValueSize     = 24
)

// 计数器槽位,与 xdp_filter.c 的 enum 对应
const (
	CntDropped = iota
	CntPassed
	CntExpired
	CntNotTarget
	CntMax
)

// Value 是 ban_value 的 Go 侧表示
type Value struct {
	ExpiresAt uint64 // 0 = 永久;否则为 bpf_ktime_get_ns 基准的纳秒
	Hits      uint64
	RuleID    uint32
}

// EncodeValue 编码 ban_value。
//
// expiresAt 用的是 bpf_ktime_get_ns 的时间基准(自系统启动的单调纳秒),
// **不是** Unix 时间。XDP 侧只能拿到 ktime,用 Unix 时间会让所有 TTL
// 判断都错(要么立即过期,要么永不过期)。转换由 KtimeDeadline 负责。
func EncodeValue(v Value) []byte {
	b := make([]byte, ValueSize)
	binary.LittleEndian.PutUint64(b[0:8], v.ExpiresAt)
	binary.LittleEndian.PutUint64(b[8:16], v.Hits)
	binary.LittleEndian.PutUint32(b[16:20], v.RuleID)
	// b[20:24] 是 _pad,保持零
	return b
}

// DecodeValue 解码 ban_value(供 reaper 扫描过期条目与统计命中数用)
func DecodeValue(b []byte) (Value, error) {
	if len(b) < ValueSize {
		return Value{}, fmt.Errorf("ban_value 长度 %d,期望 %d", len(b), ValueSize)
	}
	return Value{
		ExpiresAt: binary.LittleEndian.Uint64(b[0:8]),
		Hits:      binary.LittleEndian.Uint64(b[8:16]),
		RuleID:    binary.LittleEndian.Uint32(b[16:20]),
	}, nil
}

// EncodeGlobalKey 编码全局封禁 key(只匹配源前缀)。
// prefix 必须是 IPv4,前缀长度 0..32。
func EncodeGlobalKey(prefix netip.Prefix) ([]byte, error) {
	if !prefix.Addr().Is4() {
		return nil, fmt.Errorf("仅支持 IPv4 前缀,收到 %s", prefix)
	}
	bits := prefix.Bits()
	if bits < 0 || bits > 32 {
		return nil, fmt.Errorf("非法前缀长度 %d", bits)
	}

	// 关键:必须用 Masked() 归一化。LPM_TRIE 要求 key 中超出 prefixlen 的
	// 位为 0,否则内核插入的位置与查询时的最长匹配不一致 —— 规则写进去了
	// 但永远匹配不上。
	p := prefix.Masked()
	a4 := p.Addr().As4()

	b := make([]byte, GlobalKeySize)
	binary.LittleEndian.PutUint32(b[0:4], uint32(bits)) // prefixlen,主机序
	copy(b[4:8], a4[:])                                 // src_ip,网络字节序原样
	return b, nil
}

// EncodeSrcKey 编码定向封禁 key(target_id 精确 + 源前缀最长匹配)。
//
// prefixlen = 32 + srcBits:前 32 位(target_id)必须全部参与匹配,
// 才等价于"target_id 精确匹配"。
func EncodeSrcKey(targetID uint32, prefix netip.Prefix) ([]byte, error) {
	if !prefix.Addr().Is4() {
		return nil, fmt.Errorf("仅支持 IPv4 前缀,收到 %s", prefix)
	}
	srcBits := prefix.Bits()
	if srcBits < 0 || srcBits > 32 {
		return nil, fmt.Errorf("非法前缀长度 %d", srcBits)
	}

	p := prefix.Masked()
	a4 := p.Addr().As4()

	b := make([]byte, SrcKeySize)
	binary.LittleEndian.PutUint32(b[0:4], uint32(32+srcBits)) // prefixlen
	binary.LittleEndian.PutUint32(b[4:8], targetID)           // 精确匹配段
	copy(b[8:12], a4[:])                                      // src_ip
	return b, nil
}

// EncodeTargetKey 编码受保护目标主机 key。目标只能是单个 IPv4 主机。
func EncodeTargetKey(addr netip.Addr) ([]byte, error) {
	if !addr.Is4() {
		return nil, fmt.Errorf("目标仅支持 IPv4,收到 %s", addr)
	}
	a4 := addr.As4()
	b := make([]byte, TargetKeySize)
	copy(b, a4[:])
	return b, nil
}

// EncodeTargetID 编码 target_hosts 的 value(单个 u32)
func EncodeTargetID(id uint32) []byte {
	b := make([]byte, 4)
	binary.LittleEndian.PutUint32(b, id)
	return b
}

// KtimeDeadline 把 TTL 秒数换算成 bpf_ktime_get_ns 基准的截止时刻。
//
// 为什么不能直接用 Unix 纳秒:XDP 侧只有 bpf_ktime_get_ns(),它是
// 自系统启动的单调时钟。传 Unix 时间进去,比较结果会完全错乱 ——
// Unix 纳秒远大于任何 uptime,所有封禁都会被判成"未过期"而永久生效;
// 反过来如果基准算错方向,则所有封禁立刻失效。
//
// ttlSecs <= 0 表示永久,返回 0。
func KtimeDeadline(bootTime time.Time, now time.Time, ttlSecs int64) uint64 {
	if ttlSecs <= 0 {
		return 0
	}
	uptime := now.Sub(bootTime)
	if uptime < 0 {
		uptime = 0
	}
	return uint64(uptime) + uint64(ttlSecs)*uint64(time.Second)
}

// ParseIPv4Prefix 把 "1.2.3.4" 或 "1.2.3.0/24" 解析成 IPv4 前缀。
// 单个地址视为 /32。IPv6 显式拒绝而不是静默忽略。
func ParseIPv4Prefix(s string) (netip.Prefix, error) {
	if p, err := netip.ParsePrefix(s); err == nil {
		if !p.Addr().Is4() {
			return netip.Prefix{}, fmt.Errorf("暂不支持 IPv6: %q", s)
		}
		return p.Masked(), nil
	}
	a, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("非法地址或前缀: %q", s)
	}
	if !a.Is4() {
		return netip.Prefix{}, fmt.Errorf("暂不支持 IPv6: %q", s)
	}
	return netip.PrefixFrom(a, 32), nil
}
