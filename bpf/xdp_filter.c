/* xdp_filter.c — XDP 执行层(纯 eBPF)
 *
 * 两级匹配,支持"源地址范围 × 目标主机"的封禁:
 *
 *   ① target_hosts  HASH   dst_ip(/32) → target_id
 *      受保护的目标主机集合。数量由业务规模决定(几十到几千),很小。
 *
 *   ② src_ban       LPM_TRIE  (target_id, src_prefix) → ban_value
 *      按源前缀最长匹配。LPM_TRIE 的关键价值:一条 /8 只占 1 个表项,
 *      而不是 1600 万个 —— 按国家/AS 封禁能成立完全依赖这一点。
 *
 * 为什么要 target_id 这一级:
 *   LPM_TRIE 只能对 key 的前 prefixlen 位做最长匹配。把 target_id 放在
 *   key 的前 4 字节并让 prefixlen 恒 >= 32,就等价于"target_id 精确匹配
 *   + src_ip 前缀匹配"。这样不同目标主机的封禁范围互不干扰。
 *   (Cilium 用的是同一个技巧。)
 *
 * 为什么目标必须是 /32:
 *   若目标也允许前缀,就需要对 (dst_prefix, src_prefix) 做二维最长匹配,
 *   LPM_TRIE 做不到,只能退化成逐条遍历 —— 每包遍历在 XDP 里不可接受。
 *   限制目标为主机 IP 把二维问题降成一维。
 *
 * 编译: clang -O2 -g -target bpf -c xdp_filter.c -o xdp_filter.o
 */

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>

/* 受保护目标主机数上限。目标是"我方要保护的服务器",不是攻击源,
 * 所以这个数很小 —— 上千已属大规模部署。 */
#define MAX_TARGETS 4096

/* 源前缀封禁条目上限。
 *
 * 这个数字是内核锁定内存与覆盖能力之间的权衡,必须清醒:
 *   - 全球 BGP 表约 120 万条 IPv4 前缀(APNIC 2026),全量导入不现实
 *   - 单个大国(如 US)公告前缀可达 20 万条以上
 *   - 单个大型 AS(如 AS4134)约 1 万条
 * LPM_TRIE 每条内部节点开销约 40–50 字节且为 locked memory(不可换出)。
 * 26 万条约占 15–25 MB 内核内存,是单机可接受的上界。
 * 用户态必须在下发前做配额预检,而不是等 map 满了收 E2BIG。 */
#define MAX_SRC_BANS 262144

/* 全局兜底:XDP 侧只认这个 map 的容量。用户态若越界,插入失败并回报,
 * 绝不会静默丢规则 —— 静默失败比明确拒绝危险得多。 */

struct target_key {
    __u32 dst_ip;      /* 网络字节序,与 iphdr->daddr 一致 */
};

/* LPM_TRIE 的 key 必须以 u32 prefixlen 开头(内核约定) */
struct src_ban_key {
    __u32 prefixlen;   /* 32 + src 前缀长度,取值 32..64 */
    __u32 target_id;   /* 精确匹配部分 */
    __u32 src_ip;      /* 前缀匹配部分,网络字节序 */
};

struct ban_value {
    __u64 expires_at;  /* 0 = 永久;否则为 bpf_ktime_get_ns 时间基准 */
    __u64 hits;        /* 命中丢包数 */
    __u32 rule_id;     /* 回溯到 xdp-ban 的规则,便于审计与统计归因 */
    __u32 _pad;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct target_key);
    __type(value, __u32);          /* target_id */
    __uint(max_entries, MAX_TARGETS);
} target_hosts SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __type(key, struct src_ban_key);
    __type(value, struct ban_value);
    __uint(max_entries, MAX_SRC_BANS);
    __uint(map_flags, BPF_F_NO_PREALLOC);  /* LPM_TRIE 必须设此标志 */
} src_ban SEC(".maps");

/* 统计槽位 */
enum {
    CNT_DROPPED = 0,
    CNT_PASSED,
    CNT_EXPIRED,      /* 命中但已过期 → 放行(说明该清理了) */
    CNT_NOT_TARGET,   /* 目标不在保护集,直接放行的快路径 */
    CNT_MAX,
};

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);  /* per-CPU 免原子争抢 */
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, CNT_MAX);
} counters SEC(".maps");

static __always_inline void bump(__u32 idx)
{
    __u64 *c = bpf_map_lookup_elem(&counters, &idx);
    if (c)
        (*c)++;   /* PERCPU_ARRAY 无需原子操作 */
}

SEC("xdp")
int xdp_filter(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    if (eth->h_proto != __constant_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    /* 第一级:目标是否在保护集内。
     * 绝大多数包在这里就返回了 —— 一次 HASH 查表,是最省的快路径。 */
    struct target_key tk = { .dst_ip = ip->daddr };
    __u32 *tid = bpf_map_lookup_elem(&target_hosts, &tk);
    if (!tid) {
        bump(CNT_NOT_TARGET);
        return XDP_PASS;
    }

    /* 第二级:源地址是否落在该目标的封禁前缀内(最长匹配) */
    struct src_ban_key sk = {
        .prefixlen = 64,          /* 查询时给满位,由内核做最长匹配 */
        .target_id = *tid,
        .src_ip    = ip->saddr,
    };
    struct ban_value *bv = bpf_map_lookup_elem(&src_ban, &sk);
    if (!bv) {
        bump(CNT_PASSED);
        return XDP_PASS;
    }

    /* TTL 检查。过期不在内核里删 —— 内核侧删除需要额外的写权限与
     * 复杂度,交给用户态 reaper 定期清理,这里只放行并计数。 */
    if (bv->expires_at != 0 && bpf_ktime_get_ns() > bv->expires_at) {
        bump(CNT_EXPIRED);
        return XDP_PASS;
    }

    bv->hits++;   /* 同一条目可能被多 CPU 并发更新,计数容许微小误差 */
    bump(CNT_DROPPED);
    return XDP_DROP;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
