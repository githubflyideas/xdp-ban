/* xdp_filter.c — XDP 执行层(纯 eBPF)
 *
 * 两类封禁,两条查表路径:
 *
 *   ① src_ban_global  LPM_TRIE  src_prefix → ban_value
 *      "封掉这个源,不管它打谁"。单点封禁走这条,是最常见的需求。
 *
 *   ② target_hosts    HASH      dst_ip(/32) → target_id
 *      src_ban        LPM_TRIE  (target_id, src_prefix) → ban_value
 *      "封掉某范围的源打向某台主机的流量"。范围封禁(按国家/AS)走这条。
 *
 * 为什么定向封禁要 target_id 这一级:
 *   LPM_TRIE 只能对 key 的前 prefixlen 位做最长匹配。把 target_id 放在
 *   key 的前 4 字节并让 prefixlen 恒 >= 32,就等价于"target_id 精确匹配
 *   + src_ip 前缀匹配"。这样不同目标主机的封禁范围互不干扰。
 *   (Cilium 用的是同一个技巧。)
 *
 * 为什么定向封禁的目标必须是 /32:
 *   若目标也允许前缀,就需要对 (dst_prefix, src_prefix) 做二维最长匹配,
 *   LPM_TRIE 做不到,只能退化成逐条遍历 —— 每包遍历在 XDP 里不可接受。
 *   限制目标为主机 IP 把二维问题降成一维。
 *
 * 查表成本:正常流量是 1 次 LPM miss + 1 次 HASH miss。
 *   全局表放在最前面是刻意的 —— 单点封禁最常用,让它走最短路径。
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

/* 全局封禁条目上限。单点封禁(封一个 IP/网段,不限目标)走这里。
 * 比定向表小一个量级:人工精准封禁的数量级是千到万,不是十万。 */
#define MAX_GLOBAL_BANS 65536

/* 定向封禁(源范围 × 目标主机)条目上限。
 *
 * 这个数字是内核锁定内存与覆盖能力之间的权衡,必须清醒:
 *   - 全球 BGP 表约 120 万条 IPv4 前缀(APNIC 2026),全量导入不现实
 *   - 单个大国(如 US)公告前缀可达 20 万条以上
 *   - 单个大型 AS(如 AS4134)约 1 万条
 * LPM_TRIE 每条内部节点开销约 40–50 字节且为 locked memory(不可换出)。
 * 26 万条约占 15–25 MB 内核内存,是单机可接受的上界。
 * 用户态必须在下发前做配额预检,而不是等 map 满了收 E2BIG。 */
#define MAX_SRC_BANS 262144

/* 全局兜底:XDP 侧只认这些 map 的容量。用户态若越界,插入失败并回报,
 * 绝不会静默丢规则 —— 静默失败比明确拒绝危险得多。 */

struct target_key {
    __u32 dst_ip;      /* 网络字节序,与 iphdr->daddr 一致 */
};

/* LPM_TRIE 的 key 必须以 u32 prefixlen 开头(内核约定) */

/* 全局封禁 key:只匹配源前缀,prefixlen 取值 0..32 */
struct global_ban_key {
    __u32 prefixlen;
    __u32 src_ip;      /* 网络字节序 */
};

/* 定向封禁 key:target_id 精确 + src_ip 前缀,prefixlen 取值 32..64 */
struct src_ban_key {
    __u32 prefixlen;   /* 32 + src 前缀长度 */
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
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __type(key, struct global_ban_key);
    __type(value, struct ban_value);
    __uint(max_entries, MAX_GLOBAL_BANS);
    __uint(map_flags, BPF_F_NO_PREALLOC);  /* LPM_TRIE 必须设此标志 */
} src_ban_global SEC(".maps");

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
    __uint(map_flags, BPF_F_NO_PREALLOC);
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

/* expired 判断:0 表示永久,永不过期。
 * 过期条目不在内核里删 —— 内核侧删除需要额外的写权限与复杂度,
 * 交给用户态 reaper 定期清理,这里只放行并计数。 */
static __always_inline int is_expired(struct ban_value *bv)
{
    return bv->expires_at != 0 && bpf_ktime_get_ns() > bv->expires_at;
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

    /* 路径 ①:全局封禁 —— "封掉这个源,不管它打谁"。
     * 单点封禁最常用,放在最前面走最短路径。 */
    struct global_ban_key gk = {
        .prefixlen = 32,          /* 查询给满位,由内核做最长匹配 */
        .src_ip    = ip->saddr,
    };
    struct ban_value *gv = bpf_map_lookup_elem(&src_ban_global, &gk);
    if (gv) {
        if (is_expired(gv)) {
            bump(CNT_EXPIRED);
            return XDP_PASS;
        }
        gv->hits++;
        bump(CNT_DROPPED);
        return XDP_DROP;
    }

    /* 路径 ②:定向封禁 —— 先看目标是否在保护集内。
     * 绝大多数包在这里就返回了。 */
    struct target_key tk = { .dst_ip = ip->daddr };
    __u32 *tid = bpf_map_lookup_elem(&target_hosts, &tk);
    if (!tid) {
        bump(CNT_NOT_TARGET);
        return XDP_PASS;
    }

    /* 源地址是否落在该目标的封禁前缀内(最长匹配) */
    struct src_ban_key sk = {
        .prefixlen = 64,          /* 查询给满位 */
        .target_id = *tid,
        .src_ip    = ip->saddr,
    };
    struct ban_value *bv = bpf_map_lookup_elem(&src_ban, &sk);
    if (!bv) {
        bump(CNT_PASSED);
        return XDP_PASS;
    }

    if (is_expired(bv)) {
        bump(CNT_EXPIRED);
        return XDP_PASS;
    }

    bv->hits++;   /* 同一条目可能被多 CPU 并发更新,计数容许微小误差 */
    bump(CNT_DROPPED);
    return XDP_DROP;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
