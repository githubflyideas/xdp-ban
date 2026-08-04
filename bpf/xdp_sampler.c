/* xdp_sampler.c — XDP 包采样 (1/N packet sampling)
 *
 * 部署到采样网卡(镜像流量接收端)
 * - 只观测,不丢弃(XDP_PASS)
 * - 1/N 包采样,可运行时调整 N
 * - 统计: 总包数、采样包数、按流五元组聚合
 *
 * 编译:
 *   clang -O2 -c -target bpf xdp_sampler.c -o xdp_sampler.o
 *
 * 加载:
 *   ip link set dev eth1 xdp obj xdp_sampler.o
 *   (或用 xdp-tools/xdp-loader)
 */

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>

#define MAX_FLOWS 10000

/* 采样配置(用户态可修改) */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u32);
    __uint(max_entries, 1);
} sampling_rate SEC(".maps");  // value = N (1/N sampling)

/* 流五元组 → 流量统计 */
struct flow_key {
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u8 proto;  /* IPPROTO_TCP / IPPROTO_UDP */
    __u8 _pad[3];
};

struct flow_stats {
    __u64 packets;
    __u64 bytes;
    __u64 last_seen;  /* jiffies */
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct flow_key);
    __type(value, struct flow_stats);
    __uint(max_entries, MAX_FLOWS);
} flow_table SEC(".maps");

/* 全局统计 */
struct stats {
    __u64 total_packets;
    __u64 sampled_packets;
    __u64 total_bytes;
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, struct stats);
    __uint(max_entries, 1);
} global_stats SEC(".maps");

/* 采样数据上报(ringbuf) */
struct sample_event {
    __u64 ts;           /* 时间戳 */
    struct flow_key flow;
    __u16 pkt_len;
    __u8 sampled;       /* 1 = 本包被采样 */
    __u8 _pad;
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} samples SEC(".maps");

/* 伪随机数(简单 LCG) */
static __always_inline __u32 prng(__u32 seed) {
    return seed * 1103515245 + 12345;
}

SEC("xdp")
int xdp_sample(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    /* 仅处理 IPv4 */
    if (eth->h_proto != __constant_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    struct flow_key flow = {};
    flow.src_ip = ip->saddr;
    flow.dst_ip = ip->daddr;
    flow.proto = ip->protocol;

    /* 提取端口(TCP/UDP) */
    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = (void *)(ip + 1);
        if ((void *)(tcp + 1) > data_end)
            return XDP_PASS;
        flow.src_port = tcp->source;
        flow.dst_port = tcp->dest;
    } else if (ip->protocol == IPPROTO_UDP) {
        struct udphdr *udp = (void *)(ip + 1);
        if ((void *)(udp + 1) > data_end)
            return XDP_PASS;
        flow.src_port = udp->source;
        flow.dst_port = udp->dest;
    } else {
        /* 其他协议,跳过端口 */
        flow.src_port = 0;
        flow.dst_port = 0;
    }

    /* 更新全局统计 */
    __u32 idx = 0;
    struct stats *gs = bpf_map_lookup_elem(&global_stats, &idx);
    if (gs) {
        __sync_fetch_and_add(&gs->total_packets, 1);
        __sync_fetch_and_add(&gs->total_bytes, ctx->data_meta - data);
    }

    /* 采样判定 (1/N) */
    __u32 *rate_ptr = bpf_map_lookup_elem(&sampling_rate, &idx);
    __u32 rate = rate_ptr ? *rate_ptr : 100;  /* 默认 1/100 */

    __u32 seed = ctx->rx_queue_index;
    __u32 rand = prng(seed);
    __u8 sampled = (rand % rate) == 0;

    if (sampled && gs) {
        __sync_fetch_and_add(&gs->sampled_packets, 1);
    }

    /* 流量统计更新 */
    struct flow_stats *fstats = bpf_map_lookup_elem(&flow_table, &flow);
    if (!fstats) {
        struct flow_stats new_stats = {
            .packets = 1,
            .bytes = ctx->data_meta - data,
            .last_seen = bpf_ktime_get_ns(),
        };
        bpf_map_update_elem(&flow_table, &flow, &new_stats, 0);
    } else {
        __sync_fetch_and_add(&fstats->packets, 1);
        __sync_fetch_and_add(&fstats->bytes, ctx->data_meta - data);
        fstats->last_seen = bpf_ktime_get_ns();
    }

    /* 采样包上报 ringbuf */
    if (sampled) {
        struct sample_event *evt = bpf_ringbuf_reserve(&samples, sizeof(*evt), 0);
        if (evt) {
            evt->ts = bpf_ktime_get_ns();
            evt->flow = flow;
            evt->pkt_len = ctx->data_meta - data;
            evt->sampled = 1;
            bpf_ringbuf_submit(evt, 0);
        }
    }

    /* 旁路:不丢弃,继续转发 */
    return XDP_PASS;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
