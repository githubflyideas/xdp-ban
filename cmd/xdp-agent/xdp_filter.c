/* xdp_filter.c — XDP 执行层(nftables 后端)
 *
 * 职责:
 * - 存储 BPF map: IP 黑名单(5元组或单IP)
 * - XDP 快速路径检查:黑名单中的包直接 DROP
 * - 白名单、优先级覆盖通过 nftables 反馈
 *
 * 编译:
 *   clang -O2 -c -target bpf xdp_filter.c -o xdp_filter.o
 */

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>
#include <arpa/inet.h>

#define MAX_BANNED_IPS 10000

struct ban_entry {
    __u32 dst_ip;      /* 目标 IP */
    __u16 dst_port;    /* 目标端口(0 = 任意) */
    __u8 proto;        /* IPPROTO_TCP/UDP(0 = 任意) */
    __u8 action;       /* 0=DROP, 1=PASS */
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct ban_entry);
    __type(value, __u64);  /* 计数 */
    __uint(max_entries, MAX_BANNED_IPS);
} ban_list SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 2);
} counters SEC(".maps");  /* 0=dropped, 1=passed */

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

    struct ban_entry entry = {
        .dst_ip = ip->daddr,
        .proto = ip->protocol,
        .dst_port = 0,
    };

    /* 提取端口 */
    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = (void *)(ip + 1);
        if ((void *)(tcp + 1) > data_end)
            return XDP_PASS;
        entry.dst_port = tcp->dest;
    } else if (ip->protocol == IPPROTO_UDP) {
        struct udphdr *udp = (void *)(ip + 1);
        if ((void *)(udp + 1) > data_end)
            return XDP_PASS;
        entry.dst_port = udp->dest;
    }

    /* 查黑名单 */
    __u64 *action_ptr = bpf_map_lookup_elem(&ban_list, &entry);
    if (!action_ptr)
        return XDP_PASS;  /* 不在黑名单 */

    /* 黑名单命中:DROP + 计数 */
    __u32 drop_idx = 0;
    __u64 *drop_counter = bpf_map_lookup_elem(&counters, &drop_idx);
    if (drop_counter)
        __sync_fetch_and_add(drop_counter, 1);

    return XDP_DROP;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
