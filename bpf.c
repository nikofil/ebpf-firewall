#include <stdbool.h>
#include <linux/bpf.h>
#include <netinet/ip.h>
#include "bpf_helpers.h"

#define __section(NAME)                  \
	__attribute__((section(NAME), used))

typedef struct {
    __u32 flags;
    __u32 dstip;
    __u32 srcip;
} conn;

struct bpf_map_def __section("maps") flows_map = {
	.type = BPF_MAP_TYPE_QUEUE,
	.key_size = 0,
	.value_size = sizeof(conn),
	.max_entries = 10000,
};

struct bpf_map_def __section("maps") blocked_map = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(__u32),
	.value_size = sizeof(__u32),
	.max_entries = 10000,
};

inline bool handle_pkt(struct __sk_buff *skb, bool egress) {
    struct iphdr iph;
    bpf_skb_load_bytes(skb, 0, &iph, sizeof(struct iphdr));
    bool blocked = bpf_map_lookup_elem(&blocked_map, &iph.saddr) || bpf_map_lookup_elem(&blocked_map, &iph.daddr);
    if (iph.version == 4) {
        conn x = {
            .flags = egress | (blocked << 1),
            .srcip = iph.saddr,
            .dstip = iph.daddr,
        };

        bpf_map_push_elem(&flows_map, &x, 0);
    }
    return !blocked;
}

__section("cgroup_skb/ingress")
int ingress(struct __sk_buff *skb) {
    return (int)handle_pkt(skb, false);
}

__section("cgroup_skb/egress")
int egress(struct __sk_buff *skb) {
    return (int)handle_pkt(skb, true);
}

char __license[] __section("license") = "GPL";
