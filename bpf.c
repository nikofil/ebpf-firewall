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

struct bpf_map_def __section("maps") my_map = {
	.type = BPF_MAP_TYPE_QUEUE,
	.key_size = 0,
	.value_size = sizeof(conn),
	.max_entries = 10000,
};

inline void handle_pkt(struct __sk_buff *skb, bool egress) {
    struct iphdr iph;
    bpf_skb_load_bytes(skb, 0, &iph, sizeof(struct iphdr));
    bool blocked = true;
    if (iph.version == 4) {
        conn x = {
            .flags = egress | (blocked << 1),
            .srcip = iph.saddr,
            .dstip = iph.daddr,
        };

        bpf_map_push_elem(&my_map, &x, 0);
    }
}

__section("cgroup_skb/ingress")
int ingress(struct __sk_buff *skb) {
    handle_pkt(skb, false);
    return 0;
}

__section("cgroup_skb/egress")
int egress(struct __sk_buff *skb) {
    handle_pkt(skb, true);
    return 0;
}

char __license[] __section("license") = "GPL";
