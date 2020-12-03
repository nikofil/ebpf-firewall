#include <stdbool.h>
#include <linux/bpf.h>
#include <netinet/ip.h>
#include "bpf_helpers.h"

#define __section(NAME)                  \
	__attribute__((section(NAME), used))

/* Struct that describes a packet: srcip, dstip and flags (direction and whether it was blocked) */
typedef struct {
    __u32 flags;
    __u32 dstip;
    __u32 srcip;
} conn;

/* Map for sending flow information (srcip, dstip, direction) to userspace */
struct bpf_map_def __section("maps") flows_map = {
	.type = BPF_MAP_TYPE_QUEUE,
	.key_size = 0,
	.value_size = sizeof(conn),
	.max_entries = 10000,
};

/* Map for blocking IP addresses from userspace */
struct bpf_map_def __section("maps") blocked_map = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(__u32),
	.value_size = sizeof(__u32),
	.max_entries = 10000,
};

/* Handle a packet: send its information to userspace and return whether it should be allowed */
inline bool handle_pkt(struct __sk_buff *skb, bool egress) {
    struct iphdr iph;
    /* Load packet header */
    bpf_skb_load_bytes(skb, 0, &iph, sizeof(struct iphdr));
    /* Check if IPs are in "blocked" map */
    bool blocked = bpf_map_lookup_elem(&blocked_map, &iph.saddr) || bpf_map_lookup_elem(&blocked_map, &iph.daddr);
    if (iph.version == 4) {
        conn c = {
            .flags = egress | (blocked << 1),
            .srcip = iph.saddr,
            .dstip = iph.daddr,
        };

        /* Send packet info to user program to display */
        bpf_map_push_elem(&flows_map, &c, 0);
    }
    /* Return whether it should be allowed or dropped */
    return !blocked;
}

/* Ingress hook - handle incoming packets */
__section("cgroup_skb/ingress")
int ingress(struct __sk_buff *skb) {
    return (int)handle_pkt(skb, false);
}

/* Egress hook - handle outgoing packets */
__section("cgroup_skb/egress")
int egress(struct __sk_buff *skb) {
    return (int)handle_pkt(skb, true);
}

char __license[] __section("license") = "GPL";
