#include <linux/bpf.h>
#include <netinet/ip.h>
#include "bpf_helpers.h"

#define __section(NAME)                  \
	__attribute__((section(NAME), used))

struct bpf_map_def __section("maps") my_map = {
	.type = BPF_MAP_TYPE_QUEUE,
	.key_size = 0,
	.value_size = sizeof(__u32),
	.max_entries = 10000,
};


__section("cgroup_skb/egress")
int egress(struct __sk_buff *skb) {
	__u32 ip = skb->remote_ip4;
    struct iphdr iph;
    __u32 dstip = skb->remote_ip4;

    if (!dstip) {
        bpf_skb_load_bytes(skb, 0, &iph, sizeof(struct iphdr));
        if (iph.version == 4)
            dstip = iph.daddr;
    }

    bpf_map_push_elem(&my_map, &dstip, 0);
    return 0;
}

char __license[] __section("license") = "GPL";
