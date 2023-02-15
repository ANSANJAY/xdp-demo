// ebpf_program.c

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/tcp.h>

struct ipv4_key {
    __u32 addr;
};

struct ipv4_value {
    __u64 packet_count;
};

struct bpf_map_def SEC("maps") ipv4_map = {
    .type = BPF_MAP_TYPE_LRU_HASH,
    .key_size = sizeof(struct ipv4_key),
    .value_size = sizeof(struct ipv4_value),
    .max_entries = 1024,
};

SEC("xdp_prog")
int xdp_prog(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if (eth + 1 > data_end) {
        return XDP_DROP;
    }

    struct iphdr *ip = data + sizeof(struct ethhdr);
    if (ip + 1 > data_end) {
        return XDP_DROP;
    }

    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = data + sizeof(struct ethhdr) + sizeof(struct iphdr);
        if (tcp + 1 > data_end) {
            return XDP_DROP;
        }
    }

    struct ipv4_key key = {
        .addr = ip->saddr,
    };

    struct ipv4_value *value = bpf_map_lookup_elem(&ipv4_map, &key);
    if (!value) {
        struct ipv4_value new_value = {
            .packet_count = 1,
        };
        bpf_map_update_elem(&ipv4_map, &key, &new_value, BPF_ANY);
    } else {
        value->packet_count++;
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
