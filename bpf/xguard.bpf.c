#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>

// Unique key to be used as key in hash map to share data with user space.
// __be == Big-endian: Raw packet bytes.
struct key_t {
    __be32 src_ip;
    __be16 eth_type;  // L3 protocol (IPv4, IPv6, etc.).
    __u8 protocol;    // L4 protocol (TCP, UDP, ICMP, etc.).
};
// Define eBPF hash map to count key_t occurances.
BPF_HASH(hit_count, struct key_t, __u64, 1024);

// All pckets will be XDP_PASS, we will find and construct a uniuque key
// consisting of source IP and L3/4 protocols ans count hits on it ans share
// via eBPF hash map with user space.
int trace_with_filters(struct xdp_md *ctx) {
    // XDP packet buffer offsets: Raw date from NIC.
    void *data_end = (void *)(long) ctx->data_end;
    void *data = (void *) (long) ctx->data;
    // XDP Packet Layout:
    //|<---------------- Ethernet Frame --------------------------->|
    //+---------------+----------------+----------------------------+
    //| L2 Ethernet   | L3 IPv4        | L4 TCP / UDP / ICMP        |
    //| ethhdr        | iphdr          | tcphdr / udphdr / icmphdr  |
    //+---------------+----------------+----------------------------+
    //| Bytes: 0-13   | 14-33          | 34+                        |
    //| Size: 14B     | 20B            | TCP 20B / UDP 8B / ICMP 8B |
    //+---------------+----------------+----------------------------+

    // Point to start of ethhdr offset.
    struct ethhdr *eth = data;
    // Point to start of iphdr.
    struct iphdr *iph = (void *)(eth + 1);
    // Bounds check: ensure ethhdr header fits in packet.
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;
    // Bounds check: ensure iphdr header fits in packet.
    if ((void *)(iph + 1) > data_end)
        return XDP_PASS;

    // Its now safe to read data now from ethhdr/iphdr.
    struct key_t key = {
        .eth_type = eth->h_proto
        .src_ip = iph->saddr,
        .protocol = iph->protocol
    };

    // Lookup shared eBPF hash map and eitehr update counte ror create new entry.
    __u64 *hits = hit_count.lookup(&key);
    if (hits) {
        __sync_fetch_and_add(hits, 1);  // To handle concurrency.
    } else {
        __u64 init_val = 1;
        hit_count.update(&key, &init_val);
    }

    bpf_trace_printk("Raw XDP packets: [%x/%x]\n", key.eth_type,key.src_ip,key.protocol);

    return XDP_PASS;
}
