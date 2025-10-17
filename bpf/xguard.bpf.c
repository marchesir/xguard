#include <linux/bpf.h>
#include <linux/if_ether.h>

int drop_all(struct xdp_md *ctx) {
    // XDP packet buffer offsets.
    void *data_end = (void *)(long) ctx->data_end;
    void *data = (void *) (long) ctx->data;
    // Ethernet frame header: points to start of the XDP packet buffer.
    struct ethhdr *eth = data;
    // Set 16-bit unsigned int to 0, it will hold ethernet protocol.
    __u16 h_proto = 0;

    // Bounds check, if true we have data in XDP packet buffer, if not let the packet thru.
    if ((void *)eth + sizeof(*eth) <= data_end)
    {
        // Read 16-bit unsigned int from XDP packet buffer as big-endian.
        h_proto = eth->h_proto;
        // Converts a 16-bit value from network byte order (big-endian) to host byte order.
        __u16 proto_host = bpf_ntohs(h_proto);

        bpf_trace_printk("Blocked Ethernet Protocol: 0x%x\\n", proto_host);

        return XDP_DROP;

    }
    return XDP_PASS;
}
