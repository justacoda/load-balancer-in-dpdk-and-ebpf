#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <netinet/in.h>

#include <bpf/bpf_helpers.h>
#include <linux/bpf.h>

#include "common.h"

#define MAX_OPT_WORDS 10 // 40 bytes for options
#define MAX_TARGET_COUNT 64
#define CHECK_OUT_OF_BOUNDS(PTR, OFFSET, END)                                  \
	(((void *)PTR) + OFFSET > ((void *)END))
#define TARGET_COUNT 2  // we know loader.cpp adds exactly 2 backends

static __always_inline __u32 hash_5tuple(__u32 src_ip, __u32 dst_ip,
                                         __u16 src_port, __u16 dst_port,
                                         __u8 proto)
{
    __u32 h = src_ip;
    h ^= dst_ip;
    h ^= ((__u32)src_port << 16) | dst_port;
    h ^= proto;

    /* simple mixing, good enough for this lab */
    h ^= h >> 16;
    h *= 0x7feb352d;
    h ^= h >> 15;
    h *= 0x846ca68b;
    h ^= h >> 16;

    return h;
}

struct ipv4_psd_header {
	uint32_t src_addr; /* IP address of source host. */
	uint32_t dst_addr; /* IP address of destination host. */
	uint8_t zero;	   /* zero. */
	uint8_t proto;	   /* L4 protocol type. */
	uint16_t len;	   /* L4 length. */
};

/**
 * Map that holds the information for the target servers
 * You can assume that this map will always have two elements populated when
 * loading the XDP program
 */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, __u32);
	__type(value, struct ip_mac_pair);
	__uint(max_entries, MAX_TARGET_COUNT);
} targets_map SEC(".maps");

/**
 * Map that holds the IP and MAC address of the load balancer and the client.
 * The IP and MAC of the load balancer are in the first cell
 * and the information for the client are in the second cell.
 * This map is also populated when loading the XDP program.
 */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, __u32);
	__type(value, struct ip_mac_pair);
	__uint(max_entries, MAX_TARGET_COUNT);
} config_map SEC(".maps");

// You might want to use functions below to compute the TCP checksum
/**
 * Helper function for computing checksum
 */
static __always_inline __u16 csum_reduce_helper(__u32 csum)
{
	csum = ((csum & 0xffff0000) >> 16) + (csum & 0xffff);
	csum = ((csum & 0xffff0000) >> 16) + (csum & 0xffff);

	return csum;
}

/**
 * Compute the checksum for tcp header
 */
static __always_inline int compute_tcp_csum(struct iphdr *ip, struct tcphdr *tcp, void * data_end)
{
  struct ipv4_psd_header psdh;
  uint32_t csum;
  int ret = 0;

  tcp->check = 0;
  csum = bpf_csum_diff(0, 0, (__be32 *)tcp, sizeof(struct tcphdr), 0);
  psdh.src_addr = ip->saddr;
	psdh.dst_addr = ip->daddr;
	psdh.zero = 0;
	psdh.proto = IPPROTO_TCP;
	psdh.len = htons(ntohs(ip->tot_len) - sizeof(struct iphdr));
	csum = bpf_csum_diff(0, 0, (__be32*)&psdh, sizeof(struct ipv4_psd_header),
			csum);
  uint32_t tcphdrlen = tcp->doff * 4;

  if (tcphdrlen == sizeof(struct tcphdr))
    goto OUT;

  /* There are TCP options */
  uint32_t *opt = (uint32_t *)(tcp + 1);
  uint32_t parsed = sizeof(struct tcphdr);
  for (int i=0;i<MAX_OPT_WORDS;i++) {
    if ((void *)(opt + 1) > data_end) {
      ret = -1;
      goto OUT;
    }

    csum = bpf_csum_diff(0, 0, (__be32 *)opt, sizeof(uint32_t), csum);

    parsed += sizeof(uint32_t);
    if (parsed == tcphdrlen)
      break;
    opt++;
  }

OUT:
  tcp->check = ~csum_reduce_helper(csum);
  return ret;
}

SEC("xdp")
int xdp_lb(struct xdp_md *ctx)
{
    void *data     = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    // Ethernet header
    struct ethhdr *eth = data;
    if (CHECK_OUT_OF_BOUNDS(eth, sizeof(*eth), data_end))
        return XDP_PASS;

    // Only handle IPv4
    if (__builtin_bswap16(eth->h_proto) != ETH_P_IP)
        return XDP_PASS;

    // IPv4 header
    struct iphdr *ip = (void *)eth + sizeof(*eth);
    if (CHECK_OUT_OF_BOUNDS(ip, sizeof(*ip), data_end))
        return XDP_PASS;

    if (ip->protocol != IPPROTO_TCP)
        return XDP_PASS;

    // Assume no IP
    if (ip->ihl != 5)
        return XDP_PASS;

    const __u32 ip_hlen = sizeof(*ip);

    struct tcphdr *tcp = (void *)ip + ip_hlen;
    if (CHECK_OUT_OF_BOUNDS(tcp, sizeof(*tcp), data_end))
        return XDP_PASS;

    __u32 key = 0;
    struct ip_mac_pair *vip_cfg = bpf_map_lookup_elem(&config_map, &key);
    if (!vip_cfg)
        return XDP_PASS;

    key = 1;
    struct ip_mac_pair *client_cfg = bpf_map_lookup_elem(&config_map, &key);
    if (!client_cfg)
        return XDP_PASS;

    __u32 vip_ip    = vip_cfg->ip;    
    __u32 client_ip = client_cfg->ip;

    __u32 src_ip   = __builtin_bswap32(ip->saddr);
    __u32 dst_ip   = __builtin_bswap32(ip->daddr);
    __u16 src_port = __builtin_bswap16(tcp->source);
    __u16 dst_port = __builtin_bswap16(tcp->dest);

    // client to VIP
    if (src_ip == client_ip && dst_ip == vip_ip) {
        __u32 h   = hash_5tuple(src_ip, dst_ip, src_port, dst_port, ip->protocol);
        __u32 idx = h & 1;

        struct ip_mac_pair *backend = bpf_map_lookup_elem(&targets_map, &idx);
        if (!backend)
            return XDP_PASS;

        __u32 backend_ip = backend->ip;

        // Makes VIP source, baceknd dst
        ip->saddr = __builtin_bswap32(vip_ip);
        ip->daddr = __builtin_bswap32(backend_ip);

        // Ethernet src = VIP MAC, dst = backend MAC
        __builtin_memcpy(eth->h_source, vip_cfg->mac.addr,  ETH_ALEN);
        __builtin_memcpy(eth->h_dest,   backend->mac.addr,  ETH_ALEN);

        // Recompute IP header checksum
        ip->check = 0;
        {
            __u32 csum = bpf_csum_diff(0, 0, (void *)ip, ip_hlen, 0);
            csum = (csum & 0xffff) + (csum >> 16);
            csum = (csum & 0xffff) + (csum >> 16);
            ip->check = ~csum;
        }

        // Recompute TCP checksum
        tcp->check = 0;
        tcp->check = compute_tcp_csum(ip, tcp, data_end);

        return XDP_TX;
    }

    // Reverse path
    if (dst_ip == vip_ip) {
        struct ip_mac_pair *b0, *b1;
        __u32 k0 = 0, k1 = 1;
        int from_backend = 0;

        b0 = bpf_map_lookup_elem(&targets_map, &k0);
        if (b0 && b0->ip == src_ip)
            from_backend = 1;

        b1 = bpf_map_lookup_elem(&targets_map, &k1);
        if (b1 && b1->ip == src_ip)
            from_backend = 1;

        if (!from_backend)
            return XDP_PASS;

        ip->saddr = __builtin_bswap32(vip_ip);
        ip->daddr = __builtin_bswap32(client_ip);

        // Ethernet src = VIP MAC, dst = client MAC
        __builtin_memcpy(eth->h_source, vip_cfg->mac.addr,    ETH_ALEN);
        __builtin_memcpy(eth->h_dest,   client_cfg->mac.addr, ETH_ALEN);

        // Recompute IP header checksum
        ip->check = 0;
        {
            __u32 csum = bpf_csum_diff(0, 0, (void *)ip, ip_hlen, 0);
            csum = (csum & 0xffff) + (csum >> 16);
            csum = (csum & 0xffff) + (csum >> 16);
            ip->check = ~csum;
        }

        tcp->check = 0;
        tcp->check = compute_tcp_csum(ip, tcp, data_end);

        return XDP_TX;
    }

    return XDP_PASS;
}
char LICENSE[] SEC("license") = "GPL";
