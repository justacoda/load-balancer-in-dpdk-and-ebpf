#include <rte_arp.h>
#include <rte_ethdev.h>
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_tcp.h>
#include <netinet/in.h> 

#include <base.h>
#include <net-config.h>

static const uint32_t client_ip = RTE_IPV4(10, 0, 0, 1);

static int eth_out(struct rte_mbuf *pkt_buf, uint16_t h_proto,
				   struct rte_ether_addr *dst_haddr, uint16_t iplen)
{
	/* fill the ethernet header */
	struct rte_ether_hdr *hdr =
		rte_pktmbuf_mtod(pkt_buf, struct rte_ether_hdr *);

	hdr->dst_addr = *dst_haddr;
	memcpy(&hdr->src_addr, local_mac, 6);
	hdr->ether_type = rte_cpu_to_be_16(h_proto);

	/* Print the packet */
	// pkt_dump(pkt_buf);

	/* enqueue the packet */
	pkt_buf->data_len = iplen + sizeof(struct rte_ether_hdr);
	pkt_buf->pkt_len = pkt_buf->data_len;
	dpdk_out(pkt_buf);

	return 0;
}

static void arp_reply(struct rte_mbuf *pkt, struct rte_arp_hdr *arph)
{
	arph->arp_opcode = rte_cpu_to_be_16(RTE_ARP_OP_REPLY);

	/* fill arp body */
	arph->arp_data.arp_tip = arph->arp_data.arp_sip;
	arph->arp_data.arp_sip = rte_cpu_to_be_32(local_ip);

	arph->arp_data.arp_tha = arph->arp_data.arp_sha;
	memcpy(&arph->arp_data.arp_sha, local_mac, 6);

	eth_out(pkt, RTE_ETHER_TYPE_ARP, &arph->arp_data.arp_tha,
			sizeof(struct rte_arp_hdr));
}

static void arp_in(struct rte_mbuf *pkt)
{
	struct rte_arp_hdr *arph = rte_pktmbuf_mtod_offset(
		pkt, struct rte_arp_hdr *, sizeof(struct rte_ether_hdr));

	/* process only arp for this address */
	if (rte_be_to_cpu_32(arph->arp_data.arp_tip) != local_ip)
		goto OUT;

	switch (rte_be_to_cpu_16(arph->arp_opcode)) {
	case RTE_ARP_OP_REQUEST:
		arp_reply(pkt, arph);
		break;
	default:
		fprintf(stderr, "apr: Received unknown ARP op");
		goto OUT;
	}

	return;

OUT:
	rte_pktmbuf_free(pkt);
	return;
}

static struct rte_ether_addr *get_mac_for_ip(uint32_t ip)
{
	return &mac_addresses[(ip & 0xf) - 1];
}

static uint32_t get_target_ip(uint32_t src_ip, uint16_t src_port,
                              uint16_t dst_port)
{
    uint32_t h = src_ip;

    // pack ports into 32 bits and mix them in
    uint32_t ports = ((uint32_t)src_port << 16) | dst_port;
    h ^= ports;

    h ^= h >> 16;
    h *= 0x7feb352d;
    h ^= h >> 15;
    h *= 0x846ca68b;
    h ^= h >> 16;

    uint32_t idx = h % target_count;
    return targets[idx];
}

static void lb_in(struct rte_mbuf *pkt_buf)
{
    struct rte_ipv4_hdr *iph = rte_pktmbuf_mtod_offset(
        pkt_buf, struct rte_ipv4_hdr *, sizeof(struct rte_ether_hdr));

    // Only handle TCP
    if (iph->next_proto_id != IPPROTO_TCP) {
        rte_pktmbuf_free(pkt_buf);
        return;
    }

    struct rte_tcp_hdr *tcph = (struct rte_tcp_hdr *)(
        (unsigned char *)iph + sizeof(struct rte_ipv4_hdr));

    // Convert IPs and ports from network to host order
    uint32_t src_ip  = rte_be_to_cpu_32(iph->src_addr);
    uint32_t dst_ip  = rte_be_to_cpu_32(iph->dst_addr);
    uint16_t src_port = rte_be_to_cpu_16(tcph->src_port);
    uint16_t dst_port = rte_be_to_cpu_16(tcph->dst_port);

    // client (10.0.0.1) to VIP (10.0.0.10)
    if (src_ip == client_ip && dst_ip == local_ip) {
        // choose backend based on 5-tuple */
        uint32_t target_ip = get_target_ip(src_ip, src_port, dst_port);

        // Pretend VIP is the client
        iph->src_addr = rte_cpu_to_be_32(local_ip);   // source = VIP (10.0.0.10)
        iph->dst_addr = rte_cpu_to_be_32(target_ip);  // dest   = 10.0.0.2 or 10.0.0.3

        iph->hdr_checksum = 0;
        tcph->cksum = 0;
        iph->hdr_checksum = rte_ipv4_cksum(iph);
        tcph->cksum = rte_ipv4_udptcp_cksum(iph, tcph);

        // send to backend MAC
        struct rte_ether_addr *dst_mac = get_mac_for_ip(target_ip);
        uint16_t iplen = rte_be_to_cpu_16(iph->total_length);

        eth_out(pkt_buf, RTE_ETHER_TYPE_IPV4, dst_mac, iplen);
        return;
    }

    // reverse
    for (uint32_t i = 0; i < target_count; i++) {
        if (src_ip == targets[i] && dst_ip == local_ip) {

            iph->src_addr = rte_cpu_to_be_32(local_ip);   // source = VIP (10.0.0.10)
            iph->dst_addr = rte_cpu_to_be_32(client_ip);  // dest   = client (10.0.0.1)

            iph->hdr_checksum = 0;
            tcph->cksum = 0;
            iph->hdr_checksum = rte_ipv4_cksum(iph);
            tcph->cksum = rte_ipv4_udptcp_cksum(iph, tcph);

            // send to client MAC (10.0.0.1)
            struct rte_ether_addr *dst_mac = get_mac_for_ip(client_ip);
            uint16_t iplen = rte_be_to_cpu_16(iph->total_length);

            eth_out(pkt_buf, RTE_ETHER_TYPE_IPV4, dst_mac, iplen);
            return;
        }
    }

    rte_pktmbuf_free(pkt_buf);
}

void eth_in(struct rte_mbuf *pkt_buf)
{
	unsigned char *payload = rte_pktmbuf_mtod(pkt_buf, unsigned char *);
	struct rte_ether_hdr *hdr = (struct rte_ether_hdr *)payload;

	if (hdr->ether_type == rte_cpu_to_be_16(RTE_ETHER_TYPE_ARP)) {
		arp_in(pkt_buf);
	} else if (hdr->ether_type == rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4)) {
		lb_in(pkt_buf);
	} else {
		// printf("Unknown ether type: %" PRIu16 "\n",
		//	   rte_be_to_cpu_16(hdr->ether_type));
		rte_pktmbuf_free(pkt_buf);
	}
}
