/* SPDX-License-Identifier: GPL-2.0 */
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/in.h>
#include <linux/udp.h>
#include <string.h>

// The parsing helper functions from the packet01 lesson have moved here
#include "../common/parsing_helpers.h"

/* Defines xdp_stats_map */
#include "../common/xdp_stats_kern_user.h"
#include "../common/xdp_stats_kern.h"

SEC("xdp_pass")
int xdp_pass_func(struct xdp_md *ctx) {
	return XDP_PASS;
}

SEC("xdp_tx")
int xdp_tx_func(struct xdp_md *ctx) {
	return XDP_TX;
}

SEC("xdp_drop")
int xdp_drop_func(struct xdp_md *ctx) {
	return XDP_DROP;
}

int i = 0;
SEC("xdp_ipv4_filter")
int xdp_ipv4_filter_func(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	
	__u32 action = XDP_PASS; /* Default action */

	struct hdr_cursor nh;
	int eth_type;
	nh.pos = data;

	struct ethhdr *eth;

	eth_type = parse_ethhdr(&nh, data_end, &eth);

	if (eth_type == bpf_htons(ETH_P_IP)) {
		action = XDP_TX;
	}

	return action;  
}

SEC("xdp_ipv6_filter")
int xdp_ipv6_filter_func(struct xdp_md *ctx)
{
        void *data_end = (void *)(long)ctx->data_end;
        void *data = (void *)(long)ctx->data;

        __u32 action = XDP_PASS; /* Default action */

        struct hdr_cursor nh;
        int eth_type;
        nh.pos = data;

        struct ethhdr *eth;

        eth_type = parse_ethhdr(&nh, data_end, &eth);

        if (eth_type == bpf_htons(ETH_P_IPV6)) {
                action = XDP_TX;
        }

        return action;  
}


SEC("xdp_port_filter")
int  xdp_parser_func(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;

	__u32 action = XDP_PASS; /* Default action */

	/* These keep track of the next header type and iterator pointer */
	struct hdr_cursor nh;
	int nh_type;
	nh.pos = data;

	struct ethhdr *eth;
	struct udphdr *udphdr;

	nh_type = parse_ethhdr(&nh, data_end, &eth);

	if (nh_type == bpf_htons(ETH_P_IPV6)) {
		struct ipv6hdr *ip6h;

		nh_type = parse_ip6hdr(&nh, data_end, &ip6h);
		if (nh_type != IPPROTO_UDP)
			goto out;

	} else if (nh_type == bpf_htons(ETH_P_IP)) {
		struct iphdr *iph;

		nh_type = parse_iphdr(&nh, data_end, &iph);
		if (nh_type != IPPROTO_UDP)
			goto out;
	}

	nh_type = parse_udphdr(&nh, data_end, &udphdr);
	if (udphdr + 1 > data_end)
		return -1;
	if (bpf_ntohs(udphdr->dest) == 319) /* Port to be rejected. */
		action = XDP_TX;



 out:
	return action;
}

SEC("xdp_redirect")
int xdp_redirect_func(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct hdr_cursor nh;
	struct ethhdr *eth;
	int eth_type;
	int action = XDP_PASS;
	unsigned char dst[ETH_ALEN] = {(unsigned char) 0x001b2194deb5}; 
	unsigned ifindex = 13;

	nh.pos = data;

	/* Parse Ethernet and IP/IPv6 headers */
	eth_type = parse_ethhdr(&nh, data_end, &eth);
	if (eth_type == -1)
		goto out;

	/* Set a proper destination address */
	memcpy(eth->h_dest, dst, ETH_ALEN);
	action = bpf_redirect(ifindex, 0);

out:
	return action;
}

char _license[] SEC("license") = "GPL";
