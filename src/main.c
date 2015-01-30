#include <unistd.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ether.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>

#include "def.h"
#include "hashtable.h"
#include "rtp.h"
#include "h264.h"

#define BUFFER_SIZE 4096
#define RTSP_PORT	554

struct ip_port_pair {
	u_int32_t srcip;
	u_int32_t dstip;
	u_int16_t srcport;
	u_int16_t dstport;
	unsigned timestamp;
};

static unsigned ip_port_pair_hashcode(const void *k)
{
	struct ip_port_pair *p = (struct ip_port_pair*)k;
	return p->dstip ^ p->srcip ^ p->dstport ^ (p->srcport << 16);
}

static bool ip_port_pair_equal(const void *a, const void *b)
{
	return memcmp(a, b, 12) == 0;
}

struct hashtable *preparing_pairs;
struct hashtable *sending_pairs;

static void set_promisc(int sock_raw_fd)
{
	char *eth_name = "eth0";
	struct ifreq ethreq;
	strncpy(ethreq.ifr_name, eth_name, IFNAMSIZ);
	if(-1 == ioctl(sock_raw_fd, SIOCGIFFLAGS, &ethreq)) {
		perror("ioctl");
		close(sock_raw_fd);
		exit(-1);
	}

	ethreq.ifr_flags |= IFF_PROMISC;
	if(-1 == ioctl(sock_raw_fd, SIOCSIFFLAGS, &ethreq)) {
		perror("ioctl");
		close(sock_raw_fd);
		exit(-1);
	}
}

static int indexof(const char *str, int len1, const char *substr, int len2)
{
	int i;
	for(i=0; i<=len1-len2; i++) {
		if(strncmp(str+i, substr, len2) == 0) {
			return i;
		}
	}
	return -1;
}

static unsigned timestamp() {
	return time(NULL);
}

static unsigned exp_golomb_decode(const char **buffer, int *offset)
{
	const unsigned char *b = (const unsigned char*)*buffer;
	int off = *offset;
	unsigned r = 0;
	int zero_count = 0;

	while(!((*b >> (7-off)) & 1)) {
		zero_count++;
		off++;
		if(off >= 8) {
			off -= 8;
			b++;
		}
	}

	zero_count++;
	while(zero_count > 0) {
		r <<= 1;
		r |= (*b >> (7-off)) & 1;
		off++;
		if(off >= 8) {
			off -= 8;
			b++;
		}
		zero_count--;
	}

	r--;

	*buffer = (const char*)b;
	*offset = off;
	return r;
}

static void parse_rtsp_request(const struct iphdr *iph, const struct tcphdr *tcph, const char *buffer, int len)
{
	const char *line = buffer;
	int i;
	int n = 0;

	while(len > 0) {
		i = 0;
		while((line[i] != '\r' || line[i+1] != '\n') && len > 1) {
			i++;
			len--;
		}

		if(!(n == 0 && i>=5 && strncmp(line, "SETUP", 5))) {
			break;
		}
		if(i>=10 && strncmp(line, "Transport:", 10)) {
			int index = indexof(line, i, "client_port=", 12);
			if(index > 0) {
				unsigned long dport = atoi(line+index+12);
				struct ip_port_pair *pair = (struct ip_port_pair*)malloc(sizeof(struct ip_port_pair));
				pair->srcip = iph->saddr;
				pair->dstip = iph->daddr;
				pair->srcport = ntohs(tcph->source);
				pair->dstport = ntohs(tcph->dest);
				pair->timestamp = timestamp();
				if(ht_put(preparing_pairs, pair, (void*)dport)) {
					free(pair);
				}
			}
		}

		line += i+2;
		len -= 2;
		n++;
	}
}

static void parse_rtsp_response(const struct iphdr *iph, const struct tcphdr *tcph, const char *buffer, int len)
{
	const char *line = buffer;
	int i;
	struct ip_port_pair spair, *ppair;
	unsigned long dport;

	spair.dstip = iph->saddr;
	spair.srcip = iph->daddr;
	spair.dstport = ntohs(tcph->source);
	spair.srcport = ntohs(tcph->dest);

	if(!ht_contains(preparing_pairs, &spair)) {
		return;
	}

	dport = (unsigned long)ht_get(preparing_pairs, &spair);
	ppair = (struct ip_port_pair*)ht_get_key(preparing_pairs, &spair);

	ht_remove(preparing_pairs, ppair);
	free(ppair);

	while(len > 0) {
		i = 0;
		while((line[i] != '\r' || line[i+1] != '\n') && len > 1) {
			i++;
			len--;
		}

		if(i>=10 && strncmp(line, "Transport:", 10)) {
			int index = indexof(line, i, "server_port=", 12);
			if(index > 0) {
				unsigned long sport = atoi(line+index+12);
				struct ip_port_pair *pair = (struct ip_port_pair*)malloc(sizeof(struct ip_port_pair));
				pair->srcip = iph->saddr;
				pair->dstip = iph->daddr;
				pair->srcport = sport;
				pair->dstport = dport;
				pair->timestamp = timestamp();
				if(ht_put(sending_pairs, pair, pair)) {
					free(pair);
				}
			}
		}

		line += i+2;
		len -= 2;
	}
}

static void parse_rtsp_message(const struct iphdr *iph, const struct tcphdr *tcph, const char *buffer, int len)
{
	if(len <= 5) {
		return;
	}

	if(tcph->dest == RTSP_PORT) {
		parse_rtsp_request(iph, tcph, buffer, len);
	} else {
		parse_rtsp_response(iph, tcph, buffer, len);
	}
}

static void parse_tcp_segment(const struct iphdr *iph, const char *buffer, int len)
{
	struct tcphdr *h = (struct tcphdr*)buffer;

	if(ntohs(h->dest) == RTSP_PORT || ntohs(h->source) == RTSP_PORT) {
		parse_rtsp_message(iph, h, buffer+4*h->doff, len-4*h->doff);
	}
}

static void parse_rtp_message(const struct ip_port_pair *pair,
							const struct iphdr *iph, const struct udphdr *tcph,
							const char *buffer, int len)
{
	struct rtphdr *rh = (struct rtphdr*)buffer;
	struct nalhdr *nh = (struct nalhdr*)(buffer + sizeof(struct rtphdr) + 4*rh->csrc_count);
	const char *payload;
	int type;
	struct ip_port_pair *real_pair;

	if(!(rh->version == 2 && rh->payload_type == RTP_PAYLOAD_H264)) {
		return;
	}

	real_pair = (struct ip_port_pair*)ht_get_key(sending_pairs, pair);
	real_pair->timestamp = timestamp();

	payload = (char*)nh + 1;
	type = nh->type;
	if(nh->type == NAL_TYPE_FU_A) {
		struct fuhdr *fh = (struct fuhdr*)payload;
		if(!fh->s) {
			return;
		}
		type = fh->type;
		payload++;
	}

	if(type == NAL_TYPE_SLICE) {
		const char *p = payload;
		int offset = 0;
		int slice_type;
		exp_golomb_decode(&p, &offset);
		slice_type = exp_golomb_decode(&p, &offset) % 5;
		printf("Slice Type: %s\n", slice_type == SLICE_TYPE_P ? "P" :
				(slice_type == SLICE_TYPE_I ? "I" :
				(slice_type == SLICE_TYPE_B ? "B" : "OTHER")));
	}
}

static void parse_udp_segment(const struct iphdr *iph, const char *buffer, int len)
{
	struct udphdr *h = (struct udphdr*)buffer;
	struct ip_port_pair pair;

	pair.srcip = iph->saddr;
	pair.dstip = iph->daddr;
	pair.srcport = ntohs(h->source);
	pair.dstport = ntohs(h->dest);

	if(ht_contains(sending_pairs, &pair)) {
		parse_rtp_message(&pair, iph, h, buffer+sizeof(struct udphdr), len-sizeof(struct udphdr));
	}
}

static enum ht_traverse_action clean_iterator(void *key, void *value, void *data)
{
	int current = *(int*)data;
	struct ip_port_pair *pair = (struct ip_port_pair*)key;
	if(current - pair->timestamp > 60) {
		return REMOVE_ITEM;
	}
	return NO_ACTION;
}

static void clean_hashtables()
{
	static int last_clean_time = 0;
	static int counter = 0;
	counter++;
	if(counter == 1000) {
		int current = timestamp();
		if(current - last_clean_time > 60) {
			last_clean_time = current;
			ht_traverse(preparing_pairs, clean_iterator, &current);
			ht_traverse(sending_pairs, clean_iterator, &current);
		}
		counter = 0;
	}
}

static void parse_ip_datagram(const char *buffer, int len)
{
	struct iphdr *h = (struct iphdr*)buffer;
	int hl = h->ihl * 4;

	switch(h->protocol) {
		case IPPROTO_TCP:
			parse_tcp_segment(h, buffer+hl, len-hl);
			break;
		case IPPROTO_UDP:
			parse_udp_segment(h, buffer+hl, len-hl);
			break;
		default:
			break;
	}

	clean_hashtables();
}

static void parse_ether_frame(const char *buffer, int len)
{
	struct ethhdr *h = (struct ethhdr*)buffer;
	short proto = ntohs(h->h_proto);
	switch(proto) {
		case ETH_P_IP:
			parse_ip_datagram(buffer + sizeof(struct ethhdr), len - sizeof(struct ethhdr));
			break;
		default:
			break;
	}
}

int main(int argc, char **argv)
{
	int s = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	char *buffer = (char*)malloc(BUFFER_SIZE);
	int len;

	if(-1 == s) {
		perror("socket");
		exit(-1);
	}

	set_promisc(s);

	preparing_pairs = ht_init(128, ip_port_pair_hashcode, ip_port_pair_equal);
	sending_pairs = ht_init(128, ip_port_pair_hashcode, ip_port_pair_equal);

	while(true) {
		len = read(s, buffer, BUFFER_SIZE);
		ASSERT(len < BUFFER_SIZE);

		parse_ether_frame(buffer, len);
	}

	close(s);
	free(buffer);

	return 0;
}
