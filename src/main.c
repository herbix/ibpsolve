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
#include <inttypes.h>

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
	time_t timestamp;
};

struct rtp_connect_data {
	struct ip_port_pair *conn;
	time_t starttime;
	u_int32_t ssrc;
	u_int32_t packet_count;
	u_int32_t packet_lost;
	u_int32_t i_frame_count;
	u_int32_t p_frame_count;
	u_int32_t b_frame_count;
	u_int64_t total_bytes;
	u_int64_t i_frame_bytes;
	u_int64_t p_frame_bytes;
	u_int64_t b_frame_bytes;
	u_int64_t other_bytes;
	short current_frame_type;
	u_int16_t current_seq;
#define RECIEVED_PACKAGE_COUNT 32
	bool recieved_packages[RECIEVED_PACKAGE_COUNT];
	bool inited;
};

static bool verbose = false;

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

typedef int (*print_func)(void*, char*, ...);

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

static time_t timestamp() {
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

static int dump_ip_port_pair(const struct ip_port_pair *pair, print_func print, void *par1)
{
	const char *p = (const char*)&pair->srcport;
	int r = 0;
	r += print(par1, "%d.%d.%d.%d:%d -> ", p[0], p[1], p[2], p[3], pair->srcport);
	p = (const char*)&pair->dstport;
	r += print(par1, "%d.%d.%d.%d:%d", p[0], p[1], p[2], p[3], pair->dstport);
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

				if(verbose) {
					printf("RTSP SETUP [");
					dump_ip_port_pair(pair, (print_func)fprintf, stdout);
					printf("] client_port=%lu\n", dport);
				}

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
				struct rtp_connect_data *data = (struct rtp_connect_data*)malloc(sizeof(struct rtp_connect_data));
				pair->srcip = iph->saddr;
				pair->dstip = iph->daddr;
				pair->srcport = sport;
				pair->dstport = dport;
				pair->timestamp = timestamp();

				if(verbose) {
					printf("RTSP SETUP REPLY [");
					dump_ip_port_pair(&spair, (print_func)fprintf, stdout);
					printf("] client_port=%lu, server_port=%lu\n", dport, sport);
					printf("RTP connection[");
					dump_ip_port_pair(pair, (print_func)fprintf, stdout);
					printf("]\n");
				}

				data->inited = false;
				data->conn = pair;
				if(ht_put(sending_pairs, pair, data)) {
					free(pair);
					free(data);
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
	struct nalhdr *nh;
	const char *payload;
	int payload_len;
	int type;
	struct ip_port_pair *real_pair;
	struct rtp_connect_data *data;
	bool first_seg = true;
	bool last_seg = true;

	if(!(rh->version == 2 && rh->payload_type == RTP_PAYLOAD_H264)) {
		return;
	}

	real_pair = (struct ip_port_pair*)ht_get_key(sending_pairs, pair);
	real_pair->timestamp = timestamp();
	data = (struct rtp_connect_data*)ht_get(sending_pairs, pair);

	if(!data->inited) {
		data->inited = true;
		data->ssrc = rh->ssrc;
		data->starttime = real_pair->timestamp;
		data->packet_count = 0;
		data->packet_lost = 0;
		data->i_frame_count = 0;
		data->p_frame_count = 0;
		data->b_frame_count = 0;
		data->total_bytes = 0;
		data->i_frame_bytes = 0;
		data->p_frame_bytes = 0;
		data->b_frame_bytes = 0;
		data->other_bytes = 0;
		data->current_frame_type = -1;
		data->current_seq = rh->seq - 1;
		memset(data->recieved_packages, true, RECIEVED_PACKAGE_COUNT);
	}

	if(rh->seq > data->current_seq || rh->seq - data->current_seq < 32768) {
		int n = rh->seq - data->current_seq;
		int seq = data->current_seq + 1;
		data->packet_count += n;
		while(n > 0) {
			data->packet_lost += (data->recieved_packages[seq % RECIEVED_PACKAGE_COUNT] ? 0 : 1);
			data->recieved_packages[seq % RECIEVED_PACKAGE_COUNT] = 0;
			seq++;
			n--;
		}
		seq--;
		data->recieved_packages[seq % RECIEVED_PACKAGE_COUNT] = 1;
		data->current_seq = rh->seq;
	} else {
		if(data->current_seq - rh->seq < RECIEVED_PACKAGE_COUNT) {
			data->recieved_packages[rh->seq % RECIEVED_PACKAGE_COUNT] = 1;
		}
	}

	nh = (struct nalhdr*)(buffer + sizeof(struct rtphdr) + 4*rh->csrc_count);

	payload = (char*)nh + 1;
	type = nh->type;
	last_seg &= rh->mark;
	if(nh->type == NAL_TYPE_FU_A) {
		struct fuhdr *fh = (struct fuhdr*)payload;
		type = fh->type;
		first_seg = fh->s;
		last_seg &= fh->e;
		payload++;
	}

	payload_len = len - (payload - buffer);
	if(payload_len < 0) {
		return;
	}

	data->total_bytes += payload_len;

	if(type == NAL_TYPE_SLICE) {
		if(first_seg) {
			const char *p = payload;
			int offset = 0;
			int slice_type;
			exp_golomb_decode(&p, &offset);
			slice_type = exp_golomb_decode(&p, &offset) % 5;
			data->current_frame_type = slice_type;
			switch(slice_type) {
				case SLICE_TYPE_I:
					data->i_frame_count++;
					break;
				case SLICE_TYPE_P:
					data->p_frame_count++;
					break;
				case SLICE_TYPE_B:
					data->b_frame_count++;
					break;
			}
		}

		switch(data->current_frame_type) {
			case SLICE_TYPE_I:
				data->i_frame_bytes += payload_len;
				break;
			case SLICE_TYPE_P:
				data->p_frame_bytes += payload_len;
				break;
			case SLICE_TYPE_B:
				data->b_frame_bytes += payload_len;
				break;
			default:
				data->other_bytes += payload_len;
		}

		if(last_seg) {
			data->current_frame_type = -1;
		}
	} else {
		data->other_bytes += payload_len;
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

static void output_data(FILE *f, struct rtp_connect_data *value)
{
	static char buffer[1024];
	char *p;
	int i;

	if(!value->inited) {
		return;
	}

	for(i=0; i<RECIEVED_PACKAGE_COUNT; i++) {
		if(!value->recieved_packages[i]) {
			value->packet_lost++;
			value->recieved_packages[i] = true;
		}
	}

	p = buffer;
	p += sprintf(p, "ID: %08X [", value->ssrc);
	p += dump_ip_port_pair(value->conn, (print_func)sprintf, p);
	p += sprintf(p, "]\n");

	p += sprintf(p, "\tDuring: %s ", ctime(&value->starttime));
	p += sprintf(p, "- %s\n", ctime(&value->conn->timestamp));
	p += sprintf(p, "\tPackets: %d/%d ", value->packet_count - value->packet_lost, value->packet_count);
	p += sprintf(p, "Total Bytes: %" PRIu64 " bytes ", value->total_bytes);
	p += sprintf(p, "Non-Frame Bytes: %" PRIu64 "bytes\n", value->other_bytes);
	p += sprintf(p, "\tFrames: I:%d(%" PRIu64 " bytes) ", value->i_frame_count, value->i_frame_bytes);
	p += sprintf(p, "P:%d(%" PRIu64 " bytes) ", value->p_frame_count, value->p_frame_bytes);
	p += sprintf(p, "B:%d(%" PRIu64 " bytes)\n\n", value->b_frame_count, value->b_frame_bytes);

	if(verbose && f != stdout) {
		printf("FINISH an rtp connection: \n");
		fwrite(buffer, 1, p-buffer, stdout);
	}
	fwrite(buffer, 1, p-buffer, f);
}

static enum ht_traverse_action clean_iterator(void *key, void *value, void *dataptr)
{
	struct {time_t current; struct hashtable *ht;} *data = dataptr;
	struct ip_port_pair *pair = (struct ip_port_pair*)key;
	if(data->current - pair->timestamp > 60) {
		if(data->ht == sending_pairs) {
			FILE *f;
			f = fopen("history.txt", "a");
			if(f == NULL) {
				perror("fopen");
			} else {
				output_data(f, (struct rtp_connect_data*)value);
				fclose(f);
			}
			free(value);
		}
		free(key);
		return REMOVE_ITEM;
	}
	return NO_ACTION;
}

static void clean_hashtables(time_t current)
{
	struct {time_t current; struct hashtable *ht;} data;

	data.current = current;
	data.ht = preparing_pairs;
	ht_traverse(preparing_pairs, clean_iterator, &data);

	data.ht = sending_pairs;
	ht_traverse(sending_pairs, clean_iterator, &data);
}

static enum ht_traverse_action save_iterator(void *key, void *value, void *dataptr)
{
	output_data((FILE*)dataptr, (struct rtp_connect_data*)value);
	return NO_ACTION;
}

static void save_current_data()
{
	FILE *f = fopen("current.txt", "w");
	if(f == NULL) {
		perror("fopen");
		return;
	}
	ht_traverse(sending_pairs, save_iterator, f);
	fclose(f);
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

	static time_t last_clean_time = 0;
	static int counter = 0;
	counter++;
	if(counter == 1000) {
		time_t current = timestamp();
		if(current - last_clean_time > 60) {
			clean_hashtables(current);
			save_current_data();
			last_clean_time = current;
		}
		counter = 0;
	}
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
	static char buffer[BUFFER_SIZE];
	int s;
	int opt;

	while(-1 != (opt = getopt(argc, argv, "v"))) {
		switch(opt) {
			case 'v':
				verbose = true;
				break;
			case '?':
				printf("Usage: %s [-v]\n", argv[0]);
				return -1;
		}
	}

	s = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));

	if(-1 == s) {
		perror("socket");
		exit(-1);
	}

	set_promisc(s);

	preparing_pairs = ht_init(128, ip_port_pair_hashcode, ip_port_pair_equal);
	sending_pairs = ht_init(128, ip_port_pair_hashcode, ip_port_pair_equal);

	while(true) {
		int len = read(s, buffer, BUFFER_SIZE);
		ASSERT(len < BUFFER_SIZE);

		parse_ether_frame(buffer, len);
	}

	close(s);

	return 0;
}
