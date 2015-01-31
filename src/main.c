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
	u_int16_t current_seq;
#define RECIEVED_PACKAGE_COUNT 32
	bool recieved_packages[RECIEVED_PACKAGE_COUNT];
	u_int8_t recieved_package_type[RECIEVED_PACKAGE_COUNT];
	u_int16_t recieved_package_len[RECIEVED_PACKAGE_COUNT];
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
	const unsigned char *p = (const unsigned char*)&pair->srcip;
	const unsigned char *q = (const unsigned char*)&pair->dstip;
	int r = 0;
	r += print(par1, "%d.%d.%d.%d:%d -> %d.%d.%d.%d:%d",
				p[0], p[1], p[2], p[3], pair->srcport,
				q[0], q[1], q[2], q[3], pair->dstport);
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

		if(n == 0 && !(i >= 5 && 0 == strncmp(line, "SETUP", 5))) {
			break;
		}
		if(i >= 10 && 0 == strncmp(line, "Transport:", 10)) {
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

		if(i >= 10 && 0 == strncmp(line, "Transport:", 10)) {
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

	if(ntohs(tcph->dest) == RTSP_PORT) {
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
	int nal_type;
	struct ip_port_pair *real_pair;
	struct rtp_connect_data *data;
	bool first_seg = true;
	bool last_seg = true;
	u_int16_t rhseq;
	int slice_type = -1;

	if(!(rh->version == 2 && rh->payload_type == RTP_PAYLOAD_H264)) {
		return;
	}

	rhseq = ntohs(rh->seq);

	real_pair = (struct ip_port_pair*)ht_get_key(sending_pairs, pair);
	real_pair->timestamp = timestamp();
	data = (struct rtp_connect_data*)ht_get(sending_pairs, pair);

	if(!data->inited) {
		data->inited = true;
		data->ssrc = rh->ssrc;
		data->starttime = real_pair->timestamp;
		data->packet_count = 0;
		data->packet_lost = -RECIEVED_PACKAGE_COUNT;
		data->i_frame_count = 0;
		data->p_frame_count = 0;
		data->b_frame_count = 0;
		data->total_bytes = 0;
		data->i_frame_bytes = 0;
		data->p_frame_bytes = 0;
		data->b_frame_bytes = 0;
		data->other_bytes = 0;
		data->current_seq = rhseq - 1;
		memset(data->recieved_packages, false, RECIEVED_PACKAGE_COUNT);
		memset(data->recieved_package_type, 0xF, RECIEVED_PACKAGE_COUNT);
		memset(data->recieved_package_len, 0, sizeof(u_int16_t) * RECIEVED_PACKAGE_COUNT);
	}

	if(rhseq > data->current_seq || (rhseq - data->current_seq < 32768 && rhseq - data->current_seq > 0)) {
		int n = rhseq - data->current_seq;
		u_int16_t seq = data->current_seq + 1;
		data->packet_count += n;
		while(n > 0) {
			int pos = seq % RECIEVED_PACKAGE_COUNT;
			int recieved_len = data->recieved_package_len[pos];
			data->total_bytes += recieved_len;
			data->packet_lost += (data->recieved_packages[pos] ? 0 : 1);
			switch(data->recieved_package_type[pos] & 0xF) {
				case SLICE_TYPE_I:
					data->i_frame_bytes += recieved_len;
					if(!(data->recieved_package_type[pos] & 0x10))
						data->i_frame_count++;
					break;
				case SLICE_TYPE_P:
					data->p_frame_bytes += recieved_len;
					if(!(data->recieved_package_type[pos] & 0x10))
						data->p_frame_count++;
					break;
				case SLICE_TYPE_B:
					data->b_frame_bytes += recieved_len;
					if(!(data->recieved_package_type[pos] & 0x10))
						data->b_frame_count++;
					break;
				default:
					data->other_bytes += recieved_len;
					break;
			}
			data->recieved_packages[pos] = 0;
			if(data->recieved_package_type[(seq-1) % RECIEVED_PACKAGE_COUNT] & 0x20) {
				data->recieved_package_type[pos] = 0xF;
			} else {
				data->recieved_package_type[pos] = 0x10 | data->recieved_package_type[(seq-1) % RECIEVED_PACKAGE_COUNT];
			}
			data->recieved_package_len[pos] = 0;
			seq++;
			n--;
		}
		seq--;
		data->recieved_packages[seq % RECIEVED_PACKAGE_COUNT] = 1;
		data->current_seq = rhseq;
	} else if(!data->recieved_packages[rhseq % RECIEVED_PACKAGE_COUNT] &&
			data->current_seq - rhseq < RECIEVED_PACKAGE_COUNT) {
		data->recieved_packages[rhseq % RECIEVED_PACKAGE_COUNT] = 1;
	} else {
		return;
	}

	nh = (struct nalhdr*)(buffer + sizeof(struct rtphdr) + 4*rh->csrc_count);

	payload = (char*)nh + 1;
	nal_type = nh->type;
	last_seg &= rh->mark;
	if(nh->type == NAL_TYPE_FU_A) {
		struct fuhdr *fh = (struct fuhdr*)payload;
		nal_type = fh->type;
		first_seg = fh->s;
		last_seg &= fh->e;
		payload++;
	}

	payload_len = len - (payload - buffer);
	if(payload_len < 0) {
		return;
	}

	if(first_seg) {
		if(nal_type == NAL_TYPE_SLICE) {
			const char *p = payload;
			int offset = 0;
			exp_golomb_decode(&p, &offset);
			slice_type = exp_golomb_decode(&p, &offset) % 5;
		} else if(nal_type == NAL_TYPE_IDR) {
			slice_type = SLICE_TYPE_I;
		}

		data->recieved_package_type[rhseq % RECIEVED_PACKAGE_COUNT] = slice_type;

		u_int16_t seq = rhseq + 1;
		while(seq <= data->current_seq) {
			int pos = seq % RECIEVED_PACKAGE_COUNT;
			if(!(data->recieved_package_type[pos] & 0x10)) {
				break;
			}
			data->recieved_package_type[pos] = 0x10 | slice_type | (data->recieved_package_type[pos] & 0xE0);
			seq++;
		}
	}

	if(nal_type == NAL_TYPE_SLICE || nal_type == NAL_TYPE_IDR) {
		data->recieved_package_len[rhseq % RECIEVED_PACKAGE_COUNT] = payload_len;
	} else {
		data->other_bytes += payload_len;
	}

	if(last_seg) {
		data->recieved_package_type[rhseq % RECIEVED_PACKAGE_COUNT] |= 0x20;
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
	u_int32_t pall = value->packet_count - RECIEVED_PACKAGE_COUNT;

	if(!value->inited) {
		return;
	}

	p = buffer;
	p += sprintf(p, "ID: %08X [", value->ssrc);
	p += dump_ip_port_pair(value->conn, (print_func)sprintf, p);
	p += sprintf(p, "]\n");

	p += sprintf(p, "    During: %s ", ctime(&value->starttime));
	p += sprintf(p, "- %s\n", ctime(&value->conn->timestamp));
	p += sprintf(p, "    Packets: %d/%d ", pall - value->packet_lost, pall);
	p += sprintf(p, "Total Bytes: %" PRIu64 " bytes ", value->total_bytes);
	p += sprintf(p, "Non-Frame Bytes: %" PRIu64 " bytes\n", value->other_bytes);
	p += sprintf(p, "    Frames: I:%d(%" PRIu64 " bytes) ", value->i_frame_count, value->i_frame_bytes);
	p += sprintf(p, "P:%d(%" PRIu64 " bytes) ", value->p_frame_count, value->p_frame_bytes);
	p += sprintf(p, "B:%d(%" PRIu64 " bytes)\n\n", value->b_frame_count, value->b_frame_bytes);

	if(verbose && f != stdout) {
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
				if(verbose) {
					printf("FINISH an rtp connection: [");
					dump_ip_port_pair(pair, (print_func)fprintf, stdout);
					printf("]\n");
				}
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
	u_int16_t proto = ntohs(h->h_proto);
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
