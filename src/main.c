#include <unistd.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ether.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

#include <pcap.h>

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
#define RTSP_PORT	rtsp_port

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
#define RECIEVED_MESSAGE_COUNT	32
	bool recieved_messages[RECIEVED_MESSAGE_COUNT];
#define TYPE_SLICE_MASK			0xF
#define TYPE_SLICE_UNKNOWN		0xF
#define TYPE_FLAG_INHERT		0x10
#define TYPE_FLAG_END			0x20
	// recieved_message_type element format:
	// 8 7 6 5 4 3 2 1 0
	// +---+-+-+-------+
	// |   |E|I|   T   |
	// +---+-+-+-------+
	// T: Slice type (P=0, B=1, I=2, UNKNOWN=3~15)
	// I: The slice type of this message inherted from previous message
	// E: This message is the end of a slice
	u_int8_t recieved_message_type[RECIEVED_MESSAGE_COUNT];
	u_int16_t recieved_message_len[RECIEVED_MESSAGE_COUNT];
	bool inited;
};

static bool verbose = false;
static u_int16_t rtsp_port = 554;

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

		// According to RFC of RTSP, I know SETUP command contains
		// ports used by RTP. Here is the request:
		// SETUP rtsp://ip/uri RTSP/1.0
		// CSeq: 3
		// Transport: RTP/AVP;some params;client_port=32423;other params
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

		// According to RFC of RTSP, I know SETUP command contains
		// ports used by RTP. Here is the response:
		// RTSP/1.0 200 OK
		// CSeq: 3
		// Transport: RTP/AVP;some params;client_port=32423;server_port=34543;other params
		// Session: 12345678
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

static void add_up_data_at_pos(struct rtp_connect_data *data, int pos)
{
	int recieved_len = data->recieved_message_len[pos];
	data->total_bytes += recieved_len;
	data->packet_lost += (data->recieved_messages[pos] ? 0 : 1);
	switch(data->recieved_message_type[pos] & TYPE_SLICE_MASK) {
		case SLICE_TYPE_I:
			data->i_frame_bytes += recieved_len;
			if(!(data->recieved_message_type[pos] & TYPE_FLAG_INHERT))
				data->i_frame_count++;
			break;
		case SLICE_TYPE_P:
			data->p_frame_bytes += recieved_len;
			if(!(data->recieved_message_type[pos] & TYPE_FLAG_INHERT))
				data->p_frame_count++;
			break;
		case SLICE_TYPE_B:
			data->b_frame_bytes += recieved_len;
			if(!(data->recieved_message_type[pos] & TYPE_FLAG_INHERT))
				data->b_frame_count++;
			break;
		default:
			data->other_bytes += recieved_len;
			break;
	}
}

static void init_rtp_data(struct rtp_connect_data *data, u_int32_t ssrc, time_t timestamp)
{
	data->inited = true;
	data->ssrc = ssrc;
	data->starttime = timestamp;
	data->packet_count = 0;
	data->packet_lost = -RECIEVED_MESSAGE_COUNT;
	data->i_frame_count = 0;
	data->p_frame_count = 0;
	data->b_frame_count = 0;
	data->total_bytes = 0;
	data->i_frame_bytes = 0;
	data->p_frame_bytes = 0;
	data->b_frame_bytes = 0;
	data->other_bytes = 0;
	data->current_seq = 0;
	memset(data->recieved_messages, false, RECIEVED_MESSAGE_COUNT);
	memset(data->recieved_message_type, TYPE_SLICE_UNKNOWN, RECIEVED_MESSAGE_COUNT);
	memset(data->recieved_message_len, 0, sizeof(u_int16_t) * RECIEVED_MESSAGE_COUNT);
}

static void parse_rtp_message(const struct ip_port_pair *pair,
							const struct iphdr *iph, const struct udphdr *udph,
							const char *buffer, int len)
{
	struct rtphdr *rh = (struct rtphdr*)buffer;

	if(!(rh->version == 2 && rh->payload_type == RTP_PAYLOAD_H264)) {
		return;
	}

	struct ip_port_pair *real_pair = (struct ip_port_pair*)ht_get_key(sending_pairs, pair);
	struct rtp_connect_data *data = (struct rtp_connect_data*)ht_get(sending_pairs, pair);
	u_int16_t rhseq = ntohs(rh->seq);

	real_pair->timestamp = timestamp();

	if(!data->inited) {
		init_rtp_data(data, rh->ssrc, real_pair->timestamp);
		data->current_seq = rhseq - 1;
	}

	// Here are 3 cases of message recieving:
	// 1. New message has larger seq no. than current maxium seq no.:
	// +---------+---------+---------+---------+
	// |    1    |    2    |    _    |    4    |
	// +---------+---------+---------+---------+
	// | Recieved| Recieved| Not Rcv |   New   |
	// +---------+---------+---------+---------+
	// 2. New message has less seq no. than current maxium seq no,
	//    but no message with same seq no. recieved yet.
	// +---------+---------+---------+---------+
	// |    1    |    _    |    3    |    4    |
	// +---------+---------+---------+---------+
	// | Recieved| Not Rcv |   New   | Recieved|
	// +---------+---------+---------+---------+
	// 3. It's a duplicate message or very old message (with much less
	// seq no. than current maxium seq no.).
	if((u_int16_t)(rhseq - data->current_seq) < 32768 && rhseq != data->current_seq) {
		int n = (u_int16_t)(rhseq - data->current_seq);
		u_int16_t seq = data->current_seq + 1;
		data->packet_count += n;

		// Replace old message cached, and add up its data before.
		while(n > 0) {
			int pos = seq % RECIEVED_MESSAGE_COUNT;
			add_up_data_at_pos(data, pos);

			// If E flag of last message type is set, this message type
			// should be UNKNOWN without EI flags. Otherwise this message
			// copies last message type and sets I flag.
			if(data->recieved_message_type[(u_int16_t)(seq-1) % RECIEVED_MESSAGE_COUNT] & TYPE_FLAG_END) {
				data->recieved_message_type[pos] = TYPE_SLICE_UNKNOWN;
			} else {
				data->recieved_message_type[pos] = TYPE_FLAG_INHERT |
					data->recieved_message_type[(u_int16_t)(seq-1) % RECIEVED_MESSAGE_COUNT];
			}
			data->recieved_messages[pos] = 0;
			data->recieved_message_len[pos] = 0;
			seq++;
			n--;
		}

		seq--;
		data->recieved_messages[seq % RECIEVED_MESSAGE_COUNT] = 1;
		data->current_seq = rhseq;
	} else if(!data->recieved_messages[rhseq % RECIEVED_MESSAGE_COUNT] &&
			(u_int16_t)(data->current_seq - rhseq) < RECIEVED_MESSAGE_COUNT) {
		data->recieved_messages[rhseq % RECIEVED_MESSAGE_COUNT] = 1;
	} else {
		return;
	}

	struct nalhdr *nh = (struct nalhdr*)(buffer + sizeof(struct rtphdr) + 4*rh->csrc_count);
	const char *payload = (char*)nh + 1;
	int payload_len;
	int nal_type = nh->type;
	bool first_seg = true;
	bool last_seg = true;
	int slice_type = -1;

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

		data->recieved_message_type[rhseq % RECIEVED_MESSAGE_COUNT] = slice_type;

		u_int16_t seq = rhseq + 1;

		// Set type of messages after this message until reaching
		// a message type with I flag cleared. E flag will be kept.
		while(seq <= data->current_seq) {
			int pos = seq % RECIEVED_MESSAGE_COUNT;
			if(!(data->recieved_message_type[pos] & TYPE_FLAG_INHERT)) {
				break;
			}
			data->recieved_message_type[pos] = TYPE_FLAG_INHERT |
				slice_type | (data->recieved_message_type[pos] & 0xE0);
			seq++;
		}
	}

	// If this message doesn't contain a frame message, I count it
	// immediately instead of caching it.
	if(nal_type == NAL_TYPE_SLICE || nal_type == NAL_TYPE_IDR) {
		data->recieved_message_len[rhseq % RECIEVED_MESSAGE_COUNT] = payload_len;
	} else {
		data->other_bytes += payload_len;
		data->total_bytes += payload_len;
	}

	// Set E flag when this message is the last segment of a slice.
	if(last_seg) {
		data->recieved_message_type[rhseq % RECIEVED_MESSAGE_COUNT] |= TYPE_FLAG_END;
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
	u_int32_t pall = value->packet_count - RECIEVED_MESSAGE_COUNT;

	if(!value->inited) {
		return;
	}

	p = buffer;
	p += sprintf(p, "ID: %08X [", value->ssrc);
	p += dump_ip_port_pair(value->conn, (print_func)sprintf, p);
	p += sprintf(p, "]\n");

	{
		char *s = ctime(&value->starttime);
		s[strlen(s)-1] = 0;
		p += sprintf(p, "    During: %s ", s);
		s = ctime(&value->conn->timestamp);
		s[strlen(s)-1] = 0;
		p += sprintf(p, "- %s\n", s);
	}

	p += sprintf(p, "    Current Sequence Number: %d\n", value->current_seq);
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

	// If I haven't recieved data from a connection for 60
	// seconds, I consider it's closed.
	if(data->current - pair->timestamp > 60) {
		if(data->ht == sending_pairs) {
			FILE *f = fopen("history.txt", "a");

			if(f == NULL) {
				perror("fopen");
			} else {
				struct rtp_connect_data *rtpdata = (struct rtp_connect_data*)value;

				if(verbose) {
					printf("FINISH an rtp connection: [");
					dump_ip_port_pair(pair, (print_func)fprintf, stdout);
					printf("]\n");
				}

				if(rtpdata->inited) {
					int i;
					// The packets cached in the buffer should be counted here.
					for(i=0; i<RECIEVED_MESSAGE_COUNT; i++) {
						add_up_data_at_pos(rtpdata, i);
					}
					rtpdata->packet_count += RECIEVED_MESSAGE_COUNT;
					output_data(f, rtpdata);
				}

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

static int parse_ip_datagram(const char *buffer, int len)
{
	struct iphdr *h = (struct iphdr*)buffer;
	int hl = h->ihl * 4;

	// I assume that the network layer doesn't split transport
	// layer segments.
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

	// Each time 1000 datagrams is recieved, I remove closed
	// connections and save running data of connections.
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

	return ntohs(h->tot_len);
}

static int parse_ether_frame(const char *buffer, int len)
{
	struct ethhdr *h = (struct ethhdr*)buffer;

	if(ntohs(h->h_proto) == ETH_P_IP) {
		return sizeof(struct ethhdr) +
			parse_ip_datagram(buffer + sizeof(struct ethhdr), len - sizeof(struct ethhdr));
	}
	return len;
}

static int parse_linux_sll_frame(const char *buffer, int len)
{
	u_int16_t proto = ntohs(*(u_int16_t*)(buffer+14));
	if(proto == ETH_P_IP) {
		return 16 +
			parse_ip_datagram(buffer + 16, len - 16);
	}
	return len;
}

int main(int argc, char **argv)
{
	static char device[10] = "any";
	int opt;

	while(-1 != (opt = getopt(argc, argv, "vp:d:"))) {
		switch(opt) {
			case 'v':
				verbose = true;
				break;
			case 'p':
				rtsp_port = atoi(optarg);
				break;
			case 'd':
				strncpy(device, optarg, 9);
				break;
			case '?':
				printf("Usage: %s [-v] [-p <port>] <-d device>\n", argv[0]);
				return -1;
		}
	}

	static char buffer[BUFFER_SIZE];
	pcap_t *pcap;
	int linktype;
	int (*link_frame_parser)(const char *, int);

	pcap = pcap_open_live(device, BUFFER_SIZE, true, 10000, buffer);

	if(pcap == NULL) {
		fprintf(stderr, "pcap_open_live: %s\n", buffer);
		exit(-1);
	}

	linktype = pcap_datalink(pcap);
	if(linktype != DLT_EN10MB && linktype != DLT_LINUX_SLL) {
		fprintf(stderr, "Unsupport data link type: %d\n", linktype);
		exit(-1);
	}
	link_frame_parser = linktype == DLT_EN10MB ? parse_ether_frame : parse_linux_sll_frame;

	preparing_pairs = ht_init(128, ip_port_pair_hashcode, ip_port_pair_equal);
	sending_pairs = ht_init(128, ip_port_pair_hashcode, ip_port_pair_equal);

	while(true) {
		struct pcap_pkthdr pcaphdr;
		const u_char *c = pcap_next(pcap, &pcaphdr);
		const char *p = (const char*)c;

		if(p != NULL) {
			int len = pcaphdr.len;
			link_frame_parser(p, len);
		}
	}

	pcap_close(pcap);

	return 0;
}
