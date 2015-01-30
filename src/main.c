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

#define BUFFER_SIZE 4096

#ifdef _DEBUG
#define ASSERT(cond) \
    if(!(cond)) {   \
        printf("'%s' not satisfied at line %d.\n", #cond, __LINE__);  \
        exit(-1); \
    }
#else
#define ASSERT(cond) if(cond){}
#endif

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

static void parse_tcp_segment(const struct iphdr *iph, const char *buffer, int len)
{
    struct tcphdr *h = (struct tcphdr*)buffer;
    unsigned char *saddr = (unsigned char*)&iph->saddr;
    unsigned char *daddr = (unsigned char*)&iph->daddr;
    printf("TCP [%c%c%c%c%c%c]", ".F"[h->fin], ".S"[h->syn], ".R"[h->rst], ".P"[h->psh], ".A"[h->ack], ".U"[h->urg]);
    printf(" %d.%d.%d.%d:%d -> %d.%d.%d.%d:%d seq=%08x ack=%08x length=%d\n",
           saddr[0], saddr[1], saddr[2], saddr[3], ntohs(h->source),
           daddr[0], daddr[1], daddr[2], daddr[3], ntohs(h->dest),
           ntohl(h->seq), ntohl(h->ack_seq), len - 4*h->doff);

}

static void parse_udp_segment(const struct iphdr *iph, const char *buffer, int len)
{
    struct udphdr *h = (struct udphdr*)buffer;
    unsigned char *saddr = (unsigned char*)&iph->saddr;
    unsigned char *daddr = (unsigned char*)&iph->daddr;
    printf("UDP %d.%d.%d.%d:%d -> %d.%d.%d.%d:%d length=%d\n",
           saddr[0], saddr[1], saddr[2], saddr[3], ntohs(h->source),
           daddr[0], daddr[1], daddr[2], daddr[3], ntohs(h->dest),
           (int)(len - sizeof(struct udphdr)));
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

	while(1) {
		len = read(s, buffer, BUFFER_SIZE);
		ASSERT(len < BUFFER_SIZE);

		parse_ether_frame(buffer, len);

        /*
		ETH_HEADER *eh = (ETH_HEADER*)buffer;
		for(i=0; i<ETHER_ADDR_LEN; i++) {
			if(i != 0)
				printf(":");
			printf("%02x", eh->ether_srcmac[i]);
		}
		printf(" -> ");
		for(i=0; i<ETHER_ADDR_LEN; i++) {
			if(i != 0)
				printf(":");
			printf("%02x", eh->ether_dstmac[i]);
		}
		eh->ether_type = ntohs(eh->ether_type);
		printf(" [type=%-4s 0x%04x]", eh->ether_type == ETHERTYPE_IP ? "IP" :
						(eh->ether_type == ETHERTYPE_ARP ? "ARP" :
						(eh->ether_type == 0x86dd ? "IPv6" : "OTHER")), eh->ether_type);
		if(eh->ether_type == ETHERTYPE_IP) {
			IP_HEADER *ih = (IP_HEADER*)(buffer + sizeof(ETH_HEADER));
			printf("\n |- ");
			printf("%d.%d.%d.%d", ih->sourceIP[0], ih->sourceIP[1], ih->sourceIP[2], ih->sourceIP[3]);
			printf(" -> ");
			printf("%d.%d.%d.%d", ih->destIP[0], ih->destIP[1], ih->destIP[2], ih->destIP[3]);
			printf(" [proto=%-6s length=%-4d]", ih->proto == PROTOCOL_UDP ? "UDP" :
												(ih->proto == PROTOCOL_TCP ? "TCP" : "OTHER"), ntohs(ih->total_len));
		}
		printf("\n");
		*/
	}

	close(s);
	free(buffer);

	return 0;
}
