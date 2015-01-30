#ifndef _RTP_H_
#define _RTP_H_

#include <sys/types.h>

#define RTP_PAYLOAD_H264	96

struct rtphdr {
#if __BYTE_ORDER == __LITTLE_ENDIAN
	u_int8_t csrc_count:4;
	u_int8_t flag_extend:1;
	u_int8_t flag_padding:1;
	u_int8_t version:2;
#elif __BYTE_ORDER == __BIG_ENDIAN
	u_int8_t version:2;
	u_int8_t flag_padding:1;
	u_int8_t flag_extend:1;
	u_int8_t csrc_count:4;
#else
# error	"Please fix <bits/endian.h>"
#endif
#if __BYTE_ORDER == __LITTLE_ENDIAN
	u_int8_t payload_type:7;
	u_int8_t mark:1;
#elif __BYTE_ORDER == __BIG_ENDIAN
	u_int8_t mark:1;
	u_int8_t payload_type:7;
#else
# error	"Please fix <bits/endian.h>"
#endif
	u_int16_t seq;
	u_int32_t timestamp;
	u_int32_t ssrc;
};

#endif
