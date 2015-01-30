#ifndef _H264_H_
#define _H264_H_

#define NAL_TYPE_SLICE	1
#define NAL_TYPE_FU_A	28

struct nalhdr {
#if __BYTE_ORDER == __LITTLE_ENDIAN
	u_int8_t type:5;
	u_int8_t nri:2;
	u_int8_t f:1;
#elif __BYTE_ORDER == __BIG_ENDIAN
	u_int8_t f:1;
	u_int8_t nri:2;
	u_int8_t type:5;
#else
# error	"Please fix <bits/endian.h>"
#endif
};

struct fuhdr {
#if __BYTE_ORDER == __LITTLE_ENDIAN
	u_int8_t type:5;
	u_int8_t r:1;
	u_int8_t e:1;
	u_int8_t s:1;
#elif __BYTE_ORDER == __BIG_ENDIAN
	u_int8_t s:1;
	u_int8_t e:1;
	u_int8_t r:1;
	u_int8_t type:5;
#else
# error	"Please fix <bits/endian.h>"
#endif
};

#define SLICE_TYPE_P	0
#define SLICE_TYPE_B	1
#define SLICE_TYPE_I	2
#define SLICE_TYPE_SP	3
#define SLICE_TYPE_SI	4
#define SLICE_TYPE_P2	5
#define SLICE_TYPE_B2	6
#define SLICE_TYPE_I2	7
#define SLICE_TYPE_SP2	8
#define SLICE_TYPE_SI2	9

#endif
