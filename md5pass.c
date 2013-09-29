#include <stdio.h>
#include <stdlib.h>
#include <string.h>

char master_pass[10];
typedef unsigned long int UINT4;

typedef struct {
	UINT4 i[2];
	UINT4 buf[4];
	unsigned char in[64];
	unsigned char digest[16];
} MD5_CTX;

static unsigned char PADDING[64] = {
	0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};


#define F(x, y, z) (((x) & (y)) | ((~x) & (z)))
#define G(x, y, z) (((x) & (z)) | ((y) & (~z)))
#define H(x, y, z) ((x) ^ (y) ^ (z))
#define I(x, y, z) ((y) ^ ((x) | (~z)))
#define ROTATE_LEFT(x, n) (((x) << (n)) | ((x) >> (32-(n))))

#define FF(a, b, c, d, x, s, ac) \
	{(a) += F ((b), (c), (d)) + (x) + (UINT4)(ac); \
	(a) = ROTATE_LEFT ((a), (s)); \
	(a) += (b); \
	}
#define GG(a, b, c, d, x, s, ac) \
	{(a) += G ((b), (c), (d)) + (x) + (UINT4)(ac); \
	(a) = ROTATE_LEFT ((a), (s)); \
	(a) += (b); \
	}
#define HH(a, b, c, d, x, s, ac) \
	{(a) += H ((b), (c), (d)) + (x) + (UINT4)(ac); \
	(a) = ROTATE_LEFT ((a), (s)); \
	(a) += (b); \
	}
#define II(a, b, c, d, x, s, ac) \
	{(a) += I ((b), (c), (d)) + (x) + (UINT4)(ac); \
	(a) = ROTATE_LEFT ((a), (s)); \
	(a) += (b); \
	}


void MD5Init (MD5_CTX *mdContext) {

	mdContext->i[0] = mdContext->i[1] = (UINT4)0;
	mdContext->buf[0] = (UINT4)0x67452301;
	mdContext->buf[1] = (UINT4)0xefcdab89;
	mdContext->buf[2] = (UINT4)0x98badcfe;
	mdContext->buf[3] = (UINT4)0x10325476;
}


static void Transform (UINT4 *buf, UINT4 *in) {

	UINT4 a = buf[0], b = buf[1], c = buf[2], d = buf[3];

#define S11 7
#define S12 12
#define S13 17
#define S14 22
	FF ( a, b, c, d, in[ 0], S11, 3614090360UL);
	FF ( d, a, b, c, in[ 1], S12, 3905402710UL);
	FF ( c, d, a, b, in[ 2], S13,	606105819);
	FF ( b, c, d, a, in[ 3], S14, 3250441966UL);
	FF ( a, b, c, d, in[ 4], S11, 4118548399UL);
	FF ( d, a, b, c, in[ 5], S12, 1200080426);
	FF ( c, d, a, b, in[ 6], S13, 2821735955UL);
	FF ( b, c, d, a, in[ 7], S14, 4249261313UL);
	FF ( a, b, c, d, in[ 8], S11, 1770035416);
	FF ( d, a, b, c, in[ 9], S12, 2336552879UL);
	FF ( c, d, a, b, in[10], S13, 4294925233UL);
	FF ( b, c, d, a, in[11], S14, 2304563134UL);
	FF ( a, b, c, d, in[12], S11, 1804603682);
	FF ( d, a, b, c, in[13], S12, 4254626195UL);
	FF ( c, d, a, b, in[14], S13, 2792965006UL);
	FF ( b, c, d, a, in[15], S14, 1236535329);

#define S21 5
#define S22 9
#define S23 14
#define S24 20
	GG ( a, b, c, d, in[ 1], S21, 4129170786UL);
	GG ( d, a, b, c, in[ 6], S22, 3225465664UL);
	GG ( c, d, a, b, in[11], S23,	643717713);
	GG ( b, c, d, a, in[ 0], S24, 3921069994UL);
	GG ( a, b, c, d, in[ 5], S21, 3593408605UL);
	GG ( d, a, b, c, in[10], S22,	38016083);
	GG ( c, d, a, b, in[15], S23, 3634488961UL);
	GG ( b, c, d, a, in[ 4], S24, 3889429448UL);
	GG ( a, b, c, d, in[ 9], S21,	568446438);
	GG ( d, a, b, c, in[14], S22, 3275163606UL);
	GG ( c, d, a, b, in[ 3], S23, 4107603335UL);
	GG ( b, c, d, a, in[ 8], S24, 1163531501);
	GG ( a, b, c, d, in[13], S21, 2850285829UL);
	GG ( d, a, b, c, in[ 2], S22, 4243563512UL);
	GG ( c, d, a, b, in[ 7], S23, 1735328473);
	GG ( b, c, d, a, in[12], S24, 2368359562UL);

#define S31 4
#define S32 11
#define S33 16
#define S34 23
	HH ( a, b, c, d, in[ 5], S31, 4294588738UL);
	HH ( d, a, b, c, in[ 8], S32, 2272392833UL);
	HH ( c, d, a, b, in[11], S33, 1839030562);
	HH ( b, c, d, a, in[14], S34, 4259657740UL);
	HH ( a, b, c, d, in[ 1], S31, 2763975236UL);
	HH ( d, a, b, c, in[ 4], S32, 1272893353);
	HH ( c, d, a, b, in[ 7], S33, 4139469664UL);
	HH ( b, c, d, a, in[10], S34, 3200236656UL);
	HH ( a, b, c, d, in[13], S31,	681279174);
	HH ( d, a, b, c, in[ 0], S32, 3936430074UL);
	HH ( c, d, a, b, in[ 3], S33, 3572445317UL);
	HH ( b, c, d, a, in[ 6], S34,	76029189);
	HH ( a, b, c, d, in[ 9], S31, 3654602809UL);
	HH ( d, a, b, c, in[12], S32, 3873151461UL);
	HH ( c, d, a, b, in[15], S33,	530742520);
	HH ( b, c, d, a, in[ 2], S34, 3299628645UL);

#define S41 6
#define S42 10
#define S43 15
#define S44 21
	II ( a, b, c, d, in[ 0], S41, 4096336452UL);
	II ( d, a, b, c, in[ 7], S42, 1126891415);
	II ( c, d, a, b, in[14], S43, 2878612391UL);
	II ( b, c, d, a, in[ 5], S44, 4237533241UL);
	II ( a, b, c, d, in[12], S41, 1700485571);
	II ( d, a, b, c, in[ 3], S42, 2399980690UL);
	II ( c, d, a, b, in[10], S43, 4293915773UL);
	II ( b, c, d, a, in[ 1], S44, 2240044497UL);
	II ( a, b, c, d, in[ 8], S41, 1873313359);
	II ( d, a, b, c, in[15], S42, 4264355552UL);
	II ( c, d, a, b, in[ 6], S43, 2734768916UL);
	II ( b, c, d, a, in[13], S44, 1309151649);
	II ( a, b, c, d, in[ 4], S41, 4149444226UL);
	II ( d, a, b, c, in[11], S42, 3174756917UL);
	II ( c, d, a, b, in[ 2], S43,	718787259);
	II ( b, c, d, a, in[ 9], S44, 3951481745UL);

	buf[0] += a;
	buf[1] += b;
	buf[2] += c;
	buf[3] += d;
}


void MD5Update (MD5_CTX *mdContext, unsigned char *inBuf, unsigned int inLen) {

	UINT4 in[16];
	int mdi;
	unsigned int i, ii;

	mdi = (int)((mdContext->i[0] >> 3) & 0x3F);

	if ((mdContext->i[0] + ((UINT4)inLen << 3)) < mdContext->i[0])
	mdContext->i[1]++;
	mdContext->i[0] += ((UINT4)inLen << 3);
	mdContext->i[1] += ((UINT4)inLen >> 29);

	while (inLen--) {
		mdContext->in[mdi++] = *inBuf++;
	 
		if (mdi == 0x40) {
			for (i = 0, ii = 0; i < 16; i++, ii += 4)
				in[i] = (((UINT4)mdContext->in[ii+3]) << 24) |
					(((UINT4)mdContext->in[ii+2]) << 16) |
					(((UINT4)mdContext->in[ii+1]) << 8) |
					((UINT4)mdContext->in[ii]);
			Transform (mdContext->buf, in);
			mdi = 0;
	 	}
	}
}


void MD5Final (MD5_CTX *mdContext) {

	UINT4 in[16];
	int mdi;
	unsigned int i, ii;
	unsigned int padLen;

	in[14] = mdContext->i[0];
	in[15] = mdContext->i[1];

	mdi = (int)((mdContext->i[0] >> 3) & 0x3F);

	padLen = (mdi < 56) ? (56 - mdi) : (120 - mdi);
	MD5Update (mdContext, PADDING, padLen);

	for (i = 0, ii = 0; i < 14; i++, ii += 4)
		in[i] = (((UINT4)mdContext->in[ii+3]) << 24) |
				(((UINT4)mdContext->in[ii+2]) << 16) |
				(((UINT4)mdContext->in[ii+1]) << 8) |
				((UINT4)mdContext->in[ii]);
	
	Transform (mdContext->buf, in);

	for (i = 0, ii = 0; i < 4; i++, ii += 4) {
		mdContext->digest[ii] = (unsigned char)(mdContext->buf[i] & 0xFF);
		mdContext->digest[ii+1] = (unsigned char)((mdContext->buf[i] >> 8) & 0xFF);
		mdContext->digest[ii+2] = (unsigned char)((mdContext->buf[i] >> 16) & 0xFF);
		mdContext->digest[ii+3] = (unsigned char)((mdContext->buf[i] >> 24) & 0xFF);
	}
}


static void MDPrint (MD5_CTX *mdContext) {

	sprintf(master_pass,"%02x%02x%02x%02x", 
			mdContext->digest[0], 
			mdContext->digest[1],
			mdContext->digest[2],
			mdContext->digest[3]);
}


static void MDString(const char *inString) {

	MD5_CTX mdContext;
	unsigned int len = strlen(inString);

	MD5Init (&mdContext);
	MD5Update (&mdContext, (unsigned char *) inString, len);
	MD5Final (&mdContext);
	MDPrint (&mdContext);
}


void __usage(const char *cmd) {
	printf("\nUse: %s <some_string>\n\n", cmd);
	exit(-1);
}


int main (int argn, char **argv) {

	if (argn < 2) __usage(*argv);
	MDString(*(++argv));

	printf("\nPassword Master: %s\n\n", master_pass);
	return 0;
}

