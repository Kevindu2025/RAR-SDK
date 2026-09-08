/* myblake2.c - our SDK blake2sp impl extracted for A/B comparison with blake_ref */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static unsigned crc_table_local[256]; /* unused */

#define ROTR32(x,n) (((x)>>(n))|((x)<<(32-(n))))

static const unsigned blake2s_IV[8] = {
  0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,
  0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19
};

static const unsigned char blake2s_sigma[10][16] = {
  {0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15},
  {14,10,4,8,9,15,13,6,1,12,0,2,11,7,5,3},
  {11,8,12,0,5,2,10,14,15,1,7,4,9,3,6,13},
  {7,9,3,1,13,12,11,14,2,6,5,10,4,0,15,8},
  {9,0,5,7,2,4,10,15,14,1,11,12,6,8,3,13},
  {2,12,6,10,0,11,8,3,4,13,7,5,15,14,1,9},
  {12,5,1,15,14,13,4,10,0,7,6,3,9,2,8,11},
  {13,11,7,14,12,1,3,9,5,0,15,4,8,6,2,10},
  {6,15,14,9,11,3,0,8,12,2,13,7,1,4,10,5},
  {10,2,8,4,7,6,1,5,15,11,9,14,3,12,13,0}
};

#define B2S_G(a,b,c,d,x) do { \
  v[a]+=v[b]+(x); v[d]=ROTR32(v[d]^v[a],16); \
  v[c]+=v[d];      v[b]=ROTR32(v[b]^v[c],12); \
  v[a]+=v[b]+(y);  v[d]=ROTR32(v[d]^v[a],8); \
  v[c]+=v[d];      v[b]=ROTR32(v[b]^v[c],7); } while(0)

static void blake2s_compress2(unsigned h[8], const unsigned char block[64],
                              unsigned long long t, unsigned last, unsigned lastnode)
{
  unsigned v[16], m[16];
  for (int i = 0; i < 8; i++) v[i] = h[i];
  for (int i = 0; i < 8; i++) v[8+i] = blake2s_IV[i];
  for (int i = 0; i < 16; i++)
    m[i] = ((unsigned)block[i*4])|((unsigned)block[i*4+1]<<8)|
           ((unsigned)block[i*4+2]<<16)|((unsigned)block[i*4+3]<<24);
  v[12] ^= (unsigned)(t & 0xffffffff);
  v[13] ^= (unsigned)(t >> 32);
  if (last) v[14] = ~v[14];
  if (lastnode) v[15] = ~v[15];

  for (int r = 0; r < 10; r++) {
    const unsigned char *s = blake2s_sigma[r];
    unsigned x, y;
#define G2(a,b,c,d,i,j) do { x=m[s[i]]; y=m[s[j]]; B2S_G(a,b,c,d,x); } while(0)
    G2(0,4,8,12,0,1); G2(1,5,9,13,2,3); G2(2,6,10,14,4,5); G2(3,7,11,15,6,7);
    G2(0,5,10,15,8,9); G2(1,6,11,12,10,11); G2(2,7,8,13,12,13); G2(3,4,9,14,14,15);
  }
  for (int i = 0; i < 8; i++) h[i] ^= v[i] ^ v[i+8];
}

typedef struct {
  unsigned h[8];
  unsigned long long t;
  unsigned char buf[64];
  size_t rem;
  unsigned last;     /* last block flag */
  unsigned lastnode; /* last node flag (f[1]) */
} B2S;

static void b2s_init(B2S *s, unsigned fanout, unsigned depth, unsigned leaf)
{
  s->h[0] = blake2s_IV[0] ^ 0x02080020;
  s->h[1] = blake2s_IV[1];
  s->h[2] = blake2s_IV[2] ^ leaf;
  s->h[3] = blake2s_IV[3] ^ (unsigned)(((unsigned long long)depth << 16) | 0x20000000);
  s->h[4] = blake2s_IV[4]; s->h[5] = blake2s_IV[5];
  s->h[6] = blake2s_IV[6]; s->h[7] = blake2s_IV[7];
  (void)fanout;
  s->t = 0; s->rem = 0; s->last = 0; s->lastnode = 0;
}

static void b2s_update(B2S *s, const unsigned char *p, size_t n)
{
  while (n) {
    if (s->rem == 0 && n >= 64) {
      s->t += 64;
      blake2s_compress2(s->h, p, s->t, 0, 0);
      p += 64; n -= 64;
    } else {
      size_t take = 64 - s->rem; if (take > n) take = n;
      memcpy(s->buf + s->rem, p, take);
      s->rem += take; p += take; n -= take;
      if (s->rem == 64) {
        s->t += 64;
        blake2s_compress2(s->h, s->buf, s->t, 0, 0);
        s->rem = 0;
      }
    }
  }
}

static void b2s_final(B2S *s, unsigned char out[32])
{
  s->t += s->rem;
  memset(s->buf + s->rem, 0, 64 - s->rem);
  blake2s_compress2(s->h, s->buf, s->t, 1, s->lastnode);
  for (int i = 0; i < 8; i++) {
    out[i*4+0]=(unsigned char)s->h[i]; out[i*4+1]=(unsigned char)(s->h[i]>>8);
    out[i*4+2]=(unsigned char)(s->h[i]>>16); out[i*4+3]=(unsigned char)(s->h[i]>>24);
  }
}

void rarsdk_Blake2sp(const void *data, size_t size, unsigned char digest[32])
{
  const size_t PAR = 8, BS = 64;
  B2S leaf[8], root;
  const unsigned char *p = (const unsigned char*)data;

  for (int i = 0; i < 8; i++) {
    b2s_init(&leaf[i], 8, 0, i);
    leaf[i].lastnode = (i == 7);
  }
  printf("\n");

  size_t full = (size / (PAR * BS)) * (PAR * BS);
  for (size_t off = 0; off < full; off += PAR * BS)
    for (int i = 0; i < 8; i++)
      b2s_update(&leaf[i], p + off + i * BS, BS);

  size_t left = size - full;
  if (left > 0) {
    for (int i = 0; i < 8; i++) {
      size_t loff = (size_t)i * BS;
      if (left > loff) {
        size_t take = left - loff; if (take > BS) take = BS;
        b2s_update(&leaf[i], p + full + loff, take);
      }
    }
  }

  b2s_init(&root, 8, 1, 0);
  root.lastnode = 1;

  unsigned char ld[8][32];
  for (int i = 0; i < 8; i++) {
    b2s_final(&leaf[i], ld[i]);
    b2s_update(&root, ld[i], 32);
  }
  b2s_final(&root, digest);
}

int main(int argc, char **argv)
{
  if (argc > 1) {
    FILE *f = fopen(argv[1], "rb");
    if (!f) return 1;
    fseek(f, 0, SEEK_END); long n = ftell(f); fseek(f, 0, SEEK_SET);
    unsigned char *d = (unsigned char*)malloc(n);
    if (fread(d, 1, n, f) != (size_t)n) return 1;
    fclose(f);
    unsigned char dg[32];
    rarsdk_Blake2sp(d, n, dg);
    for (int i = 0; i < 32; i++) printf("%02X", dg[i]);
    printf("\n");
    return 0;
  }
  unsigned char dg[32];
  rarsdk_Blake2sp((const unsigned char*)"", 0, dg);
  for (int i=0;i<32;i++) printf("%02X", dg[i]); printf("\n");
  unsigned char a1[1]={'a'};
  rarsdk_Blake2sp(a1, 1, dg);
  for (int i=0;i<32;i++) printf("%02X", dg[i]); printf("\n");
  unsigned char a513[513]; for(int i=0;i<513;i++) a513[i]=(unsigned char)i;
  rarsdk_Blake2sp(a513, 513, dg);
  for (int i=0;i<32;i++) printf("%02X", dg[i]); printf("\n");
  return 0;
}
