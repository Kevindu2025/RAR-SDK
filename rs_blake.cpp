/* rs_blake.cpp - BLAKE2sp exact mirror of UnRAR blake2s.cpp/blake2sp.cpp */
#include "rs_internal.h"

static const unsigned blake2s_IV[8] = {
  0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,
  0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19
};

static const unsigned char blake2s_sigma[10][16] = {
  {0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15},
  {14,10,4,8,9,15,13,6,1,12,0,2,11,7,5,3},
  {11,8,12,0,5,2,15,13,10,14,3,6,7,1,9,4},
  {7,9,3,1,13,12,11,14,2,6,5,10,4,0,15,8},
  {9,0,5,7,2,4,10,15,14,1,11,12,6,8,3,13},
  {2,12,6,10,0,11,8,3,4,13,7,5,15,14,1,9},
  {12,5,1,15,14,13,4,10,0,7,6,3,9,2,8,11},
  {13,11,7,14,12,1,3,9,5,0,15,4,8,6,2,10},
  {6,15,14,9,11,3,0,8,12,2,13,7,1,4,10,5},
  {10,2,8,4,7,6,1,5,15,11,9,14,3,12,13,0}
};

#define B2S_BLOCKBYTES 64
#define B2S_PAR 8

typedef struct {
  unsigned h[8];
  unsigned t[2];
  unsigned f[2];
  size_t buflen;
  unsigned char buf[2 * B2S_BLOCKBYTES];
  int last_node;
} b2s_state;

static unsigned b2s_rotr(unsigned x, int n) { return (x >> n) | (x << (32 - n)); }

static void b2s_init_param(b2s_state *S, unsigned node_offset, unsigned node_depth)
{
  memset(S, 0, sizeof *S);
  for (int i = 0; i < 8; i++) S->h[i] = blake2s_IV[i];
  S->h[0] ^= 0x02080020;                 /* BLAKE2sp parameter block */
  S->h[2] ^= node_offset;
  S->h[3] ^= (node_depth << 16) | 0x20000000;
}

static void b2s_set_lastnode(b2s_state *S) { S->f[1] = ~0U; }
static void b2s_set_lastblock(b2s_state *S)
{
  if (S->last_node) b2s_set_lastnode(S);
  S->f[0] = ~0U;
}
static void b2s_increment(b2s_state *S, unsigned inc)
{
  S->t[0] += inc;
  S->t[1] += (S->t[0] < inc);
}

static void b2s_compress(b2s_state *S, const unsigned char *block)
{
  unsigned m[16], v[16];
  for (int i = 0; i < 16; i++)
    m[i] = ((unsigned)block[i*4])|((unsigned)block[i*4+1]<<8)|
           ((unsigned)block[i*4+2]<<16)|((unsigned)block[i*4+3]<<24);
  for (int i = 0; i < 8; i++) v[i] = S->h[i];
  v[ 8] = blake2s_IV[0]; v[ 9] = blake2s_IV[1];
  v[10] = blake2s_IV[2]; v[11] = blake2s_IV[3];
  v[12] = S->t[0] ^ blake2s_IV[4];
  v[13] = S->t[1] ^ blake2s_IV[5];
  v[14] = S->f[0] ^ blake2s_IV[6];
  v[15] = S->f[1] ^ blake2s_IV[7];

#define BG(r,i,a,b,c,d) \
  a = a + b + m[blake2s_sigma[r][2*i+0]]; \
  d = b2s_rotr(d ^ a, 16); \
  c = c + d; \
  b = b2s_rotr(b ^ c, 12); \
  a = a + b + m[blake2s_sigma[r][2*i+1]]; \
  d = b2s_rotr(d ^ a, 8); \
  c = c + d; \
  b = b2s_rotr(b ^ c, 7);

#define BROUND(r) \
  BG(r,0,v[0],v[4],v[8],v[12]); \
  BG(r,1,v[1],v[5],v[9],v[13]); \
  BG(r,2,v[2],v[6],v[10],v[14]); \
  BG(r,3,v[3],v[7],v[11],v[15]); \
  BG(r,4,v[0],v[5],v[10],v[15]); \
  BG(r,5,v[1],v[6],v[11],v[12]); \
  BG(r,6,v[2],v[7],v[8],v[13]); \
  BG(r,7,v[3],v[4],v[9],v[14]);

  for (unsigned r = 0; r <= 9; ++r) {
    BROUND(r);
  }
  for (int i = 0; i < 8; ++i)
    S->h[i] = S->h[i] ^ v[i] ^ v[i + 8];
}

static void b2s_update(b2s_state *S, const unsigned char *in, size_t inlen)
{
  while (inlen > 0) {
    size_t left = S->buflen;
    size_t fill = 2 * B2S_BLOCKBYTES - left;
    if (inlen > fill) {
      memcpy(S->buf + left, in, fill);
      S->buflen += fill;
      b2s_increment(S, B2S_BLOCKBYTES);
      b2s_compress(S, S->buf);
      memcpy(S->buf, S->buf + B2S_BLOCKBYTES, B2S_BLOCKBYTES);
      S->buflen -= B2S_BLOCKBYTES;
      in += fill;
      inlen -= fill;
    } else {
      memcpy(S->buf + left, in, inlen);
      S->buflen += inlen;
      in += inlen;
      inlen = 0;
    }
  }
}

static void b2s_final(b2s_state *S, unsigned char *digest)
{
  if (S->buflen > B2S_BLOCKBYTES) {
    b2s_increment(S, B2S_BLOCKBYTES);
    b2s_compress(S, S->buf);
    S->buflen -= B2S_BLOCKBYTES;
    memcpy(S->buf, S->buf + B2S_BLOCKBYTES, S->buflen);
  }
  b2s_increment(S, (unsigned)S->buflen);
  b2s_set_lastblock(S);
  memset(S->buf + S->buflen, 0, 2 * B2S_BLOCKBYTES - S->buflen);
  b2s_compress(S, S->buf);
  for (int i = 0; i < 8; ++i) {
    digest[i*4+0] = (unsigned char)(S->h[i]);
    digest[i*4+1] = (unsigned char)(S->h[i] >> 8);
    digest[i*4+2] = (unsigned char)(S->h[i] >> 16);
    digest[i*4+3] = (unsigned char)(S->h[i] >> 24);
  }
}

/* BLAKE2sp state: 8 leaves + root, with shared remainder buffer */
typedef struct {
  b2s_state S[B2S_PAR];
  b2s_state R;
  size_t buflen;
  unsigned char buf[B2S_PAR * B2S_BLOCKBYTES];
} b2sp_state;

static void b2sp_init(b2sp_state *S)
{
  memset(S->buf, 0, sizeof S->buf);
  S->buflen = 0;
  b2s_init_param(&S->R, 0, 1);
  for (unsigned i = 0; i < B2S_PAR; ++i)
    b2s_init_param(&S->S[i], i, 0);
  S->R.last_node = 1;
  S->S[B2S_PAR - 1].last_node = 1;
}

static void b2sp_update(b2sp_state *S, const unsigned char *in, size_t inlen)
{
  size_t left = S->buflen;
  size_t fill = sizeof S->buf - left;

  if (left && inlen >= fill) {
    memcpy(S->buf + left, in, fill);
    for (unsigned i = 0; i < B2S_PAR; ++i)
      b2s_update(&S->S[i], S->buf + i * B2S_BLOCKBYTES, B2S_BLOCKBYTES);
    in += fill;
    inlen -= fill;
    left = 0;
  }

  while (inlen >= B2S_PAR * B2S_BLOCKBYTES) {
    for (unsigned i = 0; i < B2S_PAR; ++i)
      b2s_update(&S->S[i], in + i * B2S_BLOCKBYTES, B2S_BLOCKBYTES);
    in += B2S_PAR * B2S_BLOCKBYTES;
    inlen -= B2S_PAR * B2S_BLOCKBYTES;
  }

  if (inlen > 0)
    memcpy(S->buf + left, in, inlen);

  S->buflen = left + inlen;
}

static void b2sp_final(b2sp_state *S, unsigned char *digest)
{
  unsigned char hash[B2S_PAR][32];

  for (unsigned i = 0; i < B2S_PAR; ++i) {
    if (S->buflen > (size_t)i * B2S_BLOCKBYTES) {
      size_t left = S->buflen - (size_t)i * B2S_BLOCKBYTES;
      if (left > B2S_BLOCKBYTES) left = B2S_BLOCKBYTES;
      b2s_update(&S->S[i], S->buf + (size_t)i * B2S_BLOCKBYTES, left);
    }
    b2s_final(&S->S[i], hash[i]);
  }

  for (unsigned i = 0; i < B2S_PAR; ++i)
    b2s_update(&S->R, hash[i], 32);

  b2s_final(&S->R, digest);
}

RARAPI void RARCALL rarsdk_Blake2sp(const void *data, size_t size, unsigned char digest[32])
{
  b2sp_state S;
  b2sp_init(&S);
  const unsigned char *p = (const unsigned char*)data;
  /* single big update, like UnRAR ComprDataIO::UnpHash path */
  if (size > 0)
    b2sp_update(&S, p, size);
  b2sp_final(&S, digest);
}
