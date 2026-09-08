/* blake_ref.c - EXACT copy of UnRAR blake2sp.cpp/blake2s.cpp logic,
   single-threaded, SSE off. For reference comparison. */
#include <stdio.h>
#include <stdint.h>
#include <string.h>

typedef unsigned char byte;
typedef unsigned int uint;

static const uint blake2s_IV[8] = {
  0x6A09E667UL, 0xBB67AE85UL, 0x3C6EF372UL, 0xA54FF53AUL,
  0x510E527FUL, 0x9B05688CUL, 0x1F83D9ABUL, 0x5BE0CD19UL
};

static const byte blake2s_sigma[10][16] = {
  { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 },
  { 14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3 },
  { 11, 8, 12, 0, 5, 2, 10, 14, 15, 1, 7, 4, 9, 3, 6, 13 },
  { 7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8 },
  { 9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13 },
  { 2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9 },
  { 12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11 },
  { 13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10 },
  { 6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5 },
  { 10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0 }
};

struct blake2s_state_t {
  uint h[8];
  uint t[2];
  uint f[2];
  size_t buflen;
  byte buf[2 * 64];
  int last_node;
};
typedef struct blake2s_state_t blake2s_state;

#define PARALLELISM_DEGREE 8
#define BLAKE2S_BLOCKBYTES 64

struct blake2sp_state_t {
  blake2s_state S[8];
  blake2s_state R;
  int buflen;
  byte buf[PARALLELISM_DEGREE * BLAKE2S_BLOCKBYTES];
};
typedef struct blake2sp_state_t blake2sp_state;

static uint rotr(uint x, int n) { return (x >> n) | (x << (32 - n)); }

static void blake2s_init_param(blake2s_state *S, uint node_offset, uint node_depth)
{
  memset(S, 0, sizeof(blake2s_state));
  for (int i = 0; i < 8; ++i)
    S->h[i] = blake2s_IV[i];
  S->h[0] ^= 0x02080020;
  S->h[2] ^= node_offset;
  S->h[3] ^= (node_depth << 16) | 0x20000000;
}

static void blake2s_set_lastnode(blake2s_state *S) { S->f[1] = ~0U; }
static void blake2s_set_lastblock(blake2s_state *S)
{
  if (S->last_node) blake2s_set_lastnode(S);
  S->f[0] = ~0U;
}
static void blake2s_increment_counter(blake2s_state *S, const uint inc)
{
  S->t[0] += inc;
  S->t[1] += (S->t[0] < inc);
}

static void blake2s_compress(blake2s_state *S, const byte block[BLAKE2S_BLOCKBYTES])
{
  uint m[16];
  uint v[16];

  for (size_t i = 0; i < 16; ++i)
    m[i] = block[i*4+0] + ((uint)block[i*4+1] << 8) + ((uint)block[i*4+2] << 16) + ((uint)block[i*4+3] << 24);

  for (size_t i = 0; i < 8; ++i)
    v[i] = S->h[i];

  v[ 8] = blake2s_IV[0];
  v[ 9] = blake2s_IV[1];
  v[10] = blake2s_IV[2];
  v[11] = blake2s_IV[3];
  v[12] = S->t[0] ^ blake2s_IV[4];
  v[13] = S->t[1] ^ blake2s_IV[5];
  v[14] = S->f[0] ^ blake2s_IV[6];
  v[15] = S->f[1] ^ blake2s_IV[7];

#define G(r,i,a,b,c,d) \
  a = a + b + m[blake2s_sigma[r][2*i+0]]; \
  d = rotr(d ^ a, 16); \
  c = c + d; \
  b = rotr(b ^ c, 12); \
  a = a + b + m[blake2s_sigma[r][2*i+1]]; \
  d = rotr(d ^ a, 8); \
  c = c + d; \
  b = rotr(b ^ c, 7);

#define ROUND(r) \
  G(r,0,v[0],v[4],v[8],v[12]); \
  G(r,1,v[1],v[5],v[9],v[13]); \
  G(r,2,v[2],v[6],v[10],v[14]); \
  G(r,3,v[3],v[7],v[11],v[15]); \
  G(r,4,v[0],v[5],v[10],v[15]); \
  G(r,5,v[1],v[6],v[11],v[12]); \
  G(r,6,v[2],v[7],v[8],v[13]); \
  G(r,7,v[3],v[4],v[9],v[14]);

  for (uint r = 0; r <= 9; ++r) {
    ROUND(r);
  }

  for (size_t i = 0; i < 8; ++i)
    S->h[i] = S->h[i] ^ v[i] ^ v[i + 8];
}

static void blake2s_update(blake2s_state *S, const byte *in, size_t inlen)
{
  size_t left = S->buflen;
  size_t fill = 2 * BLAKE2S_BLOCKBYTES - left;
  if (left && inlen >= fill) {
    memcpy(S->buf + left, in, fill);
    blake2s_increment_counter(S, BLAKE2S_BLOCKBYTES);
    blake2s_compress(S, S->buf);
    in += fill;
    inlen -= fill;
    left = 0;
  }
  while (inlen > BLAKE2S_BLOCKBYTES) {
    blake2s_increment_counter(S, BLAKE2S_BLOCKBYTES);
    blake2s_compress(S, in);
    in += BLAKE2S_BLOCKBYTES;
    inlen -= BLAKE2S_BLOCKBYTES;
  }
  if (inlen > 0) {
    memcpy(S->buf + left, in, inlen);
  }
  S->buflen = left + inlen;
}

static void blake2s_final(blake2s_state *S, byte *digest)
{
  byte hash[32];
  blake2s_increment_counter(S, S->buflen);
  memset(S->buf + S->buflen, 0, 2 * BLAKE2S_BLOCKBYTES - S->buflen);
  blake2s_set_lastblock(S);
  blake2s_compress(S, S->buf);
  for (int i = 0; i < 8; ++i) {
    hash[i*4+0] = (byte)(S->h[i]      );
    hash[i*4+1] = (byte)(S->h[i] >>  8);
    hash[i*4+2] = (byte)(S->h[i] >> 16);
    hash[i*4+3] = (byte)(S->h[i] >> 24);
  }
  memcpy(digest, hash, 32);
  memset(hash, 0, sizeof hash);
}

static void blake2sp_init(blake2sp_state *S)
{
  memset(S->buf, 0, sizeof(S->buf));
  S->buflen = 0;
  blake2s_init_param(&S->R, 0, 1);
  for (uint32_t i = 0; i < PARALLELISM_DEGREE; ++i)
    blake2s_init_param(&S->S[i], i, 0);
  S->R.last_node = 1;
  printf("leaf0 h init:");
  for (int q = 0; q < 8; q++) printf(" %08X", S->S[0].h[q]);
  printf("\n");
  S->S[PARALLELISM_DEGREE - 1].last_node = 1;
}

static void blake2sp_update(blake2sp_state *S, const byte *in, size_t inlen)
{
  size_t left = S->buflen;
  size_t fill = sizeof(S->buf) - left;

  if (left && inlen >= fill) {
    memcpy(S->buf + left, in, fill);
    for (size_t i = 0; i < PARALLELISM_DEGREE; ++i)
      blake2s_update(&S->S[i], S->buf + i * BLAKE2S_BLOCKBYTES, BLAKE2S_BLOCKBYTES);
    in += fill;
    inlen -= fill;
    left = 0;
  }

  while (inlen >= PARALLELISM_DEGREE * BLAKE2S_BLOCKBYTES) {
    for (size_t i = 0; i < PARALLELISM_DEGREE; ++i)
      blake2s_update(&S->S[i], in + i * BLAKE2S_BLOCKBYTES, BLAKE2S_BLOCKBYTES);
    in += PARALLELISM_DEGREE * BLAKE2S_BLOCKBYTES;
    inlen -= PARALLELISM_DEGREE * BLAKE2S_BLOCKBYTES;
  }

  in += inlen - inlen % (PARALLELISM_DEGREE * BLAKE2S_BLOCKBYTES);
  inlen %= PARALLELISM_DEGREE * BLAKE2S_BLOCKBYTES;

  if (inlen > 0)
    memcpy(S->buf + left, in, inlen);

  S->buflen = (int)(left + inlen);
}

static void blake2sp_final(blake2sp_state *S, byte *digest)
{
  byte hash[PARALLELISM_DEGREE][32];

  for (size_t i = 0; i < PARALLELISM_DEGREE; ++i) {
    if (S->buflen > (int)(i * BLAKE2S_BLOCKBYTES)) {
      size_t left = S->buflen - i * BLAKE2S_BLOCKBYTES;
      if (left > BLAKE2S_BLOCKBYTES) left = BLAKE2S_BLOCKBYTES;
      blake2s_update(&S->S[i], S->buf + i * BLAKE2S_BLOCKBYTES, left);
    }
    blake2s_final(&S->S[i], hash[i]);
  }

  for (size_t i = 0; i < PARALLELISM_DEGREE; ++i)
    blake2s_update(&S->R, hash[i], 32);

  blake2s_final(&S->R, digest);
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
    blake2sp_state S;
    blake2sp_init(&S);
    if (n > 0) blake2sp_update(&S, d, n);
    blake2sp_final(&S, dg);
    for (int i = 0; i < 32; i++) printf("%02X", dg[i]);
    printf("\n");
    return 0;
  }
  unsigned char dg[32];
  blake2sp_state S;
  blake2sp_init(&S);
  blake2sp_final(&S, dg);
  for (int i = 0; i < 32; i++) printf("%02X", dg[i]);
  printf("\n");
  blake2sp_state S2;
  blake2sp_init(&S2);
  unsigned char a1[1] = {'a'};
  blake2sp_update(&S2, a1, 1);
  blake2sp_final(&S2, dg);
  for (int i = 0; i < 32; i++) printf("%02X", dg[i]);
  printf("\n");
  blake2sp_state S3;
  blake2sp_init(&S3);
  unsigned char a513[513];
  for (int i = 0; i < 513; i++) a513[i] = (unsigned char)i;
  blake2sp_update(&S3, a513, 513);
  blake2sp_final(&S3, dg);
  for (int i = 0; i < 32; i++) printf("%02X", dg[i]);
  printf("\n");
  return 0;
}
