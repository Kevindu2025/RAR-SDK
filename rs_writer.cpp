/*
 * rs_writer.cpp - RAR5 archive writer (clean-room implementation)
 *
 * Format reference: "RAR 5.0 archive format" description by RarLab
 * (bundled as Rar.txt with WinRAR) + UnRAR source for constants only.
 *
 * Written features:
 *   - RAR5 signature, MAIN header, FILE headers (store method),
 *     END header
 *   - vint encoding, header CRC32, BLAKE2sp file hashes
 *   - Optional file data encryption: AES-256-CBC + PBKDF2-HMAC-SHA256
 *     (FHEXTRA_CRYPT), optional header encryption (HEAD_CRYPT block)
 *   - Optional recovery record: RS16 'RR' service header
 *
 * Not implemented (proprietary): LZ/Huffman solid compression.
 */
#include "rs_internal.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* ------------------------------------------------------------------ */
/*  Buf: growing byte buffer                                           */
/* ------------------------------------------------------------------ */

void buf_init(Buf *b)
{
  b->data = NULL; b->size = b->cap = 0;
}

void buf_reserve(Buf *b, size_t extra)
{
  if (b->size + extra > b->cap) {
    size_t ncap = b->cap ? b->cap * 2 : 4096;
    while (ncap < b->size + extra) ncap *= 2;
    b->data = (unsigned char*)realloc(b->data, ncap);
    b->cap = ncap;
  }
}

void buf_add(Buf *b, const void *p, size_t n)
{
  buf_reserve(b, n);
  memcpy(b->data + b->size, p, n);
  b->size += n;
}

void buf_add1(Buf *b, unsigned v)
{
  buf_reserve(b, 1);
  b->data[b->size++] = (unsigned char)v;
}

void buf_free(Buf *b)
{
  free(b->data); b->data = NULL; b->size = b->cap = 0;
}

/* ------------------------------------------------------------------ */
/*  vint                                                               */
/* ------------------------------------------------------------------ */

size_t rarsdk_PutVint(unsigned long long v, unsigned char *out, size_t outSize)
{
  size_t n = 0;
  do {
    unsigned char b = (unsigned char)(v & 0x7f);
    v >>= 7;
    if (v) b |= 0x80;
    if (n < outSize) out[n] = b;
    n++;
  } while (v);
  return n <= outSize ? n : 0;
}

size_t rarsdk_GetVint(const unsigned char *in, size_t inSize, unsigned long long *value)
{
  unsigned long long r = 0;
  size_t pos = 0;
  for (unsigned shift = 0; pos < inSize && shift < 64; shift += 7, pos++) {
    unsigned char c = in[pos];
    r += (unsigned long long)(c & 0x7f) << shift;
    if (!(c & 0x80)) {
      if (value) *value = r;
      return pos + 1;
    }
  }
  return 0;
}

/* ------------------------------------------------------------------ */
/*  CRC32 (classic table, poly 0xEDB88320) - same as UnRAR CRC32()     */
/* ------------------------------------------------------------------ */

static unsigned crc_table[256];
static int crc_init_done = 0;

unsigned int rarsdk_CRC32(unsigned int startCRC, const void *data, size_t size)
{
  if (!crc_init_done) {
    for (unsigned i = 0; i < 256; i++) {
      unsigned c = i;
      for (int j = 0; j < 8; j++)
        c = (c & 1) ? (c >> 1) ^ 0xEDB88320 : (c >> 1);
      crc_table[i] = c;
    }
    crc_init_done = 1;
  }
  unsigned crc = startCRC;
  const unsigned char *p = (const unsigned char*)data;
  while (size--)
    crc = crc_table[(crc ^ *p++) & 0xff] ^ (crc >> 8);
  return crc;
}

/* ------------------------------------------------------------------ */
/*  SHA-256 (needed for PBKDF2 and PswCheck csum)                      */
/* ------------------------------------------------------------------ */

static const unsigned sha256_k[64] = {
  0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
  0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
  0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
  0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
  0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
  0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
  0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
  0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

#define ROTR32(x,n) (((x)>>(n))|((x)<<(32-(n))))

void sha256_init(SHA256_CTX *c)
{
  c->len = 0; c->rem = 0;
  c->h[0]=0x6a09e667; c->h[1]=0xbb67ae85; c->h[2]=0x3c6ef372; c->h[3]=0xa54ff53a;
  c->h[4]=0x510e527f; c->h[5]=0x9b05688c; c->h[6]=0x1f83d9ab; c->h[7]=0x5be0cd19;
}

static void sha256_block(SHA256_CTX *c, const unsigned char *p)
{
  unsigned w[64], a, b, cc, d, e, f, g, h, t1, t2;
  for (int i = 0; i < 16; i++)
    w[i] = ((unsigned)p[i*4]<<24)|((unsigned)p[i*4+1]<<16)|((unsigned)p[i*4+2]<<8)|p[i*4+3];
  for (int i = 16; i < 64; i++) {
    unsigned s0 = ROTR32(w[i-15],7) ^ ROTR32(w[i-15],18) ^ (w[i-15]>>3);
    unsigned s1 = ROTR32(w[i-2],17) ^ ROTR32(w[i-2],19) ^ (w[i-2]>>10);
    w[i] = w[i-16] + s0 + w[i-7] + s1;
  }
  a=c->h[0]; b=c->h[1]; cc=c->h[2]; d=c->h[3]; e=c->h[4]; f=c->h[5]; g=c->h[6]; h=c->h[7];
  for (int i = 0; i < 64; i++) {
    unsigned S1 = ROTR32(e,6) ^ ROTR32(e,11) ^ ROTR32(e,25);
    unsigned ch = (e & f) ^ (~e & g);
    t1 = h + S1 + ch + sha256_k[i] + w[i];
    unsigned S0 = ROTR32(a,2) ^ ROTR32(a,13) ^ ROTR32(a,22);
    unsigned mj = (a & b) ^ (a & cc) ^ (b & cc);
    t2 = S0 + mj;
    h=g; g=f; f=e; e=d+t1; d=cc; cc=b; b=a; a=t1+t2;
  }
  c->h[0]+=a; c->h[1]+=b; c->h[2]+=cc; c->h[3]+=d;
  c->h[4]+=e; c->h[5]+=f; c->h[6]+=g; c->h[7]+=h;
}

void sha256_update(SHA256_CTX *c, const void *data, size_t len)
{
  const unsigned char *p = (const unsigned char*)data;
  c->len += len;
  if (c->rem) {
    size_t take = 64 - c->rem; if (take > len) take = len;
    memcpy(c->buf + c->rem, p, take);
    c->rem += take; p += take; len -= take;
    if (c->rem == 64) { sha256_block(c, c->buf); c->rem = 0; }
  }
  while (len >= 64) { sha256_block(c, p); p += 64; len -= 64; }
  if (len) { memcpy(c->buf, p, len); c->rem = len; }
}

void sha256_final(SHA256_CTX *c, unsigned char out[32])
{
  unsigned long long bits = c->len * 8;
  unsigned char pad = 0x80;
  sha256_update(c, &pad, 1);
  pad = 0;
  while (c->rem != 56) sha256_update(c, &pad, 1);
  unsigned char lenb[8];
  for (int i = 0; i < 8; i++) lenb[i] = (unsigned char)(bits >> (56 - i*8));
  sha256_update(c, lenb, 8);
  for (int i = 0; i < 8; i++) {
    out[i*4+0] = (unsigned char)(c->h[i]>>24); out[i*4+1] = (unsigned char)(c->h[i]>>16);
    out[i*4+2] = (unsigned char)(c->h[i]>>8);  out[i*4+3] = (unsigned char)(c->h[i]);
  }
}

void sha256(const void *data, size_t len, unsigned char out[32])
{
  SHA256_CTX c; sha256_init(&c); sha256_update(&c, data, len); sha256_final(&c, out);
}

/* ------------------------------------------------------------------ */
/*  HMAC-SHA256 + PBKDF2 (RFC 2104 / 2898, RAR5 flavor)                */
/* ------------------------------------------------------------------ */

static void hmac_sha256(const unsigned char *key, size_t keyLen,
                        const unsigned char *data, size_t dataLen,
                        unsigned char out[32])
{
  unsigned char k[64], kd[64], ih[32], oh[32];
  SHA256_CTX c;
  if (keyLen > 64) { sha256(key, keyLen, k); memset(k+32, 0, 32); }
  else { memcpy(k, key, keyLen); memset(k+keyLen, 0, 64-keyLen); }
  for (int i = 0; i < 64; i++) kd[i] = k[i] ^ 0x36;
  sha256_init(&c); sha256_update(&c, kd, 64); sha256_update(&c, data, dataLen);
  sha256_final(&c, ih);
  for (int i = 0; i < 64; i++) kd[i] = k[i] ^ 0x5c;
  sha256_init(&c); sha256_update(&c, kd, 64); sha256_update(&c, ih, 32);
  sha256_final(&c, oh);
  memcpy(out, oh, 32);
}

void rs_hmac_sha256(const unsigned char *key, size_t keyLen,
                    const unsigned char *data, size_t dataLen,
                    unsigned char out[32])
{
  hmac_sha256(key, keyLen, data, dataLen, out);
}

/* RAR5 pbkdf2: produces Key(32) + HashKey(32) + PswCheck(32 raw) */
static void pbkdf2_rar5(const char *pwd, const unsigned char salt[16],
                        unsigned iterLog2,
                        unsigned char key[32], unsigned char hashKey[32],
                        unsigned char pswCheckRaw[32])
{
  unsigned char saltData[16 + 4];
  memcpy(saltData, salt, 16);
  saltData[16] = saltData[17] = saltData[18] = 0; saltData[19] = 1; /* block #1 */

  unsigned char U1[32], U2[32], Fn[32];
  size_t plen = strlen(pwd);
  hmac_sha256((const unsigned char*)pwd, plen, saltData, 20, U1);
  memcpy(Fn, U1, 32);

  unsigned counts[3] = { (1u<<iterLog2) - 1, 16, 16 };
  unsigned char *outs[3] = { key, hashKey, pswCheckRaw };
  for (int i = 0; i < 3; i++) {
    for (unsigned j = 0; j < counts[i]; j++) {
      hmac_sha256((const unsigned char*)pwd, plen, U1, 32, U2);
      memcpy(U1, U2, 32);
      for (int k = 0; k < 32; k++) Fn[k] ^= U1[k];
    }
    memcpy(outs[i], Fn, 32);
  }
  memset(saltData, 0, sizeof saltData);
  memset(U1, 0, 32); memset(U2, 0, 32); memset(Fn, 0, 32);
}

int rarsdk_Rar5KDF(const char *utf8Password, const unsigned char salt[16],
                   unsigned int lg2Count,
                   unsigned char key[32], unsigned char hashKey[32],
                   unsigned char pswCheck[8])
{
  if (!utf8Password || !salt || lg2Count > 24) return RARSDK_E_PARAM;
  unsigned char raw[32];
  pbkdf2_rar5(utf8Password, salt, lg2Count, key, hashKey, raw);
  memset(pswCheck, 0, 8);
  for (int i = 0; i < 32; i++) pswCheck[i % 8] ^= raw[i];
  memset(raw, 0, 32);
  return RARSDK_OK;
}

/* ------------------------------------------------------------------ */
/*  BLAKE2sp (parallel 8x BLAKE2s) - matches RAR5 file checksums        */
/* ------------------------------------------------------------------ */
