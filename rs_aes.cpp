/* rs_aes.cpp - AES-128/192/256 CBC (FIPS-197 software implementation)
 * + RAR5 padding behavior (tail block uses previous full block as IV,
 * no standard padding).
 */
#include "rs_internal.h"
#include <time.h>

static const unsigned char AES_SBOX[256] = {
  0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
  0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
  0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
  0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
  0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
  0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
  0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
  0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
  0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
  0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
  0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
  0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
  0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
  0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
  0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
  0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16
};

/* Multiply in GF(2^8) */
static unsigned gmul(unsigned a, unsigned b)
{
  unsigned r = 0;
  while (b) {
    if (b & 1) r ^= a;
    a <<= 1;
    if (a & 0x100) a ^= 0x11b;
    b >>= 1;
  }
  return r;
}

static unsigned char inv_sbox[256];

static void build_inv_sbox(void)
{
  static int done = 0;
  if (done) return;
  for (int i = 0; i < 256; i++) inv_sbox[AES_SBOX[i]] = (unsigned char)i;
  done = 1;
}

#define GETU32(p) (((unsigned)(p)[0]<<24)|((unsigned)(p)[1]<<16)|((unsigned)(p)[2]<<8)|((unsigned)(p)[3]))
#define PUTU32(p,v) do { (p)[0]=(unsigned char)((v)>>24);(p)[1]=(unsigned char)((v)>>16);(p)[2]=(unsigned char)((v)>>8);(p)[3]=(unsigned char)(v);} while(0)

struct AES_KEYI {
  int nr;
  unsigned long enc[15*4];  /* 4-byte words, stored as host-endian 32-bit words */
  unsigned long dec[15*4];
};

/* expand into 32-bit words stored big-endian-normalized (host words) */
static int expand_words(struct AES_KEYI *k, const unsigned char *key, unsigned keyBits)
{
  int nk = keyBits/32, nr = nk+6;
  k->nr = nr;
  unsigned *w = (unsigned*)k->enc;
  for (int i = 0; i < nk; i++) w[i] = GETU32(key + 4*i);
  for (int i = nk; i < 4*(nr+1); i++) {
    unsigned t = w[i-1];
    if (i % nk == 0) {
      t = (t<<8)|(t>>24);                       /* RotWord */
      t = ((unsigned)AES_SBOX[(t>>24)&0xff]<<24) |
          ((unsigned)AES_SBOX[(t>>16)&0xff]<<16) |
          ((unsigned)AES_SBOX[(t>>8)&0xff]<<8)  |
           (unsigned)AES_SBOX[t&0xff];          /* SubWord */
      unsigned rc = 1;
      for (int q = 1; q < i/nk; q++) { rc <<= 1; if (rc & 0x100) rc = (rc ^ 0x11b) & 0xff; }
      t ^= rc << 24;
    } else if (nk > 6 && i % nk == 4) {
      t = ((unsigned)AES_SBOX[(t>>24)&0xff]<<24) |
          ((unsigned)AES_SBOX[(t>>16)&0xff]<<16) |
          ((unsigned)AES_SBOX[(t>>8)&0xff]<<8)  |
           (unsigned)AES_SBOX[t&0xff];
    }
    w[i] = w[i-nk] ^ t;
  }
  /* decrypt schedule */
  unsigned *dw = (unsigned*)k->dec;
  for (int i = 0; i < 4*(nr+1); i++) dw[i] = w[i];
  for (int r = 1; r < nr; r++) {
    for (int c = 0; c < 4; c++) {
      unsigned x = dw[4*r + c];
      unsigned b0=(x>>24)&0xff, b1=(x>>16)&0xff, b2=(x>>8)&0xff, b3=x&0xff;
      dw[4*r+c] = ((gmul(b0,14) ^ gmul(b1,11) ^ gmul(b2,13) ^ gmul(b3,9))<<24) |
                  ((gmul(b0,9)  ^ gmul(b1,14) ^ gmul(b2,11) ^ gmul(b3,13))<<16) |
                  ((gmul(b0,13) ^ gmul(b1,9)  ^ gmul(b2,14) ^ gmul(b3,11))<<8) |
                  ((gmul(b0,11) ^ gmul(b1,13) ^ gmul(b2,9)  ^ gmul(b3,14)));
    }
  }
  return nr;
}

static void add_round_key(unsigned st[4], const unsigned *w)
{
  /* state stored column-wise: st[col] = column */
  st[0]^=w[0]; st[1]^=w[1]; st[2]^=w[2]; st[3]^=w[3];
}

static void sub_bytes(unsigned st[4])
{
  for (int c = 0; c < 4; c++)
    st[c] = ((unsigned)AES_SBOX[(st[c]>>24)&0xff]<<24) |
            ((unsigned)AES_SBOX[(st[c]>>16)&0xff]<<16) |
            ((unsigned)AES_SBOX[(st[c]>>8)&0xff]<<8) |
             (unsigned)AES_SBOX[st[c]&0xff];
}

static void shift_rows(unsigned st[4])
{
  unsigned char s[16], out[16];
  for (int c = 0; c < 4; c++) PUTU32(s + 4*c, st[c]);
  for (int c = 0; c < 4; c++) {
    out[4*c+0] = s[4*((c+0)%4)+0];
    out[4*c+1] = s[4*((c+1)%4)+1];
    out[4*c+2] = s[4*((c+2)%4)+2];
    out[4*c+3] = s[4*((c+3)%4)+3];
  }
  for (int c = 0; c < 4; c++) st[c] = GETU32(out + 4*c);
}

static void shift_rows_inv(unsigned st[4])
{
  unsigned char s[16], out[16];
  for (int c = 0; c < 4; c++) PUTU32(s + 4*c, st[c]);
  for (int c = 0; c < 4; c++) {
    out[4*c+0] = s[4*((c-0+4)%4)+0];
    out[4*c+1] = s[4*((c-1+4)%4)+1];
    out[4*c+2] = s[4*((c-2+4)%4)+2];
    out[4*c+3] = s[4*((c-3+4)%4)+3];
  }
  for (int c = 0; c < 4; c++) st[c] = GETU32(out + 4*c);
}

static void mix_columns(unsigned st[4])
{
  for (int c = 0; c < 4; c++) {
    unsigned x = st[c];
    unsigned a0=(x>>24)&0xff, a1=(x>>16)&0xff, a2=(x>>8)&0xff, a3=x&0xff;
    st[c] = ((gmul(a0,2)^gmul(a1,3)^a2^a3)<<24) |
            ((a0^gmul(a1,2)^gmul(a2,3)^a3)<<16) |
            ((a0^a1^gmul(a2,2)^gmul(a3,3))<<8)  |
             (gmul(a0,3)^a1^a2^gmul(a3,2));
  }
}

static void mix_columns_inv(unsigned st[4])
{
  for (int c = 0; c < 4; c++) {
    unsigned x = st[c];
    unsigned a0=(x>>24)&0xff, a1=(x>>16)&0xff, a2=(x>>8)&0xff, a3=x&0xff;
    st[c] = ((gmul(a0,14)^gmul(a1,11)^gmul(a2,13)^gmul(a3,9))<<24) |
            ((gmul(a0,9)^gmul(a1,14)^gmul(a2,11)^gmul(a3,13))<<16) |
            ((gmul(a0,13)^gmul(a1,9)^gmul(a2,14)^gmul(a3,11))<<8) |
            ((gmul(a0,11)^gmul(a1,13)^gmul(a2,9)^gmul(a3,14)));
  }
}

static void sub_bytes_inv(unsigned st[4])
{
  build_inv_sbox();
  for (int c = 0; c < 4; c++)
    st[c] = ((unsigned)inv_sbox[(st[c]>>24)&0xff]<<24) |
            ((unsigned)inv_sbox[(st[c]>>16)&0xff]<<16) |
            ((unsigned)inv_sbox[(st[c]>>8)&0xff]<<8) |
             (unsigned)inv_sbox[st[c]&0xff];
}

static void aes_encrypt_block(const struct AES_KEYI *k, const unsigned char in[16], unsigned char out[16])
{
  unsigned st[4];
  const unsigned *w = (const unsigned*)k->enc;
  for (int c = 0; c < 4; c++) st[c] = GETU32(in + 4*c) ^ w[c];
  for (int r = 1; r < k->nr; r++) {
    sub_bytes(st); shift_rows(st); mix_columns(st); add_round_key(st, w + 4*r);
  }
  sub_bytes(st); shift_rows(st); add_round_key(st, w + 4*k->nr);
  for (int c = 0; c < 4; c++) PUTU32(out + 4*c, st[c]);
}

static void aes_decrypt_block(const struct AES_KEYI *k, const unsigned char in[16], unsigned char out[16])
{
  unsigned st[4];
  const unsigned *w = (const unsigned*)k->dec;
  for (int c = 0; c < 4; c++) st[c] = GETU32(in + 4*c) ^ w[4*k->nr + c];
  for (int r = k->nr-1; r > 0; r--) {
    shift_rows_inv(st); sub_bytes_inv(st);
    add_round_key(st, w + 4*r);
    mix_columns_inv(st);
  }
  shift_rows_inv(st); sub_bytes_inv(st); add_round_key(st, w);
  for (int c = 0; c < 4; c++) PUTU32(out + 4*c, st[c]);
}

/* ---------------- CBC with RAR5 tail semantics ------------------ */

int rs_aes_init(struct RARSDK_AES *ctx, int decrypt, const void *key, unsigned keyBits,
               const void *iv16)
{
  struct AES_KEYI *k = (struct AES_KEYI*)ctx->rk;
  memset(ctx, 0, sizeof *ctx);
  if (!expand_words(k, (const unsigned char*)key, keyBits)) return RARSDK_E_PARAM;
  ctx->decrypt = decrypt != 0;
  ctx->nr = k->nr;
  memcpy(ctx->iv, iv16, 16);
  ctx->have_next_iv = 0;
  ctx->processed = 0;
  return RARSDK_OK;
}

RARAPI RARSDK_AES* RARCALL rarsdk_AESInit(int encrypt, const void *key, unsigned keyBits,
                                          const void *iv16)
{
  RARSDK_AES *ctx = (RARSDK_AES*)malloc(sizeof(RARSDK_AES));
  if (!ctx) return NULL;
  if (rs_aes_init(ctx, !encrypt, key, keyBits, iv16) != RARSDK_OK) {
    free(ctx); return NULL;
  }
  return ctx;
}

RARAPI void RARCALL rarsdk_AESFree(RARSDK_AES *ctx)
{
  if (ctx) { memset(ctx, 0, sizeof *ctx); free(ctx); }
}

/* process whole buffer in CBC; if size%16!=0 the remainder 1..15 bytes are
   handled with RAR5 tail semantics via rs_aes_cbc_tail automatically. */
RARAPI void RARCALL rarsdk_AESProcess(RARSDK_AES *ctx, void *data, size_t size)
{
  struct AES_KEYI *k = (struct AES_KEYI*)ctx->rk;
  unsigned char *p = (unsigned char*)data;
  unsigned char iv[16];
  memcpy(iv, ctx->iv, 16);
  size_t full = size & ~(size_t)15;
  for (size_t off = 0; off < full; off += 16) {
    if (!ctx->decrypt) {
      for (int i = 0; i < 16; i++) p[off+i] ^= iv[i];
      aes_encrypt_block(k, p+off, p+off);
      memcpy(iv, p+off, 16);
    } else {
      unsigned char cur[16];
      memcpy(cur, p+off, 16);
      aes_decrypt_block(k, p+off, p+off);
      for (int i = 0; i < 16; i++) p[off+i] ^= iv[i];
      memcpy(iv, cur, 16);
    }
  }
  memcpy(ctx->iv, iv, 16);
  ctx->processed += full;

  size_t tail = size - full;
  if (tail > 0)
    rs_aes_cbc_tail(ctx, p + full, tail);
}

/* RAR5 tail: final 1..15 bytes are encrypted in place without growth.
 * The tail is zero-padded to 16, CBC-encrypted using the last full
 * ciphertext block as IV; only the first 'tail' bytes are stored.
 * This mirrors WinRAR's writer/UnRAR's reader behavior for packed
 * data tails. */
void rs_aes_cbc_tail(struct RARSDK_AES *ctx, void *data, size_t size)
{
  struct AES_KEYI *k = (struct AES_KEYI*)ctx->rk;
  unsigned char *p = (unsigned char*)data;
  if (ctx->decrypt) {
    unsigned char blk[16]; memset(blk, 0, 16);
    memcpy(blk, p, size);
    aes_decrypt_block(k, blk, blk);
    for (size_t i = 0; i < size; i++) p[i] = blk[i] ^ ctx->iv[i];
  } else {
    unsigned char blk[16]; memset(blk, 0, 16);
    memcpy(blk, p, size);
    for (int i = 0; i < 16; i++) blk[i] ^= ctx->iv[i];
    aes_encrypt_block(k, blk, blk);
    memcpy(p, blk, size);
    memcpy(ctx->iv, blk, 16);
  }
  ctx->processed += size;
}

void rs_aes_cbc(struct RARSDK_AES *ctx, void *data, size_t size)
{
  rarsdk_AESProcess(ctx, data, size);
}

/* ------------- random bytes ------------- */
#ifdef _WIN32
#include <wincrypt.h>
void rs_rand_bytes(unsigned char *buf, size_t n)
{
  static HCRYPTPROV prov = 0;
  if (!prov) {
    if (!CryptAcquireContextW(&prov, NULL, NULL, PROV_RSA_FULL,
                              CRYPT_VERIFYCONTEXT | CRYPT_SILENT))
      prov = (HCRYPTPROV)-1;
  }
  if (prov != (HCRYPTPROV)-1 && CryptGenRandom(prov, (DWORD)n, buf))
    return;
  /* fallback */
  unsigned long long s = (unsigned long long)time(NULL) ^ (unsigned long long)(size_t)buf;
  for (size_t i = 0; i < n; i++) {
    s = s * 6364136223846793005ULL + 1442695040888963407ULL;
    buf[i] = (unsigned char)(s >> 33);
  }
}
#else
#include <time.h>
void rs_rand_bytes(unsigned char *buf, size_t n)
{
  FILE *f = fopen("/dev/urandom","rb");
  if (f) { size_t got = fread(buf,1,n,f); fclose(f); if (got==n) return; }
  unsigned long long s = (unsigned long long)time(NULL) ^ (unsigned long long)(size_t)buf;
  for (size_t i = 0; i < n; i++) {
    s = s*6364136223846793005ULL+1442695040888963407ULL;
    buf[i]=(unsigned char)(s>>33);
  }
}
#endif
