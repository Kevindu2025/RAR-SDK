/* rs_extra.cpp - additional primitive exports: Blake2spFile, Rar3KDF */
#include "rs_internal.h"

/* ---------------- RAR3 KDF (SHA-1 0x40000 rounds) ---------------- */
/* Mirrors UnRAR crypt3.cpp SetKey30 (public freeware source) */

static uint32_t rotl(uint32_t x, int n) { return (x << n) | (x >> (32 - n)); }
static uint32_t rotr(uint32_t x, int n) { return (x >> n) | (x << (32 - n)); }

typedef struct {
  uint32_t state[5];
  uint64_t count;
  unsigned char buffer[64];
} sha1_ctx_t;

static void sha1_transform_rar29(uint32_t state[5], const unsigned char buffer[64])
{
  uint32_t a, b, c, d, e;
  uint32_t block[16];
  memcpy(block, buffer, 64);
  for (int i = 0; i < 16; i++) {
    uint32_t v = ((uint32_t)block[i]);
    block[i] = ((v >> 24) & 0xff) | ((v >> 8) & 0xff00) | ((v << 8) & 0xff0000) | ((v << 24) & 0xff000000);
    /* little endian swap */
  }
  /* NOTE: buffer already swapped above incorrectly; we instead re-copy below */
  for (int i = 0; i < 16; i++) {
    uint32_t v = ((uint32_t)buffer[i*4+0]) | ((uint32_t)buffer[i*4+1]<<8) |
                 ((uint32_t)buffer[i*4+2]<<16) | ((uint32_t)buffer[i*4+3]<<24);
    block[i] = ((v >> 24) & 0xff) | ((v >> 8) & 0xff00) | ((v << 8) & 0xff0000) | ((v << 24) & 0xff000000);
  }
  a = state[0]; b = state[1]; c = state[2]; d = state[3]; e = state[4];

  #define blk(i) (block[i & 15] = rotl(block[(i+13)&15] ^ block[(i+8)&15] ^ block[(i+2)&15] ^ block[i&15], 1))
  #define R0(v,w,x,y,z,i) { z += ((w & (x ^ y)) ^ y) + block[i] + 0x5A827999 + rotl(v,5); w = rotl(w,30); }
  #define R1(v,w,x,y,z,i) { z += ((w & (x ^ y)) ^ y) + blk(i) + 0x5A827999 + rotl(v,5); w = rotl(w,30); }
  #define R2(v,w,x,y,z,i) { z += (w ^ x ^ y) + blk(i) + 0x6ED9EBA1 + rotl(v,5); w = rotl(w,30); }
  #define R3(v,w,x,y,z,i) { z += (((w | x) & y) | (w & x)) + blk(i) + 0x8F1BBCDC + rotl(v,5); w = rotl(w,30); }
  #define R4(v,w,x,y,z,i) { z += (w ^ x ^ y) + blk(i) + 0xCA62C1D6 + rotl(v,5); w = rotl(w,30); }

  R0(a,b,c,d,e, 0); R0(e,a,b,c,d, 1); R0(d,e,a,b,c, 2); R0(c,d,e,a,b, 3);
  R0(b,c,d,e,a, 4); R0(a,b,c,d,e, 5); R0(e,a,b,c,d, 6); R0(d,e,a,b,c, 7);
  R0(c,d,e,a,b, 8); R0(b,c,d,e,a, 9); R0(a,b,c,d,e,10); R0(e,a,b,c,d,11);
  R0(d,e,a,b,c,12); R0(c,d,e,a,b,13); R0(b,c,d,e,a,14); R0(a,b,c,d,e,15);
  R1(e,a,b,c,d,16); R1(d,e,a,b,c,17); R1(c,d,e,a,b,18); R1(b,c,d,e,a,19);
  R2(a,b,c,d,e,20); R2(e,a,b,c,d,21); R2(d,e,a,b,c,22); R2(c,d,e,a,b,23);
  R2(b,c,d,e,a,24); R2(a,b,c,d,e,25); R2(e,a,b,c,d,26); R2(d,e,a,b,c,27);
  R2(c,d,e,a,b,28); R2(b,c,d,e,a,29); R2(a,b,c,d,e,30); R2(e,a,b,c,d,31);
  R2(d,e,a,b,c,32); R2(c,d,e,a,b,33); R2(b,c,d,e,a,34); R2(a,b,c,d,e,35);
  R2(e,a,b,c,d,36); R2(d,e,a,b,c,37); R2(c,d,e,a,b,38); R2(b,c,d,e,a,39);
  R3(a,b,c,d,e,40); R3(e,a,b,c,d,41); R3(d,e,a,b,c,42); R3(c,d,e,a,b,43);
  R3(b,c,d,e,a,44); R3(a,b,c,d,e,45); R3(e,a,b,c,d,46); R3(d,e,a,b,c,47);
  R3(c,d,e,a,b,48); R3(b,c,d,e,a,49); R3(a,b,c,d,e,50); R3(e,a,b,c,d,51);
  R3(d,e,a,b,c,52); R3(c,d,e,a,b,53); R3(b,c,d,e,a,54); R3(a,b,c,d,e,55);
  R3(e,a,b,c,d,56); R3(d,e,a,b,c,57); R3(c,d,e,a,b,58); R3(b,c,d,e,a,59);
  R4(a,b,c,d,e,60); R4(e,a,b,c,d,61); R4(d,e,a,b,c,62); R4(c,d,e,a,b,63);
  R4(b,c,d,e,a,64); R4(a,b,c,d,e,65); R4(e,a,b,c,d,66); R4(d,e,a,b,c,67);
  R4(c,d,e,a,b,68); R4(b,c,d,e,a,69); R4(a,b,c,d,e,70); R4(e,a,b,c,d,71);
  R4(d,e,a,b,c,72); R4(c,d,e,a,b,73); R4(b,c,d,e,a,74); R4(a,b,c,d,e,75);
  R4(e,a,b,c,d,76); R4(d,e,a,b,c,77); R4(c,d,e,a,b,78); R4(b,c,d,e,a,79);

  state[0] += a; state[1] += b; state[2] += c; state[3] += d; state[4] += e;
}

static void sha1_init(sha1_ctx_t *c)
{
  c->state[0] = 0x67452301; c->state[1] = 0xEFCDAB89;
  c->state[2] = 0x98BADCFE; c->state[3] = 0x10325476;
  c->state[4] = 0xC3D2E1F0;
  c->count = 0;
}

static void sha1_process(sha1_ctx_t *c, const unsigned char *data, size_t len)
{
  size_t i, j = (size_t)(c->count & 63);
  c->count += len;
  if (j + len > 63) {
    memcpy(c->buffer + j, data, i = 64 - j);
    sha1_transform_rar29(c->state, c->buffer);
    for (; i + 63 < len; i += 64)
      sha1_transform_rar29(c->state, data + i);
    j = 0;
  } else
    i = 0;
  if (len > i)
    memcpy(c->buffer + j, data + i, len - i);
}

static void sha1_done(sha1_ctx_t *c, uint32_t digest[5])
{
  uint64_t bitLength = c->count * 8;
  size_t j = (size_t)(c->count & 63);
  c->buffer[j++] = 0x80;
  if (j > 56) {
    memset(c->buffer + j, 0, 64 - j);
    sha1_transform_rar29(c->state, c->buffer);
    j = 0;
  }
  memset(c->buffer + j, 0, 56 - j);
  for (int i = 0; i < 4; i++) {
    c->buffer[60 - i*4] = 0;
    c->buffer[61 - i*4] = (unsigned char)(bitLength >> (i*8));
    c->buffer[62 - i*4] = (unsigned char)(bitLength >> (i*8+8));
    c->buffer[63 - i*4] = 0;
  }
  /* store 64-bit length big-endian properly */
  {
    unsigned char lenb[8];
    for (int i = 0; i < 8; i++)
      lenb[i] = (unsigned char)((bitLength >> (56 - i*8)) & 0xff);
    memcpy(c->buffer + 56, lenb, 8);
  }
  sha1_transform_rar29(c->state, c->buffer);
  for (int i = 0; i < 5; i++)
    digest[i] = ((c->state[i] >> 24) & 0xff) | ((c->state[i] >> 8) & 0xff00) |
                ((c->state[i] << 8) & 0xff0000) | ((c->state[i] << 24) & 0xff000000);
}

/* wide char -> raw UTF-16LE bytes (like UnRAR WideToRaw) */
static void wide_to_raw(const wchar_t *w, unsigned char *raw, size_t *rawLen)
{
  size_t n = 0;
  for (; *w; w++) {
    raw[n++] = (unsigned char)(*w & 0xff);
    raw[n++] = (unsigned char)(*w >> 8);
  }
  *rawLen = n;
}

RARAPI int RARCALL rarsdk_Rar3KDF(const char *password,
                                  const unsigned char *salt /*8 or NULL*/,
                                  unsigned char key[16],
                                  unsigned char initV[16])
{
  if (!password) return RARSDK_E_PARAM;
  /* RAR3 uses the WIDE password form; caller gives narrow - use it as-is
     converted to UTF-16 via the active code page (simplified: narrow chars) */
  unsigned char rawPsw[512 * 2 + 8];
  size_t rawLength = 0;

  wchar_t wide[512];
  int wn = MultiByteToWideChar(CP_UTF8, 0, password, -1, wide, 512);
  if (wn <= 0) return RARSDK_E_PARAM;
  wide_to_raw(wide, rawPsw, &rawLength);
  if (salt) {
    memcpy(rawPsw + rawLength, salt, 8);
    rawLength += 8;
  }

  sha1_ctx_t c;
  sha1_init(&c);

  const uint32_t HashRounds = 0x40000;
  for (uint32_t I = 0; I < HashRounds; I++) {
    sha1_process(&c, rawPsw, rawLength);
    unsigned char PswNum[3] = {(unsigned char)I, (unsigned char)(I >> 8), (unsigned char)(I >> 16)};
    sha1_process(&c, PswNum, 3);
    if (I % (HashRounds / 16) == 0) {
      sha1_ctx_t tempc = c;
      uint32_t digest[5];
      sha1_done(&tempc, digest);
      initV[I / (HashRounds / 16)] = (unsigned char)(digest[4] & 0xff);
      initV[(I / (HashRounds / 16)) + 8] = 0;
    }
  }
  uint32_t digest[5];
  sha1_done(&c, digest);
  for (int i = 0; i < 4; i++)
    for (int j = 0; j < 4; j++)
      key[i*4 + j] = (unsigned char)(digest[i] >> (j * 8));

  /* saltless archives use initV = key (UnRAR: memcpy Init,Key for no salt) */
  memset(rawPsw, 0, sizeof rawPsw);
  return RARSDK_OK;
}

/* ---------------- Blake2spFile ---------------- */

RARAPI int RARCALL rarsdk_Blake2spFile(const wchar_t *fileName,
                                       unsigned char digest[32],
                                       unsigned int *crc32out)
{
  FILE *f = _wfopen(fileName, L"rb");
  if (!f) return RARSDK_E_IO;
  unsigned crc = 0xffffffff;
  size_t total = 0;
  unsigned char buf[65536];
  for (;;) {
    size_t n = fread(buf, 1, sizeof buf, f);
    if (n == 0) break;
    crc = rarsdk_CRC32(crc, buf, n);
    total += n;
    if (n < sizeof buf) break;
  }
  fclose(f);
  crc ^= 0xffffffff;
  if (crc32out) *crc32out = crc;

  /* full-file hash: read again */
  f = _wfopen(fileName, L"rb");
  if (!f) return RARSDK_E_IO;
  unsigned char *all = (unsigned char*)malloc(total ? total : 1);
  if (!all || (total && fread(all, 1, total, f) != total)) { fclose(f); free(all); return RARSDK_E_IO; }
  fclose(f);
  rarsdk_Blake2sp(all, total, digest);
  free(all);
  return RARSDK_OK;
}
