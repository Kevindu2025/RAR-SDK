/* rrmk2.c - correct rebuild: MAIN w/ locator + copied file blocks + RR + ENDARC
   (with solved CRC64 checksums: crcA/crcB = halves of one CRC64 chain) */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

static uint32_t crct[256];
static uint64_t crc64t[256];
static void init_tables(void) {
  for (uint32_t i = 0; i < 256; i++) {
    uint32_t c = i;
    for (int k = 0; k < 8; k++) c = (c & 1) ? (c >> 1) ^ 0xEDB88320u : c >> 1;
    crct[i] = c;
    uint64_t c64 = i;
    for (int k = 0; k < 8; k++) c64 = (c64 & 1) ? (c64 >> 1) ^ 0xC96C5795D7870F42ULL : c64 >> 1;
    crc64t[i] = c64;
  }
}
static uint32_t crc_upd(uint32_t crc, const uint8_t *p, size_t n) {
  while (n--) crc = crct[(crc ^ *p++) & 0xff] ^ (crc >> 8);
  return crc;
}
static uint64_t crc64_upd(uint64_t crc, const uint8_t *p, size_t n) {
  while (n--) crc = crc64t[(crc ^ *p++) & 0xff] ^ (crc >> 8);
  return crc;
}
static void put32(uint8_t *p, uint32_t v) { memcpy(p, &v, 4); }
static size_t put_vint(uint8_t *p, uint64_t v)
{
  size_t n = 0; uint8_t tmp[10];
  do { uint8_t c = v & 0x7f; v >>= 7; if (v) c |= 0x80; tmp[n++] = c; } while (v);
  memcpy(p, tmp, n);
  return n;
}
static void put_vint5(uint8_t *p, uint64_t v)
{
  p[0] = (uint8_t)(v & 0x7f) | 0x80;
  p[1] = (uint8_t)((v >> 7) & 0x7f) | 0x80;
  p[2] = (uint8_t)((v >> 14) & 0x7f) | 0x80;
  p[3] = (uint8_t)((v >> 21) & 0x7f) | 0x80;
  p[4] = (uint8_t)((v >> 28) & 0x7f);
}

int main(int argc, char **argv)
{
  init_tables();
  const char *inName = argv[1], *outName = argv[2];
  FILE *f = fopen(inName, "rb");
  fseek(f, 0, SEEK_END); long fsz = ftell(f); fseek(f, 0, SEEK_SET);
  uint8_t *b = malloc(fsz);
  if (fread(b, 1, fsz, f) != (size_t)fsz) return 1;
  fclose(f);

  /* ---- parse old MAIN size (at offset 8) ---- */
  long oldMainTotal;
  {
    long p = 12; uint64_t hs = 0; unsigned sh = 0;
    while (1) { uint8_t c = b[p++]; hs |= (uint64_t)(c & 0x7f) << sh; sh += 7; if (!(c & 0x80)) break; }
    oldMainTotal = 4 + (sh/7) + (long)hs;
  }
  long filesOff = 8 + oldMainTotal;
  long filesLen = fsz - filesOff;

  /* ---- sizes ---- */
  long newMainTotal = 4 + 1 + 17;
  long rrStart = 8 + newMainTotal + filesLen;
  long rrRel = rrStart - 8;

  /* ---- build new MAIN ---- */
  uint8_t mainh[64]; size_t mp = 0;
  uint32_t mcrc;
  mainh[mp++] = 17;
  mainh[mp++] = 1;
  mainh[mp++] = 5;
  mainh[mp++] = 13;
  mainh[mp++] = 8;     /* PROTECT */
  mainh[mp++] = 12;
  mainh[mp++] = 1;
  mainh[mp++] = 3;
  put_vint5(mainh + mp, 0); mp += 5;
  put_vint5(mainh + mp, (uint64_t)rrRel); mp += 5;
  mcrc = ~crc_upd(0xffffffff, mainh, mp);

  /* ---- RR subdata ---- */
  long X = rrStart;
  long Xpad = X + (X & 1);
  long subLen = 80 + Xpad;
  uint8_t *sd = calloc(1, subLen);
  put32(sd + 16, 0x50);
  sd[20] = 1; sd[21] = 1;
  put32(sd + 30, (uint32_t)X);
  put32(sd + 34, (uint32_t)X);
  put32(sd + 38, 0);
  put32(sd + 42, (uint32_t)Xpad);
  put32(sd + 46, 0);
  put32(sd + 50, (uint32_t)subLen);
  put32(sd + 54, 0);
  sd[58] = 1; sd[59] = 0;
  sd[60] = 1; sd[61] = 0;
  sd[62] = 0; sd[63] = 0;
  /* mystery1 random-ish (use time) */
  uint64_t m1 = (uint64_t)(uintptr_t)&subLen ^ (uint64_t)time(NULL) * 0x9E3779B97F4A7C15ULL;
  m1 ^= m1 >> 29; m1 *= 0xBF58476D1CE4E5B9ULL; m1 ^= m1 >> 32;
  memcpy(sd + 72, &m1, 8);

  /* ---- RR service header ---- */
  uint8_t rrh[64]; size_t rp = 0;
  size_t bn = 0; uint8_t body[32];
  body[bn++] = 0;
  bn += put_vint(body + bn, (uint64_t)subLen);
  body[bn++] = 0;
  body[bn++] = 0x80; body[bn++] = 0x00;
  body[bn++] = 0;
  body[bn++] = 2;
  body[bn++] = 'R'; body[bn++] = 'R';
  uint8_t extra[3] = {0x02, 0x07, 0x03};
  uint8_t dsV[10]; size_t dn = 0;
  { uint64_t v = (uint64_t)subLen; do { uint8_t c = v & 0x7f; v >>= 7; if (v) c |= 0x80; dsV[dn++] = c; } while (v); }
  rrh[rp++] = 3;
  rrh[rp++] = 7;
  rrh[rp++] = 3;
  memcpy(rrh + rp, dsV, dn); rp += dn;
  memcpy(rrh + rp, body, bn); rp += bn;
  memcpy(rrh + rp, extra, 3); rp += 3;
  size_t rrHdrSize = rp;
  size_t rrHdrTotal = 1 + 4 + rrHdrSize;

  /* ---- ENDARC ---- */
  uint8_t endh[16]; size_t ep2 = 0;
  uint8_t eblk[4]; size_t eb = 0;
  eblk[eb++] = 5; eblk[eb++] = 0x04; eblk[eb++] = 0;
  endh[ep2++] = (uint8_t)eb;
  memcpy(endh + ep2, eblk, eb); ep2 += eb;
  uint32_t ecrc = ~crc_upd(0xffffffff, endh, ep2);
  size_t endTotal = 4 + ep2;

  /* ---- assemble output ---- */
  long outLen = rrStart + rrHdrTotal + subLen + endTotal;
  uint8_t *outb = malloc(outLen);
  long op = 0;
  memcpy(outb + op, b, 8); op += 8;
  put32(outb + op, mcrc); op += 4;
  memcpy(outb + op, mainh, mp); op += mp;
  memcpy(outb + op, b + filesOff, filesLen); op += filesLen;  /* op == rrStart */

  /* fill ECC over [0..rrStart) of OUTPUT */
  memcpy(sd + 80, outb, X);
  if (X & 1) sd[80 + X] = 0;

  /* mystery0 = crc64(0, covered) */
  uint64_t m0 = crc64_upd(0, outb, X);
  memcpy(sd + 64, &m0, 8);

  /* magic + subLen + CRC64 chain */
  put32(sd + 0, 0x7D42527B);
  put32(sd + 12, (uint32_t)subLen);
  {
    uint64_t seed = crc64_upd(~(uint64_t)0, sd + 12, 68);
    uint64_t r = ~crc64_upd(seed, sd + 80, Xpad);
    put32(sd + 4, (uint32_t)r);
    put32(sd + 8, (uint32_t)(r >> 32));
  }

  /* RR header */
  { uint8_t h[64]; size_t hp = 0;
    hp += put_vint(h, (uint64_t)rrHdrSize);
    memcpy(h + hp, rrh, rrHdrSize); hp += rrHdrSize;
    uint32_t hcrc = ~crc_upd(0xffffffff, h, hp);
    put32(outb + op, hcrc); op += 4;
    memcpy(outb + op, h, hp); op += hp;
  }
  memcpy(outb + op, sd, subLen); op += subLen;
  /* ENDARC */
  put32(outb + op, ecrc); op += 4;
  memcpy(outb + op, endh, ep2); op += ep2;

  FILE *o = fopen(outName, "wb");
  fwrite(outb, 1, outLen, o);
  fclose(o);
  printf("ok: rrStart=%ld rrRel=%ld X=%ld Xpad=%ld subLen=%ld outLen=%ld m0=%016llX\n",
         rrStart, rrRel, X, Xpad, subLen, outLen, (unsigned long long)m0);
  return 0;
}

