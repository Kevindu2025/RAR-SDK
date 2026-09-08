/* rrparse6.c - identify mystery[0..8) (deterministic) and verify crcA/crcB over regions
   including mystery bytes */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

static uint32_t crct[256];
static void init_crc(void) {
  for (uint32_t i = 0; i < 256; i++) {
    uint32_t c = i;
    for (int k = 0; k < 8; k++) c = (c & 1) ? (c >> 1) ^ 0xEDB88320u : c >> 1;
    crct[i] = c;
  }
}
static uint32_t crc_upd(uint32_t crc, const uint8_t *p, size_t n) {
  while (n--) crc = crct[(crc ^ *p++) & 0xff] ^ (crc >> 8);
  return crc;
}
static uint64_t rd64(const uint8_t *p) { uint64_t v; memcpy(&v, p, 8); return v; }
static uint32_t rd32(const uint8_t *p) { uint32_t v; memcpy(&v, p, 4); return v; }
static uint16_t rd16(const uint8_t *p) { uint16_t v; memcpy(&v, p, 2); return v; }

int main(int argc, char **argv)
{
  init_crc();
  for (int a = 1; a < argc; a++) {
    FILE *f = fopen(argv[a], "rb");
    fseek(f, 0, SEEK_END); long fsz = ftell(f); fseek(f, 0, SEEK_SET);
    uint8_t *b = malloc(fsz); if (fread(b, 1, fsz, f) != (size_t)fsz) return 1; fclose(f);

    long pos = 8, rrStart = -1, rrSub = -1, rrSubLen = 0;
    while (pos < fsz - 3) {
      long bs = pos;
      pos += 4;
      uint64_t hs = 0; unsigned sh = 0;
      while (pos < fsz) { uint8_t c = b[pos++]; hs |= (uint64_t)(c & 0x7f) << sh; sh += 7; if (!(c & 0x80)) break; }
      long hdrEnd = pos + hs;
      uint64_t t = 0; sh = 0;
      while (pos < fsz) { uint8_t c = b[pos++]; t |= (uint64_t)(c & 0x7f) << sh; sh += 7; if (!(c & 0x80)) break; }
      uint64_t flags = 0; sh = 0;
      while (pos < fsz) { uint8_t c = b[pos++]; flags |= (uint64_t)(c & 0x7f) << sh; sh += 7; if (!(c & 0x80)) break; }
      uint64_t extra = 0, data = 0;
      if (flags & 1) { sh = 0; while (pos < fsz) { uint8_t c = b[pos++]; extra |= (uint64_t)(c&0x7f)<<sh; sh+=7; if(!(c&0x80))break; } }
      if (flags & 2) { sh = 0; while (pos < fsz) { uint8_t c = b[pos++]; data |= (uint64_t)(c&0x7f)<<sh; sh+=7; if(!(c&0x80))break; } }
      if (t == 3) { rrStart = bs; rrSub = hdrEnd; rrSubLen = data; }
      pos = hdrEnd + data;
    }
    uint8_t *sd = b + rrSub;
    uint32_t crcA = rd32(sd+4), crcB = rd32(sd+8);
    uint64_t myst0 = rd64(sd+64), myst1 = rd64(sd+72);
    printf("== %s RR@%ld subLen=%ld crcA=%08X crcB=%08X myst0=%016llX myst1=%016llX\n",
           argv[a], rrStart, rrSubLen, crcA, crcB,
           (unsigned long long)myst0, (unsigned long long)myst1);

    /* deterministic part myst0: test hashes of covered area and of fields */
    uint32_t cov0 = crc_upd(0, b, rrStart);
    uint32_t covI = ~crc_upd(0xffffffff, b, rrStart);
    uint32_t f0 = crc_upd(0, sd+16, 48);
    uint32_t fI = ~crc_upd(0xffffffff, sd+16, 48);
    printf("cov crc0=%08X ~cov=%08X | fld crc0=%08X ~fld=%08X\n", cov0, covI, f0, fI);
    printf("myst0 lo=%08X hi=%08X  cov=%08X\n", (uint32_t)myst0, (uint32_t)(myst0>>32), cov0);
    /* maybe myst0 = two crc32 of halves? */
    uint32_t c1 = crc_upd(0, b, rrStart/2);
    uint32_t c2 = crc_upd(0, b+rrStart/2, rrStart-rrStart/2);
    printf("halves: %08X %08X\n", c1, c2);
    /* crcA/crcB candidates with mystery included */
    {
      /* ECC region */
      long Xpad = (long)rd32(sd+42);
      long eccOff = 80;
      /* try crcA = crc32 over [0..80)+? or [16..80)+ECC? */
      uint32_t t1 = crc_upd(0, sd+16, 64 + Xpad);
      uint32_t t2 = ~crc_upd(0xffffffff, sd+16, 64 + Xpad);
      uint32_t t3 = crc_upd(0, sd+80, Xpad);
      uint32_t t4 = ~crc_upd(0xffffffff, sd+80, Xpad);
      uint32_t t5 = crc_upd(0, sd, 16);
      uint32_t t6 = crc_upd(0, sd+16, 64);
      uint32_t t7 = crc_upd(0, sd, 80 + Xpad);
      uint32_t t8 = ~crc_upd(0xffffffff, sd, 80 + Xpad);
      uint32_t t9 = crc_upd(0, sd+64, 16);
      uint32_t t10 = ~crc_upd(0xffffffff, sd+64, 16);
      uint32_t t11 = crc_upd(0, sd+72, 8);
      uint32_t t12 = ~crc_upd(0xffffffff, sd+72, 8);
      uint32_t t13 = crc_upd(0, b, rrStart + (rrStart&1));
      uint32_t t14 = crc_upd(0, sd+80, Xpad - (Xpad & 1));
      printf("cand crcA: f16_80_ECC=%08X i=%08X ECC0=%08X ECCi=%08X hdr=%08X fld=%08X rec=%08X reci=%08X myst=%08X/%08X rnd=%08X/%08X covpad=%08X eccnopad=%08X\n",
             t1, t2, t3, t4, t5, t6, t7, t8, t9, t10, t11, t12, t13, t14);
    }
  }
  return 0;
}
