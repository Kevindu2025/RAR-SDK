/* rrcrc.c - test mystery0 = CRC64 of covered? and identify crcA/crcB formulas.
   Samples: tiny(covered83): m0=ACBE037E197E1D3C crcA=98997167 crcB=1D0DC305
            big(452):        m0=C01DE09F4AD69E7F crcA=47AB7F47 crcB=C0E5E05E
            ref2(807):       m0=66AB5C6FDAC05808 crcA=74344D88 crcB=37F4D7FF
*/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

static uint32_t crct[256];
static uint64_t crc64t[256];
static void init_tables(void) {
  for (int i = 0; i < 256; i++) {
    uint32_t c = i;
    for (int k = 0; k < 8; k++) c = (c & 1) ? (c >> 1) ^ 0xEDB88320u : c >> 1;
    crct[i] = c;
    uint64_t c64 = i;
    for (int k = 0; k < 8; k++) c64 = (c64 & 1) ? (c64 >> 1) ^ 0xC96C5795D7870F42ULL : c64 >> 1;
    crc64t[i] = c64;
  }
}
static uint32_t crc32_upd(uint32_t crc, const uint8_t *p, size_t n) {
  while (n--) crc = crct[(crc ^ *p++) & 0xff] ^ (crc >> 8);
  return crc;
}
static uint64_t crc64_upd(uint64_t crc, const uint8_t *p, size_t n) {
  while (n--) crc = crc64t[(crc ^ *p++) & 0xff] ^ (crc >> 8);
  return crc;
}
static uint64_t rd64(const uint8_t *p) { uint64_t v; memcpy(&v, p, 8); return v; }
static uint32_t rd32(const uint8_t *p) { uint32_t v; memcpy(&v, p, 4); return v; }

int main(int argc, char **argv)
{
  init_tables();
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
    uint64_t m0 = rd64(sd+64), m1 = rd64(sd+72);
    uint32_t crcA = rd32(sd+4), crcB = rd32(sd+8);
    printf("== %s cov=%ld m0=%016llX m1=%016llX crcA=%08X crcB=%08X\n",
           argv[a], rrStart, (unsigned long long)m0, (unsigned long long)m1, crcA, crcB);

    /* mystery0 hypotheses */
    uint64_t c64 = crc64_upd(~(uint64_t)0, b, rrStart) ^ ~(uint64_t)0;  /* standard crc64 */
    uint64_t c64b = crc64_upd(0, b, rrStart);
    uint64_t c64c = ~crc64_upd(~(uint64_t)0, b, rrStart);
    printf("  crc64 std=%016llX raw0=%016llX inv=%016llX\n",
           (unsigned long long)c64, (unsigned long long)c64b, (unsigned long long)c64c);
    /* crc64 of ECC region */
    long Xpad = (long)rd32(sd+42);
    uint64_t e64 = crc64_upd(~(uint64_t)0, sd+80, Xpad) ^ ~(uint64_t)0;
    printf("  crc64 ECC=%016llX (Xpad=%ld)\n", (unsigned long long)e64, Xpad);
    /* maybe m0 = crc64 over covered in slices? ND=1 -> single... */
    /* maybe m0 = (crc64 of record fields)? */
    uint64_t f64 = crc64_upd(~(uint64_t)0, sd+16, 48) ^ ~(uint64_t)0;
    printf("  crc64 fields=%016llX\n", (unsigned long long)f64);

    /* crcA/crcB with m0/m1 knowledge: maybe crcA = crc32 over [16..80)+ECC? */
    uint32_t c1 = crc32_upd(0, sd+16, 64 + Xpad);
    uint32_t c2 = crc32_upd(0xffffffff, sd+16, 64 + Xpad);
    printf("  crc32(f16..ECC end) c0=%08X cF=%08X (~%08X)\n", c1, c2, ~c2);
    /* chain: v40 = crc32(-1, m1?) then over fields? over ECC? */
    for (int use = 0; use < 4; use++) {
      uint32_t seed;
      if (use == 0) { uint8_t t8[8]; memcpy(t8, &m1, 8); seed = crc32_upd(0xffffffff, t8, 8); }
      else if (use == 1) { uint8_t t8[8]; memcpy(t8, &m0, 8); seed = crc32_upd(0xffffffff, t8, 8); }
      else if (use == 2) { uint8_t t8[16]; memcpy(t8, sd+64, 16); seed = crc32_upd(0xffffffff, t8, 16); }
      else { uint8_t t8[16]; memcpy(t8, sd+64, 16); seed = crc32_upd(0, t8, 16); }
      uint32_t r1 = ~crc32_upd(seed, sd+16, 48);
      uint32_t r2 = ~crc32_upd(seed, sd+16, 64);
      uint32_t r3 = ~crc32_upd(seed, sd+80, Xpad);
      uint32_t r4 = ~crc32_upd(seed, sd+16, 64 + Xpad);
      uint32_t r5 = crc32_upd(seed, sd+16, 64);
      uint32_t r6 = crc32_upd(seed, sd+80, Xpad);
      printf("  seed%d=%08X: f48=%08X f64=%08X ecc=%08X fe=%08X | f64d=%08X eccd=%08X\n",
             use, seed, r1, r2, r3, r4, r5, r6);
    }
  }
  return 0;
}
