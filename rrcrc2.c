/* rrcrc2.c - verify crcA = ~crc64(chain over v58/v59 sizes, ECC) + solve crcB + m1 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

static uint64_t crc64t[256];
static void init_tables(void) {
  for (int i = 0; i < 256; i++) {
    uint64_t c = i;
    for (int k = 0; k < 8; k++) c = (c & 1) ? (c >> 1) ^ 0xC96C5795D7870F42ULL : c >> 1;
    crc64t[i] = c;
  }
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
    uint32_t crcA = rd32(sd+4), crcB = rd32(sd+8);
    long X = rrStart, Xpad = X + (X & 1);
    long eccLen = Xpad;
    long subLen = rrSubLen;
    uint64_t m0 = rd64(sd+64), m1 = rd64(sd+72);
    printf("== %s crcA=%08X crcB=%08X m0=%016llX m1=%016llX X=%ld Xpad=%ld subLen=%ld\n",
           argv[a], crcA, crcB, (unsigned long long)m0, (unsigned long long)m1, X, Xpad, subLen);

    /* writer: v58 = v37 + v36 ; v59 = v36
       v36 = 16 + extracted  = record size = subLen? (extracted = subLen-16)
       v37 = ecc chunk size
       v40 = crc64(0xFFFFFFFFFFFFFFFF, [v58 v59], 8)
       crcA = ~crc64(v40, ecc, v37)
       Try: v36 = subLen, v37 = eccLen, v58 = subLen+eccLen */
    {
      uint8_t sz[8];
      uint32_t lo, hi;
      lo = (uint32_t)(subLen + eccLen); hi = (uint32_t)subLen;
      memcpy(sz, &lo, 4); memcpy(sz+4, &hi, 4);
      uint64_t v40 = crc64_upd(~(uint64_t)0, sz, 8);
      uint64_t cA64 = ~crc64_upd(v40, sd+80, eccLen);
      printf("  v58=rec+ecc v59=rec: v40=%016llX crcA(crc64 low32)=%08X high=%08X (want %08X)\n",
             (unsigned long long)v40, (uint32_t)cA64, (uint32_t)(cA64>>32), crcA);
      /* variants */
      lo = (uint32_t)eccLen; hi = (uint32_t)subLen;
      memcpy(sz, &lo, 4); memcpy(sz+4, &hi, 4);
      v40 = crc64_upd(~(uint64_t)0, sz, 8);
      cA64 = ~crc64_upd(v40, sd+80, eccLen);
      printf("  v58=ecc v59=rec:      crcA=%08X\n", (uint32_t)cA64);
      lo = (uint32_t)subLen; hi = (uint32_t)eccLen;
      memcpy(sz, &lo, 4); memcpy(sz+4, &hi, 4);
      v40 = crc64_upd(~(uint64_t)0, sz, 8);
      cA64 = ~crc64_upd(v40, sd+80, eccLen);
      printf("  v58=rec v59=ecc:      crcA=%08X\n", (uint32_t)cA64);
      /* seed over m1? over myst16? */
      {
        uint8_t m8[8]; memcpy(m8, &m1, 8);
        v40 = crc64_upd(~(uint64_t)0, m8, 8);
        cA64 = ~crc64_upd(v40, sd+80, eccLen);
        printf("  seed=m1:              crcA=%08X\n", (uint32_t)cA64);
      }
      {
        v40 = crc64_upd(~(uint64_t)0, sd+64, 16);
        cA64 = ~crc64_upd(v40, sd+80, eccLen);
        printf("  seed=myst16:          crcA=%08X\n", (uint32_t)cA64);
        cA64 = crc64_upd(v40, sd+80, eccLen);
        printf("  seed=myst16 (no inv):  crcA=%08X\n", (uint32_t)cA64);
      }
      {
        v40 = crc64_upd(~(uint64_t)0, sd+16, 64);
        cA64 = ~crc64_upd(v40, sd+80, eccLen);
        printf("  seed=fields64:        crcA=%08X\n", (uint32_t)cA64);
      }
      {
        v40 = crc64_upd(0, sd+16, 64);
        cA64 = ~crc64_upd(v40, sd+80, eccLen);
        printf("  seed=fields64(0):      crcA=%08X\n", (uint32_t)cA64);
      }
      /* crcB: maybe = crc64 low of (v40) itself? or seed over record? */
      {
        uint8_t sz2[8]; uint32_t lo2=(uint32_t)(subLen+eccLen), hi2=(uint32_t)subLen;
        memcpy(sz2, &lo2, 4); memcpy(sz2+4, &hi2, 4);
        uint64_t s2 = crc64_upd(~(uint64_t)0, sz2, 8);
        printf("  v40 itself: low=%08X high=%08X (crcB=%08X)\n",
               (uint32_t)s2, (uint32_t)(s2>>32), crcB);
      }
      /* crcB over m1 or record? */
      {
        uint64_t cB = crc64_upd(0, sd+64, 16);
        printf("  crc64(myst16)=%08X | over m1=%016llX\n", (uint32_t)cB, (unsigned long long)crc64_upd(0, sd+72, 8));
      }
    }
  }
  return 0;
}
