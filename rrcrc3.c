/* rrcrc3.c - exhaustive: crcA = ~crc64(seed, region) over starts {64,72,80} and
   seeds from [v58 v59] size-pairs; also try including m1 into seed. */
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
    long subLen = rrSubLen;
    long recLen16 = subLen - Xpad; /* = 80 */
    printf("== %s crcA=%08X crcB=%08X\n", argv[a], crcA, crcB);

    /* brute force: seed = crc64(0xFFFF.., 8 bytes of various u32 pairs) [v58][v59]
       then crcA = (~crc64(seed, sd+START, LEN)) & mask32, try (low32, high32, ~low, ~high)
       START in {64, 72, 80}; LEN in {Xpad, Xpad+8, Xpad+16} */
    uint32_t cand58[] = {(uint32_t)subLen, (uint32_t)Xpad, (uint32_t)(subLen+Xpad), (uint32_t)X, (uint32_t)(recLen16+Xpad), (uint32_t)recLen16};
    uint32_t cand59[] = {(uint32_t)subLen, (uint32_t)Xpad, (uint32_t)(subLen+Xpad), (uint32_t)X, (uint32_t)(recLen16+Xpad), (uint32_t)recLen16};
    int foundA = 0, foundB = 0;
    for (int i = 0; i < 6 && !foundA; i++) {
      for (int j = 0; j < 6 && !foundA; j++) {
        uint8_t sz[8]; memcpy(sz, &cand58[i], 4); memcpy(sz+4, &cand59[j], 4);
        uint64_t seed = crc64_upd(~(uint64_t)0, sz, 8);
        for (int st = 64; st <= 80 && !foundA; st += 8) {
          for (int l = 0; l < 3 && !foundA; l++) {
            long len = Xpad + l*8;
            uint64_t r = ~crc64_upd(seed, sd+st, len);
            uint32_t vals[4] = {(uint32_t)r, (uint32_t)(r>>32), ~(uint32_t)r, ~(uint32_t)(r>>32)};
            for (int vi = 0; vi < 4; vi++) {
              if (vals[vi] == crcA && !foundA) {
                printf("  crcA FOUND: v58=%u v59=%u start=%d len=%ld val=%08X(%s)\n",
                       cand58[i], cand59[j], st, len, vals[vi], vi<2?"direct":"inv");
                foundA = 1;
              }
              if (vals[vi] == crcB && !foundB) {
                printf("  crcB FOUND: v58=%u v59=%u start=%d len=%ld val=%08X(%s)\n",
                       cand58[i], cand59[j], st, len, vals[vi], vi<2?"direct":"inv");
                foundB = 1;
              }
            }
          }
        }
      }
    }
    if (!foundA) printf("  crcA not found in this candidate set\n");
  }
  return 0;
}
