/* rrcrc4.c - targeted brute force with exact writer semantics:
   v36 = record size = 16 + 56 + ... empirically [12..16)=subLen total though...
   We brute seed sources: all 4/8-byte windows in sd[0..96) + size pairs,
   final = ~crc64(seed, ECC@80, Xpad) low32/high32/inv, compare crcA/crcB.
*/
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
    printf("== %s crcA=%08X crcB=%08X X=%ld Xpad=%ld subLen=%ld\n",
           argv[a], crcA, crcB, X, Xpad, subLen);

    /* ECC region candidates */
    long starts[] = {80, 72, 64};
    long lens[] = {Xpad, X, Xpad-8, Xpad-16};

    int foundA = 0, foundB = 0;

    /* 1) seed = crc64(-1, sd+st, n) over windows within sd[0..96) */
    for (long st = 0; st <= 88 && !foundA; st++) {
      for (long n = 1; n <= 96 - st && !foundA; n++) {
        uint64_t seed = crc64_upd(~(uint64_t)0, sd + st, n);
        for (int si = 0; si < 3 && !foundA; si++) {
          for (int li = 0; li < 4 && !foundA; li++) {
            if (starts[si] + lens[li] > subLen) continue;
            uint64_t r = ~crc64_upd(seed, sd + starts[si], lens[li]);
            uint32_t v[4] = {(uint32_t)r, (uint32_t)(r>>32), ~(uint32_t)r, ~(uint32_t)(r>>32)};
            for (int vi = 0; vi < 4; vi++) {
              if (v[vi] == crcA && !foundA) {
                printf("  crcA: seed=crc64(-1,sd+%ld,%ld) ecc@%ld len=%ld val=%08X %s\n",
                       st, n, starts[si], lens[li], v[vi], vi<2?"direct":"inv");
                foundA = 1;
              }
              if (v[vi] == crcB && !foundB) {
                printf("  crcB: seed=crc64(-1,sd+%ld,%ld) ecc@%ld len=%ld val=%08X %s\n",
                       st, n, starts[si], lens[li], v[vi], vi<2?"direct":"inv");
                foundB = 1;
              }
            }
          }
        }
      }
    }

    /* 2) seed over 8-byte size pairs [lo][hi] */
    {
      uint32_t loC[] = {(uint32_t)subLen, (uint32_t)Xpad, (uint32_t)X, 72,
                        (uint32_t)(subLen+Xpad), (uint32_t)(72+Xpad), (uint32_t)(subLen-80)};
      uint32_t hiC[] = {(uint32_t)subLen, (uint32_t)Xpad, (uint32_t)X, 72, 80,
                        (uint32_t)(subLen+Xpad), (uint32_t)(72+Xpad)};
      for (int i = 0; i < 7 && !foundA; i++)
        for (int j = 0; j < 7 && !foundA; j++) {
          uint8_t sz[8]; memcpy(sz, &loC[i], 4); memcpy(sz+4, &hiC[j], 4);
          uint64_t seed = crc64_upd(~(uint64_t)0, sz, 8);
          for (int si = 0; si < 3 && !foundA; si++)
            for (int li = 0; li < 4 && !foundA; li++) {
              if (starts[si] + lens[li] > subLen) continue;
              uint64_t r = ~crc64_upd(seed, sd + starts[si], lens[li]);
              uint32_t v[4] = {(uint32_t)r, (uint32_t)(r>>32), ~(uint32_t)r, ~(uint32_t)(r>>32)};
              for (int vi = 0; vi < 4; vi++) {
                if (v[vi] == crcA && !foundA) {
                  printf("  crcA: seed=pair[%u,%u] ecc@%ld len=%ld val=%08X %s\n",
                         loC[i], hiC[j], starts[si], lens[li], v[vi], vi<2?"direct":"inv");
                  foundA = 1;
                }
                if (v[vi] == crcB && !foundB) {
                  printf("  crcB: seed=pair[%u,%u] ecc@%ld len=%ld val=%08X %s\n",
                         loC[i], hiC[j], starts[si], lens[li], v[vi], vi<2?"direct":"inv");
                  foundB = 1;
                }
              }
            }
        }
    }

    /* 3) crcA/crcB as plain crc64 (no seed) of windows incl archive bytes */
    for (long st = 0; st <= 96 && !foundA; st++)
      for (long n = 1; n <= 96 - st; n++) {
        uint64_t r0 = crc64_upd(0, sd + st, n);
        uint64_t rF = ~crc64_upd(~(uint64_t)0, sd + st, n);
        uint32_t v[8] = {(uint32_t)r0, (uint32_t)(r0>>32), ~(uint32_t)r0, ~(uint32_t)(r0>>32),
                         (uint32_t)rF, (uint32_t)(rF>>32), ~(uint32_t)rF, ~(uint32_t)(rF>>32)};
        for (int vi = 0; vi < 8; vi++) {
          if (v[vi] == crcA && !foundA) { printf("  crcA: crc64(sd+%ld,%ld) var%d\n", st, n, vi); foundA = 1; }
          if (v[vi] == crcB && !foundB) { printf("  crcB: crc64(sd+%ld,%ld) var%d\n", st, n, vi); foundB = 1; }
        }
      }

    if (!foundA) printf("  crcA: NOT FOUND\n");
    if (!foundB) printf("  crcB: NOT FOUND\n");
  }
  return 0;
}
