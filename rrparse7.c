/* rrparse7.c - brute force crcA/crcB as writer-style chains:
   v40 = crc32(0xffffffff, [u32 v58][u32 v59], 8)
   crcA = ~crc32(v40, ecc, eccLen)
   Try combos of (v58, v59) from size set. Also brute crcB as crc over regions.
*/
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
static uint32_t rd32(const uint8_t *p) { uint32_t v; memcpy(&v, p, 4); return v; }

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
    long X = rrStart, Xpad = X + (X & 1);
    long eccLen = Xpad; /* ECC bytes at sd+80..80+Xpad, padded */
    long recLen = rrSubLen; /* record total incl trailing pad? subLen = 80 + Xpad(+pad?) */
    printf("== %s crcA=%08X crcB=%08X X=%ld Xpad=%ld subLen=%ld\n",
           argv[a], crcA, crcB, X, Xpad, rrSubLen);

    /* candidate (v58,v59) pairs */
    long v58c[] = {eccLen, recLen, recLen+eccLen, Xpad, X, 80, eccLen+80, recLen+80};
    long v59c[] = {recLen, eccLen, 80, Xpad, X, recLen+eccLen};
    for (int i = 0; i < 8; i++) for (int j = 0; j < 6; j++) {
      uint32_t lo = (uint32_t)v58c[i], hi = (uint32_t)v59c[j];
      uint8_t sz[8]; memcpy(sz, &lo, 4); memcpy(sz+4, &hi, 4);
      uint32_t v40 = crc_upd(0xffffffff, sz, 8);
      /* ecc candidates: with pad / without pad; and 'record content' variant */
      uint32_t c1 = ~crc_upd(v40, sd+80, eccLen);
      uint32_t c2 = ~crc_upd(v40, sd+80, eccLen - (X&1));
      uint32_t c3 = ~crc_upd(v40, sd+16, 64);
      uint32_t c4 = ~crc_upd(v40, sd+16, 64+eccLen);
      if (c1==crcA||c2==crcA||c3==crcA||c4==crcA) printf("  crcA MATCH v58=%ld v59=%ld (%08X %08X %08X %08X)\n", v58c[i], v59c[j], c1,c2,c3,c4);
      if (c1==crcB||c2==crcB||c3==crcB||c4==crcB) printf("  crcB MATCH v58=%ld v59=%ld (%08X %08X %08X %08X)\n", v58c[i], v59c[j], c1,c2,c3,c4);
    }
    /* also direct: crcB = crc32(0, [v58 v59]) with pairs? or = crc of sd[12..16)+myst? */
    for (long s = 0; s <= 96; s += 4) {
      for (long n = 4; n <= 96 - s; n += 4) {
        uint32_t c0 = crc_upd(0, sd+s, n);
        uint32_t cI = ~crc_upd(0xffffffff, sd+s, n);
        if (c0 == crcA || cI == crcA) printf("  crcA region start=%ld n=%ld %s\n", s, n, c0==crcA?"c0":"cI");
        if (c0 == crcB || cI == crcB) printf("  crcB region start=%ld n=%ld %s\n", s, n, c0==crcB?"c0":"cI");
      }
    }
    /* over covered data */
    for (long n = Xpad; n >= Xpad-2 && n > 0; n--) {
      uint32_t c0 = crc_upd(0, b, n);
      uint32_t cI = ~crc_upd(0xffffffff, b, n);
      if (c0 == crcA || cI == crcA) printf("  crcA covered n=%ld\n", n);
      if (c0 == crcB || cI == crcB) printf("  crcB covered n=%ld\n", n);
    }
    /* chain: crc over record hdr+fields then ecc */
    {
      uint32_t chain = crc_upd(0, sd, 80);
      uint32_t cE = ~crc_upd(chain ^ 0xffffffff, sd+80, eccLen);
      uint32_t cE2 = crc_upd(chain, sd+80, eccLen);
      if (cE==crcA) printf("  crcA = chain(hdr80)+ecc(inv)!\n");
      if (cE2==crcA) printf("  crcA = chain(hdr80)+ecc(direct)!\n");
    }
  }
  return 0;
}
