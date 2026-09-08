/* rrparse5.c - verify crcA/crcB semantics + mystery 16 bytes at [64..80) */
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
    printf("== %s: RR@%ld subLen=%ld\n", argv[a], rrStart, rrSubLen);
    uint32_t crcA = rd32(sd+4), crcB = rd32(sd+8);
    printf("crcA=%08X crcB=%08X\n", crcA, crcB);

    /* ECC = sd[80..80+rrStartEven) ; rrStartEven = rrStart + (rrStart&1) */
    long eccLen = rrStart + (rrStart & 1);
    long eccAvail = rrSubLen - 80 - 1; /* leave possible trailing byte */
    if (eccLen > eccAvail) eccLen = rrSubLen - 80;
    uint8_t *ecc = sd + 80;

    /* guess 1: crcA = ~crc32chain over sizes-then-ECC like writer:
       v40 = crc_upd(0xffffffff, [v58 v59] 8 bytes); crcA = ~crc_upd(v40, ecc, eccLen)
       We don't know v58/v59 exactly, but v59 = recordSize(subLen), v58 = ??? */
    /* try v58 = eccLen, v59 = subLen */
    {
      uint8_t sz8[8];
      uint32_t lo = (uint32_t)eccLen, hi = (uint32_t)rrSubLen;
      memcpy(sz8, &lo, 4); memcpy(sz8+4, &hi, 4);
      uint32_t v40 = crc_upd(0xffffffff, sz8, 8);
      uint32_t cA = ~crc_upd(v40, ecc, eccLen);
      printf("g1 (v58=eccLen,v59=subLen): crcA=%08X %s\n", cA, cA==crcA?"MATCH":"");
    }
    /* try v58 = subLen+eccLen, v59 = subLen */
    {
      uint8_t sz8[8];
      uint32_t lo = (uint32_t)(rrSubLen + eccLen), hi = (uint32_t)rrSubLen;
      memcpy(sz8, &lo, 4); memcpy(sz8+4, &hi, 4);
      uint32_t v40 = crc_upd(0xffffffff, sz8, 8);
      uint32_t cA = ~crc_upd(v40, ecc, eccLen);
      printf("g2 (v58=ecc+rec,v59=rec):   crcA=%08X %s\n", cA, cA==crcA?"MATCH":"");
    }
    /* try plain crc32 of ecc */
    {
      uint32_t cA = ~crc_upd(0xffffffff, ecc, eccLen);
      uint32_t cA2 = crc_upd(0, ecc, eccLen);
      printf("g3 plain ~crc32(ECC)=%08X crc32_0(ECC)=%08X\n", cA, cA2);
    }
    /* crcB candidates: crc over [0..80)? over record? over covered? */
    {
      uint32_t c0 = ~crc_upd(0xffffffff, sd, 80);
      uint32_t c1 = ~crc_upd(0xffffffff, sd, rrSubLen);
      uint32_t c2 = ~crc_upd(0xffffffff, b, rrStart);
      uint32_t c3 = crc_upd(0, b, rrStart);
      uint32_t c4 = ~crc_upd(0xffffffff, sd+16, 64);
      uint32_t c5 = ~crc_upd(0xffffffff, sd+16, 48); /* fields to b64 */
      printf("crcB cand: hdr80=%08X rec=%08X cov=%08X cov0=%08X f16_64=%08X f16_48=%08X (crcB=%08X)\n",
             c0, c1, c2, c3, c4, c5, crcB);
    }
    /* mystery 16 bytes at 64..80 */
    printf("myst: [64..72)=%016llX [72..80)=%016llX\n",
           (unsigned long long)rd64(sd+64), (unsigned long long)rd64(sd+72));
    /* candidates: shard crcs? crc32(b[0..rrStartEven)) split? */
    {
      uint32_t cc = crc_upd(0, b, rrStart + (rrStart&1));
      uint32_t ci = ~crc_upd(0xffffffff, b, rrStart + (rrStart&1));
      printf("cov crc0=%08X ~crc=%08X | as u32@64=%08X u32@68=%08X u32@72=%08X u32@76=%08X\n",
             cc, ci, rd32(sd+64), rd32(sd+68), rd32(sd+72), rd32(sd+76));
    }
  }
  return 0;
}
