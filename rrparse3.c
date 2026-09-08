/* rrparse3.c - final RR layout decode with ECC verification */
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

static void hd(const char *tag, const uint8_t *p, long n)
{
  printf("%s [%ld]: ", tag, n);
  for (long i = 0; i < n; i++) printf("%02X", p[i]);
  printf("\n");
}

int main(int argc, char **argv)
{
  init_crc();
  FILE *f = fopen(argv[1], "rb");
  fseek(f, 0, SEEK_END); long fsz = ftell(f); fseek(f, 0, SEEK_SET);
  uint8_t *b = malloc(fsz); if (fread(b, 1, fsz, f) != (size_t)fsz) return 1; fclose(f);

  long pos = 8, rrStart = -1, rrSub = -1, rrSubLen = 0, mainStart = -1;
  while (pos < fsz - 3) {
    long bs = pos;
    pos += 4;
    uint64_t hs = 0; unsigned sh = 0;
    while (pos < fsz) { uint8_t c = b[pos++]; hs |= (uint64_t)(c & 0x7f) << sh; sh += 7; if (!(c & 0x80)) break; }
    long hdrEnd = pos + hs;
    uint64_t t = 0; sh = 0;
    while (pos < fsz) { uint8_t c = b[pos++]; t |= (uint64_t)(c & 0x7f) << sh; sh += 7; if (!(c & 0x80)) break; }
    if (t == 1) mainStart = bs;
    uint64_t flags = 0; sh = 0;
    while (pos < fsz) { uint8_t c = b[pos++]; flags |= (uint64_t)(c & 0x7f) << sh; sh += 7; if (!(c & 0x80)) break; }
    uint64_t extra = 0, data = 0;
    if (flags & 1) { sh = 0; while (pos < fsz) { uint8_t c = b[pos++]; extra |= (uint64_t)(c&0x7f)<<sh; sh+=7; if(!(c&0x80))break; } }
    if (flags & 2) { sh = 0; while (pos < fsz) { uint8_t c = b[pos++]; data |= (uint64_t)(c&0x7f)<<sh; sh+=7; if(!(c&0x80))break; } }
    if (t == 3) { rrStart = bs; rrSub = hdrEnd; rrSubLen = data; }
    pos = hdrEnd + data;
  }
  printf("RR@%ld sub@%ld subLen=%ld covered=%ld mainStart=%ld fsz=%ld\n",
         rrStart, rrSub, rrSubLen, rrStart - mainStart, mainStart, fsz);

  uint8_t *sd = b + rrSub;
  long covered = rrStart - mainStart;

  /* Field walk (fixed-width, per byte analysis of tiny+ref2):
     [0..3]   magic 0x7D42527B
     [4..7]   crc32? A
     [8..11]  crc32? B
     [12..15] u32 total subdata size (=rrSubLen)
     [16..19] u32 0x50 (80) - ??? maybe 'version+type' 0x50 = 'P'? or record count?
     [20]     u8 1
     [21]     u8 1
     [22..29] u64 offset-in-covered (0)
     [30..37] u64 coveredLen (75)
     [38..45] u64 coveredLen again? (ref2: 807??) let's verify with actual reads
     ...
     We'll print assumed u64 slots. */
  uint32_t magic, cA, cB, sizeF;
  memcpy(&magic, sd, 4); memcpy(&cA, sd+4, 4); memcpy(&cB, sd+8, 4); memcpy(&sizeF, sd+12, 4);
  printf("magic=%08X cA=%08X cB=%08X sizeF=%u\n", magic, cA, cB, sizeF);

  hd("hdr16", sd, 16);

  /* u64 slots from 16 */
  for (int i = 16; i <= 64; i += 8) {
    uint64_t v; memcpy(&v, sd + i, 8);
    printf("u64@%d = %llu (0x%llX)\n", i, (unsigned long long)v, (unsigned long long)v);
  }
  printf("u32@16=%u u8@24=%u u8@25=%u\n",
         (uint32_t)(sd[16] | sd[17]<<8 | sd[18]<<16 | (uint32_t)sd[19]<<24), sd[24], sd[25]);

  /* After u64 slots, u16s at 58,60,62 then ECC start at 64+? find ECC: it should equal covered data (ND=1) */
  hd("bytes 50..end", sd + 50, rrSubLen - 50);

  /* search for covered data inside subdata */
  if (covered <= fsz) {
    const uint8_t *cov = b + mainStart; /* from MAIN? covered starts at mainStart? Actually covered = after MAIN block: dataStart */
    /* try find b[mainStart..rrStart) inside sd */
    for (long off = 16; off < rrSubLen - covered; off++) {
      if (memcmp(sd + off, b + mainStart, covered) == 0) {
        printf("covered copy found at subdata+%ld (exact match)\n", off);
      }
      /* XOR-masked? check xor with first byte */
      int xmatch = 1;
      uint8_t key = sd[off] ^ b[mainStart];
      for (long i = 1; i < covered; i++) if ((sd[off+i] ^ b[mainStart+i]) != key) { xmatch = 0; break; }
      if (xmatch) printf("covered XOR-masked copy at subdata+%ld with key %02X\n", off, key);
    }
  }

  /* verify cA/cB = crc32 variants of regions */
  {
    /* try ECC region guesses */
    for (long start = 16; start < rrSubLen; start++) {
      for (long n = 1; n <= rrSubLen - start; n++) {
        /* too slow to try all; only test 'ECC = last N bytes' hypotheses */
      }
    }
    /* targeted: ECC = subdata[64 .. 64+blockSize) */
    long blockSize = covered; /* 75 */
    long eccStart = 64;
    if (eccStart + blockSize <= rrSubLen) {
      uint32_t c = crc_upd(0xffffffff, sd + eccStart, blockSize) ^ 0xffffffff;
      printf("crc32(ECC@64,%ld)=%08X  (cA=%08X cB=%08X)\n", blockSize, c, cA, cB);
    }
    /* try ECC at 65, 66, ... */
    for (long eccS = 60; eccS < 80; eccS++) {
      if (eccS + blockSize > rrSubLen) break;
      uint32_t c = crc_upd(0xffffffff, sd + eccS, blockSize) ^ 0xffffffff;
      if (c == cA || c == cB) printf("MATCH crc at eccStart=%ld -> %08X\n", eccS, c);
    }
  }
  return 0;
}
