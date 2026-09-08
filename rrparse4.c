/* rrparse4.c - exact byte-indexed RR subdata field dumper */
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

    long pos = 8, rrStart = -1, rrSub = -1, rrSubLen = 0, mainStart = -1, endStart = -1;
    while (pos < fsz - 3) {
      long bs = pos;
      pos += 4;
      uint64_t hs = 0; unsigned sh = 0;
      while (pos < fsz) { uint8_t c = b[pos++]; hs |= (uint64_t)(c & 0x7f) << sh; sh += 7; if (!(c & 0x80)) break; }
      long hdrEnd = pos + hs;
      uint64_t t = 0; sh = 0;
      while (pos < fsz) { uint8_t c = b[pos++]; t |= (uint64_t)(c & 0x7f) << sh; sh += 7; if (!(c & 0x80)) break; }
      if (t == 1) mainStart = bs;
      if (t == 5) endStart = bs;
      uint64_t flags = 0; sh = 0;
      while (pos < fsz) { uint8_t c = b[pos++]; flags |= (uint64_t)(c & 0x7f) << sh; sh += 7; if (!(c & 0x80)) break; }
      uint64_t extra = 0, data = 0;
      if (flags & 1) { sh = 0; while (pos < fsz) { uint8_t c = b[pos++]; extra |= (uint64_t)(c&0x7f)<<sh; sh+=7; if(!(c&0x80))break; } }
      if (flags & 2) { sh = 0; while (pos < fsz) { uint8_t c = b[pos++]; data |= (uint64_t)(c&0x7f)<<sh; sh+=7; if(!(c&0x80))break; } }
      if (t == 3) { rrStart = bs; rrSub = hdrEnd; rrSubLen = data; }
      pos = hdrEnd + data;
    }
    printf("== %s\n", argv[a]);
    printf("RR@%ld sub@%ld subLen=%ld rrEnd=%ld mainStart=%ld endArc@%ld fsz=%ld\n",
           rrStart, rrSub, rrSubLen, rrSub + rrSubLen, mainStart, endStart, fsz);
    uint8_t *sd = b + rrSub;
    long covered = rrStart - 8; /* protected: [8, rrStart) */

    printf("magic=%08X crcA=%08X crcB=%08X sizeF=%u\n", rd32(sd), rd32(sd+4), rd32(sd+8), rd32(sd+12));
    printf("[16]u32=%u [20]u8=%u [21]u8=%u [22]u64=%llu [30]u64=%llu [38]u64=%llu [46]u64=%llu [54]u64=%llu\n",
           rd32(sd+16), sd[20], sd[21],
           (unsigned long long)rd64(sd+22), (unsigned long long)rd64(sd+30),
           (unsigned long long)rd64(sd+38), (unsigned long long)rd64(sd+46),
           (unsigned long long)rd64(sd+54));
    printf("[62]u16=%u [64]u16=%u [66]u16=%u [68]u8=%u\n",
           rd16(sd+62), rd16(sd+64), rd16(sd+66), sd[68]);

    /* find covered data copy inside subdata */
    long copyAt = -1;
    for (long off = 16; off + covered <= rrSubLen; off++)
      if (memcmp(sd + off, b + 8, covered) == 0) { copyAt = off; break; }
    printf("covered(%ld) copy at subdata offset: %ld (=> copy length from there to end: %ld)\n",
           covered, copyAt, rrSubLen - copyAt);

    /* identify remaining field region [68 .. copyAt) */
    printf("field bytes [%ld..%ld): ", 68L, copyAt < 0 ? rrSubLen : copyAt);
    for (long i = 68; i < (copyAt < 0 ? rrSubLen : copyAt); i++) printf("%02X", sd[i]);
    printf("\n");
    if (copyAt >= 0) {
      /* bytes between copy end and subdata end */
      long copyEnd = copyAt + covered;
      if (copyEnd < rrSubLen) {
        printf("after copy [%ld..%ld): ", copyEnd, rrSubLen);
        for (long i = copyEnd; i < rrSubLen; i++) printf("%02X", sd[i]);
        printf("\n");
      }
      /* verify crcA/crcB over candidate regions */
      uint32_t cE = crc_upd(0xffffffff, sd + copyAt, covered) ^ 0xffffffff;
      uint32_t cE2 = crc_upd(0, sd + copyAt, covered);
      printf("crc32(ECC=copy, %ld) = %08X | as start0 %08X\n", covered, cE, cE2);
      /* crc over full record */
      uint32_t cR = crc_upd(0xffffffff, sd, rrSubLen) ^ 0xffffffff;
      printf("crc32(record all) = %08X\n", cR);
      /* crc over record after header16 */
      uint32_t cR2 = crc_upd(0xffffffff, sd + 16, rrSubLen - 16) ^ 0xffffffff;
      printf("crc32(after16) = %08X (crcA=%08X crcB=%08X)\n", cR2, rd32(sd+4), rd32(sd+8));
      /* crcB maybe over header16 only or field area only */
      uint32_t cF = crc_upd(0xffffffff, sd + 16, (copyAt<0?68:copyAt) - 16) ^ 0xffffffff;
      printf("crc32(fields only) = %08X\n", cF);
    }
  }
  return 0;
}
