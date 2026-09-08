/* rrparse2.c - definitive RR subdata layout analysis */
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
/* CRC32 in RAR style: StartCRC already inverted outside; match CRC32(0, data, n) = raw */
static uint32_t crc32_raw(uint32_t crc, const uint8_t *p, size_t n) {
  /* UnRAR style: crc is 0xffffffff initially, tables applied directly, no final inversion:
     but rarsdk_CRC32(start,..) with start=0xffffffff and final ^0xffffffff */
  while (n--) crc = crct[(crc ^ *p++) & 0xff] ^ (crc >> 8);
  return crc;
}

int main(int argc, char **argv)
{
  init_crc();
  FILE *f = fopen(argv[1], "rb");
  fseek(f, 0, SEEK_END); long fsz = ftell(f); fseek(f, 0, SEEK_SET);
  uint8_t *b = malloc(fsz); if (fread(b, 1, fsz, f) != (size_t)fsz) return 1; fclose(f);

  /* walk blocks to find RR service */
  long pos = 8, rrStart = -1, rrSub = -1, rrSubLen = 0, mainStart = -1;
  while (pos < fsz - 3) {
    long bs = pos;
    pos += 4; /* crc */
    uint64_t hs = 0; unsigned sh = 0; int vlen = 0;
    while (pos < fsz) { uint8_t c = b[pos++]; vlen++; hs |= (uint64_t)(c & 0x7f) << sh; sh += 7; if (!(c & 0x80)) break; }
    long hdrEnd = pos + hs;
    uint64_t t = 0; sh = 0;
    while (pos < fsz) { uint8_t c = b[pos++]; t |= (uint64_t)(c & 0x7f) << sh; sh += 7; if (!(c & 0x80)) break; }
    if (t == 1) mainStart = bs;
    uint64_t flags = 0; sh = 0;
    while (pos < fsz) { uint8_t c = b[pos++]; flags |= (uint64_t)(c & 0x7f) << sh; sh += 7; if (!(c & 0x80)) break; }
    uint64_t extra = 0, data = 0;
    if (flags & 1) { sh = 0; while (pos < fsz) { uint8_t c = b[pos++]; extra |= (uint64_t)(c&0x7f)<<sh; sh+=7; if(!(c&0x80))break; } }
    if (flags & 2) { sh = 0; while (pos < fsz) { uint8_t c = b[pos++]; data |= (uint64_t)(c&0x7f)<<sh; sh+=7; if(!(c&0x80))break; } }
    if (t == 3) {
      rrStart = bs;
      rrSub = hdrEnd;
      rrSubLen = data;
      printf("RR@%ld subdata@%ld len=%llu covered=%ld mainStart=%ld\n",
             bs, rrSub, (unsigned long long)data, bs - mainStart, mainStart);
    }
    pos = hdrEnd + data;
  }
  if (rrStart < 0) { printf("no RR\n"); return 1; }

  uint8_t *sd = b + rrSub;
  printf("subdata exact hex (all %ld bytes):\n", rrSubLen);
  for (long i = 0; i < rrSubLen; i++) {
    printf("%02X", sd[i]);
    if ((i & 31) == 31) printf("\n");
  }
  printf("\n");

  /* record header guess: [u32 magic][u32 crc][u32 ?][u32 size] */
  uint32_t magic, crcField, f2, sizeField;
  memcpy(&magic, sd, 4); memcpy(&crcField, sd+4, 4); memcpy(&f2, sd+8, 4); memcpy(&sizeField, sd+12, 4);
  printf("magic=%08X crcF=%08X f2=%08X sizeF=%u\n", magic, crcField, f2, sizeField);

  /* Hypothesis A (from writer 0542CC):
     record = [v56 magic][v57 crc-of-ecc-chunk][v58 ???][v59 size]
     content = put32(0)?? no - we need actual bytes.
     Try to identify: after 16 bytes, the writer's put sequence with extract skipping
     the first 8 buffer bytes. Buffer = put32(0), put1(1), put1(1), put64(off), put32(len),...
     first 8 bytes of buffer = [00 00 00 00][01][01] + first 2 bytes of put64(off).
     => extracted (record content) = off bytes [2..7] + put32(len) + put64(a) + put64(b) +
        put64(c) + put16(ND) + put16(NR) + put16(idx) + ND*put64(shardsize) + put64(a1[15])
     For tiny: off=0 (first record), so extracted starts with 6 zeros of off + ...??
     tiny bytes rel16: 50 00 00 00 ... hmm extracted would start '00 00 00 00 00 00 [put32 len]'...
     Doesn't match '50 00 00 00'. REJECT hypothesis A for record-content start.
  */

  /* Hypothesis B: the record is a "sub-block descriptor":
     [u32 0x50=80 'record type/version?'][u8 1][u8 1][u64 off][u32 len]... but '50 00 00 00' then '01 01'... 80?? 
     Actually wait: 0x50 = 80. In rr_other_549c0 (Protect+) the block size was 512=0x200 and
     v5 = sub_140054F80(a2, v4) = computed shard count. Not 80.
     What if '50' is actually part of the preceding u64?? sizeField at rel12..15='78 03 00 00' for ref2,
     'A4 00 00 00' for tiny... and '50 00 00 00' at rel16-19 could be u64 with rel20+? 
     Check ref2: covered=799, RR@807. 799+8=807. len of covered=799. '50'=80? no.
     0x378=888 (ref2 subdata size), 0xA4=164 (tiny subdata size).
     Look at tiny covered=75: shards: ND=1 (75 bytes -> 1 shard of 75?), blockSize=75, NR=1?
     ECC chunk = 75? record = 16 + fields + 75 = 164? 164-75-16 = 73 bytes of fields?? too many.
     Try: ECC chunk = blockSize rounded to even = 74? 164-16-74=74?? hmm.
     Actually tiny: f2=0x1D0DC305, f1=0x98997167=crc? sizeField=164=ALL subdata.
     Let's find ECC chunk: crc32 over candidate regions and compare with f1 and f2.
  */
  /* test: f1 = ~crc32(0xffffffff, ecc, n) for various n and start offsets */
  for (long start = 16; start < 90; start++) {
    for (long n = 164 - start - 8; n <= 164 - start; n++) {
      if (n <= 0) continue;
      uint32_t c = crc32_raw(0xffffffff, sd + start, n) ^ 0xffffffff;
      if (c == crcField || c == f2) {
        printf("MATCH! start=%ld n=%ld : crc=%08X (crcField=%08X f2=%08X)\n", start, n, c, crcField, f2);
      }
    }
  }
  /* test: f2 or f1 = crc of covered area (mainStart..rrStart) */
  {
    uint32_t c = crc32_raw(0xffffffff, b, rrStart) ^ 0xffffffff;
    uint32_t c2 = crc32_raw(0xffffffff, b + 8, rrStart - 8) ^ 0xffffffff;
    uint32_t c0 = crc32_raw(0, b, rrStart);
    printf("covered crc: all=%08X from8=%08X crc32(0)all=%08X  (crcField=%08X f2=%08X)\n",
           c, c2, c0, crcField, f2);
  }
  return 0;
}
