/* rrparse.c - parse reference RAR5 RR block + verify CRC assumptions */
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
static uint32_t crc32(uint32_t crc, const uint8_t *p, size_t n) {
  crc = ~crc;
  while (n--) crc = crct[(crc ^ *p++) & 0xff] ^ (crc >> 8);
  return ~crc;
}

int main(int argc, char **argv)
{
  init_crc();
  FILE *f = fopen(argv[1], "rb");
  fseek(f, 0, SEEK_END); long fsz = ftell(f); fseek(f, 0, SEEK_SET);
  uint8_t *b = malloc(fsz); fread(b, 1, fsz, f); fclose(f);

  /* walk blocks */
  long pos = 8;
  long rrStart = -1;
  while (pos < fsz - 3) {
    long blockStart = pos;
    uint32_t crc = b[pos] | (b[pos+1]<<8) | ((uint32_t)b[pos+2]<<16) | ((uint32_t)b[pos+3]<<24);
    pos += 4;
    /* vint hsize */
    uint64_t hsize = 0; unsigned sh = 0;
    while (pos < fsz) { uint8_t c = b[pos++]; hsize |= (uint64_t)(c & 0x7f) << sh; sh += 7; if (!(c & 0x80)) break; }
    long hdrEnd = pos + hsize;
    /* vint type */
    uint64_t t = 0; sh = 0;
    while (pos < fsz) { uint8_t c = b[pos++]; t |= (uint64_t)(c & 0x7f) << sh; sh += 7; if (!(c & 0x80)) break; }
    printf("block@%ld type=%llu hdrEnd=%ld hdrCRC=%08X calcCRC=%08X\n",
           blockStart, (unsigned long long)t, hdrEnd, crc,
           crc32(0xffffffff, b + blockStart + 4 - 4 + 4, 0)); /* placeholder */
    if (t == 3) rrStart = blockStart;
    /* skip: recompute end incl data - need flags; simpler: parse again below */
    pos = hdrEnd;
    /* temporarily break after header end; we'll parse data sizes separately */
    /* reparse flags/dataSize to skip data */
    /* parse again from after type: */
    long p2 = blockStart + 4;
    uint64_t hs2 = 0; sh = 0;
    while (p2 < fsz) { uint8_t c = b[p2++]; hs2 |= (uint64_t)(c & 0x7f) << sh; sh += 7; if (!(c & 0x80)) break; }
    /* type */
    p2++; /* type vint (1 byte assumption ok) */
    uint64_t flags = 0; sh = 0;
    while (p2 < fsz) { uint8_t c = b[p2++]; flags |= (uint64_t)(c & 0x7f) << sh; sh += 7; if (!(c & 0x80)) break; }
    uint64_t extra = 0, data = 0;
    if (flags & 1) { sh = 0; while (p2 < fsz) { uint8_t c = b[p2++]; extra |= (uint64_t)(c&0x7f)<<sh; sh+=7; if(!(c&0x80))break; } }
    if (flags & 2) { sh = 0; while (p2 < fsz) { uint8_t c = b[p2++]; data |= (uint64_t)(c&0x7f)<<sh; sh+=7; if(!(c&0x80))break; } }
    printf("  flags=%llx extra=%llu data=%llu\n", (unsigned long long)flags,
           (unsigned long long)extra, (unsigned long long)data);
    pos = hdrEnd + data;
  }
  printf("RR block at %ld\n", rrStart);
  if (rrStart < 0) return 1;

  /* The header of RR block: hsize vint etc. compute subdata start */
  long p = rrStart + 4;
  uint64_t hs = 0; unsigned sh = 0;
  while (1) { uint8_t c = b[p++]; hs |= (uint64_t)(c&0x7f)<<sh; sh+=7; if(!(c&0x80)) break; }
  long sub = rrStart + 4 + (sh/7) + hs; /* subdata = after header (sh/7 = bytes of size vint) */
  printf("subdata at %ld\n", sub);

  /* verify header CRC: crc32 over [size vint .. header end] */
  {
    long start = rrStart + 4;
    long end = sub;
    /* recompute size vint length properly */
    long q = rrStart + 4; int vlen = 0;
    while (q < fsz && (b[q] & 0x80)) { q++; vlen++; }
    vlen++; /* last byte */
    uint32_t hc = crc32(0xffffffff, b + start, end - start);
    uint32_t stored = b[rrStart] | (b[rrStart+1]<<8) | ((uint32_t)b[rrStart+2]<<16) | ((uint32_t)b[rrStart+3]<<24);
    printf("hdrCRC stored=%08X calc=%08X %s\n", stored, hc, stored==hc?"OK":"FAIL");
  }

  /* parse RR subdata records: [magic u32][crc u32][size u32][?]... */
  uint8_t *sd = b + sub;
  long sdLeft = fsz - sub - 8; /* minus ENDARC ~8 bytes - rough */
  printf("subdata bytes (first 64):\n  ");
  for (int i = 0; i < 64 && i < sdLeft; i++) printf("%02X ", sd[i]);
  printf("\n");

  /* try: record = magic(4)+crc(4)+size(4)+size2(4)? then fields */
  uint32_t magic = sd[0] | (sd[1]<<8) | (sd[2]<<16) | (sd[3]<<24);
  uint32_t f1 = sd[4] | (sd[5]<<8) | (sd[6]<<16) | (sd[7]<<24);
  uint32_t f2 = sd[8] | (sd[9]<<8) | (sd[10]<<16) | (sd[11]<<24);
  uint32_t f3 = sd[12] | (sd[13]<<8) | (sd[14]<<16) | (sd[15]<<24);
  printf("magic=%08X f1=%08X f2=%08X f3=%08X (f2 as size=%u, f3=%u)\n", magic, f1, f2, f3, f2, f3);

  /* check: is f2 = crc32 of covered area (archive start .. RR block start)? */
  {
    uint32_t c = crc32(0, b, rrStart);
    uint32_t c2 = crc32(0, b + 8, rrStart - 8);
    printf("crc32(all %ld bytes)=%08X inv=%08X | crc32(8..%ld)=%08X inv=%08X\n",
           rrStart, c, ~c, rrStart, c2, ~c2);
  }
  /* ECC chunk location: record size f3=888 = whole subdata? then ECC chunk = inside.
     Try to find ECC start: after the ND put64 sizes list. Search from offset 16:
     fields: put32(0)[?], put1(1), put1(1), put64(off), put32(len), put64(a), put64(b), put64(c),
             put16(ND), put16(NR), put16(idx), ND*put64(sz), put64(x) -> then ECC.
     From dump after 16: 50 00 00 00 | 01 01 | 00*8 | 00 27 03 | 00 00 27 03 | ...
     Try: u32 f4=0x50(80?) no wait '50 00 00 00' LE = 0x50 = 80?? Then '01','01', then u64=0,
     then '00 27 03 00 00 27 03 00 00 00 00 00 00 28 03 00 00 00 00 00 00 78 03 00 00 00 00 00 00'
     = looks like THREE u64: (00 27 03 00 00 27 03 00)?? no...
     Try u64s: bytes 26..33: '00 00 00 00 00 00 00 00' = 0; then u64 '00 27 03 00 00 27 03 00' nonsense.
     Try: after u64(0): '00 27 03 00 00 27 03 00 00 00 00 00 00 28 03 00 00 00 00 00 00 78 03 00 00 00 00 00 00'
     as 7 u32: 0x00032700, 0x00032700, 0x00000000, 0x00000328, 0x00000000, 0x00000378, 0x00000000
     or as u64 x3: 0x032700_00032700?? Let me just print u32/u16 sequences.
  */
  printf("u32 from 16: ");
  for (int i = 16; i < 76; i += 4) {
    uint32_t v = sd[i] | (sd[i+1]<<8) | (sd[i+2]<<16) | ((uint32_t)sd[i+3]<<24);
    printf("%08X ", v);
  }
  printf("\nu16 from 16: ");
  for (int i = 16; i < 76; i += 2) {
    uint16_t v = sd[i] | (sd[i+1]<<8);
    printf("%04X ", v);
  }
  printf("\nbytes 16..100: ");
  for (int i = 16; i < 100; i++) printf("%02X", sd[i]);
  printf("\n");
  return 0;
}
