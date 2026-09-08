/* rrmk.c - build complete test archive with RR:
   copy file blocks from a no-RR archive, rewrite MAIN with locator+PROTECT,
   append RR service (clone format) + ENDARC. Then we can test WinRAR 'r' repair.
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
static void put32(uint8_t *p, uint32_t v) { memcpy(p, &v, 4); }

static size_t put_vint(uint8_t *p, uint64_t v)
{
  size_t n = 0; uint8_t tmp[10];
  do { uint8_t c = v & 0x7f; v >>= 7; if (v) c |= 0x80; tmp[n++] = c; } while (v);
  memcpy(p, tmp, n);
  return n;
}
/* 5-byte padded vint like WinRAR locator offsets */
static void put_vint5(uint8_t *p, uint64_t v)
{
  p[0] = (uint8_t)(v & 0x7f) | 0x80;
  p[1] = (uint8_t)((v >> 7) & 0x7f) | 0x80;
  p[2] = (uint8_t)((v >> 14) & 0x7f) | 0x80;
  p[3] = (uint8_t)((v >> 21) & 0x7f) | 0x80;
  p[4] = (uint8_t)((v >> 28) & 0x7f);
}

int main(int argc, char **argv)
{
  init_crc();
  const char *inName = argv[1], *outName = argv[2];
  FILE *f = fopen(inName, "rb");
  fseek(f, 0, SEEK_END); long fsz = ftell(f); fseek(f, 0, SEEK_SET);
  uint8_t *b = malloc(fsz);
  if (fread(b, 1, fsz, f) != (size_t)fsz) return 1;
  fclose(f);

  /* parse: MAIN at 8 (hdrSize vint at 12), then file blocks to end */
  /* new MAIN with locator: type=1, flags=5, extraSize=13, mainflags=8(PROTECT),
     extra: 0C 01 03 [QOoffset5=0] [RRoffset5] */
  /* We need final RR offset = (files end) - 8. files end = current fsz - 8 + newMainSize - oldMainSize */
  long oldMainSize = 4 + 1 + (4 + 1 + 17 - 4 - 1); /* hdrSize=17 for ref-style... but norr main hdrSize=12 (4 crc + 1 vint + 12) */
  /* parse old main size */
  long oldHdrSize;
  {
    long p = 12; uint64_t hs = 0; unsigned sh = 0;
    while (1) { uint8_t c = b[p++]; hs |= (uint64_t)(c & 0x7f) << sh; sh += 7; if (!(c & 0x80)) break; }
    oldHdrSize = 4 + (sh/7) + hs;
  }
  long filesEnd = fsz;
  long newMainSize = 4 + 1 + 17; /* crc(4)+vint(1)+17 */
  long rrStart = 8 + newMainSize + (filesEnd - 8 - oldMainSize);
  long rrRel = rrStart - 8;

  /* build MAIN */
  uint8_t mainh[64]; size_t mp = 0;
  mp += 4; /* crc */
  mainh[mp++] = 17;    /* hdrSize vint = 0x11 */
  mainh[mp++] = 1;     /* type MAIN */
  mainh[mp++] = 5;     /* flags EXTRA|SKIP */
  mainh[mp++] = 13;    /* extraSize */
  mainh[mp++] = 8;     /* mainflags: PROTECT */
  /* extra: fieldSize(12) type(1) flags(3) QO(5) RR(5) */
  mainh[mp++] = 12;    /* fieldSize */
  mainh[mp++] = 1;     /* LOCATOR */
  mainh[mp++] = 3;     /* QLIST|RR */
  put_vint5(mainh + mp, 0); mp += 5;          /* QOoffset = 0 */
  put_vint5(mainh + mp, (uint64_t)rrRel); mp += 5; /* RRoffset rel to MAIN */
  uint32_t mcrc = ~crc_upd(0xffffffff, mainh + 4, mp - 4);
  put32(mainh + 0, mcrc);

  /* RR service block: header + subdata (clone format) */
  long X = rrStart;               /* covered = [0..rrStart) from file start */
  long Xpad = X + (X & 1);
  long subLen = 80 + Xpad;
  uint8_t *sd = calloc(1, subLen);
  put32(sd + 0, 0x7D42527B);
  put32(sd + 4, 0);
  put32(sd + 8, 0);
  put32(sd + 12, (uint32_t)subLen);
  put32(sd + 16, 0x50);
  sd[20] = 1; sd[21] = 1;
  put32(sd + 30, (uint32_t)X);
  put32(sd + 34, (uint32_t)X);
  put32(sd + 38, 0);
  put32(sd + 42, (uint32_t)Xpad);
  put32(sd + 46, 0);
  put32(sd + 50, (uint32_t)subLen);
  put32(sd + 54, 0);
  sd[58] = 1; sd[59] = 0;  /* ND=1 */
  sd[60] = 1; sd[61] = 0;  /* NR=1 */
  sd[62] = 0; sd[63] = 0;  /* idx=0 */
  uint64_t myst0 = 0xACBE037E197E1D3CULL, myst1 = 0x9988776655443322ULL;
  memcpy(sd + 64, &myst0, 8);
  memcpy(sd + 72, &myst1, 8);
  /* NOTE: covered copy must be written AFTER we know final content:
     content = signature(8) + new MAIN + files. Build final buffer first. */

  long totalFiles = fsz - 8 - oldMainSize;
  uint8_t *outb = malloc(8 + newMainSize + totalFiles + subLen + 64);
  memcpy(outb, b, 8);
  memcpy(outb + 8, mainh, newMainSize);
  memcpy(outb + 8 + newMainSize, b + 8 + oldMainSize, totalFiles);
  memcpy(outb + 8 + newMainSize + totalFiles, sd, 0); /* placeholder */
  /* fill ECC copy now */
  memcpy(sd + 80, outb, X);
  if (X & 1) sd[80 + X] = 0;
  memcpy(outb + rrStart, sd, subLen);

  /* RR service header (verbatim clone style) */
  {
    uint8_t hdr[64]; size_t hp = 0;
    uint8_t body[32]; size_t bn = 0;
    body[bn++] = 0;                       /* fileFlags */
    bn += put_vint(body + bn, (uint64_t)subLen); /* unpSize */
    body[bn++] = 0;                       /* attr */
    body[bn++] = 0x80; body[bn++] = 0x00; /* compInfo=0 (2-byte vint) */
    body[bn++] = 0;                       /* hostOS */
    body[bn++] = 2;
    body[bn++] = 'R'; body[bn++] = 'R';
    uint8_t extra[3] = {0x02, 0x07, 0x03};
    uint8_t dsV[10]; size_t dn = 0;
    { uint64_t v = subLen; do { uint8_t c = v & 0x7f; v >>= 7; if (v) c |= 0x80; dsV[dn++] = c; } while (v); }
    size_t hdrSize = 1 + 1 + 1 + dn + bn + 3;
    hp += 4;
    { uint64_t v = hdrSize; do { uint8_t c = v & 0x7f; v >>= 7; if (v) c |= 0x80; hdr[hp++] = c; } while (v); }
    hdr[hp++] = 3; hdr[hp++] = 7; hdr[hp++] = 3;
    memcpy(hdr + hp, dsV, dn); hp += dn;
    memcpy(hdr + hp, body, bn); hp += bn;
    memcpy(hdr + hp, extra, 3); hp += 3;
    uint32_t hcrc = ~crc_upd(0xffffffff, hdr + 4, hp - 4);
    put32(hdr + 0, hcrc);
    /* insert header before subdata: move subdata back by hp bytes */
    memmove(outb + rrStart + hp, outb + rrStart, subLen);
    memcpy(outb + rrStart, hdr, hp);
    subLen += hp; /* total appended = hdr + sd */
  }
  long outLen = rrStart + subLen;

  /* ENDARC */
  {
    uint8_t eblk[8]; size_t eb = 0;
    eblk[eb++] = 5; eblk[eb++] = 0x04; eblk[eb++] = 0;
    uint8_t eh[32]; size_t ehp = 0;
    ehp += 4;
    { uint64_t v = eb; do { uint8_t c = v & 0x7f; v >>= 7; if (v) c |= 0x80; eh[ehp++] = c; } while (v); }
    memcpy(eh + ehp, eblk, eb); ehp += eb;
    uint32_t ecrc = ~crc_upd(0xffffffff, eh + 4, ehp - 4);
    put32(eh + 0, ecrc);
    memcpy(outb + outLen, eh, ehp);
    outLen += ehp;
  }

  FILE *o = fopen(outName, "wb");
  fwrite(outb, 1, outLen, o);
  fclose(o);
  printf("built: rrStart=%ld rrRel=%ld X=%ld subLen(orig)=%ld total=%ld\n",
         rrStart, rrRel, X, subLen, outLen);
  return 0;
}
