/* rrclone.c - build archive with our own cloned-format RR record, then test WinRAR repair */
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
static void put16(uint8_t *p, uint16_t v) { memcpy(p, &v, 2); }

/* Append RR service block to archive [inName] -> [outName]
   Covered = everything from offset 0 to current EOF (matching RAR behavior:
   covers signature too). ND=1, NR=1: ECC = exact copy of covered bytes,
   padded to even length with one 0 byte if odd.
   mystery0: taken as parameter; mystery1: random (or given).
   crcA/crcB: set to 0 for now (WinRAR may ignore for repair). */
int append_rr(const char *inName, const char *outName,
              uint64_t myst0, uint64_t myst1)
{
  init_crc();
  FILE *f = fopen(inName, "rb");
  if (!f) return 1;
  fseek(f, 0, SEEK_END); long fsz = ftell(f); fseek(f, 0, SEEK_SET);
  uint8_t *b = malloc(fsz);
  if (fread(b, 1, fsz, f) != (size_t)fsz) { fclose(f); return 1; }
  fclose(f);

  long X = fsz;             /* covered len (from offset 0) */
  long Xpad = X + (X & 1);  /* padded */
  long eccLen = Xpad;
  long subLen = 80 + eccLen;

  /* MAIN header locator RR offset patch: MAIN block is at offset 8.
     Parse MAIN to find locator RR offset field, patch to point at RR block start.
     RR block start = fsz (we append). Rel offset = fsz - 8. */
  /* -- but the MAIN already may contain a locator if created by RAR.
     For our own archives we write the locator ourselves. Here: assume caller
     built the archive via our SDK or RAR without RR. We must ADD locator.
     Simplest: caller handles MAIN locator. Here we just append the block. */

  long rrStart = fsz;
  uint8_t *sd = calloc(1, subLen);
  put32(sd + 0, 0x7D42527B);
  put32(sd + 4, 0);          /* crcA - TODO */
  put32(sd + 8, 0);          /* crcB - TODO */
  put32(sd + 12, (uint32_t)subLen);
  put32(sd + 16, 0x50);      /* const seen in all samples */
  sd[20] = 1; sd[21] = 1;
  /* [22..30) u64 0 */
  put32(sd + 30, (uint32_t)X);
  put32(sd + 34, (uint32_t)X);
  put32(sd + 38, 0);
  put32(sd + 42, (uint32_t)Xpad);
  put32(sd + 46, 0);
  put32(sd + 50, (uint32_t)subLen);
  put32(sd + 54, 0);
  put16(sd + 58, 1);         /* ND */
  put16(sd + 60, 1);         /* NR */
  put16(sd + 62, 0);         /* eccIdx */
  memcpy(sd + 64, &myst0, 8);
  memcpy(sd + 72, &myst1, 8);
  /* ECC: copy of b[0..X), padded */
  memcpy(sd + 80, b, X);
  if (X & 1) sd[80 + X] = 0;

  /* Build service header "RR":
     CRC32(4) | vint hdrSize | type=3 | flags=HFL_EXTRA|HFL_DATA|SKIPIFUNKNOWN(0x07)
     | extraSize vint(3) | dataSize vint | body | extra(3 bytes: 02 07 03) ...
     body (like file header): fileFlags vint | unpSize vint | attr vint
     [crc32 if flag] | compInfo vint | hostOS vint | nameSize vint | name
     For store service: fileFlags=0 (no CRC32 of subdata? samples show 0!)
     Let's replicate sample: type=3, flags=7, extra=3, data=subLen,
     fileFlags=0, unpSize=subLen, attr=0, compInfo=0(vint '80 00'? sample: 80 00 = 0
     with 2 bytes? '80 00': first byte has high bit set! so vint = 0 encoded in 2 bytes),
     hostOS=0, nameSize=2, 'RR'.
     Sample extra bytes: '02 07 03' - FHEXTRA? size=2 type=7(SUBDATA) value=3? */
  /* vint helper */
  uint8_t body[128]; size_t bn = 0;
  uint8_t vb[10];
  /* fileFlags=0 */
  body[bn++] = 0;
  /* unpSize = subLen (vint) */
  { size_t n = 0; uint64_t v = subLen; uint8_t tmp[10]; size_t i = 0;
    do { uint8_t c2 = v & 0x7f; v >>= 7; if (v) c2 |= 0x80; tmp[i++] = c2; } while (v);
    for (size_t k = 0; k < i; k++) body[bn++] = tmp[k]; }
  /* attr = 0 */
  body[bn++] = 0;
  /* compInfo: sample uses '80 00' (vint 2-byte zero) - but 1-byte '00' also valid.
     Use 1-byte 0 for simplicity first; can adjust. */
  body[bn++] = 0;
  /* hostOS = 0 (Windows) */
  body[bn++] = 0;
  /* nameSize = 2, name "RR" */
  body[bn++] = 2;
  body[bn++] = 'R'; body[bn++] = 'R';
  /* total body = 8 bytes? sample body was: 00 F8 06 00 80 00 00 02 52 52
     => fileFlags(1) unpSize(2) attr(1) compInfo(2!) hostOS(1) nameSize(1) name(2) = 10
     compInfo 2-byte zero '80 00'! Match sample: */
  /* rebuild body to match sample layout exactly: */
  bn = 0;
  body[bn++] = 0;                       /* fileFlags */
  { uint64_t v = subLen; uint8_t tmp[10]; size_t i = 0;
    do { uint8_t c2 = v & 0x7f; v >>= 7; if (v) c2 |= 0x80; tmp[i++] = c2; } while (v);
    for (size_t k = 0; k < i; k++) body[bn++] = tmp[k]; }  /* unpSize */
  body[bn++] = 0;                       /* attr */
  body[bn++] = 0x80; body[bn++] = 0x00; /* compInfo = 0 as 2-byte vint (RAR quirk) */
  body[bn++] = 0;                       /* hostOS */
  body[bn++] = 2;                       /* nameSize */
  body[bn++] = 'R'; body[bn++] = 'R';

  /* extra: '02 07 03' - FHEXTRA area: size=2, type=7?? sample extra bytes were
     '02 07 03'. Hmm 3 bytes: extraSize vint was 3 at flags. So extra = 02 07 03:
     field size vint=2, field type vint=7, then 1 byte value=3?? FHEXTRA_SUBDATA=7.
     Value 3 = ??? Copy verbatim. */
  uint8_t extra[3] = {0x02, 0x07, 0x03};

  /* header assembly: type(1) flags(1) extraSize(1: 3) dataSize(vint) body(10) extra(3)
     = 1+1+1+D+10+3 ; hdrSize counts everything after the hdrSize vint */
  uint8_t dsV[10]; size_t dn = 0;
  { uint64_t v = subLen; do { uint8_t c2 = v & 0x7f; v >>= 7; if (v) c2 |= 0x80; dsV[dn++] = c2; } while (v); }
  size_t hdrSize = 1 + 1 + 1 + dn + bn + 3;

  uint8_t *hdr = malloc(4 + 10 + hdrSize);
  size_t hp = 0;
  /* CRC placeholder */
  hp += 4;
  /* hdrSize vint */
  { uint64_t v = hdrSize; do { uint8_t c2 = v & 0x7f; v >>= 7; if (v) c2 |= 0x80; hdr[hp++] = c2; } while (v); }
  hdr[hp++] = 3;          /* type SERVICE */
  hdr[hp++] = 7;          /* flags: EXTRA|DATA|SKIP */
  hdr[hp++] = 3;          /* extraSize */
  memcpy(hdr + hp, dsV, dn); hp += dn;
  memcpy(hdr + hp, body, bn); hp += bn;
  memcpy(hdr + hp, extra, 3); hp += 3;

  /* CRC32 over [hdrSize vint .. end] */
  /* find hdrSize vint length */
  size_t svlen = 0;
  { uint64_t v = hdrSize; do { svlen++; v >>= 7; } while (v); }
  uint32_t hcrc = ~crc_upd(0xffffffff, hdr + 4, 4 - 4 + hp - 4);
  hcrc = ~crc_upd(0xffffffff, hdr + 4, hp - 4);
  put32(hdr + 0, hcrc);

  FILE *o = fopen(outName, "wb");
  fwrite(b, 1, fsz, o);
  fwrite(hdr, 1, hp, o);
  fwrite(sd, 1, subLen, o);
  /* ENDARC */
  {
    uint8_t endh[16]; size_t ep = 4;
    /* type=5, flags=0(SKIPIFUNKNOWN), endflags vint 0 */
    uint8_t eblk[8]; size_t eb = 0;
    eblk[eb++] = 5; eblk[eb++] = 0x04; /* HFL_SKIPIFUNKNOWN */
    eblk[eb++] = 0;                    /* endarc flags */
    size_t ehs = eb;
    uint8_t eh[32]; size_t ehp = 0;
    ehp += 4;
    { uint64_t v = ehs; do { uint8_t c2 = v & 0x7f; v >>= 7; if (v) c2 |= 0x80; eh[ehp++] = c2; } while (v); }
    memcpy(eh + ehp, eblk, eb); ehp += eb;
    uint32_t ecrc = ~crc_upd(0xffffffff, eh + 4, ehp - 4);
    put32(eh + 0, ecrc);
    fwrite(eh, 1, ehp, o);
  }
  fclose(o);
  free(hdr); free(sd); free(b);
  printf("appended RR: rrStart=%ld subLen=%ld eccLen=%ld\n", rrStart, subLen, eccLen);
  return 0;
}

int main(int argc, char **argv)
{
  if (argc < 3) { printf("usage: rrclone in.rar out.rar [myst0hex myst1hex]\n"); return 1; }
  uint64_t m0 = 0, m1 = 0x1122334455667788ULL;
  if (argc >= 4) m0 = strtoull(argv[3], NULL, 16);
  if (argc >= 5) m1 = strtoull(argv[4], NULL, 16);
  return append_rr(argv[1], argv[2], m0, m1);
}
