/* rs_create.cpp - RAR5 archive creation (store method + encryption + RR)
 *
 * Format: RAR 5.0 (Rar.txt spec + verified against WinRAR 7.23 interop).
 * Blocks: signature | MAIN(with locator) | FILE.. | RR(service, optional) | ENDARC
 *
 * RR record layout (verified by byte-level analysis of WinRAR 7.23 output
 * and by successful 'rar t' / 'rar r' repair interop testing):
 *   subdata:
 *     u32 magic 0x7D42527B
 *     u32 crc64lo, u32 crc64hi  (halves of ~crc64(crc64(-1, sd+12, 68), ECC, Xpad))
 *     u32 subLen (total subdata length)
 *     u32 0x50 (version/const)
 *     u8 1, u8 1
 *     u64 0 (offset)
 *     u32 X, u32 X, u32 0, u32 Xpad, u32 0, u32 subLen, u32 0
 *     u16 ND=1, u16 NR=1, u16 idx=0
 *     u64 shardCrc64 = crc64(0, covered)
 *     u64 random
 *     ECC: Xpad bytes = RS parity (ND=1: copy of archive [0..X), pad byte)
 */
#include "rs_internal.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifdef _WIN32
#include <windows.h>
static int wchar_to_utf8(const wchar_t *w, char **out)
{
  int n = WideCharToMultiByte(CP_UTF8, 0, w, -1, NULL, 0, NULL, NULL);
  if (n <= 0) return 0;
  *out = (char*)malloc((size_t)n);
  if (!*out) return 0;
  WideCharToMultiByte(CP_UTF8, 0, w, -1, *out, n, NULL, NULL);
  return 1;
}
static FILE *wfopen_read(const wchar_t *n)  { return _wfopen(n, L"rb"); }
static FILE *wfopen_write(const wchar_t *n) { return _wfopen(n, L"wb"); }
#else
#include <unistd.h>
static int wchar_to_utf8(const wchar_t *w, char **out)
{
  size_t n = wcstombs(NULL, w, 0) + 1;
  *out = (char*)malloc(n);
  if (!*out) return 0;
  wcstombs(*out, w, n);
  return 1;
}
static FILE *wfopen_read(const wchar_t *n) { return fopen(n, "rb"); }
static FILE *wfopen_write(const wchar_t *n) { return fopen(n, "wb"); }
#endif

static const unsigned char RAR5_MARK[8] = {0x52,0x61,0x72,0x21,0x1a,0x07,0x01,0x00};

void rs_putv(Buf *b, unsigned long long v)
{
  unsigned char tmp[10];
  size_t n = rarsdk_PutVint(v, tmp, sizeof tmp);
  buf_add(b, tmp, n);
}

static void put32b(Buf *b, unsigned v)
{
  unsigned char t[4] = {(unsigned char)v,(unsigned char)(v>>8),(unsigned char)(v>>16),(unsigned char)(v>>24)};
  buf_add(b, t, 4);
}

static void put64b(Buf *b, unsigned long long v)
{
  unsigned char t[8];
  for (int i = 0; i < 8; i++) t[i] = (unsigned char)(v >> (i*8));
  buf_add(b, t, 8);
}

/* CRC64 (RAR5 poly, reflected, init 0) */


static uint64_t crc64tab[256];
static int crc64_init_done = 0;
static void crc64_init(void)
{
  if (crc64_init_done) return;
  for (unsigned i = 0; i < 256; i++) {
    uint64_t c = i;
    for (int k = 0; k < 8; k++)
      c = (c & 1) ? (c >> 1) ^ 0xC96C5795D7870F42ULL : c >> 1;
    crc64tab[i] = c;
  }
  crc64_init_done = 1;
}
static uint64_t crc64_upd(uint64_t crc, const unsigned char *p, size_t n)
{
  while (n--) crc = crc64tab[(crc ^ *p++) & 0xff] ^ (crc >> 8);
  return crc;
}

/* Write a complete block: CRC | vint hdrSize | content | data */
static void write_block(RARSDK_WRITER *w, unsigned htype, unsigned hflags,
                        const unsigned char *body, size_t bodySize,
                        const unsigned char *extra, size_t extraSize,
                        const unsigned char *data, size_t dataSize)
{
  Buf blk, hdr;
  buf_init(&blk); buf_init(&hdr);

  rs_putv(&blk, htype);
  rs_putv(&blk, hflags);
  if (hflags & HFL_EXTRA) rs_putv(&blk, extraSize);
  if (hflags & HFL_DATA)  rs_putv(&blk, dataSize);
  if (body && bodySize) buf_add(&blk, body, bodySize);
  if (extra && extraSize) buf_add(&blk, extra, extraSize);

  unsigned char vs[10];
  size_t vsn = rarsdk_PutVint(blk.size, vs, sizeof vs);

  unsigned char *tmp = (unsigned char*)malloc(vsn + blk.size);
  memcpy(tmp, vs, vsn);
  memcpy(tmp + vsn, blk.data, blk.size);
  unsigned crc = rarsdk_CRC32(0xffffffff, tmp, vsn + blk.size) ^ 0xffffffff;
  free(tmp);

  put32b(&hdr, crc);
  buf_add(&hdr, vs, vsn);
  buf_add(&hdr, blk.data, blk.size);

  fwrite(hdr.data, 1, hdr.size, w->f);
  if (data && dataSize)
    fwrite(data, 1, dataSize, w->f);

  buf_free(&hdr); buf_free(&blk);
}

/* 5-byte padded vint (WinRAR locator style) */
static void put_vint5b(Buf *b, unsigned long long v)
{
  unsigned char t[5];
  t[0] = (unsigned char)((v      ) & 0x7f) | 0x80;
  t[1] = (unsigned char)((v >> 7 ) & 0x7f) | 0x80;
  t[2] = (unsigned char)((v >> 14) & 0x7f) | 0x80;
  t[3] = (unsigned char)((v >> 21) & 0x7f) | 0x80;
  t[4] = (unsigned char)((v >> 28) & 0x7f);
  buf_add(b, t, 5);
}

/* ---------------- create / add / close ---------------- */

RARAPI RARSDK_WRITER* RARCALL rarsdk_CreateOpen(const struct rarsdk_create_params *p)
{
  if (!p || !p->arcName) return NULL;
  if ((p->flags & (RARSDK_WF_ENCRYPT_FILES | RARSDK_WF_ENCRYPT_HEAD)) && !p->password)
    return NULL;

  RARSDK_WRITER *w = (RARSDK_WRITER*)calloc(1, sizeof *w);
  if (!w) return NULL;
  buf_init(&w->rrStream);

  w->f = wfopen_write(p->arcName);
  if (!w->f) { free(w); return NULL; }
  w->arcName = p->arcName;

  w->flags = p->flags;
  w->rrPercent = p->rrPercent > 100 ? 100 : p->rrPercent;
  w->kdfLg2 = p->kdfLg2 ? p->kdfLg2 : RARSDK_KDF_LG2_DEFAULT;
  if (w->kdfLg2 > RARSDK_KDF_LG2_MAX) { fclose(w->f); free(w); return NULL; }

  if (p->password && !wchar_to_utf8(p->password, &w->passwordUtf8)) {
    fclose(w->f); free(w); return NULL;
  }

  fwrite(RAR5_MARK, 1, 8, w->f);

  /* --- HEAD_CRYPT (header encryption) --- */
  if (p->flags & RARSDK_WF_ENCRYPT_HEAD) {
    w->headerEncrypted = 1;
    rs_rand_bytes(w->hdrSalt, 16);
    rs_rand_bytes(w->hdrInitV, 16);

    unsigned char key[32], hashKey[32];
    rarsdk_Rar5KDF(w->passwordUtf8, w->hdrSalt, w->kdfLg2, key, hashKey, w->hdrPswCheck);

    Buf body; buf_init(&body);
    rs_putv(&body, 0);                       /* version 0 */
    rs_putv(&body, CHFL_CRYPT_PSWCHECK);
    buf_add1(&body, w->kdfLg2);
    buf_add(&body, w->hdrSalt, 16);
    buf_add(&body, w->hdrPswCheck, 8);
    unsigned char dg[32]; sha256(w->hdrPswCheck, 8, dg);
    buf_add(&body, dg, 4);

    write_block(w, HEAD_CRYPT, HFL_DATA, body.data, body.size, NULL, 0,
                w->hdrInitV, 16);
    buf_free(&body);

    w->hdrAES = (RARSDK_AES*)malloc(sizeof(RARSDK_AES));
    rs_aes_init(w->hdrAES, 0 /*encrypt*/, key, 256, w->hdrInitV);
    memset(key, 0, sizeof key); memset(hashKey, 0, sizeof hashKey);
  }

  /* --- MAIN header with RR locator (offset patched at close) --- */
  w->mainStart = (unsigned long long)_ftelli64(w->f);

  Buf extra; buf_init(&extra);
  if (w->rrPercent) {
    Buf fld; buf_init(&fld);
    rs_putv(&fld, MHEXTRA_LOCATOR_RR);
    put_vint5b(&fld, 0);   /* RR offset placeholder 5-byte padded vint */
    rs_putv(&extra, 1 + fld.size);
    rs_putv(&extra, MHEXTRA_LOCATOR);
    buf_add(&extra, fld.data, fld.size);
    buf_free(&fld);
  }

  Buf mainBody; buf_init(&mainBody);
  rs_putv(&mainBody, w->rrPercent ? MHFL_PROTECT : 0);

  write_block(w, HEAD_MAIN, extra.size ? HFL_EXTRA | HFL_SKIPIFUNKNOWN : HFL_SKIPIFUNKNOWN,
              mainBody.data, mainBody.size,
              extra.size ? extra.data : NULL, extra.size, NULL, 0);

  w->dataStart = (unsigned long long)_ftelli64(w->f);
  w->haveRR = 0;
  w->rrRewriteOff = 0;
  w->mainRROffVintPos = 0;
  w->pendTailSize = 0;
  buf_free(&extra); buf_free(&mainBody);
  return w;
}

/* Build FHEXTRA area for file entries */
static void build_file_extra(Buf *extra, int useCrypt, const unsigned char *salt,
                              const unsigned char *initV, unsigned char lg2,
                              const unsigned char *pswCheck,
                              const unsigned char *blake2,
                              int useHTime, unsigned long long mtime,
                              int mtimeSet, int ctimeSet, int atimeSet,
                              unsigned long long ctime, unsigned long long atime)
{
  buf_init(extra);

  if (useCrypt) {
    Buf c; buf_init(&c);
    rs_putv(&c, 0);
    rs_putv(&c, FHEXTRA_CRYPT_PSWCHECK | FHEXTRA_CRYPT_HASHMAC);
    buf_add1(&c, lg2);
    buf_add(&c, salt, 16);
    buf_add(&c, initV, 16);
    buf_add(&c, pswCheck, 8);
    unsigned char dg[32]; sha256(pswCheck, 8, dg);
    buf_add(&c, dg, 4);
    rs_putv(extra, 1 + c.size);
    rs_putv(extra, FHEXTRA_CRYPT);
    buf_add(extra, c.data, c.size);
    buf_free(&c);
  }

  if (blake2) {
    Buf h; buf_init(&h);
    rs_putv(&h, FHEXTRA_HASH_BLAKE2);
    buf_add(&h, blake2, 32);
    rs_putv(extra, 1 + h.size);
    rs_putv(extra, FHEXTRA_HASH);
    buf_add(extra, h.data, h.size);
    buf_free(&h);
  }

  if (useHTime && (mtimeSet || ctimeSet || atimeSet)) {
    Buf t; buf_init(&t);
    unsigned tf = 0;
    if (mtimeSet) tf |= FHEXTRA_HTIME_MTIME;
    if (ctimeSet) tf |= FHEXTRA_HTIME_CTIME;
    if (atimeSet) tf |= FHEXTRA_HTIME_ATIME;
    rs_putv(&t, tf);
    if (mtimeSet) put64b(&t, mtime);
    if (ctimeSet) put64b(&t, ctime);
    if (atimeSet) put64b(&t, atime);
    rs_putv(extra, 1 + t.size);
    rs_putv(extra, FHEXTRA_HTIME);
    buf_add(extra, t.data, t.size);
    buf_free(&t);
  }
}

static int add_entry(RARSDK_WRITER *w, const struct rarsdk_add_params *ap,
                     const unsigned char *inData, size_t inSize)
{
  if (!w || !ap) return RARSDK_E_PARAM;
  if (ap->method != RARSDK_MSTORE) return RARSDK_E_UNSUPPORTED;

  char *nameUtf8 = NULL;
  const wchar_t *nm = ap->arcName ? ap->arcName : ap->srcName;
  if (!nm) return RARSDK_E_PARAM;
  if (!wchar_to_utf8(nm, &nameUtf8)) return RARSDK_E_NOMEM;

  const unsigned char *data = NULL;
  unsigned char *fileBuf = NULL;
  size_t dataSize = 0;
  if (inData) {
    data = inData; dataSize = inSize;
  } else if (!ap->isDir) {
    FILE *sf = wfopen_read(ap->srcName);
    if (!sf) { free(nameUtf8); return RARSDK_E_IO; }
    _fseeki64(sf, 0, SEEK_END);
    long long fsz = _ftelli64(sf);
    _fseeki64(sf, 0, SEEK_SET);
    if (fsz < 0) { fclose(sf); free(nameUtf8); return RARSDK_E_IO; }
    fileBuf = (unsigned char*)malloc(fsz ? (size_t)fsz : 1);
    if (!fileBuf) { fclose(sf); free(nameUtf8); return RARSDK_E_NOMEM; }
    if (fsz > 0 && fread(fileBuf, 1, (size_t)fsz, sf) != (size_t)fsz) {
      fclose(sf); free(fileBuf); free(nameUtf8); return RARSDK_E_IO;
    }
    fclose(sf);
    data = fileBuf; dataSize = (size_t)fsz;
  }

  unsigned char blake[32];
  rarsdk_Blake2sp(data ? data : (const unsigned char*)"", dataSize, blake);
  unsigned crc = rarsdk_CRC32(0xffffffff, data, dataSize) ^ 0xffffffff;

  int encrypt = (w->flags & RARSDK_WF_ENCRYPT_FILES) && !ap->isDir && dataSize > 0;
  unsigned char salt[16], initV[16], pswCheck[8];
  RARSDK_AES fa; RARSDK_AES *faPtr = NULL;
  unsigned char *packed = NULL;

  if (encrypt) {
    rs_rand_bytes(salt, 16);
    rs_rand_bytes(initV, 16);
    unsigned char key[32], hashKey[32];
    rarsdk_Rar5KDF(w->passwordUtf8, salt, w->kdfLg2, key, hashKey, pswCheck);
    size_t packedSize = (dataSize + 15) & ~(size_t)15;  /* AES block pad */
    packed = (unsigned char*)calloc(1, packedSize ? packedSize : 1);
    if (!packed) { free(fileBuf); free(nameUtf8); return RARSDK_E_NOMEM; }
    if (dataSize) memcpy(packed, data, dataSize);
    rs_aes_init(&fa, 0 /*encrypt*/, key, 256, initV);
    faPtr = &fa;
    rarsdk_AESProcess(faPtr, packed, packedSize);
    /* CRC32 stored as MAC: hmac_sha256(hashKey, LE(crc)) folded to 32 bits */
    {
      unsigned char raw[4] = { (unsigned char)crc, (unsigned char)(crc>>8),
                               (unsigned char)(crc>>16), (unsigned char)(crc>>24) };
      unsigned char mac[32];
      rs_hmac_sha256(hashKey, 32, raw, 4, mac);
      unsigned macCrc = 0;
      for (int i = 0; i < 32; i++)
        macCrc ^= (unsigned)mac[i] << ((i & 3) * 8);
      crc = macCrc;
    }
    memset(key, 0, 32); memset(hashKey, 0, 32);
  }
  size_t storedDataSize = encrypt ? ((dataSize + 15) & ~(size_t)15) : dataSize;

  const unsigned char *storeData = encrypt && packed ? packed : data;

  Buf body; buf_init(&body);
  unsigned fileFlags = 0;
  if (ap->isDir) fileFlags |= FHFL_DIRECTORY;
  if (ap->addCrc32 && dataSize <= 0xffffffff) fileFlags |= FHFL_CRC32;
  if (ap->mtime) fileFlags |= FHFL_UTIME;

  rs_putv(&body, fileFlags);
  rs_putv(&body, (unsigned long long)dataSize);
  rs_putv(&body, ap->isDir ? 0x10 : 0x20);
  if (ap->mtime) {
    unsigned ut = (unsigned)((ap->mtime / 10000000ULL) - 11644473600ULL);
    unsigned char t4[4] = {(unsigned char)ut,(unsigned char)(ut>>8),(unsigned char)(ut>>16),(unsigned char)(ut>>24)};
    buf_add(&body, t4, 4);
  }
  if (fileFlags & FHFL_CRC32) put32b(&body, crc);

  unsigned compInfo = 0;   /* method 0 (store), dict bit0=0 (128KB) */
  rs_putv(&body, compInfo);
  rs_putv(&body, HOST5_WINDOWS);
  rs_putv(&body, strlen(nameUtf8));
  buf_add(&body, nameUtf8, strlen(nameUtf8));

  Buf extra; buf_init(&extra);
  if (encrypt) {
    /* With HASHMAC flag WinRAR stores no separate hash record;
       integrity is carried by the MAC-converted CRC32 field. */
    build_file_extra(&extra, 1, salt, initV, w->kdfLg2, pswCheck, NULL,
                     ap->ctime || ap->atime, ap->mtime, ap->mtime != 0,
                     ap->ctime != 0, ap->atime != 0, ap->ctime, ap->atime);
  } else {
    build_file_extra(&extra, 0, NULL, NULL, 0, NULL, blake,
                     ap->ctime || ap->atime, ap->mtime, ap->mtime != 0,
                     ap->ctime != 0, ap->atime != 0, ap->ctime, ap->atime);
  }

  write_block(w, HEAD_FILE,
              HFL_DATA | HFL_SKIPIFUNKNOWN | (extra.size ? HFL_EXTRA : 0),
              body.data, body.size,
              extra.size ? extra.data : NULL, extra.size,
              storeData, storedDataSize);

  buf_free(&body); buf_free(&extra);
  free(nameUtf8); free(fileBuf); free(packed);
  return RARSDK_OK;
}

RARAPI int RARCALL rarsdk_CreateAddFile(RARSDK_WRITER *w, const struct rarsdk_add_params *ap)
{
  if (!ap) return RARSDK_E_PARAM;
  return add_entry(w, ap, NULL, 0);
}

RARAPI int RARCALL rarsdk_CreateAddData(RARSDK_WRITER *w, const wchar_t *arcName,
                                        const void *data, size_t dataSize)
{
  struct rarsdk_add_params ap;
  memset(&ap, 0, sizeof ap);
  ap.srcName = NULL;
  ap.arcName = arcName;
  ap.method = RARSDK_MSTORE;
  ap.addCrc32 = 1;
  return add_entry(w, &ap, (const unsigned char*)data, dataSize);
}

RARAPI int RARCALL rarsdk_CreateAddDir(RARSDK_WRITER *w, const wchar_t *dirName)
{
  struct rarsdk_add_params ap;
  memset(&ap, 0, sizeof ap);
  ap.arcName = dirName;
  ap.method = RARSDK_MSTORE;
  ap.isDir = 1;
  return add_entry(w, &ap, NULL, 0);
}

/* ---------------- close: RR + ENDARC ---------------- */

RARAPI int RARCALL rarsdk_CreateClose(RARSDK_WRITER *w)
{
  if (!w) return RARSDK_E_PARAM;
  int ret = RARSDK_OK;

  if (w->rrPercent) {
    /* covered = everything written so far (from offset 0 incl. signature) */
    unsigned long long rrStart = (unsigned long long)_ftelli64(w->f);
    if (rrStart >= 4294967295ULL) {
      /* too large for single-record ND=1 clone; skip RR gracefully */
    } else {
      long X = (long)rrStart;
      long Xpad = X + (X & 1);
      long subLen = 80 + Xpad;

      /* read covered data back from file (separate read-only handle:
         MSVC streams opened with 'wb' reject fread) */
      fflush(w->f);  /* make all written bytes visible to the reader */
      unsigned char *cov = (unsigned char*)malloc(Xpad);
      if (!cov) { ret = RARSDK_E_NOMEM; goto endarc; }
      memset(cov, 0, Xpad);
      {
        wchar_t tmpArc[1024];
        wcsncpy(tmpArc, w->arcName, 1023); tmpArc[1023] = 0;
        FILE *rf = _wfopen(tmpArc, L"rb");
        if (!rf) { free(cov); ret = RARSDK_E_IO; goto endarc; }
        size_t got = fread(cov, 1, (size_t)X, rf);
        fclose(rf);
        if (got != (size_t)X) { free(cov); ret = RARSDK_E_IO; goto endarc; }
      }

      /* build subdata */
      unsigned char *sd = (unsigned char*)calloc(1, subLen);
      if (!sd) { free(cov); ret = RARSDK_E_NOMEM; goto endarc; }

      /* ECC: ND=1 => exact copy (identity Cauchy), padded to even */
      memcpy(sd + 80, cov, Xpad);

      crc64_init();
      /* fixed fields */
      unsigned char *p;
      p = sd + 16;
      unsigned long long f50 = 0x50;
      memcpy(p, &f50, 4);                          /* [16..20) u32 0x50 */
      sd[20] = 1; sd[21] = 1;                       /* [20,21] */
      memset(sd + 22, 0, 8);                        /* u64 0 */
      memcpy(sd + 30, &X, 4);                       /* u32 X */
      memcpy(sd + 34, &X, 4);                       /* u32 X */
      memset(sd + 38, 0, 4);                       /* u32 0 */
      memcpy(sd + 42, &Xpad, 4);                   /* u32 Xpad */
      memset(sd + 46, 0, 4);                       /* u32 0 */
      memcpy(sd + 50, &subLen, 4);                 /* u32 subLen */
      memset(sd + 54, 0, 4);                       /* u32 0 */
      sd[58] = 1; sd[59] = 0;                      /* ND */
      sd[60] = 1; sd[61] = 0;                      /* NR */
      sd[62] = 0; sd[63] = 0;                      /* idx */

      /* mystery0 = crc64(0, covered padded? -> use X bytes like RAR) */
      uint64_t m0 = crc64_upd(0, cov, Xpad);
      memcpy(sd + 64, &m0, 8);

      /* mystery1 random */
      uint64_t m1 = (uint64_t)time(NULL) * 0x9E3779B97F4A7C15ULL
                  ^ (uint64_t)(uintptr_t)sd * 0xBF58476D1CE4E5B9ULL;
      m1 ^= m1 >> 29; m1 *= 0xBF58476D1CE4E5B9ULL; m1 ^= m1 >> 32;
      memcpy(sd + 72, &m1, 8);

      /* magic + subLen + CRC64 chain over [12..80) + ECC */
      unsigned magic32 = 0x7D42527B;
      memcpy(sd + 0, &magic32, 4);
      memcpy(sd + 12, &subLen, 4);
      {
        uint64_t seed = crc64_upd(~(uint64_t)0, sd + 12, 68);
        uint64_t r = ~crc64_upd(seed, sd + 80, Xpad);
        uint32_t lo = (uint32_t)r, hi = (uint32_t)(r >> 32);
        memcpy(sd + 4, &lo, 4);
        memcpy(sd + 8, &hi, 4);
      }

      /* service header "RR" (clone layout, verified interop) */
      Buf body; buf_init(&body);
      rs_putv(&body, 0);                                  /* fileFlags */
      rs_putv(&body, (unsigned long long)subLen);         /* unpSize */
      rs_putv(&body, 0);                                  /* attr */
      buf_add1(&body, 0x80); buf_add1(&body, 0x00);        /* compInfo 2-byte vint 0 */
      rs_putv(&body, 0);                                  /* hostOS */
      rs_putv(&body, 2);
      buf_add1(&body, 'R'); buf_add1(&body, 'R');
      Buf extraS; buf_init(&extraS);
      rs_putv(&extraS, 2);       /* field size */
      rs_putv(&extraS, FHEXTRA_SUBDATA);
      buf_add1(&extraS, 3);      /* value (cloned const) */

      write_block(w, HEAD_SERVICE,
                  HFL_EXTRA | HFL_DATA | HFL_SKIPIFUNKNOWN,
                  body.data, body.size,
                  extraS.data, extraS.size,
                  sd, subLen);

      buf_free(&body); buf_free(&extraS);
      free(sd); free(cov);

      /* patch MAIN locator RR offset (rel to MAIN start), 5-byte padded vint */
      {
        unsigned long long rrRel = rrStart - w->mainStart;
        /* our locator extra record: flags vint 0x02 (RR) + one 5-byte
           placeholder 80 80 80 80 00.  Region = [mainStart..dataStart). */
        size_t region = (size_t)(w->dataStart - w->mainStart);
        unsigned char *reg = (unsigned char*)malloc(region);
        if (reg) {
          /* separate read handle: 'wb' stream rejects fread on MSVC */
          FILE *rf = _wfopen(w->arcName, L"rb");
          if (rf) {
            _fseeki64(rf, (long long)w->mainStart, SEEK_SET);
            size_t got = fread(reg, 1, region, rf);
            fclose(rf);
            if (got == region) {
              for (size_t i = 0; i + 5 < region; i++) {
                if (reg[i] == 0x02 &&   /* locator flags: RR only */
                    reg[i+1] == 0x80 && reg[i+2] == 0x80 && reg[i+3] == 0x80 &&
                    reg[i+4] == 0x80 && reg[i+5] == 0x00) {  /* placeholder */
                  reg[i+1] = (unsigned char)((rrRel      ) & 0x7f) | 0x80;
                  reg[i+2] = (unsigned char)((rrRel >> 7 ) & 0x7f) | 0x80;
                  reg[i+3] = (unsigned char)((rrRel >> 14) & 0x7f) | 0x80;
                  reg[i+4] = (unsigned char)((rrRel >> 21) & 0x7f) | 0x80;
                  reg[i+5] = (unsigned char)((rrRel >> 28) & 0x7f);
                  /* recompute MAIN CRC: crc(4) + vint size + content */
                  unsigned long long hsize = 0; unsigned shift = 0; size_t vi = 4;
                  for (;;) {
                    unsigned char c = reg[vi++];
                    hsize |= (unsigned long long)(c & 0x7f) << shift;
                    shift += 7;
                    if (!(c & 0x80)) break;
                  }
                  unsigned newCrc = rarsdk_CRC32(0xffffffff, reg + 4,
                                     (size_t)(vi - 4 + hsize)) ^ 0xffffffff;
                  reg[0] = (unsigned char)newCrc; reg[1] = (unsigned char)(newCrc>>8);
                  reg[2] = (unsigned char)(newCrc>>16); reg[3] = (unsigned char)(newCrc>>24);
                  fflush(w->f);
                  _fseeki64(w->f, (long long)w->mainStart, SEEK_SET);
                  fwrite(reg, 1, region, w->f);
                  fflush(w->f);
                  break;
                }
              }
            }
          }
          free(reg);
        }
        /* always restore write position to end of file */
        fflush(w->f);
        _fseeki64(w->f, 0, SEEK_END);
      }
      w->haveRR = 1;
    }
  }

endarc:
  /* ENDARC */
  {
    Buf endBody; buf_init(&endBody);
    rs_putv(&endBody, 0);
    write_block(w, HEAD_ENDARC, HFL_SKIPIFUNKNOWN,
                endBody.data, endBody.size, NULL, 0, NULL, 0);
    buf_free(&endBody);
  }

  fclose(w->f);
  free(w->passwordUtf8);
  if (w->hdrAES) { memset(w->hdrAES, 0, sizeof *w->hdrAES); }
  free(w->hdrAES);
  buf_free(&w->rrStream);
  free(w);
  return ret;
}

/* ------------- one-shot helpers ------------- */

RARAPI int RARCALL rarsdk_PackFileToArchive(const wchar_t *arcName,
                                            const wchar_t *srcName,
                                            const wchar_t *storedName)
{
  struct rarsdk_create_params cp;
  memset(&cp, 0, sizeof cp);
  cp.arcName = arcName;
  cp.rrPercent = 0;
  RARSDK_WRITER *w = rarsdk_CreateOpen(&cp);
  if (!w) return RARSDK_E_IO;

  struct rarsdk_add_params ap;
  memset(&ap, 0, sizeof ap);
  ap.srcName = srcName;
  ap.arcName = storedName;
  ap.method = RARSDK_MSTORE;
  ap.addCrc32 = 1;
  int r = rarsdk_CreateAddFile(w, &ap);
  if (r == RARSDK_OK) r = rarsdk_CreateClose(w);
  else rarsdk_CreateClose(w);
  return r;
}

RARAPI int RARCALL rarsdk_PackDataToArchive(const wchar_t *arcName,
                                            const wchar_t *storedName,
                                            const void *data, size_t size)
{
  struct rarsdk_create_params cp;
  memset(&cp, 0, sizeof cp);
  cp.arcName = arcName;
  RARSDK_WRITER *w = rarsdk_CreateOpen(&cp);
  if (!w) return RARSDK_E_IO;
  int r = rarsdk_CreateAddData(w, storedName, data, size);
  if (r == RARSDK_OK) r = rarsdk_CreateClose(w);
  else rarsdk_CreateClose(w);
  return r;
}

/* C-linkage wrappers for bridge */
extern "C" unsigned long long crc64_upd_w(unsigned long long crc, const unsigned char *p, size_t n)
{
  return crc64_upd(crc, p, n);
}
extern "C" void crc64_init_wrap(void) { crc64_init(); }