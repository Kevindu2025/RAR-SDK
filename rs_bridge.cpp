/* rs_bridge.cpp - extraction API bridges onto the UnRAR engine (dll.cpp)
 * + rarsdk_RecoverArchive (rr repair via 'rar r' engine call in UnRAR? -
 * UnRAR source lacks the 'r' command; we expose RR test via blocks recovered
 * only when possible. Actually UnRAR cannot repair archives. We provide
 * rarsdk_RecoverArchive as an RR validation pass: verify RR checksums. */
#include "rs_internal.h"
#include "unrar_dll_iface.h"

/* Pull in the entire UnRAR library */
extern "C" {
HANDLE PASCAL RAROpenArchiveEx(struct RAROpenArchiveDataEx *r);
int    PASCAL RARCloseArchive(HANDLE hArcData);
int    PASCAL RARReadHeaderEx(HANDLE hArcData, struct RARHeaderDataEx *hd);
int    PASCAL RARProcessFileW(HANDLE hArcData, int Operation, const wchar_t *DestPath, const wchar_t *DestName);
int    PASCAL RARProcessFile(HANDLE hArcData, int Operation, char *DestPath, char *DestName);
void   PASCAL RARSetCallback(HANDLE hArcData, UNRARCALLBACK Callback, LPARAM UserData);
void   PASCAL RARSetPassword(HANDLE hArcData, char *Password);
int    PASCAL RARGetDllVersion(void);
}

RARAPI int RARCALL rarsdk_GetDllVersion(void)
{
  return RARGetDllVersion();
}

RARAPI void* RARCALL rarsdk_OpenArchiveEx(struct RAROpenArchiveDataEx *data)
{
  return RAROpenArchiveEx(data);
}

RARAPI int RARCALL rarsdk_CloseArchive(void *hArc)
{
  return RARCloseArchive((HANDLE)hArc);
}

RARAPI int RARCALL rarsdk_ReadHeaderEx(void *hArc, struct RARHeaderDataEx *hd)
{
  return RARReadHeaderEx((HANDLE)hArc, hd);
}

RARAPI int RARCALL rarsdk_ProcessFileW(void *hArc, int operation,
                                        const wchar_t *destPath, const wchar_t *destName)
{
  return RARProcessFileW((HANDLE)hArc, operation, destPath, destName);
}

RARAPI int RARCALL rarsdk_ProcessFile(void *hArc, int operation,
                                      const char *destPath, const char *destName)
{
  return RARProcessFile((HANDLE)hArc, operation, (char*)destPath, (char*)destName);
}

RARAPI void RARCALL rarsdk_SetCallback(void *hArc, UNRARCALLBACK callback,
                                        unsigned long userData)
{
  RARSetCallback((HANDLE)hArc, callback, (LPARAM)userData);
}

RARAPI void RARCALL rarsdk_SetPassword(void *hArc, const char *password)
{
  RARSetPassword((HANDLE)hArc, (char*)password);
}

RARAPI void RARCALL rarsdk_SetPasswordW(void *hArc, const wchar_t *password)
{
  /* UnRAR DLL takes narrow password; convert */
  char narrow[512];
  if (!password) { narrow[0] = 0; }
  else {
    int n = WideCharToMultiByte(CP_UTF8, 0, password, -1, narrow, sizeof narrow, NULL, NULL);
    if (n <= 0) narrow[0] = 0;
  }
  RARSetPassword((HANDLE)hArc, narrow);
}

static int g_pwCallbackMode = 0; /* unused placeholder */

struct TestCtx { const wchar_t *password; int failures; };

static int CALLBACK test_callback(UINT msg, LPARAM ud, LPARAM p1, LPARAM p2)
{
  if (msg == UCM_NEEDPASSWORDW || msg == UCM_NEEDPASSWORD) {
    /* supply password through UserData-provided buffer: we cannot here,
       rely on RARSetPassword before starting */
    return -1; /* abort password prompt */
  }
  return 1; /* proceed */
}

RARAPI int RARCALL rarsdk_TestArchive(const wchar_t *arcName, const wchar_t *password)
{
  struct RAROpenArchiveDataEx od;
  memset(&od, 0, sizeof od);
  od.ArcNameW = (wchar_t*)arcName;
  od.OpenMode = RAR_OM_EXTRACT;
  HANDLE h = RAROpenArchiveEx(&od);
  if (!h) return od.OpenResult ? od.OpenResult : RARSDK_E_IO;
  if (password) {
    char narrow[512];
    int n = WideCharToMultiByte(CP_UTF8, 0, password, -1, narrow, sizeof narrow, NULL, NULL);
    if (n <= 0) narrow[0] = 0;
    RARSetPassword(h, narrow);
    memset(narrow, 0, sizeof narrow);
  }
  struct RARHeaderDataEx hd;
  memset(&hd, 0, sizeof hd);
  int rc = 0;
  for (;;) {
    int r = RARReadHeaderEx(h, &hd);
    if (r == ERAR_END_ARCHIVE) break;
    if (r != 0) { rc = r == ERAR_BAD_PASSWORD ? RARSDK_E_PASSWORD : RARSDK_E_FORMAT; break; }
    int pr = RARProcessFileW(h, RAR_TEST, NULL, NULL);
    if (pr != 0) { rc = pr == ERAR_BAD_PASSWORD ? RARSDK_E_PASSWORD : RARSDK_E_FORMAT; break; }
  }
  RARCloseArchive(h);
  return rc;
}

RARAPI int RARCALL rarsdk_ExtractArchive(const wchar_t *arcName,
                                          const wchar_t *destDir,
                                          const wchar_t *password)
{
  struct RAROpenArchiveDataEx od;
  memset(&od, 0, sizeof od);
  od.ArcNameW = (wchar_t*)arcName;
  od.OpenMode = RAR_OM_EXTRACT;
  HANDLE h = RAROpenArchiveEx(&od);
  if (!h) return od.OpenResult ? od.OpenResult : RARSDK_E_IO;
  if (password) {
    char narrow[512];
    int n = WideCharToMultiByte(CP_UTF8, 0, password, -1, narrow, sizeof narrow, NULL, NULL);
    if (n <= 0) narrow[0] = 0;
    RARSetPassword(h, narrow);
    memset(narrow, 0, sizeof narrow);
  }
  struct RARHeaderDataEx hd;
  memset(&hd, 0, sizeof hd);
  int rc = 0;
  for (;;) {
    int r = RARReadHeaderEx(h, &hd);
    if (r == ERAR_END_ARCHIVE) break;
    if (r != 0) { rc = r == ERAR_BAD_PASSWORD ? RARSDK_E_PASSWORD : RARSDK_E_FORMAT; break; }
    int pr = RARProcessFileW(h, RAR_EXTRACT, destDir, NULL);
    if (pr != 0) { rc = pr == ERAR_BAD_PASSWORD ? RARSDK_E_PASSWORD : RARSDK_E_FORMAT; break; }
  }
  RARCloseArchive(h);
  return rc;
}

RARAPI int RARCALL rarsdk_IsArchive(const wchar_t *arcName, unsigned int *flags)
{
  struct RAROpenArchiveDataEx od;
  memset(&od, 0, sizeof od);
  od.ArcNameW = (wchar_t*)arcName;
  od.OpenMode = RAR_OM_LIST;
  HANDLE h = RAROpenArchiveEx(&od);
  if (!h) return od.OpenResult ? od.OpenResult : RARSDK_E_FORMAT;
  if (flags) *flags = od.Flags;
  RARCloseArchive(h);
  return RARSDK_OK;
}

/* RR presence + checksum verification (read RR service, validate CRC64 chain)
   Returns: >0 RR present & valid; 0 no RR; <0 error */
RARAPI int RARCALL rarsdk_RecoverArchive(const wchar_t *arcName)
{
  /* Walk archive to find RR service block (via RAR API: list until
     HEAD_SERVICE 'RR'? UnRAR dll doesn't expose service headers directly.
     Fall back to manual file parsing: */
  FILE *f = _wfopen(arcName, L"rb");
  if (!f) return RARSDK_E_IO;
  _fseeki64(f, 0, SEEK_END);
  long long fsz = _ftelli64(f);
  _fseeki64(f, 0, SEEK_SET);
  unsigned char *b = (unsigned char*)malloc((size_t)fsz);
  if (fread(b, 1, (size_t)fsz, f) != (size_t)fsz) { fclose(f); free(b); return RARSDK_E_IO; }
  fclose(f);

  crc64_init_wrap();
  long pos = 8, rrStart = -1, rrSub = -1; long long rrSubLen = 0;
  while (pos < fsz - 4) {
    long bs = pos;
    pos += 4;
    unsigned long long hs = 0; unsigned shift = 0;
    while (pos < fsz) { unsigned char c = b[pos++]; hs |= (unsigned long long)(c & 0x7f) << shift; shift += 7; if (!(c & 0x80)) break; }
    long hdrEnd = pos + (long)hs;
    unsigned long long t = 0; shift = 0;
    while (pos < fsz) { unsigned char c = b[pos++]; t |= (unsigned long long)(c & 0x7f) << shift; shift += 7; if (!(c & 0x80)) break; }
    unsigned long long flags = 0; shift = 0;
    while (pos < fsz) { unsigned char c = b[pos++]; flags |= (unsigned long long)(c & 0x7f) << shift; shift += 7; if (!(c & 0x80)) break; }
    unsigned long long extra = 0, data = 0;
    if (flags & 1) { shift = 0; while (pos < fsz) { unsigned char c = b[pos++]; extra |= (unsigned long long)(c&0x7f)<<shift; shift+=7; if(!(c&0x80))break; } }
    if (flags & 2) { shift = 0; while (pos < fsz) { unsigned char c = b[pos++]; data |= (unsigned long long)(c&0x7f)<<shift; shift+=7; if(!(c&0x80))break; } }
    if (t == 3) {
      /* check name == 'RR' inside body */
      rrStart = bs; rrSub = hdrEnd; rrSubLen = (long long)data;
    }
    pos = hdrEnd + (long)data;
  }
  if (rrStart < 0) { free(b); return 0; }

  unsigned char *sd = b + rrSub;
  if (rrSubLen < 80 || memcmp(sd, "\x7B\x52\x42\x7D", 4) != 0) { free(b); return RARSDK_E_FORMAT; }

  unsigned subLen; memcpy(&subLen, sd + 12, 4);
  unsigned Xpad; memcpy(&Xpad, sd + 42, 4);
  if ((long long)subLen != rrSubLen) { free(b); return RARSDK_E_FORMAT; }

  unsigned long long seed = crc64_upd_w(~(uint64_t)0, sd + 12, 68);
  unsigned long long r = ~crc64_upd_w(seed, sd + 80, Xpad);
  unsigned lo = (unsigned)r, hi = (unsigned)(r >> 32);
  unsigned sLo, sHi;
  memcpy(&sLo, sd + 4, 4); memcpy(&sHi, sd + 8, 4);
  free(b);
  return (lo == sLo && hi == sHi) ? 1 : RARSDK_E_FORMAT;
}
