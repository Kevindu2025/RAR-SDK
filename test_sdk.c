/* test_sdk.c - comprehensive SDK test:
   1. create store archive (SDK) -> verify with official Rar.exe (t/x)
   2. create encrypted archive -> verify with Rar.exe t + wrong/right password
   3. create archive + RR -> damage -> verify official 'rar r' repair
   4. extract our archive with SDK extraction API
   5. primitives self-test (vint roundtrip, CRC32 vs known vector, Blake2sp empty)
*/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>
#include "rarsdk.h"

static int run(const char *cmd)
{
  char buf[4096];
  FILE *p = _popen(cmd, "r");
  if (!p) return -1;
  while (fgets(buf, sizeof buf, p)) { fputs(buf, stdout); }
  return _pclose(p);
}

static void wr(const wchar_t *name, const unsigned char *data, size_t n)
{
  FILE *f = _wfopen(name, L"wb");
  fwrite(data, 1, n, f);
  fclose(f);
}

int main(void)
{
  const wchar_t *dir = L"C:\\Users\\Kevin\\AppData\\Local\\Temp\\opencode\\rar_rev\\rrtest";
  const wchar_t *arc = L"C:\\Users\\Kevin\\AppData\\Local\\Temp\\opencode\\rar_rev\\rrtest\\sdktest.rar";
  int rc;

  printf("== rarsdk self-test ==\n");
  printf("dll version: %d\n", rarsdk_GetDllVersion());

  /* --- primitives --- */
  {
    unsigned char v[10];
    unsigned long long back;
    size_t n = rarsdk_PutVint(0x123456789ABCDULL, v, sizeof v);
    size_t n2 = rarsdk_GetVint(v, n, &back);
    printf("vint: n=%zu n2=%zu val=%llX %s\n", n, n2, back,
           n2 == n && back == 0x123456789ABCDULL ? "OK" : "FAIL");
    unsigned crc = rarsdk_CRC32(0xffffffff, "123456789", 9) ^ 0xffffffff;
    printf("crc32('123456789')=%08X %s\n", crc, crc == 0xCBF43926 ? "OK" : "FAIL");
    unsigned char dg[32];
    rarsdk_Blake2sp("", 0, dg);
    printf("blake2sp(empty)=");
    for (int i = 0; i < 4; i++) printf("%02X", dg[i]);
    printf("... %s\n", dg[0]==0xdd && dg[1]==0x0e && dg[2]==0x89 && dg[3]==0x17 ? "OK" : "FAIL");
  }

  /* --- test 1: plain store archive --- */
  {
    struct rarsdk_create_params cp;
    memset(&cp, 0, sizeof cp);
    cp.arcName = arc;
    cp.rrPercent = 0;
    RARSDK_WRITER *w = rarsdk_CreateOpen(&cp);
    if (!w) { printf("FAIL: create open\n"); return 1; }
    unsigned char data1[1000];
    for (int i = 0; i < 1000; i++) data1[i] = (unsigned char)(i * 7);
    rc = rarsdk_CreateAddData(w, L"alpha.bin", data1, sizeof data1);
    printf("add alpha: %d\n", rc);
    struct rarsdk_add_params ap;
    memset(&ap, 0, sizeof ap);
    ap.srcName = L"C:\\Users\\Kevin\\AppData\\Local\\Temp\\opencode\\rar_rev\\rrtest\\test1.bin";
    ap.method = RARSDK_MSTORE;
    ap.addCrc32 = 1;
    rc = rarsdk_CreateAddFile(w, &ap);
    printf("add test1.bin: %d\n", rc);
    rc = rarsdk_CreateAddDir(w, L"subdir");
    printf("add dir: %d\n", rc);
    rc = rarsdk_CreateClose(w);
    printf("close: %d\n", rc);
  }
  printf("-- official rar t --\n");
  {
    char cmd[1024];
    wchar_t wcmd[1024];
    _snwprintf(wcmd, 1024, L"\"D:\\tmp\\RAR\\Rar.exe\" t -y \"%s\"", arc);
    int wn = WideCharToMultiByte(CP_ACP, 0, wcmd, -1, cmd, 1024, NULL, NULL);
    (void)wn;
    run(cmd);
  }

  /* --- test 2: SDK extraction of our own archive --- */
  {
    rc = rarsdk_TestArchive(arc, NULL);
    printf("sdk TestArchive: %d\n", rc);
    rc = rarsdk_ExtractArchive(arc, L"C:\\Users\\Kevin\\AppData\\Local\\Temp\\opencode\\rar_rev\\rrtest\\sdkout", NULL);
    printf("sdk ExtractArchive: %d\n", rc);
  }

  /* --- test 3: encrypted archive + official verify --- */
  {
    struct rarsdk_create_params cp;
    memset(&cp, 0, sizeof cp);
    cp.arcName = L"C:\\Users\\Kevin\\AppData\\Local\\Temp\\opencode\\rar_rev\\rrtest\\sdkenc.rar";
    cp.flags = RARSDK_WF_ENCRYPT_FILES;
    cp.password = L"secret123";
    cp.kdfLg2 = 15;
    RARSDK_WRITER *w = rarsdk_CreateOpen(&cp);
    if (!w) { printf("FAIL: enc create\n"); return 1; }
    unsigned char data2[3000];
    for (size_t i = 0; i < sizeof data2; i++) data2[i] = (unsigned char)(i * 13);
    rc = rarsdk_CreateAddData(w, L"beta.bin", data2, sizeof data2);
    rc |= rarsdk_CreateClose(w) << 8;
    printf("enc create: %d\n", rc & 0xff);
  }
  printf("-- official rar t (right password) --\n");
  {
    char cmd[1024]; wchar_t wcmd[1024];
    _snwprintf(wcmd, 1024, L"\"D:\\tmp\\RAR\\Rar.exe\" t -y -psecret123 \"%s\"", L"C:\\Users\\Kevin\\AppData\\Local\\Temp\\opencode\\rar_rev\\rrtest\\sdkenc.rar");
    WideCharToMultiByte(CP_ACP, 0, wcmd, -1, cmd, 1024, NULL, NULL);
    run(cmd);
  }
  printf("-- sdk extract encrypted --\n");
  {
    rc = rarsdk_ExtractArchive(L"C:\\Users\\Kevin\\AppData\\Local\\Temp\\opencode\\rar_rev\\rrtest\\sdkenc.rar",
                               L"C:\\Users\\Kevin\\AppData\\Local\\Temp\\opencode\\rar_rev\\rrtest\\sdkenc_out",
                               L"secret123");
    printf("sdk extract enc: %d\n", rc);
    rc = rarsdk_ExtractArchive(L"C:\\Users\\Kevin\\AppData\\Local\\Temp\\opencode\\rar_rev\\rrtest\\sdkenc.rar",
                               L"C:\\Users\\Kevin\\AppData\\Local\\Temp\\opencode\\rar_rev\\rrtest\\sdkenc_bad",
                               L"wrongpass");
    printf("sdk extract wrongpass (expect -5): %d\n", rc);
  }

  /* --- test 4: RR archive + official repair --- */
  {
    struct rarsdk_create_params cp;
    memset(&cp, 0, sizeof cp);
    cp.arcName = L"C:\\Users\\Kevin\\AppData\\Local\\Temp\\opencode\\rar_rev\\rrtest\\sdkrr.rar";
    cp.rrPercent = 10;
    RARSDK_WRITER *w = rarsdk_CreateOpen(&cp);
    unsigned char data3[5000];
    for (size_t i = 0; i < sizeof data3; i++) data3[i] = (unsigned char)(i * 31 + 7);
    rc = rarsdk_CreateAddData(w, L"gamma.bin", data3, sizeof data3);
    rc |= rarsdk_CreateClose(w) << 8;
    printf("rr create: %d\n", rc & 0xff);
  }
  printf("-- official rar t (RR) --\n");
  {
    char cmd[1024]; wchar_t wcmd[1024];
    _snwprintf(wcmd, 1024, L"\"D:\\tmp\\RAR\\Rar.exe\" t -y \"%s\"", L"C:\\Users\\Kevin\\AppData\\Local\\Temp\\opencode\\rar_rev\\rrtest\\sdkrr.rar");
    WideCharToMultiByte(CP_ACP, 0, wcmd, -1, cmd, 1024, NULL, NULL);
    run(cmd);
  }
  /* corrupt + repair */
  {
    FILE *f = _wfopen(L"C:\\Users\\Kevin\\AppData\\Local\\Temp\\opencode\\rar_rev\\rrtest\\sdkrrc.rar", L"wb");
    FILE *g = _wfopen(L"C:\\Users\\Kevin\\AppData\\Local\\Temp\\opencode\\rar_rev\\rrtest\\sdkrr.rar", L"rb");
    unsigned char buf[65536]; size_t n;
    while ((n = fread(buf, 1, sizeof buf, g)) > 0) fwrite(buf, 1, n, f);
    fclose(g);
    _fseeki64(f, 300, SEEK_SET);
    unsigned char x = 0xFF; fputc(x ^ fgetc(f) ? 0 : 0, f); /* noop to avoid confusing */
    fclose(f);
    /* do the corruption directly */
    f = _wfopen(L"C:\\Users\\Kevin\\AppData\\Local\\Temp\\opencode\\rar_rev\\rrtest\\sdkrrc.rar", L"r+b");
    _fseeki64(f, 300, SEEK_SET);
    int c0 = fgetc(f);
    _fseeki64(f, 300, SEEK_SET);
    fputc(c0 ^ 0xFF, f);
    fclose(f);
  }
  printf("-- official rar r (repair) --\n");
  {
    char cmd[1024]; wchar_t wcmd[1024];
    _snwprintf(wcmd, 1024, L"\"D:\\tmp\\RAR\\Rar.exe\" r -y \"%s\"", L"C:\\Users\\Kevin\\AppData\\Local\\Temp\\opencode\\rar_rev\\rrtest\\sdkrrc.rar");
    WideCharToMultiByte(CP_ACP, 0, wcmd, -1, cmd, 1024, NULL, NULL);
    run(cmd);
  }
  printf("-- verify repaired --\n");
  {
    char cmd[1024]; wchar_t wcmd[1024];
    _snwprintf(wcmd, 1024, L"\"D:\\tmp\\RAR\\Rar.exe\" t -y \"%s\"", L"D:\\tmp\\RAR\\fixed.sdkrrc.rar");
    WideCharToMultiByte(CP_ACP, 0, wcmd, -1, cmd, 1024, NULL, NULL);
    run(cmd);
  }

  printf("== all done ==\n");
  return 0;
}
