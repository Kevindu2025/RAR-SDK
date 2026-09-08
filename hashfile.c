/* hashfile.c - hash a file with SDK's Blake2sp, print digest */
#include <stdio.h>
#include <stdlib.h>
#include "rarsdk.h"

int main(int argc, char **argv)
{
  if (argc < 2) return 1;
  wchar_t wname[1024];
  MultiByteToWideChar(CP_ACP, 0, argv[1], -1, wname, 1024);
  unsigned char dg[32];
  unsigned crc;
  int rc = rarsdk_Blake2spFile(wname, dg, &crc);
  if (rc != 0) { printf("err %d\n", rc); return 1; }
  for (int i = 0; i < 32; i++) printf("%02X", dg[i]);
  printf(" crc=%08X\n", crc);
  return 0;
}
