#include "rar.hpp"
#include <stdio.h>
int main() {
  blake2sp_state S;
  blake2sp_init(&S);
  byte dg[32];
  blake2sp_final(&S, dg);
  for (int i=0;i<32;i++) printf("%02X", dg[i]);
  printf("\n");
  blake2sp_state S2; blake2sp_init(&S2);
  byte buf[1] = {'a'};
  blake2sp_update(&S2, buf, 1);
  blake2sp_final(&S2, dg);
  for (int i=0;i<32;i++) printf("%02X", dg[i]);
  printf("\n");
  return 0;
}
