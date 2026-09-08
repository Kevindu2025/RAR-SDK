#include <stdio.h>
#include <stdint.h>
#include <string.h>
typedef unsigned char byte;
typedef unsigned int uint;
static const uint blake2s_IV_ref[8] = {0x6A09E667UL,0xBB67AE85UL,0x3C6EF372UL,0xA54FF53AUL,0x510E527FUL,0x9B05688CUL,0x1F83D9ABUL,0x5BE0CD19UL};
#define PARALLELISM_DEGREE 8
#define BLAKE2S_BLOCKBYTES 64
#define BLAKE2S_OUTBYTES 32
struct blake2s_state__ { uint h[8], t[2], f[2]; size_t buflen; byte buf[2*BLAKE2S_BLOCKBYTES]; int last_node; };
typedef struct blake2s_state__ blake2sp_leaf;
struct blake2sp_state__ { blake2sp_leaf S[8]; blake2sp_leaf R; int buflen; byte buf[PARALLELISM_DEGREE*BLAKE2S_BLOCKBYTES]; void *ThPool; uint MaxThreads; };
#define blake2s_state blake2s_state__
#define blake2sp_state blake2sp_state__
static uint rotr32x(uint x, int n) { return (x>>n)|(x<<(32-n)); }
#define rotl32x(x,n) (((x)<<(n))|((x)>>(32-(n))))
static uint RawGet4x(const void *Data) { byte *D=(byte*)Data; return D[0]+(D[1]<<8)+(D[2]<<16)+((uint)D[3]<<24); }
#include "blake2s_body_ref.h"
int main() {
  blake2sp_state S; blake2sp_init(&S);
  byte dg[32]; blake2sp_final(&S, dg);
  for (int i=0;i<32;i++) printf("%02X", dg[i]); printf("\n");
  blake2sp_state S2; blake2sp_init(&S2);
  byte b1[1]={'a'}; blake2sp_update(&S2, b1, 1);
  blake2sp_final(&S2, dg);
  for (int i=0;i<32;i++) printf("%02X", dg[i]); printf("\n");
  return 0;
}