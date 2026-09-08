/* rs_rs16.cpp - Reed-Solomon GF(2^16) for RAR5 recovery records.
 * Clean-room reimplementation matching the public RAR5 RR format
 * (Cauchy matrix, poly 0x1100B) as documented by the UnRAR source
 * (rs16.cpp - freeware) which is used for decoding.
 */
#include "rs_internal.h"

#define GFSIZE 65535

static unsigned gfExp[4*GFSIZE+1+64];
static unsigned gfLog[GFSIZE+1];
static int gf_init_done = 0;

static void gf_init(void)
{
  if (gf_init_done) return;
  for (unsigned l = 0, e = 1; l < GFSIZE; l++) {
    gfLog[e] = l;
    gfExp[l] = e;
    gfExp[l + GFSIZE] = e;
    e <<= 1;
    if ((int)e > GFSIZE) e ^= 0x1100B; /* field polynomial */
  }
  gfLog[0] = 2*GFSIZE;
  for (unsigned i = 2*GFSIZE; i <= 4*GFSIZE; i++)
    gfExp[i] = 0;
  gf_init_done = 1;
}

static unsigned gfmul(unsigned a, unsigned b) { return gfExp[gfLog[a]+gfLog[b]]; }
static unsigned gfinv(unsigned a) { return a==0 ? 0 : gfExp[GFSIZE-gfLog[a]]; }

RARAPI RARSDK_RS16* RARCALL rarsdk_RS16Init(unsigned dataCount, unsigned recCount,
                                            const unsigned char *validityFlags)
{
  gf_init();
  if (dataCount == 0 || recCount == 0 ||
      dataCount + recCount > GFSIZE) return NULL;

  RARSDK_RS16 *rs = (RARSDK_RS16*)calloc(1, sizeof(*rs));
  if (!rs) return NULL;
  rs->ND = dataCount; rs->NR = recCount;
  rs->decoding = validityFlags != NULL;
  rs->gfExp = gfExp; rs->gfLog = gfLog; /* static tables; keep fields for compat */

  if (rs->decoding) {
    rs->valid = (unsigned char*)malloc(dataCount + recCount);
    if (!rs->valid) { free(rs); return NULL; }
    memcpy(rs->valid, validityFlags, dataCount + recCount);
    rs->NE = 0;
    for (unsigned i = 0; i < dataCount; i++) if (!rs->valid[i]) rs->NE++;
    if (rs->NE == 0) { free(rs->valid); free(rs); return NULL; }
    rs->mx = (unsigned*)calloc((size_t)rs->NE * dataCount, sizeof(unsigned));
    /* decoder matrix: rows for broken units from valid recovery rows */
    unsigned dest = 0;
    for (unsigned flag = 0, r = dataCount; flag < dataCount; flag++) {
      if (!rs->valid[flag]) {
        while (!rs->valid[r]) r++;
        for (unsigned j = 0; j < dataCount; j++)
          rs->mx[dest*dataCount + j] = gfinv(r ^ j);
        dest++; r++;
      }
    }
    /* NOTE: full Gauss-Jordan inversion needed for actual decoding is not
       required by this SDK (we only encode recovery records); UnRAR handles
       decoding. We keep the decoder matrix for API completeness. */
  } else {
    rs->mx = (unsigned*)malloc((size_t)recCount * dataCount * sizeof(unsigned));
    if (!rs->mx) { free(rs); return NULL; }
    for (unsigned i = 0; i < recCount; i++)
      for (unsigned j = 0; j < dataCount; j++)
        rs->mx[i*dataCount + j] = gfinv((i + dataCount) ^ j);
  }
  return rs;
}

RARAPI void RARCALL rarsdk_RS16UpdateECC(RARSDK_RS16 *rs, unsigned dataNum,
                                         unsigned eccNum,
                                         const unsigned char *data,
                                         unsigned char *ecc,
                                         size_t blockSize)
{
  if (!rs || dataNum >= rs->ND) return;
  unsigned count = rs->decoding ? rs->NE : rs->NR;
  if (eccNum >= count) return;
  if (dataNum == 0) memset(ecc, 0, blockSize);

  if (eccNum == 0) {
    if (rs->dataLogSize != blockSize) {
      free(rs->dataLog);
      rs->dataLog = (unsigned*)malloc(blockSize * sizeof(unsigned));
      rs->dataLogSize = blockSize;
    }
    for (size_t i = 0; i < blockSize; i += 2) {
      unsigned d = data[i] + data[i+1]*256;
      rs->dataLog[i] = gfLog[d];
    }
  }

  unsigned ml = gfLog[rs->mx[eccNum * rs->ND + dataNum]];
  for (size_t i = 0; i < blockSize; i += 2) {
    unsigned r = gfExp[ml + rs->dataLog[i]];
    ecc[i]   ^= (unsigned char)r;
    ecc[i+1] ^= (unsigned char)(r >> 8);
  }
}

RARAPI void RARCALL rarsdk_RS16Free(RARSDK_RS16 *rs)
{
  if (rs) {
    free(rs->valid);
    free(rs->mx);
    free(rs->dataLog);
    free(rs);
  }
}
