/* rs_internal.h - internal defs for the RAR5 writer implementation */
#ifndef RS_INTERNAL_H
#define RS_INTERNAL_H

#include "rarsdk.h"
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>

#ifdef _WIN32
#include <windows.h>
#endif

typedef unsigned char byte;

/* --- Buf --- */
typedef struct {
  unsigned char *data;
  size_t size, cap;
} Buf;

void buf_init(Buf *b);
void buf_reserve(Buf *b, size_t extra);
void buf_add(Buf *b, const void *p, size_t n);
void buf_add1(Buf *b, unsigned v);
void buf_free(Buf *b);

/* --- SHA-256 --- */
typedef struct {
  unsigned h[8];
  unsigned long long len;
  unsigned char buf[64];
  size_t rem;
} SHA256_CTX;

void sha256_init(SHA256_CTX *c);
void sha256_update(SHA256_CTX *c, const void *data, size_t len);
void sha256_final(SHA256_CTX *c, unsigned char out[32]);
void sha256(const void *data, size_t len, unsigned char out[32]);
void rs_hmac_sha256(const unsigned char *key, size_t keyLen,
                    const unsigned char *data, size_t dataLen,
                    unsigned char out[32]);

/* --- AES (in rs_aes.cpp) --- */
struct RARSDK_AES {
  int decrypt;
  int nr;                       /* rounds */
  unsigned long rk[15*4*2];     /* enc+dec keys (max AES-256) */
  unsigned char iv[16];
  unsigned char next_iv[16];
  int have_next_iv;
  unsigned long long processed; /* for unaligned tail handling */
};

/* --- RS16 GF(2^16) --- */
struct RARSDK_RS16 {
  unsigned ND, NR, NE;
  int decoding;
  unsigned char *valid;   /* NULL in encoder mode */
  unsigned *mx;           /* NR*ND or NE*ND matrix */
  unsigned *gfExp;        /* 4*65535+1 */
  unsigned *gfLog;        /* 65536 */
  unsigned *dataLog;      /* per-block log cache */
  size_t dataLogSize;
};

/* --- RAR5 constants (from headers5.hpp, format spec) --- */
#define HFL_EXTRA        0x0001
#define HFL_DATA         0x0002
#define HFL_SKIPIFUNKNOWN 0x0004
#define HFL_SPLITBEFORE  0x0008
#define HFL_SPLITAFTER   0x0010
#define HFL_CHILD        0x0020
#define HFL_INHERITED    0x0040

#define MHFL_VOLUME      0x0001
#define MHFL_VOLNUMBER   0x0002
#define MHFL_SOLID       0x0004
#define MHFL_PROTECT     0x0008
#define MHFL_LOCK        0x0010

#define FHFL_DIRECTORY   0x0001
#define FHFL_UTIME       0x0002
#define FHFL_CRC32       0x0004
#define FHFL_UNPUNKNOWN  0x0008

#define EHFL_NEXTVOLUME  0x0001

#define CHFL_CRYPT_PSWCHECK 0x0001

#define FCI_SOLID        0x00000040
#define FCI_METHOD_BIT0  0x00000080
#define FCI_METHOD_BIT1  0x00000100
#define FCI_METHOD_BIT2  0x00000200
#define FCI_DICT_BIT0    0x00000400
#define FCI_DICT_BIT1    0x00000800
#define FCI_DICT_BIT2    0x00001000
#define FCI_DICT_BIT3    0x00002000
#define FCI_DICT_BIT4    0x00004000

#define MHEXTRA_LOCATOR      0x01
#define MHEXTRA_LOCATOR_QLIST 0x01
#define MHEXTRA_LOCATOR_RR    0x02

#define FHEXTRA_CRYPT      0x01
#define FHEXTRA_HASH       0x02
#define FHEXTRA_HTIME      0x03
#define FHEXTRA_REDIR      0x05
#define FHEXTRA_UOWNER     0x06
#define FHEXTRA_SUBDATA    0x07
#define FHEXTRA_HASH_BLAKE2 0x00

#define FHEXTRA_CRYPT_PSWCHECK 0x01
#define FHEXTRA_CRYPT_HASHMAC  0x02
#define FHEXTRA_HTIME_MTIME    0x02
#define FHEXTRA_HTIME_CTIME    0x04
#define FHEXTRA_HTIME_ATIME    0x08

#define HEAD_MARK   0
#define HEAD_MAIN   1
#define HEAD_FILE   2
#define HEAD_SERVICE 3
#define HEAD_CRYPT  4
#define HEAD_ENDARC 5

#define HOST5_WINDOWS 0
#define HOST5_UNIX    1

/* RAR5 block layout helpers (writer side) */


/* Writer internal state */
struct RARSDK_WRITER {
  FILE *f;
  const wchar_t *arcName;
  unsigned flags;
  char *passwordUtf8;   /* UTF-8 form */
  unsigned kdfLg2;
  size_t rrPercent;

  /* Header encryption state (HEAD_CRYPT written once) */
  int headerEncrypted;
  unsigned char hdrSalt[16];
  unsigned char hdrInitV[16];
  unsigned char hdrPswCheck[8];
  RARSDK_AES *hdrAES;

  /* Recovery record accounting */
  unsigned long long rrOffset;    /* absolute offset of RR block */
  int haveRR;
  Buf rrStream;                   /* stream of raw "protected" data = all
                                     preceding archive bytes (we re-read
                                     the archive from disk when finishing) */
  unsigned long long mainStart;   /* file offset where MAIN block starts */
  unsigned long long dataStart;   /* first byte protected by RR */
  unsigned long long rrRewriteOff;/* offset of RR-offset vint inside MAIN   */
  unsigned long long mainRROffVintPos; /* abs file offset of 9-byte RR-offset */
  unsigned char pendTail[16];     /* pending header-tail block bytes */
  size_t pendTailSize;
};

/* AES helpers used by writer */
int rs_aes_init(struct RARSDK_AES *ctx, int decrypt, const void *key, unsigned keyBits,
               const void *iv16);
void rs_aes_cbc(struct RARSDK_AES *ctx, void *data, size_t size); /* whole buffer, size%16==0 */
void rs_aes_cbc_tail(struct RARSDK_AES *ctx, void *data, size_t size);
/* RAR pads the final partial block by repeating the last full ciphertext block
   ("copy the previous block" padding - see UnRAR CryptData::DecryptBlock and
   WinRAR writer behavior: last incomplete block is encrypted as-is without
   standard PKCS padding; UnRAR decrypts it by using the preceding block
   as ciphertext IV and truncating). We replicate exactly that. */

/* random bytes (bcrypt on Windows, fallback LCG) */
void rs_rand_bytes(unsigned char *buf, size_t n);

/* CRC64 helpers shared with bridge (defined in rs_create.cpp) */
#ifdef __cplusplus
extern "C" {
#endif
void crc64_init_wrap(void);
unsigned long long crc64_upd_w(unsigned long long crc, const unsigned char *p, size_t n);
#ifdef __cplusplus
}
#endif

#endif /* RS_INTERNAL_H */
