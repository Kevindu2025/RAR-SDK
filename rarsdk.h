/*
 * rarsdk.h - RAR Archive Development Kit - Public API
 *
 * Part of the SDK:
 *   - Decompression: based on official UnRAR source (freeware license,
 *     see unrar/license.txt). Cannot be used to re-create RAR compression.
 *   - Archive creation (RAR5 format): clean-room implementation derived
 *     from public format documentation (Rar.txt by rarlab) and format
 *     interoperability requirements, implementing: header writing, vint,
 *     CRC32, BLAKE2sp, AES-256-CBC encryption with PBKDF2-HMAC-SHA256 KDF,
 *     Reed-Solomon recovery records (GF(2^16), poly 0x1100B) and
 *     store-mode file packing.
 *   - Solid compression and RAR5 LZ/Huffman compression algorithm are
 *     proprietary and are NOT implemented. Use "store" method.
 *
 * License notes for distribution: UnRAR source license terms (unrar/license.txt)
 * apply to the decompression part. You may not use this SDK or the UnRAR
 * source to develop a RAR (WinRAR) compatible archiver re-creating the
 * proprietary RAR compression algorithm. "Store" mode is provided only for
 * archival/interoperability purposes.
 */

#ifndef RARSDK_H
#define RARSDK_H

#include <stddef.h>

#ifdef _WIN32
#  ifdef RARSDK_BUILD
#    define RARAPI __declspec(dllexport)
#  else
#    define RARAPI __declspec(dllimport)
#  endif
#  define RARCALL __stdcall
#else
#  define RARAPI __attribute__((visibility("default")))
#  define RARCALL
#endif

#ifdef __cplusplus
extern "C" {
#endif

/* ===================================================================== */
/*  Version / errors                                                     */
/* ===================================================================== */

#define RARSDK_VERSION_MAJOR 1
#define RARSDK_VERSION_MINOR 0
#define RARSDK_VERSION       0x00010000

/* Error codes (negative = failure) */
#define RARSDK_OK              0
#define RARSDK_E_PARAM        -1   /* invalid argument / NULL handle */
#define RARSDK_E_IO           -2   /* file I/O error */
#define RARSDK_E_NOMEM        -3   /* allocation failure */
#define RARSDK_E_FORMAT      -4   /* malformed archive / unsupported feature */
#define RARSDK_E_PASSWORD     -5   /* password missing or wrong */
#define RARSDK_E_EXISTS       -6   /* output file exists and overwrite denied */
#define RARSDK_E_WRITE        -7   /* cannot create output file */
#define RARSDK_E_RANGE        -8   /* value out of allowed range */
#define RARSDK_E_INTERNAL     -9   /* internal error */
#define RARSDK_E_UNSUPPORTED -10   /* e.g. solid / LZ compressed by this SDK */

/* ===================================================================== */
/*  Compression method (for creation)                                    */
/* ===================================================================== */

#define RARSDK_MSTORE  0            /* no compression (supported)  */
#define RARSDK_MFAST   1            /* LZ fastest  (read-only for SDK) */
#define RARSDK_MNORMAL 2            /* LZ normal   (read-only)    */
#define RARSDK_MGOOD   3            /* LZ good     (read-only)    */
#define RARSDK_MBEST   4            /* LZ best     (read-only)    */
/* 5 = PPMd (read-only) */

/* KDF power (log2 of PBKDF2 iterations). WinRAR default = 15 (32768). */
#define RARSDK_KDF_LG2_MIN       0
#define RARSDK_KDF_LG2_MAX      24
#define RARSDK_KDF_LG2_DEFAULT  15

/* ===================================================================== */
/*  Part 1: Archive extraction (official UnRAR engine)                   */
/*        API mirrors unrar.dll (RAROpenArchiveEx & co) but prefixed     */
/* ===================================================================== */

/* See unrar/dll.hpp for the full struct definitions - we reuse them. */
#include "unrar_dll_iface.h"        /* RARHeaderDataEx, RAROpenArchiveDataEx, ... */

RARAPI int    RARCALL rarsdk_GetDllVersion(void);
RARAPI void*  RARCALL rarsdk_OpenArchiveEx(struct RAROpenArchiveDataEx *data);
RARAPI int    RARCALL rarsdk_CloseArchive(void *hArc);
RARAPI int    RARCALL rarsdk_ReadHeaderEx(void *hArc, struct RARHeaderDataEx *hd);
RARAPI int    RARCALL rarsdk_ProcessFileW(void *hArc, int operation,
                                          const wchar_t *destPath,
                                          const wchar_t *destName);
RARAPI int    RARCALL rarsdk_ProcessFile(void *hArc, int operation,
                                         const char *destPath,
                                         const char *destName);
RARAPI void   RARCALL rarsdk_SetCallback(void *hArc, UNRARCALLBACK callback,
                                         unsigned long userData);
RARAPI void   RARCALL rarsdk_SetPassword(void *hArc, const char *password);
RARAPI void   RARCALL rarsdk_SetPasswordW(void *hArc, const wchar_t *password);
RARAPI int    RARCALL rarsdk_TestArchive(const wchar_t *arcName,
                                         const wchar_t *password);
RARAPI int    RARCALL rarsdk_ExtractArchive(const wchar_t *arcName,
                                            const wchar_t *destDir,
                                            const wchar_t *password);
RARAPI int    RARCALL rarsdk_IsArchive(const wchar_t *arcName,
                                       unsigned int *flags); /* ROADF_* out */

/* Recovery record test/repair (uses UnRAR RS16 decoder) */
RARAPI int    RARCALL rarsdk_RecoverArchive(const wchar_t *arcName);  /* rc >0: blocks recovered */

/* ===================================================================== */
/*  Part 2: Archive creation (RAR5, clean-room writer)                   */
/* ===================================================================== */

typedef struct RARSDK_WRITER RARSDK_WRITER;   /* opaque */

/* Extra header options */
#define RARSDK_WF_ENCRYPT_FILES  0x01  /* encrypt file data */
#define RARSDK_WF_ENCRYPT_HEAD   0x02  /* encrypt headers (incl. main header) */

struct rarsdk_add_params {
    const wchar_t *srcName;        /* source file path (NULL + data = memory) */
    const wchar_t *arcName;         /* name to store inside archive (UTF-8 conv),
                                       NULL: use srcName basename */
    const void     *data;          /* in-memory data (if srcName==NULL) */
    size_t          dataSize;
    unsigned int    method;         /* RARSDK_MSTORE only (others rejected) */
    unsigned int    kdfLg2;         /* when encrypted; 0 => default (15) */
    int             addCrc32;      /* also store CRC32 (WinRAR stores both CRC32
                                       for small and BLAKE2sp for all files) */
    int             isDir;         /* create directory entry */
    /* time fields: Windows FILETIME, 0 = not set */
    unsigned long long mtime;
    unsigned long long ctime;
    unsigned long long atime;
};

struct rarsdk_create_params {
    const wchar_t *arcName;         /* archive to create (overwritten) */
    unsigned int  flags;            /* RARSDK_WF_* */
    const wchar_t *password;        /* required if any WF_ENCRYPT */
    unsigned int  kdfLg2;           /* 0 => default(15), max 24 */
    size_t        rrPercent;        /* 0 = no recovery record; 1..100 */
                                     /* RR created as 'RR' service block */
};

RARAPI RARSDK_WRITER* RARCALL rarsdk_CreateOpen(const struct rarsdk_create_params *p);
RARAPI int    RARCALL rarsdk_CreateAddFile(RARSDK_WRITER *w,
                                          const struct rarsdk_add_params *ap);
RARAPI int    RARCALL rarsdk_CreateAddData(RARSDK_WRITER *w,
                                          const wchar_t *arcName,
                                          const void *data, size_t dataSize);
RARAPI int    RARCALL rarsdk_CreateAddDir(RARSDK_WRITER *w, const wchar_t *dirName);
RARAPI int    RARCALL rarsdk_CreateClose(RARSDK_WRITER *w); /* writes EndArc; frees */

/* Simple one-shot helpers */
RARAPI int    RARCALL rarsdk_PackFileToArchive(const wchar_t *arcName,
                                               const wchar_t *srcName,
                                               const wchar_t *storedName);
RARAPI int    RARCALL rarsdk_PackDataToArchive(const wchar_t *arcName,
                                               const wchar_t *storedName,
                                               const void *data, size_t size);

/* ===================================================================== */
/*  Part 3: Low-level primitives exposed for advanced users              */
/* ===================================================================== */

/* --- RAR5 vint --- */
/* Encodes value, returns number of bytes written (<=10). */
RARAPI size_t RARCALL rarsdk_PutVint(unsigned long long v,
                                     unsigned char *out, size_t outSize);
/* Decodes, returns bytes consumed (0 = error), *value receives number. */
RARAPI size_t RARCALL rarsdk_GetVint(const unsigned char *in, size_t inSize,
                                     unsigned long long *value);

/* --- CRC32 (same as RAR/ZLIB, reflected 0xEDB88320) --- */
RARAPI unsigned int RARCALL rarsdk_CRC32(unsigned int startCRC,
                                         const void *data, size_t size);

/* --- BLAKE2sp (RAR5 file checksum, 32-byte digest) --- */
RARAPI void   RARCALL rarsdk_Blake2sp(const void *data, size_t size,
                                      unsigned char digest[32]);
RARAPI int    RARCALL rarsdk_Blake2spFile(const wchar_t *fileName,
                                          unsigned char digest[32],
                                          unsigned int *crc32 /*optional*/);

/* --- RAR5 PBKDF2-HMAC-SHA256 KDF --- */
RARAPI int    RARCALL rarsdk_Rar5KDF(const char *utf8Password,
                                     const unsigned char salt[16],
                                     unsigned int lg2Count,
                                     unsigned char key[32],        /* AES-256 key */
                                     unsigned char hashKey[32],     /* BLAKE2sp MAC key */
                                     unsigned char pswCheck[8]);    /* password check */

/* --- RAR3 KDF (SHA-1 x0x40000) --- */
RARAPI int    RARCALL rarsdk_Rar3KDF(const char *password,
                                     const unsigned char *salt /*8 or NULL*/,
                                     unsigned char key[16],
                                     unsigned char initV[16]);

/* --- AES-256/128 CBC (software, block=16) --- */
typedef struct RARSDK_AES RARSDK_AES;
RARAPI RARSDK_AES* RARCALL rarsdk_AESInit(int encrypt,
                                          const void *key, unsigned keyBits,
                                          const void *iv16);
RARAPI void   RARCALL rarsdk_AESProcess(RARSDK_AES *ctx, void *data, size_t size);
RARAPI void   RARCALL rarsdk_AESFree(RARSDK_AES *ctx);

/* --- Reed-Solomon GF(2^16), poly 0x1100B (RAR5 recovery records) --- */
typedef struct RARSDK_RS16 RARSDK_RS16;
/* dataCount+recCount <= 65535; validity NULL => encoder mode */
RARAPI RARSDK_RS16* RARCALL rarsdk_RS16Init(unsigned dataCount,
                                           unsigned recCount,
                                           const unsigned char *validityFlags);
/* Apply data block to ecc blocks:
   for (d=0; d<dataCount; d++)
     for (r=0; r<recCount; r++)
       RS16UpdateECC(rs, d, r, dataBlock_d, ecc_r, blockSize);  */
RARAPI void   RARCALL rarsdk_RS16UpdateECC(RARSDK_RS16 *rs,
                                            unsigned dataNum, unsigned eccNum,
                                            const unsigned char *data,
                                            unsigned char *ecc,
                                            size_t blockSize);
RARAPI void   RARCALL rarsdk_RS16Free(RARSDK_RS16 *rs);

/* ===================================================================== */
/*  Part 4: Reusable compression / crypto primitives                      */
/*         (merged from learnarc; public-domain teaching implementations) */
/* ===================================================================== */

/* These are independent from the RAR5-specific rarsdk_AESInit / rarsdk_Rar5KDF
 * APIs above. They expose the underlying learnarc primitives for any caller
 * who wants fine-grained control (LZ77+Huffman, PPM, SHA-256, AES-CBC,
 * LArc container). Implementation files: la_sha256.cpp / la_aes.cpp /
 * la_lzh.cpp / la_ppm.cpp / la_larc.cpp. Headers available to C++ users at
 * include/learnarc/*.hpp. */

/* --- SHA-256 (incremental + one-shot) --- */
/* Opaque context type - sizeof = underlying Sha256Ctx. Allocate on stack
 * or heap; never inspect fields. */
typedef struct rarsdk_la_sha256_ctx {
    unsigned char _opaque[112];     /* sizeof(learnarc::Sha256Ctx) on x64 */
} rarsdk_la_sha256_ctx;

RARAPI void   RARCALL rarsdk_LaSha256Init(rarsdk_la_sha256_ctx *ctx);
RARAPI void   RARCALL rarsdk_LaSha256Update(rarsdk_la_sha256_ctx *ctx,
                                            const void *data, size_t n);
RARAPI void   RARCALL rarsdk_LaSha256Final(rarsdk_la_sha256_ctx *ctx,
                                           unsigned char out[32]);
RARAPI void   RARCALL rarsdk_LaSha256(const void *data, size_t n,
                                       unsigned char out[32]);

/* --- HMAC-SHA-256 (RFC 2104) --- */
RARAPI void   RARCALL rarsdk_LaHmacSha256(const void *key, size_t keyLen,
                                          const void *data, size_t dataLen,
                                          unsigned char out[32]);

/* --- PBKDF2-HMAC-SHA-256 (RFC 2898) ---
 * iterations: count (>=1); outLen: <=4GB. */
RARAPI int    RARCALL rarsdk_LaPbkdf2HmacSha256(const char *password,
                                                 const unsigned char *salt, size_t saltLen,
                                                 unsigned int iterations,
                                                 unsigned char *out, size_t outLen);

/* --- AES-128/192/256 block + CBC (teaching implementation, FIPS-197) ---
 * Separate from the RAR5-specific rarsdk_AESInit/Process above. Use this
 * if you want plain block-level access or generic CBC chaining with
 * application-managed padding. */
typedef void * rarsdk_la_aes;        /* opaque AesKey* */
RARAPI rarsdk_la_aes RARCALL rarsdk_LaAesInit(const void *key, unsigned int keyBits);
RARAPI void   RARCALL rarsdk_LaAesEncryptBlock(rarsdk_la_aes ctx,
                                                const void *in16, void *out16);
RARAPI void   RARCALL rarsdk_LaAesDecryptBlock(rarsdk_la_aes ctx,
                                                const void *in16, void *out16);
/* bytes must be a multiple of 16. */
RARAPI void   RARCALL rarsdk_LaAesCbcEncrypt(rarsdk_la_aes ctx, const void *iv16,
                                              const void *in, void *out, size_t bytes);
RARAPI void   RARCALL rarsdk_LaAesCbcDecrypt(rarsdk_la_aes ctx, const void *iv16,
                                              const void *in, void *out, size_t bytes);
RARAPI void   RARCALL rarsdk_LaAesFree(rarsdk_la_aes ctx);

/* --- LZ77 + canonical Huffman (RLE/LZ family: "lzh" / "-m1..-m4" idea) ---
 * Encode: returns compressed byte count on success, RARSDK_E_UNSUPPORTED
 *         if no gain (caller should fall back to store), RARSDK_E_* otherwise.
 * Decode: returns decoded byte count (== originalLen) on success.
 * windowSize: 64KB..4MB recommended; maxChain: 4..256 typical. */
RARAPI int    RARCALL rarsdk_LaLzhEncode(const void *data, size_t n,
                                          unsigned int windowSize, unsigned int maxChain,
                                          void *out, size_t outCap);
RARAPI int    RARCALL rarsdk_LaLzhDecode(const void *in, size_t inSize,
                                          size_t originalLen,
                                          void *out, size_t outCap);

/* --- PPM (Prediction by Partial Matching) + range coder ("-m5" idea) ---
 * order: 1..16 typical. */
RARAPI int    RARCALL rarsdk_LaPpmCompress(const void *data, size_t n,
                                            unsigned int order,
                                            void *out, size_t outCap);
RARAPI int    RARCALL rarsdk_LaPpmDecompress(const void *in, size_t inSize,
                                              size_t originalLen, unsigned int order,
                                              void *out, size_t outCap);

/* ===================================================================== */
/*  Part 5: LArc container format (LA v1, from learnarc)                 */
/* ===================================================================== */
/*
 * LArc is a self-contained teaching-grade archive format with per-entry
 * CRC32 header, store/lzh/ppm methods, and optional RAR5-style AES-256
 * encryption. Open in a hex editor - see include/learnarc/container.hpp
 * for the full spec.
 *
 * Method values for the LArcWriter* APIs:
 *   0 = store (no compression)
 *   1 = LZ77 + canonical Huffman
 *   2 = PPM + range coder
 *
 * Compression methods are NOT intercompatible with WinRAR / RAR format.
 */

typedef struct rarsdk_larc_writer rarsdk_larc_writer;
typedef struct rarsdk_larc_reader rarsdk_larc_reader;

RARAPI rarsdk_larc_writer * RARCALL rarsdk_LArcWriterCreate(void);
RARAPI int   RARCALL rarsdk_LArcWriterAddFile(rarsdk_larc_writer *w,
                                                const wchar_t *srcPath,
                                                const char *arcName,
                                                unsigned int method,
                                                unsigned int kdfLg2,
                                                const char *password,
                                                int encrypt);
RARAPI int   RARCALL rarsdk_LArcWriterAddData(rarsdk_larc_writer *w,
                                                const char *arcName,
                                                const void *data, size_t size,
                                                unsigned int method,
                                                unsigned int kdfLg2,
                                                const char *password,
                                                int encrypt);
RARAPI int   RARCALL rarsdk_LArcWriterAddDir(rarsdk_larc_writer *w,
                                               const char *dirName);
RARAPI int   RARCALL rarsdk_LArcWriterSave(rarsdk_larc_writer *w,
                                             const wchar_t *path);
RARAPI void  RARCALL rarsdk_LArcWriterFree(rarsdk_larc_writer *w);

RARAPI rarsdk_larc_reader * RARCALL rarsdk_LArcReaderOpen(const wchar_t *path);
RARAPI void  RARCALL rarsdk_LArcReaderClose(rarsdk_larc_reader *r);

typedef int (RARCALL *rarsdk_LArcEntryCallback)(void *user,
                                                  const char *name,
                                                  unsigned int method,
                                                  int encrypted,
                                                  unsigned long long origLen,
                                                  unsigned long long compLen);
RARAPI int   RARCALL rarsdk_LArcReaderList(rarsdk_larc_reader *r,
                                             rarsdk_LArcEntryCallback cb,
                                             void *user);
RARAPI int   RARCALL rarsdk_LArcReaderExtractAll(rarsdk_larc_reader *r,
                                                   const wchar_t *outDir,
                                                   const char *password);

#ifdef __cplusplus
}
#endif

#endif /* RARSDK_H */
