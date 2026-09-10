/*
 * test_all.c - comprehensive test of every public function in rarsdk.h
 *
 * Covers all 5 parts of the SDK public API:
 *   Part 1: RAR5 extraction  (10 functions)
 *   Part 2: RAR5 creation    (7 functions)
 *   Part 3: RAR5 primitives  (12 functions)
 *   Part 4: learnarc primitives (16 functions)
 *   Part 5: LArc container   (10 functions)
 *
 * Requires Rar.exe at D:\tmp\RAR\Rar.exe for official-WinRAR cross-check.
 * Each section reports per-assertion OK/FAIL with a final summary.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <wchar.h>

#ifdef _WIN32
#include <windows.h>
#include <io.h>
#endif

#include "rarsdk.h"

static int g_pass = 0;
static int g_fail = 0;
static int g_section = 0;

#define OK(expr) do {                                                       \
    g_pass++;                                                               \
    fprintf(stdout, "  [PASS] %s\n", #expr);                                \
} while (0)

#define FAILX(label, fmt, ...) do {                                         \
    g_fail++;                                                               \
    fprintf(stdout, "  [FAIL] %s " fmt "\n", label, ##__VA_ARGS__);         \
} while (0)

#define EXPECT(cond) do {                                                   \
    if (cond) { g_pass++; fprintf(stdout, "  [PASS] %s\n", #cond); }       \
    else      { g_fail++; fprintf(stdout, "  [FAIL] %s (line %d)\n",       \
                                   #cond, __LINE__); }                      \
} while (0)

#define SECTION(name) do {                                                  \
    g_section++; fprintf(stdout, "\n[%d] %s\n", g_section, name);          \
} while (0)

/* ----------------------------------------------------------------- */
static int run_cmd(const char *cmd)
{
    fprintf(stdout, "  $ %s\n", cmd);
    FILE *p = _popen(cmd, "r");
    if (!p) return -1;
    char buf[1024];
    while (fgets(buf, sizeof buf, p)) fputs(buf, stdout);
    return _pclose(p);
}

static int read_file_w(const wchar_t *path, unsigned char **out, size_t *outSize)
{
    FILE *f = _wfopen(path, L"rb");
    if (!f) return -1;
    _fseeki64(f, 0, SEEK_END);
    long long sz = _ftelli64(f);
    _fseeki64(f, 0, SEEK_SET);
    if (sz < 0) { fclose(f); return -1; }
    *out = (unsigned char*)malloc((size_t)sz);
    *outSize = fread(*out, 1, (size_t)sz, f);
    fclose(f);
    return 0;
}

static void write_file_w(const wchar_t *path, const void *data, size_t n)
{
    FILE *f = _wfopen(path, L"wb");
    fwrite(data, 1, n, f);
    fclose(f);
}

/* ================================================================== */
/*  Part 3: RAR5 primitives                                              */
/* ================================================================== */
static void test_part3_rar5_primitives(void)
{
    SECTION("Part 3: RAR5 primitives");

    /* --- vint --- */
    unsigned char v[10];
    size_t n = rarsdk_PutVint(0x123456789ABCDULL, v, sizeof v);
    EXPECT(n == 7);
    unsigned long long back = 0;
    size_t n2 = rarsdk_GetVint(v, n, &back);
    EXPECT(n2 == n);
    EXPECT(back == 0x123456789ABCDULL);

    /* small vint (single byte) */
    n = rarsdk_PutVint(127, v, sizeof v);
    EXPECT(n == 1);
    EXPECT(v[0] == 127);
    n2 = rarsdk_GetVint(v, n, &back);
    EXPECT(n2 == 1 && back == 127);

    /* --- CRC32 --- */
    /* Reference: CRC32("123456789") = 0xCBF43926 (RFC 3720 / PNG) */
    unsigned crc = rarsdk_CRC32(0xffffffff, "123456789", 9) ^ 0xffffffff;
    EXPECT(crc == 0xCBF43926);

    /* --- Blake2sp --- */
    unsigned char dg[32];
    rarsdk_Blake2sp("", 0, dg);
    EXPECT(dg[0] == 0xdd && dg[1] == 0x0e && dg[2] == 0x89 && dg[3] == 0x17);

    /* Blake2sp of "abc" - just sanity non-zero, deterministic */
    unsigned char dg_abc[32];
    rarsdk_Blake2sp("abc", 3, dg_abc);
    EXPECT(dg_abc[0] != 0);
    rarsdk_Blake2sp("abc", 3, dg);
    EXPECT(memcmp(dg, dg_abc, 32) == 0);

    /* Blake2spFile */
    unsigned char fdg[32]; unsigned int fcrc = 0;
    int rc = rarsdk_Blake2spFile(L"rarsdk.h", fdg, &fcrc);
    EXPECT(rc == 0);

    /* --- Rar5KDF --- */
    unsigned char key[32], hashKey[32], pswCheck[8];
    unsigned char salt[16] = { 0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,
                               0xfe,0xdc,0xba,0x98,0x76,0x54,0x32,0x10 };
    rc = rarsdk_Rar5KDF("password", salt, 15, key, hashKey, pswCheck);
    EXPECT(rc == 0);

    /* --- Rar3KDF --- */
    unsigned char r3key[16], r3iv[16];
    unsigned char r3salt[8] = { 1,2,3,4,5,6,7,8 };
    rc = rarsdk_Rar3KDF("test", r3salt, r3key, r3iv);
    EXPECT(rc == 0);

    /* --- AES (RAR5 context) --- */
    unsigned char aeskey[16] = { 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16 };
    unsigned char iv[16] = {0};
    RARSDK_AES *aes = rarsdk_AESInit(1, aeskey, 128, iv);
    EXPECT(aes != NULL);
    if (aes) {
        unsigned char blk[16] = {0};
        rarsdk_AESProcess(aes, blk, 16);
        /* not zero anymore after encryption */
        EXPECT(blk[0] != 0 || blk[1] != 0 || blk[15] != 0);
        rarsdk_AESFree(aes);
    }

    /* --- RS16 GF(2^16) --- */
    RARSDK_RS16 *rs = rarsdk_RS16Init(8, 2, NULL);
    EXPECT(rs != NULL);
    if (rs) {
        unsigned char data[16], ecc[16];
        memset(data, 0x55, 16);
        memset(ecc, 0, 16);
        for (unsigned d = 0; d < 8; d++) {
            for (unsigned r = 0; r < 2; r++) {
                unsigned char dd[16] = {0};
                dd[0] = (unsigned char)d;
                rarsdk_RS16UpdateECC(rs, d, r, dd, ecc, 16);
            }
        }
        EXPECT(ecc[0] != 0);   /* some parity accumulated */
        rarsdk_RS16Free(rs);
    }
}

/* ================================================================== */
/*  Part 4: learnarc primitives                                          */
/* ================================================================== */
static void test_part4_learnarc(void)
{
    SECTION("Part 4: learnarc primitives (rarsdk_La*)");

    /* SHA-256 "abc" */
    unsigned char dg[32];
    static const unsigned char SHA256_ABC[32] = {
        0xba,0x78,0x16,0xbf,0x8f,0x01,0xcf,0xea,0x41,0x41,0x40,0xde,0x5d,0xae,0x22,0x23,
        0xb0,0x03,0x61,0xa3,0x96,0x17,0x7a,0x9c,0xb4,0x10,0xff,0x61,0xf2,0x00,0x15,0xad
    };
    rarsdk_LaSha256("abc", 3, dg);
    EXPECT(memcmp(dg, SHA256_ABC, 32) == 0);

    /* SHA-256 incremental */
    rarsdk_la_sha256_ctx ctx;
    rarsdk_LaSha256Init(&ctx);
    rarsdk_LaSha256Update(&ctx, "ab", 2);
    rarsdk_LaSha256Update(&ctx, "c", 1);
    rarsdk_LaSha256Final(&ctx, dg);
    EXPECT(memcmp(dg, SHA256_ABC, 32) == 0);

    /* HMAC-SHA256 RFC 4231 test case 1 */
    unsigned char mac[32];
    static const unsigned char HMAC_RFC4231_1[32] = {
        0xb0,0x34,0x4c,0x61,0xd8,0xdb,0x38,0x53,0x5c,0xa8,0xaf,0xce,0xaf,0x0b,0xf1,0x2b,
        0x88,0x1d,0xc2,0x00,0xc9,0x83,0x3d,0xa7,0x26,0xe9,0x37,0x6c,0x2e,0x32,0xcf,0xf7
    };
    unsigned char k1[20]; memset(k1, 0x0b, 20);
    rarsdk_LaHmacSha256(k1, 20, "Hi There", 8, mac);
    EXPECT(memcmp(mac, HMAC_RFC4231_1, 32) == 0);

    /* PBKDF2-HMAC-SHA256 sanity:
       1) two calls with same params produce same output (determinism)
       2) different password => different output
       3) different iterations => different output
       4) multi-block output > 32 bytes works */
    unsigned char dk1a[64], dk1b[64], dk2[64], dk3[64];
    unsigned char pbkdf_salt[4] = { 's','a','l','t' };
    EXPECT(rarsdk_LaPbkdf2HmacSha256("password", pbkdf_salt, 4, 1024, dk1a, 64) == 0);
    EXPECT(rarsdk_LaPbkdf2HmacSha256("password", pbkdf_salt, 4, 1024, dk1b, 64) == 0);
    EXPECT(memcmp(dk1a, dk1b, 64) == 0);
    EXPECT(rarsdk_LaPbkdf2HmacSha256("Password", pbkdf_salt, 4, 1024, dk2, 64) == 0);
    EXPECT(memcmp(dk1a, dk2, 64) != 0);
    EXPECT(rarsdk_LaPbkdf2HmacSha256("password", pbkdf_salt, 4, 2048, dk3, 64) == 0);
    EXPECT(memcmp(dk1a, dk3, 64) != 0);

    /* AES-256 block (FIPS-197 F.1.5 first block) */
    static const unsigned char K[32] = {
        0x60,0x3d,0xeb,0x10,0x15,0xca,0x71,0xbe,0x2b,0x73,0xae,0xf0,0x85,0x7d,0x77,0x81,
        0x1f,0x35,0x2c,0x07,0x3b,0x61,0x08,0xd7,0x2d,0x98,0x10,0xa3,0x09,0x14,0xdf,0xf4
    };
    static const unsigned char PT[16] = {
        0x6b,0xc1,0xbe,0xe2,0x2e,0x40,0x9f,0x96,0xe9,0x3d,0x7e,0x11,0x73,0x93,0x17,0x2a
    };
    static const unsigned char CT[16] = {
        0xf3,0xee,0xd1,0xbd,0xb5,0xd2,0xa0,0x3c,0x06,0x4b,0x5a,0x7e,0x3d,0xb1,0x81,0xf8
    };
    rarsdk_la_aes a = rarsdk_LaAesInit(K, 256);
    EXPECT(a != NULL);
    unsigned char out[16];
    rarsdk_LaAesEncryptBlock(a, PT, out);
    EXPECT(memcmp(out, CT, 16) == 0);
    rarsdk_LaAesDecryptBlock(a, CT, out);
    EXPECT(memcmp(out, PT, 16) == 0);

    /* AES-128 CBC roundtrip */
    static const unsigned char K128[16] = {
        0x2b,0x7e,0x15,0x16,0x28,0xae,0xd2,0xa6,0xab,0xf7,0x15,0x88,0x09,0xcf,0x4f,0x3c
    };
    unsigned char iv128[16] = {0};
    unsigned char plain[64], enc[64], dec[64];
    for (int i = 0; i < 64; i++) plain[i] = (unsigned char)i;
    rarsdk_la_aes a128 = rarsdk_LaAesInit(K128, 128);
    rarsdk_LaAesCbcEncrypt(a128, iv128, plain, enc, 64);
    EXPECT(memcmp(enc, plain, 64) != 0);
    rarsdk_LaAesCbcDecrypt(a128, iv128, enc, dec, 64);
    EXPECT(memcmp(dec, plain, 64) == 0);
    rarsdk_LaAesFree(a128);

    rarsdk_LaAesFree(a);

    /* LZH roundtrip */
    char text[4096];
    for (int i = 0; i < 4096; i++) text[i] = "learnarc LZ77+Huffman test "[i % 27];
    size_t tn = sizeof(text);
    unsigned char *comp = (unsigned char*)malloc(tn);
    int cn = rarsdk_LaLzhEncode(text, tn, 4 << 20, 64, comp, tn);
    EXPECT(cn > 0 && (size_t)cn < tn);
    unsigned char *back = (unsigned char*)malloc(tn);
    int dn = rarsdk_LaLzhDecode(comp, cn, tn, back, tn);
    EXPECT(dn == (int)tn && memcmp(back, text, tn) == 0);
    free(comp); free(back);

    /* PPM roundtrip */
    const char *ptxt = "the quick brown fox jumps over the lazy dog. "
                       "the quick brown fox jumps over the lazy dog. "
                       "the quick brown fox jumps over the lazy dog. ";
    size_t pn = strlen(ptxt);
    unsigned char *pcomp = (unsigned char*)malloc(pn + 64);
    int pcn = rarsdk_LaPpmCompress(ptxt, pn, 6, pcomp, pn + 64);
    EXPECT(pcn > 0);
    unsigned char *pdec = (unsigned char*)malloc(pn + 1);
    int pdn = rarsdk_LaPpmDecompress(pcomp, pcn, pn, 6, pdec, pn);
    EXPECT(pdn == (int)pn && memcmp(pdec, ptxt, pn) == 0);
    free(pcomp); free(pdec);
}

/* ================================================================== */
/*  Part 5: LArc container                                              */
/* ================================================================== */
static int larc_list_cb(void *u, const char *name, unsigned int method,
                        int encrypted, unsigned long long origLen, unsigned long long compLen)
{
    (void)u; (void)method; (void)encrypted; (void)origLen; (void)compLen;
    fprintf(stdout, "    entry: %s (%llu -> %llu)\n", name, origLen, compLen);
    return 0;
}

static void test_part5_larc(void)
{
    SECTION("Part 5: LArc container");

    /* store */
    rarsdk_larc_writer *w = rarsdk_LArcWriterCreate();
    EXPECT(w != NULL);
    const char *hello = "hello store";
    int rc = rarsdk_LArcWriterAddData(w, "hello.txt", hello, strlen(hello),
                                       0, 0, NULL, 0);
    EXPECT(rc == 0);
    rc = rarsdk_LArcWriterSave(w, L"test_all_store.la");
    EXPECT(rc == 0);
    rarsdk_LArcWriterFree(w);

    rarsdk_larc_reader *r = rarsdk_LArcReaderOpen(L"test_all_store.la");
    EXPECT(r != NULL);
    rc = rarsdk_LArcReaderList(r, larc_list_cb, NULL);
    EXPECT(rc == 0);
    rc = rarsdk_LArcReaderExtractAll(r, L"out_store_all", NULL);
    EXPECT(rc >= 1);
    rarsdk_LArcReaderClose(r);

    /* encrypted */
    w = rarsdk_LArcWriterCreate();
    char payload[1024];
    for (int i = 0; i < 1024; i++) payload[i] = "encrypted arc test "[i % 19];
    rc = rarsdk_LArcWriterAddData(w, "enc.bin", payload, sizeof(payload),
                                   1, 15, "P@ssw0rd", 1);
    EXPECT(rc == 0);
    rc = rarsdk_LArcWriterSave(w, L"test_all_enc.la");
    EXPECT(rc == 0);
    rarsdk_LArcWriterFree(w);

    /* AddFile / AddDir */
    write_file_w(L"test_all_src.txt", payload, sizeof(payload));
    w = rarsdk_LArcWriterCreate();
    rc = rarsdk_LArcWriterAddFile(w, L"test_all_src.txt", "renamed.txt",
                                    0, 0, NULL, 0);
    EXPECT(rc == 0);
    rc = rarsdk_LArcWriterAddDir(w, "subdir");
    EXPECT(rc == 0);
    rc = rarsdk_LArcWriterSave(w, L"test_all_misc.la");
    EXPECT(rc == 0);
    rarsdk_LArcWriterFree(w);

    /* Extract correct password */
    r = rarsdk_LArcReaderOpen(L"test_all_enc.la");
    EXPECT(r != NULL);
    rc = rarsdk_LArcReaderExtractAll(r, L"out_enc_all", "P@ssw0rd");
    EXPECT(rc >= 1);
    rarsdk_LArcReaderClose(r);

    /* wrong password rejected */
    r = rarsdk_LArcReaderOpen(L"test_all_enc.la");
    EXPECT(r != NULL);
    rc = rarsdk_LArcReaderExtractAll(r, L"out_wrong_all", "wrong");
    EXPECT(rc <= 0);
    rarsdk_LArcReaderClose(r);
}

/* ================================================================== */
/*  Part 1 + 2: RAR5 full roundtrip via SDK                                */
/* ================================================================== */

/* callback: count progress events */
static unsigned g_cb_total = 0, g_cb_files = 0;
static int CALLBACK progress_cb(UINT msg, LPARAM ud, LPARAM p1, LPARAM p2)
{
    (void)ud; (void)p1;
    if (msg == 1 /*UCM_PROCESSDATA*/) g_cb_total += (unsigned)p2;
    return 0;
}

static void test_part1_2_rar5(void)
{
    SECTION("Part 1: RAR5 extraction (full API)");
    /* Use the encrypted archive from previous tests */
    const wchar_t *arc = L"sdkenc.rar";
    const wchar_t *outdir = L"sdkout";

    /* Create a fresh test archive first */
    {
        struct rarsdk_create_params cp; memset(&cp, 0, sizeof cp);
        cp.arcName = arc;
        cp.rrPercent = 0;
        RARSDK_WRITER *w = rarsdk_CreateOpen(&cp);
        EXPECT(w != NULL);
        if (w) {
            unsigned char d[1500];
            for (int i = 0; i < 1500; i++) d[i] = (unsigned char)(i * 11);
            int rc = rarsdk_CreateAddData(w, L"a.bin", d, sizeof d);
            EXPECT(rc == 0);
            EXPECT(rarsdk_CreateClose(w) == 0);
        }
    }

    /* GetDllVersion */
    int v = rarsdk_GetDllVersion();
    EXPECT(v >= RAR_DLL_VERSION);

    /* IsArchive */
    unsigned int flags = 0;
    int rc = rarsdk_IsArchive(arc, &flags);
    EXPECT(rc == 0);   /* returns RARSDK_OK on success */

    /* TestArchive */
    rc = rarsdk_TestArchive(arc, NULL);
    EXPECT(rc == 0);

    /* ExtractArchive */
    rc = rarsdk_ExtractArchive(arc, outdir, NULL);
    EXPECT(rc == 0);

    /* OpenArchiveEx + ReadHeaderEx + ProcessFile (Test) */
    {
        struct RAROpenArchiveDataEx od; memset(&od, 0, sizeof od);
        od.ArcNameW = (wchar_t*)arc;
        od.OpenMode = RAR_OM_EXTRACT;
        void *h = rarsdk_OpenArchiveEx(&od);
        EXPECT(h != NULL && od.OpenResult == 0);
        if (h) {
            rarsdk_SetCallback(h, progress_cb, 0);
            struct RARHeaderDataEx hd; memset(&hd, 0, sizeof hd);
            rc = rarsdk_ReadHeaderEx(h, &hd);
            EXPECT(rc == 0);
            if (rc == 0) {
                g_cb_total = 0;
                rc = rarsdk_ProcessFileW(h, RAR_TEST, NULL, NULL);
                EXPECT(rc == 0);
            }
            rarsdk_CloseArchive(h);
        }
    }

    SECTION("Part 2: RAR5 creation (helpers + encrypted + RR)");

    /* PackDataToArchive (one-shot helper) */
    {
        unsigned char d[256];
        for (int i = 0; i < 256; i++) d[i] = (unsigned char)i;
        int rc = rarsdk_PackDataToArchive(L"sdkpack.rar", L"packed.bin", d, 256);
        EXPECT(rc == 0);
        EXPECT(rarsdk_TestArchive(L"sdkpack.rar", NULL) == 0);
    }

    /* PackFileToArchive (one-shot helper) */
    {
        write_file_w(L"sdkpack_src.bin", "source file content for pack helper test", 40);
        int rc = rarsdk_PackFileToArchive(L"sdkfile.rar", L"sdkpack_src.bin", L"file.txt");
        EXPECT(rc == 0);
        EXPECT(rarsdk_TestArchive(L"sdkfile.rar", NULL) == 0);
    }

    /* Encrypted with right/wrong password */
    {
        struct rarsdk_create_params cp; memset(&cp, 0, sizeof cp);
        cp.arcName = L"sdkenc.rar";
        cp.flags = RARSDK_WF_ENCRYPT_FILES;
        cp.password = L"secret123";
        cp.kdfLg2 = 15;
        RARSDK_WRITER *w = rarsdk_CreateOpen(&cp);
        EXPECT(w != NULL);
        if (w) {
            unsigned char d[2000];
            for (size_t i = 0; i < sizeof d; i++) d[i] = (unsigned char)(i * 13);
            EXPECT(rarsdk_CreateAddData(w, L"enc.bin", d, sizeof d) == 0);
            EXPECT(rarsdk_CreateClose(w) == 0);
        }
    }
    EXPECT(rarsdk_TestArchive(L"sdkenc.rar", L"secret123") == 0);
    EXPECT(rarsdk_ExtractArchive(L"sdkenc.rar", L"sdkenc_out", L"secret123") == 0);
    EXPECT(rarsdk_ExtractArchive(L"sdkenc.rar", L"sdkenc_bad", L"wrong") == RARSDK_E_PASSWORD);

    /* AddFile from real disk */
    {
        write_file_w(L"sdksrc.bin", "alpha bravo charlie delta echo", 31);
        struct rarsdk_create_params cp; memset(&cp, 0, sizeof cp);
        cp.arcName = L"sdkaf.rar";
        RARSDK_WRITER *w = rarsdk_CreateOpen(&cp);
        EXPECT(w != NULL);
        if (w) {
            struct rarsdk_add_params ap; memset(&ap, 0, sizeof ap);
            ap.srcName = L"sdksrc.bin";
            ap.method = RARSDK_MSTORE;
            ap.addCrc32 = 1;
            EXPECT(rarsdk_CreateAddFile(w, &ap) == 0);
            EXPECT(rarsdk_CreateAddDir(w, L"mydir") == 0);
            EXPECT(rarsdk_CreateClose(w) == 0);
        }
        EXPECT(rarsdk_TestArchive(L"sdkaf.rar", NULL) == 0);
    }

    /* RR archive */
    {
        struct rarsdk_create_params cp; memset(&cp, 0, sizeof cp);
        cp.arcName = L"sdkrr.rar";
        cp.rrPercent = 10;
        RARSDK_WRITER *w = rarsdk_CreateOpen(&cp);
        EXPECT(w != NULL);
        if (w) {
            unsigned char d[3000];
            for (size_t i = 0; i < sizeof d; i++) d[i] = (unsigned char)(i * 31 + 7);
            EXPECT(rarsdk_CreateAddData(w, L"rr.bin", d, sizeof d) == 0);
            EXPECT(rarsdk_CreateClose(w) == 0);
        }
    }

    /* RecoverArchive (RS decode path) */
    {
        /* Copy archive and flip one byte in the data area */
        unsigned char *buf; size_t bufsz;
        EXPECT(read_file_w(L"sdkrr.rar", &buf, &bufsz) == 0);
        if (buf && bufsz > 200) {
            buf[200] ^= 0xFF;
            write_file_w(L"sdkrrc.rar", buf, bufsz);
            free(buf);
            int n = rarsdk_RecoverArchive(L"sdkrrc.rar");
            fprintf(stdout, "  RecoverArchive returned %d blocks (>= 0 means ran)\n", n);
            EXPECT(n >= 0);
        }
    }

    /* SetPasswordW */
    {
        struct RAROpenArchiveDataEx od; memset(&od, 0, sizeof od);
        od.ArcNameW = (wchar_t*)L"sdkenc.rar";
        od.OpenMode = RAR_OM_LIST;
        void *h = rarsdk_OpenArchiveEx(&od);
        EXPECT(h != NULL);
        if (h) {
            rarsdk_SetPasswordW(h, L"secret123");
            struct RARHeaderDataEx hd; memset(&hd, 0, sizeof hd);
            rc = rarsdk_ReadHeaderEx(h, &hd);
            EXPECT(rc == 0);
            if (rc == 0) {
                EXPECT((hd.Flags & RHDF_ENCRYPTED) != 0);
                rc = rarsdk_ProcessFileW(h, RAR_SKIP, NULL, NULL);
                EXPECT(rc == 0);
            }
            rarsdk_CloseArchive(h);
        }
    }

    /* ProcessFile (ANSI variant) */
    {
        struct RAROpenArchiveDataEx od; memset(&od, 0, sizeof od);
        od.ArcName = (char*)"sdkpack.rar";
        od.OpenMode = RAR_OM_EXTRACT;
        void *h = rarsdk_OpenArchiveEx(&od);
        EXPECT(h != NULL);
        if (h) {
            struct RARHeaderDataEx hd; memset(&hd, 0, sizeof hd);
            rc = rarsdk_ReadHeaderEx(h, &hd);
            EXPECT(rc == 0);
            if (rc == 0) {
                rc = rarsdk_ProcessFile(h, RAR_TEST, NULL, NULL);
                EXPECT(rc == 0);
            }
            rarsdk_CloseArchive(h);
        }
    }
}

/* ================================================================== */
/*  Cross-validation with official Rar.exe (if available)                 */
/* ================================================================== */
static void test_cross_official_rar(void)
{
    SECTION("Cross-validation with official Rar.exe (D:\\tmp\\RAR\\Rar.exe)");
    FILE *p = _popen("\"D:\\tmp\\RAR\\Rar.exe\" 2>&1", "r");
    if (!p) {
        fprintf(stdout, "  [SKIP] Rar.exe not available\n");
        return;
    }
    char buf[256]; (void)fgets(buf, sizeof buf, p);
    _pclose(p);
    fprintf(stdout, "  Rar.exe present: %s", buf);

    /* Test our plain store archive */
    run_cmd("\"D:\\tmp\\RAR\\Rar.exe\" t -y sdkpack.rar");
    /* Test our encrypted archive */
    run_cmd("\"D:\\tmp\\RAR\\Rar.exe\" t -y -psecret123 sdkenc.rar");
    /* Test our RR archive */
    run_cmd("\"D:\\tmp\\RAR\\Rar.exe\" t -y sdkrr.rar");
    /* Verify RR recovery */
    run_cmd("\"D:\\tmp\\RAR\\Rar.exe\" rv -y sdkrr.rar");
}

/* ================================================================== */
int main(void)
{
    fprintf(stdout, "=== rarsdk comprehensive test ===\n");
    fprintf(stdout, "DLL version: %d (RAR_DLL_VERSION=%d)\n",
            rarsdk_GetDllVersion(), RAR_DLL_VERSION);

    test_part3_rar5_primitives();
    test_part4_learnarc();
    test_part5_larc();
    test_part1_2_rar5();
    test_cross_official_rar();

    fprintf(stdout, "\n=== summary: %d passed, %d failed ===\n", g_pass, g_fail);
    return g_fail ? 1 : 0;
}
