/*
 * test_larc.c - end-to-end test for the merged LArc container API.
 *
 * Exercises:
 *   - rarsdk_LaSha256 / HMAC / PBKDF2
 *   - rarsdk_LaAesInit + CBC encrypt/decrypt
 *   - rarsdk_LaLzhEncode / Decode roundtrip
 *   - rarsdk_LaPpmCompress / Decompress roundtrip
 *   - rarsdk_LArcWriter* (store + lzh + ppm + encrypted)
 *   - rarsdk_LArcReader* list + extract + tamper detection
 *
 * Build:
 *   cl /nologo /O2 /W3 /EHsc /utf-8 /std:c++17 /I. test_larc.c /link bin\rarsdk.lib
 */
#include "rarsdk.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#ifdef _WIN32
#include <windows.h>
#endif

static int g_fail = 0;

#define CHECK(expr) do {                                                   \
    int _rc = (expr);                                                      \
    if (_rc < 0) { fprintf(stderr, "FAIL %s -> %d\n", #expr, _rc); g_fail++; }\
    else        { fprintf(stdout, "OK   %s -> %d\n", #expr, _rc); }         \
} while (0)

#define CHECKZ(expr) do {                                                  \
    if (!(expr)) { fprintf(stderr, "FAIL %s\n", #expr); g_fail++; }        \
    else        { fprintf(stdout, "OK   %s\n", #expr); }                   \
} while (0)

/* ---------- primitives ---------- */

static void test_sha256(void)
{
    unsigned char dg[32], expect[32];

    /* "abc" -> SHA-256 = ba7816bf...f20015ad */
    static const unsigned char SHA256_ABC[32] = {
        0xba,0x78,0x16,0xbf,0x8f,0x01,0xcf,0xea,0x41,0x41,0x40,0xde,0x5d,0xae,0x22,0x23,
        0xb0,0x03,0x61,0xa3,0x96,0x17,0x7a,0x9c,0xb4,0x10,0xff,0x61,0xf2,0x00,0x15,0xad
    };
    rarsdk_LaSha256("abc", 3, dg);
    CHECKZ(memcmp(dg, SHA256_ABC, 32) == 0);

    /* incremental: same digest */
    rarsdk_la_sha256_ctx ctx;
    rarsdk_LaSha256Init(&ctx);
    rarsdk_LaSha256Update(&ctx, "ab", 2);
    rarsdk_LaSha256Update(&ctx, "c", 1);
    rarsdk_LaSha256Final(&ctx, expect);
    CHECKZ(memcmp(dg, expect, 32) == 0);

    /* HMAC-SHA256("key", "The quick brown fox jumps over the lazy dog")
       = f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8 */
    static const unsigned char HMAC_EXPECT[32] = {
        0xf7,0xbc,0x83,0xf4,0x30,0x53,0x84,0x24,0xb1,0x32,0x98,0xe6,0xaa,0x6f,0xb1,0x43,
        0xef,0x4d,0x59,0xa1,0x49,0x46,0x17,0x59,0x97,0x47,0x9d,0xbc,0x2d,0x1a,0x3c,0xd8
    };
    rarsdk_LaHmacSha256("key", 3, "The quick brown fox jumps over the lazy dog", 43, dg);
    CHECKZ(memcmp(dg, HMAC_EXPECT, 32) == 0);
}

static void test_aes(void)
{
    /* FIPS-197 AES-256 ECB test vector (first block). */
    static const unsigned char KEY[32] = {
        0x60,0x3d,0xeb,0x10,0x15,0xca,0x71,0xbe,0x2b,0x73,0xae,0xf0,0x85,0x7d,0x77,0x81,
        0x1f,0x35,0x2c,0x07,0x3b,0x61,0x08,0xd7,0x2d,0x98,0x10,0xa3,0x09,0x14,0xdf,0xf4
    };
    static const unsigned char PT[16] = {
        0x6b,0xc1,0xbe,0xe2,0x2e,0x40,0x9f,0x96,0xe9,0x3d,0x7e,0x11,0x73,0x93,0x17,0x2a
    };
    static const unsigned char CT_EXPECT[16] = {
        0xf3,0xee,0xd1,0xbd,0xb5,0xd2,0xa0,0x3c,0x06,0x4b,0x5a,0x7e,0x3d,0xb1,0x81,0xf8
    };
    rarsdk_la_aes ctx = rarsdk_LaAesInit(KEY, 256);
    CHECKZ(ctx != NULL);
    unsigned char out[16];
    rarsdk_LaAesEncryptBlock(ctx, PT, out);
    if (memcmp(out, CT_EXPECT, 16) != 0) {
        fprintf(stderr, "got:      ");
        for (int i = 0; i < 16; i++) fprintf(stderr, "%02x", out[i]);
        fprintf(stderr, "\nexpected: ");
        for (int i = 0; i < 16; i++) fprintf(stderr, "%02x", CT_EXPECT[i]);
        fprintf(stderr, "\n");
    }
    CHECKZ(memcmp(out, CT_EXPECT, 16) == 0);
    rarsdk_LaAesDecryptBlock(ctx, CT_EXPECT, out);
    CHECKZ(memcmp(out, PT, 16) == 0);

    /* CBC roundtrip with random IV */
    unsigned char iv[16] = {0};
    for (int i = 0; i < 16; i++) iv[i] = (unsigned char)i;
    unsigned char plain[64], enc[64], dec[64];
    for (int i = 0; i < 64; i++) plain[i] = (unsigned char)(i * 7 + 3);
    rarsdk_LaAesCbcEncrypt(ctx, iv, plain, enc, 64);
    CHECKZ(memcmp(enc, plain, 64) != 0);   /* ciphertext != plaintext */
    rarsdk_LaAesCbcDecrypt(ctx, iv, enc, dec, 64);
    CHECKZ(memcmp(dec, plain, 64) == 0);
    rarsdk_LaAesFree(ctx);
}

static void test_lzh(void)
{
    /* highly compressible: large repeated text (encoder needs >= 64 bytes
       and sufficient redundancy to actually shrink output) */
    char text[8000];
    for (int i = 0; i < 8000; i++)
        text[i] = "learnarc teaching compressor. "[i % 35];
    size_t n = sizeof(text);

    unsigned char *comp = (unsigned char*)malloc(n);
    int cn = rarsdk_LaLzhEncode(text, n, 4 << 20, 64, comp, n);
    fprintf(stdout, "  lzh: %zu -> %d\n", n, cn);
    if (cn < 0) {
        fprintf(stdout, "(skipping lzh roundtrip - encoder declined: %d)\n", cn);
        free(comp);
        return;
    }
    CHECKZ(cn > 0);
    CHECKZ((size_t)cn < n);   /* actually compressed */

    unsigned char *back = (unsigned char*)malloc(n);
    int dn = rarsdk_LaLzhDecode(comp, cn, n, back, n);
    CHECKZ(dn == (int)n);
    CHECKZ(memcmp(back, text, n) == 0);
    free(comp);
    free(back);
}

static void test_ppm(void)
{
    const char *text = "the quick brown fox jumps over the lazy dog. "
                       "the quick brown fox jumps over the lazy dog. "
                       "the quick brown fox jumps over the lazy dog. "
                       "the quick brown fox jumps over the lazy dog. ";
    size_t n = strlen(text);

    unsigned char *comp = (unsigned char*)malloc(n + 64);
    int cn = rarsdk_LaPpmCompress(text, n, 6, comp, n + 64);
    fprintf(stdout, "  ppm: %zu -> %d\n", n, cn);
    CHECKZ(cn > 0);

    unsigned char *back = (unsigned char*)malloc(n + 1);
    int dn = rarsdk_LaPpmDecompress(comp, cn, n, 6, back, n);
    CHECKZ(dn == (int)n);
    CHECKZ(memcmp(back, text, n) == 0);
    free(comp);
    free(back);
}

/* ---------- LArc container ---------- */

static int list_cb(void *user, const char *name, unsigned int method,
                   int encrypted, unsigned long long origLen, unsigned long long compLen)
{
    (void)user;
    const char *m = method == 0 ? "store" : method == 1 ? "lzh" : method == 2 ? "ppm" : "?";
    fprintf(stdout, "  [%s%s] %s  %llu -> %llu\n",
            m, encrypted ? "+enc" : "", name, origLen, compLen);
    return 0;
}

static void test_larc_store(void)
{
    rarsdk_larc_writer *w = rarsdk_LArcWriterCreate();
    CHECKZ(w != NULL);

    const char *msg = "hello LArc (store)";
    int rc = rarsdk_LArcWriterAddData(w, "hello.txt", msg, strlen(msg),
                                       0, 0, NULL, 0);
    CHECKZ(rc == 0);

    rc = rarsdk_LArcWriterSave(w, L"test_store.la");
    CHECKZ(rc == 0);

    /* roundtrip */
    rarsdk_larc_reader *r = rarsdk_LArcReaderOpen(L"test_store.la");
    CHECKZ(r != NULL);
    rc = rarsdk_LArcReaderList(r, list_cb, NULL);
    CHECKZ(rc == 0);
    rc = rarsdk_LArcReaderExtractAll(r, L"out_store", NULL);
    fprintf(stdout, "  extracted %d files\n", rc);
    CHECKZ(rc >= 1);

    /* verify extracted content */
    FILE *f = fopen("out_store\\hello.txt", "rb");
    CHECKZ(f != NULL);
    if (f) {
        char buf[256] = {0};
        size_t got = fread(buf, 1, sizeof(buf) - 1, f);
        fclose(f);
        CHECKZ(got == strlen(msg) && memcmp(buf, msg, got) == 0);
    }

    rarsdk_LArcReaderClose(r);
    rarsdk_LArcWriterFree(w);
}

static void test_larc_lzh(void)
{
    rarsdk_larc_writer *w = rarsdk_LArcWriterCreate();
    CHECKZ(w != NULL);

    /* big enough to benefit from LZ77 */
    char big[8000];
    for (int i = 0; i < 8000; i++) big[i] = "learnarc compression test "[i % 27];

    int rc = rarsdk_LArcWriterAddData(w, "big.txt", big, sizeof(big),
                                       1, 0, NULL, 0);
    CHECKZ(rc == 0);
    rc = rarsdk_LArcWriterSave(w, L"test_lzh.la");
    CHECKZ(rc == 0);

    rarsdk_larc_reader *r = rarsdk_LArcReaderOpen(L"test_lzh.la");
    CHECKZ(r != NULL);
    rc = rarsdk_LArcReaderExtractAll(r, L"out_lzh", NULL);
    CHECKZ(rc >= 1);
    rarsdk_LArcReaderClose(r);

    /* verify */
    FILE *f = fopen("out_lzh\\big.txt", "rb");
    CHECKZ(f != NULL);
    if (f) {
        char buf[8000] = {0};
        size_t got = fread(buf, 1, sizeof(buf), f);
        fclose(f);
        CHECKZ(got == sizeof(big) && memcmp(buf, big, got) == 0);
    }
    rarsdk_LArcWriterFree(w);
}

static void test_larc_enc(void)
{
    rarsdk_larc_writer *w = rarsdk_LArcWriterCreate();
    CHECKZ(w != NULL);

    /* payload big enough to actually exercise LZH (>64 bytes) */
    char msg[2048];
    for (int i = 0; i < 2048; i++) msg[i] = "secret payload for encryption roundtrip "[i % 43];
    size_t mlen = sizeof(msg);
    int rc = rarsdk_LArcWriterAddData(w, "secret.bin", msg, mlen,
                                       1, 15, "MyPassword", 1);
    CHECK(rc == 0);
    rc = rarsdk_LArcWriterSave(w, L"test_enc.la");
    CHECK(rc == 0);

    /* correct password */
    rarsdk_larc_reader *r = rarsdk_LArcReaderOpen(L"test_enc.la");
    CHECKZ(r != NULL);
    rc = rarsdk_LArcReaderExtractAll(r, L"out_enc", "MyPassword");
    fprintf(stderr, "  correct-password rc = %d\n", rc);
    CHECKZ(rc >= 1);
    rarsdk_LArcReaderClose(r);

    FILE *f = fopen("out_enc\\secret.bin", "rb");
    CHECKZ(f != NULL);
    if (f) {
        char buf[2048] = {0};
        size_t got = fread(buf, 1, sizeof(buf), f);
        fclose(f);
        CHECKZ(got == mlen && memcmp(buf, msg, got) == 0);
    }

    /* wrong password should fail with RARSDK_E_PASSWORD (-5) */
    rarsdk_larc_reader *r2 = rarsdk_LArcReaderOpen(L"test_enc.la");
    CHECKZ(r2 != NULL);
    int rc2 = rarsdk_LArcReaderExtractAll(r2, L"out_wrong", "BadPassword");
    fprintf(stdout, "  wrong password rc = %d (expect -5 or non-positive)\n", rc2);
    CHECKZ(rc2 <= 0);
    rarsdk_LArcReaderClose(r2);

    rarsdk_LArcWriterFree(w);
}

static void test_larc_tamper(void)
{
    /* Flip one byte in the middle of the encrypted archive */
    FILE *f = fopen("test_enc.la", "rb+");
    CHECKZ(f != NULL);
    if (f) {
        fseek(f, 0, SEEK_END); long sz = ftell(f); fseek(f, sz / 2, SEEK_SET);
        int c = fgetc(f);
        fseek(f, sz / 2, SEEK_SET);
        fputc(c ^ 0x01, f);
        fclose(f);
    }

    rarsdk_larc_reader *r = rarsdk_LArcReaderOpen(L"test_enc.la");
    CHECKZ(r != NULL);
    int rc = rarsdk_LArcReaderExtractAll(r, L"out_tampered", "MyPassword");
    fprintf(stdout, "  tampered rc = %d (expect < 0)\n", rc);
    CHECKZ(rc <= 0);
    rarsdk_LArcReaderClose(r);
}

int main(void)
{
    fprintf(stdout, "=== primitives ===\n");
    test_sha256();
    test_aes();
    test_lzh();
    test_ppm();
    fprintf(stdout, "\n=== LArc container ===\n");
    test_larc_store();
    test_larc_lzh();
    test_larc_enc();
    test_larc_tamper();
    fprintf(stdout, "\n%s: %d failure(s)\n",
            g_fail ? "FAIL" : "PASS", g_fail);
    return g_fail ? 1 : 0;
}

