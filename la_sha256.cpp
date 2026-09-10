/*
 * la_sha256.cpp - C wrapper exposing learnarc's SHA-256/HMAC/PBKDF2
 *                  as rarsdk_La* C functions.
 *
 * The underlying implementation is in include/learnarc/sha256.hpp
 * (educational, public-domain style; comments preserved verbatim).
 * This file just bridges the C++ namespace to the SDK's C ABI.
 */
#include "rarsdk.h"
#include "include/learnarc/sha256.hpp"

#include <cstring>
#include <cstdint>

extern "C" {

/* ---- incremental SHA-256 ---- */

void RARCALL rarsdk_LaSha256Init(rarsdk_la_sha256_ctx *ctx)
{
    if (!ctx) return;
    learnarc::sha256_init(reinterpret_cast<learnarc::Sha256Ctx*>(ctx));
}

void RARCALL rarsdk_LaSha256Update(rarsdk_la_sha256_ctx *ctx,
                                    const void *data, size_t n)
{
    if (!ctx) return;
    learnarc::sha256_update(reinterpret_cast<learnarc::Sha256Ctx*>(ctx), data, n);
}

void RARCALL rarsdk_LaSha256Final(rarsdk_la_sha256_ctx *ctx,
                                   unsigned char out[32])
{
    if (!ctx || !out) return;
    learnarc::sha256_final(reinterpret_cast<learnarc::Sha256Ctx*>(ctx), out);
}

void RARCALL rarsdk_LaSha256(const void *data, size_t n, unsigned char out[32])
{
    if (!out) return;
    learnarc::sha256(data, n, out);
}

/* ---- HMAC-SHA-256 ---- */

void RARCALL rarsdk_LaHmacSha256(const void *key, size_t keyLen,
                                  const void *data, size_t dataLen,
                                  unsigned char out[32])
{
    if (!out) return;
    learnarc::hmac_sha256(static_cast<const unsigned char*>(key), keyLen,
                          data, dataLen, out);
}

/* ---- PBKDF2-HMAC-SHA-256 (RFC 2898, multi-block capable) ---- */
/* Returns 0 on success, -1 on bad params, -2 on saltLen overflow. */

int RARCALL rarsdk_LaPbkdf2HmacSha256(const char *password,
                                       const unsigned char *salt, size_t saltLen,
                                       unsigned int iterations,
                                       unsigned char *out, size_t outLen)
{
    if (!password || !salt || !out || iterations == 0 || outLen == 0) return -1;
    if (saltLen == 0 || saltLen > 76) return -2;

    size_t plen = strlen(password);
    uint32_t block = 1;
    size_t produced = 0;
    while (produced < outLen) {
        uint8_t sdata[80];
        memcpy(sdata, salt, saltLen);
        /* INT(i) = 4-byte big-endian block index */
        sdata[saltLen+0] = (unsigned char)(block >> 24);
        sdata[saltLen+1] = (unsigned char)(block >> 16);
        sdata[saltLen+2] = (unsigned char)(block >> 8);
        sdata[saltLen+3] = (unsigned char)(block);

        uint8_t u[32], fn[32];
        learnarc::hmac_sha256((const unsigned char*)password, plen,
                              sdata, saltLen + 4, u);
        memcpy(fn, u, 32);
        for (uint32_t i = 1; i < iterations; i++) {
            learnarc::hmac_sha256((const unsigned char*)password, plen,
                                  u, 32, u);
            for (int j = 0; j < 32; j++) fn[j] ^= u[j];
        }
        size_t take = (outLen - produced > 32) ? 32 : (outLen - produced);
        memcpy(out + produced, fn, take);
        produced += take;
        block++;
        if (block == 0) return -1;        /* INT32 overflow */
    }
    return 0;
}

}  /* extern "C" */
