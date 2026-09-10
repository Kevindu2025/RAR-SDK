/*
 * la_aes.cpp - C wrapper exposing learnarc's AES-128/256 block + CBC
 *              as rarsdk_LaAes* C functions.
 *
 * Underlying implementation: include/learnarc/aes.hpp (FIPS-197, teaching
 * implementation). This file bridges the C++ namespace to the SDK's C ABI.
 *
 * Note: rarsdk_AESInit/Process/Free in rarsdk.h is a *separate* API used by
 * the RAR5 writer (in rs_aes.cpp) and intentionally retained. The LaAes* API
 * is the lower-level, key-per-op, block-level primitive that callers who
 * want fine-grained control over CBC padding/chaining should prefer.
 */
#include "rarsdk.h"
#include "include/learnarc/aes.hpp"

#include <cstdlib>
#include <cstring>

extern "C" {

rarsdk_la_aes RARCALL rarsdk_LaAesInit(const void *key, unsigned int keyBits)
{
    if (!key) return NULL;
    if (keyBits != 128 && keyBits != 192 && keyBits != 256) return NULL;
    learnarc::AesKey *k = new learnarc::AesKey();
    learnarc::aes_key_init(k, static_cast<const unsigned char*>(key), (int)keyBits);
    return reinterpret_cast<rarsdk_la_aes>(k);
}

void RARCALL rarsdk_LaAesEncryptBlock(rarsdk_la_aes ctx,
                                       const void *in16, void *out16)
{
    if (!ctx || !in16 || !out16) return;
    learnarc::aes_encrypt_block(reinterpret_cast<learnarc::AesKey*>(ctx),
                                static_cast<const unsigned char*>(in16),
                                static_cast<unsigned char*>(out16));
}

void RARCALL rarsdk_LaAesDecryptBlock(rarsdk_la_aes ctx,
                                       const void *in16, void *out16)
{
    if (!ctx || !in16 || !out16) return;
    learnarc::aes_decrypt_block(reinterpret_cast<learnarc::AesKey*>(ctx),
                                static_cast<const unsigned char*>(in16),
                                static_cast<unsigned char*>(out16));
}

void RARCALL rarsdk_LaAesCbcEncrypt(rarsdk_la_aes ctx, const void *iv16,
                                     const void *in, void *out, size_t bytes)
{
    if (!ctx || !iv16 || (bytes && (!in || !out))) return;
    if (bytes % 16 != 0) return;
    learnarc::aes_cbc_encrypt(reinterpret_cast<learnarc::AesKey*>(ctx),
                              static_cast<const unsigned char*>(iv16),
                              static_cast<const unsigned char*>(in),
                              static_cast<unsigned char*>(out),
                              bytes);
}

void RARCALL rarsdk_LaAesCbcDecrypt(rarsdk_la_aes ctx, const void *iv16,
                                     const void *in, void *out, size_t bytes)
{
    if (!ctx || !iv16 || (bytes && (!in || !out))) return;
    if (bytes % 16 != 0) return;
    learnarc::aes_cbc_decrypt(reinterpret_cast<learnarc::AesKey*>(ctx),
                              static_cast<const unsigned char*>(iv16),
                              static_cast<const unsigned char*>(in),
                              static_cast<unsigned char*>(out),
                              bytes);
}

void RARCALL rarsdk_LaAesFree(rarsdk_la_aes ctx)
{
    if (!ctx) return;
    delete reinterpret_cast<learnarc::AesKey*>(ctx);
}

}  /* extern "C" */
