/*
 * la_lzh.cpp - C wrapper exposing learnarc's LZ77 + canonical Huffman
 *              as rarsdk_LaLzhEncode / rarsdk_LaLzhDecode C functions.
 *
 * Underlying implementation: include/learnarc/lzh.hpp.
 *
 * Encode: returns compressed byte count on success (>= 0), or negative
 *         RARSDK_E_* code if no gain / OOM / invalid args.
 * Decode: returns decoded byte count on success (== originalLen), negative
 *         RARSDK_E_* on failure.
 */
#include "rarsdk.h"
#include "include/learnarc/lzh.hpp"

#include <cstring>
#include <vector>

extern "C" {

int RARCALL rarsdk_LaLzhEncode(const void *data, size_t n,
                                unsigned int windowSize, unsigned int maxChain,
                                void *out, size_t outCap)
{
    if (!data && n) return RARSDK_E_PARAM;
    if (!out && outCap) return RARSDK_E_PARAM;
    if (n < 64) return RARSDK_E_RANGE;            /* encoder always pays back below */

    std::vector<uint8_t> dst;
    if (!learnarc::LzhEncoder::encode(static_cast<const uint8_t*>(data), n,
                                       (int)windowSize, (int)maxChain, dst))
        return RARSDK_E_UNSUPPORTED;             /* no gain: caller should fall back to store */

    if (dst.size() > outCap) return RARSDK_E_RANGE;
    if (dst.size() > 0) memcpy(out, dst.data(), dst.size());
    return (int)dst.size();
}

int RARCALL rarsdk_LaLzhDecode(const void *in, size_t inSize, size_t originalLen,
                                void *out, size_t outCap)
{
    if (!in && inSize) return RARSDK_E_PARAM;
    if (!out && outCap) return RARSDK_E_PARAM;
    if (originalLen > outCap) return RARSDK_E_RANGE;

    std::vector<uint8_t> dst;
    if (!learnarc::lzh_decode(static_cast<const uint8_t*>(in), inSize,
                               originalLen, 0, dst))
        return RARSDK_E_FORMAT;
    if (dst.size() != originalLen) return RARSDK_E_FORMAT;
    if (dst.size() > 0) memcpy(out, dst.data(), dst.size());
    return (int)dst.size();
}

}  /* extern "C" */
