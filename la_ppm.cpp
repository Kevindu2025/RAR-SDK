/*
 * la_ppm.cpp - C wrapper exposing learnarc's simplified PPM (range-coded)
 *              as rarsdk_LaPpmCompress / rarsdk_LaPpmDecompress C functions.
 *
 * Underlying implementation: include/learnarc/ppm.hpp.
 *
 * Compress: returns compressed byte count on success (>= 0), or negative
 *           RARSDK_E_* if no gain / invalid args.
 * Decompress: returns decoded byte count (== originalLen), or negative on failure.
 */
#include "rarsdk.h"
#include "include/learnarc/ppm.hpp"

#include <cstring>
#include <vector>

extern "C" {

int RARCALL rarsdk_LaPpmCompress(const void *data, size_t n,
                                  unsigned int order,
                                  void *out, size_t outCap)
{
    if (!data && n) return RARSDK_E_PARAM;
    if (!out && outCap) return RARSDK_E_PARAM;
    if (order < 1 || order > 16) return RARSDK_E_RANGE;

    std::vector<uint8_t> dst;
    if (!learnarc::ppm_compress(static_cast<const uint8_t*>(data), n,
                                 (int)order, dst))
        return RARSDK_E_UNSUPPORTED;             /* no gain */

    if (dst.size() > outCap) return RARSDK_E_RANGE;
    if (dst.size() > 0) memcpy(out, dst.data(), dst.size());
    return (int)dst.size();
}

int RARCALL rarsdk_LaPpmDecompress(const void *in, size_t inSize,
                                    size_t originalLen, unsigned int order,
                                    void *out, size_t outCap)
{
    if (!in && inSize) return RARSDK_E_PARAM;
    if (!out && outCap) return RARSDK_E_PARAM;
    if (originalLen > outCap) return RARSDK_E_RANGE;
    if (order < 1 || order > 16) return RARSDK_E_RANGE;

    std::vector<uint8_t> dst;
    if (!learnarc::ppm_decompress(static_cast<const uint8_t*>(in), inSize,
                                   originalLen, (int)order, dst))
        return RARSDK_E_FORMAT;
    if (dst.size() != originalLen) return RARSDK_E_FORMAT;
    if (dst.size() > 0) memcpy(out, dst.data(), dst.size());
    return (int)dst.size();
}

}  /* extern "C" */
