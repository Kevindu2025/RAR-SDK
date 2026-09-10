// ============================================================================
// container.hpp - learnarc archive container format (LA v1)
// ----------------------------------------------------------------------------
// A real container you can open in a hex editor and study. Design borrows
// three ideas from RAR5:
//
//   1. per-entry CRC32 (RAR's "header CRC + whole-data CRC" layering)
//   2. method field: store / lzh / ppm (RAR's COMPINFO bit-field idea)
//   3. optional encryption with per-file salt/initV (RAR's FHEXTRA_CRYPT)
//
// Binary layout (all little-endian):
//
//   magic  "LArc\x01\x00"                     6
//   -- repeated until end mark: one entry --
//   entryCRC32                                 4   (covers nameLen .. data end)
//   nameLen                                     2
//   name (UTF-8)                               N
//   method                                      1   0=store 1=lzh 2=ppm
//   flags                                       1   bit0=encrypted
//   origLen                                    8
//   compLen                                    8
//   origCRC32                                  4   (plain CRC, or MAC if enc)
//   [flags.encrypted] salt[16] initV[16] lg2(1) pswCheck[8] csum[4]
//   data (compLen)                             M
//   -- end mark: two bytes FFFF read as nameLen --
//
// Security details (mirroring real RAR5, see arcrypto.hpp comments):
//   * after decompress we always verify origLen + CRC - silent corruption
//     can never pass
//   * when encrypted, the stored CRC is an HMAC-folded value: without the
//     password you cannot forge a checksum for modified ciphertext
//   * pswCheck + csum: fast password trial without decrypting; the check
//     value itself is protected against tampering (sha256 prefix)
// ============================================================================
#pragma once
#include "sha256.hpp"
#include "arcrypto.hpp"
#include "lzh.hpp"
#include "ppm.hpp"
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>
#include <cstdio>
#include <functional>

namespace learnarc {

constexpr char LA_MAGIC[6] = { 'L','A','r','c', 1, 0 };
constexpr uint16_t LA_ENDMARK = 0xFFFF;

// --------------------------------------------------------- CRC32 (RAR style) --
inline uint32_t crc32_update(uint32_t crc, const void *data, size_t n)
{
    static uint32_t tab[256]; static bool init = false;
    if (!init) {
        for (uint32_t i = 0; i < 256; i++) {
            uint32_t c = i;
            for (int k = 0; k < 8; k++) c = (c & 1) ? (c >> 1) ^ 0xEDB88320u : c >> 1;
            tab[i] = c;
        }
        init = true;
    }
    const uint8_t *p = (const uint8_t*)data;
    while (n--) crc = tab[(crc ^ *p++) & 0xff] ^ (crc >> 8);
    return crc;
}
inline uint32_t crc32_buf(const void *d, size_t n)
{ return crc32_update(0xFFFFFFFFu, d, n) ^ 0xFFFFFFFFu; }

// --------------------------------------------------------------- random --
// IV/salt must come from the OS CSPRNG. We call RtlGenRandom
// (advapi32!SystemFunction036) directly - no macro switches needed, and it
// shows how a system entropy source is invoked. Production code may prefer
// BCryptGenRandom.
extern "C" __declspec(dllimport) int __stdcall SystemFunction036(void *, unsigned long);
inline void fill_random(uint8_t *p, size_t n)
{
    if (n) SystemFunction036(p, (unsigned long)n);
}

// -------------------------------------------------------------- LE I/O --
inline void w16(std::vector<uint8_t> &v, uint16_t x)
{ v.push_back((uint8_t)x); v.push_back((uint8_t)(x >> 8)); }
inline void w32(std::vector<uint8_t> &v, uint32_t x)
{ for (int i = 0; i < 4; i++) v.push_back((uint8_t)(x >> (8*i))); }
inline void w64(std::vector<uint8_t> &v, uint64_t x)
{ for (int i = 0; i < 8; i++) v.push_back((uint8_t)(x >> (8*i))); }
struct Rd { const uint8_t *p; size_t n, pos = 0;
    bool ok() const { return pos < n; }
    uint8_t  u8()  { return ok() ? p[pos++] : 0; }
    uint16_t u16() { uint16_t a = u8(); return (uint16_t)(a | ((uint16_t)u8() << 8)); }
    uint32_t u32() { uint32_t a = u16(); return a | ((uint32_t)u16() << 16); }
    uint64_t u64() { uint64_t a = u32(); return a | ((uint64_t)u32() << 32); }
    void bytes(uint8_t *dst, size_t k) { for (size_t i = 0; i < k; i++) dst[i] = u8(); }
    std::string str(size_t k) { if (pos + k > n) k = n - pos; std::string s((const char*)p + pos, k); pos += k; return s; }
};

// ----------------------------------------------------------- write side --
struct AddOptions {
    int  method = 1;          // 0 store / 1 lzh / 2 ppm
    int  ppmOrder = 6;
    bool encrypt = false;
    const char *password = nullptr;
    unsigned kdfLg2 = 15;
};

inline void archive_init(std::vector<uint8_t> &arc)
{ arc.clear(); arc.insert(arc.end(), LA_MAGIC, LA_MAGIC + 6); }

inline void archive_finish(std::vector<uint8_t> &arc)
{ w16(arc, LA_ENDMARK); }

// Compress one file and append as an entry. 0 = ok, negative = error.
inline int add_one(std::vector<uint8_t> &arc, const std::string &name,
                   const uint8_t *data, size_t n,
                   const AddOptions &opt, std::string *err = nullptr)
{
    // ---- 1. method layer: try to compress; fall back to store ----
    int method = 0;
    std::vector<uint8_t> payload;
    uint32_t contentCrc = crc32_buf(data, n);

    if (opt.method == 1 && n >= 64) {
        std::vector<uint8_t> tmp;
        // window 4 MB / chain depth 64 ~ RAR -m3 match strength
        if (LzhEncoder::encode(data, n, 4 << 20, 64, tmp)) { payload = std::move(tmp); method = 1; }
    } else if (opt.method == 2 && n >= 64) {
        std::vector<uint8_t> tmp;
        if (ppm_compress(data, n, opt.ppmOrder, tmp)) { payload = std::move(tmp); method = 2; }
    }
    if (method == 0 || payload.size() >= n) {
        payload.assign(data, data + n);
        method = 0;
    }

    // ---- 2. encryption layer (RAR5 semantics) ----
    uint8_t salt[16] = {}, initV[16] = {}, pswCheck[8] = {}, csum4[4] = {};
    uint32_t storedCrc = contentCrc;
    if (opt.encrypt) {
        if (!opt.password || !*opt.password) { if (err) *err = "encryption needs a password"; return -1; }
        fill_random(salt, 16);
        fill_random(initV, 16);
        Rar5Keys keys;
        derive_keys(opt.password, salt, opt.kdfLg2, &keys);
        memcpy(pswCheck, keys.pswCheck, 8);
        pswcheck_csum(pswCheck, csum4);
        // RAR padding: zero-pad to 16 multiple (true length lives in header)
        size_t padded = (payload.size() + 15) & ~(size_t)15; if (!padded) padded = 16;
        std::vector<uint8_t> enc(padded);
        size_t encLen = encrypt_stream(&keys, initV, payload.data(), payload.size(), enc.data());
        enc.resize(encLen);
        payload = std::move(enc);
        storedCrc = mac_crc32(&keys, contentCrc);   // CRC -> MAC (anti-forgery)
    }

    // ---- 3. serialize ----
    std::vector<uint8_t> body;
    w16(body, (uint16_t)name.size());
    for (char c : name) body.push_back((uint8_t)c);
    body.push_back((uint8_t)method);
    body.push_back((uint8_t)(opt.encrypt ? 1 : 0));
    w64(body, n);
    w64(body, payload.size());
    w32(body, storedCrc);
    if (opt.encrypt) {
        body.insert(body.end(), salt, salt + 16);
        body.insert(body.end(), initV, initV + 16);
        body.push_back((uint8_t)opt.kdfLg2);
        body.insert(body.end(), pswCheck, pswCheck + 8);
        body.insert(body.end(), csum4, csum4 + 4);
    }
    uint32_t entryCrc = crc32_buf(body.data(), body.size());
    entryCrc = crc32_update(entryCrc ^ 0xFFFFFFFFu, payload.data(), payload.size()) ^ 0xFFFFFFFFu;

    w32(arc, entryCrc);
    arc.insert(arc.end(), body.begin(), body.end());
    arc.insert(arc.end(), payload.begin(), payload.end());
    return 0;
}

// ----------------------------------------------------------- read side --
struct EntryInfo {
    std::string name;
    int method = 0;
    bool encrypted = false;
    size_t origLen = 0, compLen = 0;
    uint32_t crcStored = 0;
    // encryption header fields (filled by iterate, used by extract)
    uint8_t salt[16] = {}, initV[16] = {}, pswCheck[8] = {}, csum4[4] = {};
    uint8_t lg2 = 15;
    uint32_t entryCrc = 0;
};

inline int iterate(const uint8_t *arc, size_t n,
                   const std::function<int(const EntryInfo&, const uint8_t*, size_t)> &fn,
                   std::string *err = nullptr)
{
    if (n < 6 || memcmp(arc, LA_MAGIC, 6) != 0) { if (err) *err = "not a LArc archive"; return -1; }
    Rd rd { arc + 6, n - 6 };
    while (true) {
        if (rd.pos + 2 > rd.n) { if (err) *err = "truncated (no end mark)"; return -1; }
        uint16_t peek = (uint16_t)(rd.p[rd.pos] | ((uint16_t)rd.p[rd.pos+1] << 8));
        if (peek == LA_ENDMARK) return 0;
        if (rd.pos + 4 > rd.n) { if (err) *err = "truncated entry"; return -1; }
        size_t entryStart = rd.pos;
        EntryInfo ei;
        ei.entryCrc = rd.u32();
        uint16_t nameLen = rd.u16();
        ei.name = rd.str(nameLen);
        ei.method = rd.u8();
        ei.encrypted = (rd.u8() & 1) != 0;
        ei.origLen = (size_t)rd.u64();
        ei.compLen = (size_t)rd.u64();
        ei.crcStored = rd.u32();
        if (ei.encrypted) {
            rd.bytes(ei.salt, 16); rd.bytes(ei.initV, 16);
            ei.lg2 = rd.u8(); rd.bytes(ei.pswCheck, 8); rd.bytes(ei.csum4, 4);
        }
        if (rd.pos + ei.compLen > rd.n) { if (err) *err = "truncated data: " + ei.name; return -1; }
        // entryCRC covers [nameLen .. dataEnd)
        uint32_t calc = crc32_update(0xFFFFFFFFu, arc + 6 + entryStart + 4,
                                     (rd.pos - entryStart - 4) + ei.compLen);
        calc ^= 0xFFFFFFFFu;
        if (calc != ei.entryCrc) { if (err) *err = "entry CRC mismatch: " + ei.name; return -2; }
        int rc = fn(ei, arc + 6 + rd.pos, ei.compLen);
        if (rc) return rc;
        rd.pos += ei.compLen;
    }
}

// Extract one entry. password is required for encrypted entries;
// wrong password => -5 (same semantics as RARSDK_E_PASSWORD).
inline int extract_entry(const EntryInfo &ei, const uint8_t *comp, size_t compLen,
                         const char *password,
                         std::vector<uint8_t> &out, std::string *err = nullptr)
{
    const uint8_t *payload = comp;
    size_t payloadLen = compLen;
    Rar5Keys keys;
    std::vector<uint8_t> decBuf;

    if (ei.encrypted) {
        if (!password || !*password) { if (err) *err = "password required: " + ei.name; return -5; }
        // pswCheck self-verify (third layer of the three-layer defense)
        uint8_t cs[4]; pswcheck_csum(ei.pswCheck, cs);
        if (memcmp(cs, ei.csum4, 4) != 0) { if (err) *err = "pswcheck damaged: " + ei.name; return -2; }
        derive_keys(password, ei.salt, ei.lg2, &keys);
        if (memcmp(keys.pswCheck, ei.pswCheck, 8) != 0) {
            if (err) *err = "wrong password: " + ei.name; return -5;   // fast check
        }
        decBuf.resize(compLen & ~(size_t)15);
        decrypt_stream(&keys, ei.initV, comp, compLen, decBuf.data());
        payload = decBuf.data();
        payloadLen = compLen & ~(size_t)15;
    }

    // ---- method layer ----
    std::vector<uint8_t> plain;
    bool ok = false;
    if (ei.method == 0) {
        plain.assign(payload, payload + payloadLen);
        ok = plain.size() == ei.origLen;
    } else if (ei.method == 1) {
        ok = lzh_decode(payload, payloadLen, ei.origLen, 0, plain);
    } else if (ei.method == 2) {
        ok = ppm_decompress(payload, payloadLen, ei.origLen, 6, plain);
    }
    if (!ok) { if (err) *err = "decompress failed: " + ei.name; return -3; }

    // ---- final verification ----
    // Plain: compare CRC directly.
    // Encrypted: the header stores MAC(CRC) - so we MAC our computed CRC and
    // compare. MAC's meaning: an attacker without the password cannot forge
    // a ciphertext that passes verification.
    uint32_t contentCrc = crc32_buf(plain.data(), plain.size());
    if (ei.encrypted) contentCrc = mac_crc32(&keys, contentCrc);
    if (contentCrc != ei.crcStored) { if (err) *err = "CRC mismatch: " + ei.name; return -4; }
    out = std::move(plain);
    return 0;
}

} // namespace learnarc
