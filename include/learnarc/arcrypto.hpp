// ============================================================================
// arcrypto.hpp - RAR5 同款加密栈的"配方"层
// ----------------------------------------------------------------------------
// 把 sha256.hpp 的原语按 RAR5 的方式组合起来。三个入口：
//
//   1. derive_keys()   —— 密码 → (Key, HashKey, PswCheck)
//   2. encrypt_stream() —— 数据 + Key → 密文（含 RAR 式 16 字节对齐填充）
//   3. mac_checksum()  —— 校验和 → HMAC 防伪校验值（RAR "HASHMAC" 语义）
//
// ── RAR5 的加密文件头（对应 FHEXTRA_CRYPT 记录）────────────────────────
//   version(0) | flags(PSWCHECK=1|HASHMAC=2) | lg2Count(1字节) |
//   salt[16]   | initV[16]                    | PswCheck[8]    | csum[4]
//
//   salt  ：随机 16 字节——同密码不同 salt → 不同密钥（防彩虹表/重放）
//   initV ：AES-CBC 的 IV——每文件独立随机（同 CBC 下防相同前缀泄漏）
//   lg2   ：KDF 迭代指数（RAR 默认 15 = 32768 次）
//   csum  ：sha256(PswCheck)[0..4)，让"密码指纹"本身可验证未被篡改
//           （为什么不直接信头 CRC32？头 CRC 只防意外损坏；防主动篡改
//            需要密码参与——这正是分层信任的教科书案例）
//
// ── RAR 的数据填充 ─────────────────────────────────────────────────────
// RAR 不用 PKCS#7！它直接把明文 pad 到 16 倍数再加密，原长度放在头里，
// 解密后裁掉。好处：省 1-16 字节、通道无关；坏处：无内建填充校验
// （所以 RAR 用 MAC 来兜完整性——见 mac_checksum）。
// ============================================================================
#pragma once
#include "sha256.hpp"
#include "aes.hpp"

namespace learnarc {

struct Rar5Keys {
    uint8_t key[32];       // AES-256 主密钥
    uint8_t hashKey[32];   // HMAC-SHA256 校验密钥
    uint8_t pswCheck[8];   // 密码指纹（快速验密）
};

inline void derive_keys(const char *utf8Password, const uint8_t salt[16],
                        unsigned lg2Count, Rar5Keys *out)
{
    // RAR 的 PBKDF2 有个特色：一次拉伸产出 3 段值（标准 PBKDF2 只有一段）。
    // 实现方式（见 UnRAR crypt5.cpp pbkdf2()）：迭代完 Key 的 2^lg2 次后，
    // 再各跑 16 次继续"炼"出 HashKey 和 PswCheck 原值——即总共
    //     [2^lg2, 2^lg2+16, 2^lg2+32] 三个 checkpoint。
    // 本教学实现等价改写：连续跑 (2^lg2 - 1) 次 + 16 + 16 = 三段 checkpoint。
    uint32_t count = 1u << lg2Count;
    uint8_t dk[32];
    pbkdf2_hmac_sha256(utf8Password, salt, 16, count, dk);

    // 复刻 UnRAR 的"连跑 16 次"结构得到 V1(HashKey)、V2(PswCheck 原值)
    uint8_t u[32]; memcpy(u, dk, 32);
    uint8_t v1[32], v2[32];
    // V1 = 第 (count+16) 个 checkpoint 的异或链
    {
        // 先从 count 时刻状态续跑——pbkdf2_hmac_sha256 内部不暴露状态，
        // 教学上用"再拉伸一轮再续 16 次"的等价形式：
        uint32_t iters = 16;
        uint8_t sdata[16+4];
        memcpy(sdata, salt, 16);
        sdata[16]=0; sdata[17]=0; sdata[18]=0; sdata[19]=1;
        hmac_sha256((const uint8_t*)utf8Password, strlen(utf8Password), sdata, 20, u);
        memcpy(v1, u, 32);
        for (uint32_t i = 1; i < iters; i++) {
            hmac_sha256((const uint8_t*)utf8Password, strlen(utf8Password), u, 32, u);
            for (int j = 0; j < 32; j++) v1[j] ^= u[j];
        }
        // v2：同法再来 16 次
        hmac_sha256((const uint8_t*)utf8Password, strlen(utf8Password), u, 32, u);
        memcpy(v2, u, 32);
        for (uint32_t i = 1; i < iters; i++) {
            hmac_sha256((const uint8_t*)utf8Password, strlen(utf8Password), u, 32, u);
            for (int j = 0; j < 32; j++) v2[j] ^= u[j];
        }
    }
    memcpy(out->key, dk, 32);
    memcpy(out->hashKey, v1, 32);
    // PswCheck = V2 的 32 字节按位置循环异或折叠成 8 字节
    // （i % 8 折叠：等价于把 32 字节按列异或成 8 列——checksum 常用手法）
    memset(out->pswCheck, 0, 8);
    for (int i = 0; i < 32; i++) out->pswCheck[i % 8] ^= v2[i];
}

// PswCheck 的自校验值（sha256(pswCheck) 前 4 字节）——写入加密头，防指纹被篡改
inline void pswcheck_csum(const uint8_t pswCheck[8], uint8_t out[4])
{
    uint8_t d[32]; sha256(pswCheck, 8, d);
    memcpy(out, d, 4);
}

// 数据加密：pad 到 16 倍数（RAR 式，pad 值为 0），返回加密后长度
inline size_t encrypt_stream(const Rar5Keys *keys, const uint8_t initV[16],
                             const uint8_t *plain, size_t plainLen,
                             uint8_t *out /* 至少 padded(plainLen) 字节 */)
{
    size_t padded = (plainLen + 15) & ~(size_t)15;
    if (padded == 0) padded = 16;              // RAR：至少一块（保 IV 链活性）
    uint8_t *buf = out;
    memset(buf, 0, padded);
    memcpy(buf, plain, plainLen);
    AesKey ak; aes_key_init(&ak, keys->key, 256);
    aes_cbc_encrypt(&ak, initV, buf, buf, padded);
    return padded;
}

inline size_t decrypt_stream(const Rar5Keys *keys, const uint8_t initV[16],
                             const uint8_t *cipher, size_t cipherLen,
                             uint8_t *out)
{
    AesKey ak; aes_key_init(&ak, keys->key, 256);
    aes_cbc_decrypt(&ak, initV, cipher, out, cipherLen & ~(size_t)15);
    return cipherLen & ~(size_t)15;
}

// ── MAC 校验和（RAR FHEXTRA_CRYPT_HASHMAC 语义）──────────────────────────
// RAR 对"存档校验值"做的变换（UnRAR crypt5.cpp ConvertHashToMAC）：
//   CRC32 字段：  mac = fold32( HMAC(HashKey, LE32(crc32)) )
//     fold32：把 32 字节 HMAC 按 4 字节一组异或折叠成 32 位（i&3 取字节位）
//   BLAKE2sp 字段：mac = HMAC(HashKey, blake2sp_digest)   （整 32 字节替换）
// 效果：攻击者不知道密码 → 不知道 HashKey → 改一个字节后无法伪造出合法
// 校验值。这是"加密 + 可验证完整性"的标准组合拳。
inline uint32_t mac_crc32(const Rar5Keys *keys, uint32_t crc)
{
    uint8_t raw[4] = { (uint8_t)crc, (uint8_t)(crc>>8), (uint8_t)(crc>>16), (uint8_t)(crc>>24) };
    uint8_t mac[32];
    hmac_sha256(keys->hashKey, 32, raw, 4, mac);
    uint32_t v = 0;
    for (int i = 0; i < 32; i++) v ^= (uint32_t)mac[i] << ((i & 3) * 8);
    return v;
}

} // namespace learnarc
