// ============================================================================
// sha256.hpp - SHA-256 哈希 + HMAC-SHA256 + PBKDF2（教学实现）
// ----------------------------------------------------------------------------
// 这是整套学习的密码学地基。RAR5 加密栈的完整链条是：
//
//   用户密码(UTF-8)
//        │
//        ▼  PBKDF2-HMAC-SHA256(密码, salt[16], 2^lg2Count)
//   ┌────┴────────────────┬────────────────┐
//   Key[32]          HashKey[32]      PswCheck 原始值[32]
//   AES-256 主密钥   校验MAC的密钥      按字节异或折叠 → PswCheck[8]
//
// 为什么是这三个值？（对应 UnRAR crypt5.cpp 的 SetKey50）
//   * Key      —— 用来做 AES 加解密（真正的"锁芯"）
//   * HashKey  —— 用来做 HMAC（校验和防伪造：没有密码就伪造不出合法校验值）
//   * PswCheck —— 8 字节"密码指纹"，让解压者不解密数据就能快速判断密码对不对
//
// 教学要点：
//   1. SHA-256 本身只做一件事：把任意长度输入搅成 32 字节"指纹"。
//      它是单向的：无法从指纹还原输入。
//   2. HMAC = Hash( (K^opad) || Hash( (K^ipad) || data ) )
//      即"带密钥的哈希"。直接 hash(key||data) 是不安全的（长度扩展攻击），
//      HMAC 的内外双哈希结构防住了这一点。
//   3. PBKDF2 = 重复迭代 HMAC 来"炼化"密码。密码本身熵往往不足
//      （人类密码 ~20-40 bit 熵），暴力枚举太便宜；迭代 2^15=32768 次
//      让每次尝试都花 32768 次 HMAC 的代价，把攻击成本拉高 4 个数量级。
//      这就是"密钥拉伸"(key stretching)。
//
// 本文件实现遵循 FIPS 180-4 (SHA-256)、RFC 2104 (HMAC)、RFC 2898 (PBKDF2)。
// 代码优先照顾可读性（对照规范逐行看），不做性能优化。
// ============================================================================
#pragma once
#include <cstdint>
#include <cstring>
#include <cstdio>

namespace learnarc {

// ---------------------------------------------------------------- SHA-256 --
// 状态：8 个 32 位工作变量（初始化为分数常数开方的前 32 位——
// 这是中本聪式"没什么道理但人人可验证"的常数，防有人挑后门常数）
struct Sha256Ctx {
    uint32_t h[8];      // 工作变量 a..h 的持久部分
    uint64_t len;       // 已处理的总字节数（用于最终长度填充）
    uint8_t  buf[64];   // 当前未满块缓冲
    size_t   bufLen;
};

static const uint32_t SHA256_K[64] = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

inline void sha256_init(Sha256Ctx *c)
{
    // FIPS 180-4 section 5.3.3 的初值 H0..H7
    static const uint32_t IV[8] = {
        0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,
        0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19
    };
    memcpy(c->h, IV, sizeof IV);
    c->len = 0; c->bufLen = 0;
}

// 压缩函数：64 字节块 → 更新 8 个工作变量。
// 这就是 SHA-256 的"搅拌轮"：64 轮混合，每轮非线性 + 循环移位 + 常数加。
inline void sha256_block(Sha256Ctx *c, const uint8_t p[64])
{
    uint32_t w[64];
    // 消息调度：前 16 个字直接来自输入，后 48 个由前面的字递推
    // （w[i] = w[i-16] ^ σ0(w[i-15]) ^ w[i-7] ^ σ1(w[i-2])）
    for (int i = 0; i < 16; i++)
        w[i] = (uint32_t)p[4*i] << 24 | (uint32_t)p[4*i+1] << 16
             | (uint32_t)p[4*i+2] << 8 | (uint32_t)p[4*i+3];
    for (int i = 16; i < 64; i++) {
        uint32_t s0 = ((w[i-15]>>7)|(w[i-15]<<25)) ^ ((w[i-15]>>18)|(w[i-15]<<14)) ^ (w[i-15]>>3);
        uint32_t s1 = ((w[i-2]>>17)|(w[i-2]<<15)) ^ ((w[i-2]>>19)|(w[i-2]<<13)) ^ (w[i-2]>>10);
        w[i] = w[i-16] + s0 + w[i-7] + s1;
    }
    uint32_t a=c->h[0],b=c->h[1],cc=c->h[2],d=c->h[3];
    uint32_t e=c->h[4],f=c->h[5],g=c->h[6],h=c->h[7];
    for (int i = 0; i < 64; i++) {
        // Σ1(e) 和 Ch(e,f,g)：-majority/choice 函数提供非线性
        uint32_t S1 = ((e>>6)|(e<<26)) ^ ((e>>11)|(e<<21)) ^ ((e>>25)|(e<<7));
        uint32_t ch = (e & f) ^ (~e & g);
        uint32_t t1 = h + S1 + ch + SHA256_K[i] + w[i];
        // Σ0(a) 和 Maj(a,b,c)
        uint32_t S0 = ((a>>2)|(a<<30)) ^ ((a>>13)|(a<<19)) ^ ((a>>22)|(a<<10));
        uint32_t mj = (a & b) ^ (a & cc) ^ (b & cc);
        uint32_t t2 = S0 + mj;
        h=g; g=f; f=e; e=d+t1; d=cc; cc=b; b=a; a=t1+t2;
    }
    // Davies-Meyer 结构：输出 = 初值 ⊕ 轮结果（防逆推，单向性的来源）
    c->h[0]+=a; c->h[1]+=b; c->h[2]+=cc; c->h[3]+=d;
    c->h[4]+=e; c->h[5]+=f; c->h[6]+=g; c->h[7]+=h;
}

inline void sha256_update(Sha256Ctx *c, const void *data, size_t n)
{
    const uint8_t *p = (const uint8_t*)data;
    c->len += n;
    while (n) {
        size_t take = 64 - c->bufLen; if (take > n) take = n;
        memcpy(c->buf + c->bufLen, p, take);
        c->bufLen += take; p += take; n -= take;
        if (c->bufLen == 64) { sha256_block(c, c->buf); c->bufLen = 0; }
    }
}

inline void sha256_final(Sha256Ctx *c, uint8_t out[32])
{
    uint64_t bits = c->len * 8;
    // Merkle-Damgård 填充：0x80，然后零，最后 8 字节大端位长度
    uint8_t pad = 0x80; sha256_update(c, &pad, 1);
    pad = 0;
    while (c->bufLen != 56) sha256_update(c, &pad, 1);   // 凑到 56 字节
    uint8_t lenb[8];
    for (int i = 0; i < 8; i++) lenb[i] = (uint8_t)(bits >> (56 - 8*i));
    sha256_update(c, lenb, 8);
    for (int i = 0; i < 8; i++) {
        out[4*i+0]=(uint8_t)(c->h[i]>>24); out[4*i+1]=(uint8_t)(c->h[i]>>16);
        out[4*i+2]=(uint8_t)(c->h[i]>>8);  out[4*i+3]=(uint8_t)(c->h[i]);
    }
}

inline void sha256(const void *data, size_t n, uint8_t out[32])
{
    Sha256Ctx c; sha256_init(&c); sha256_update(&c, data, n); sha256_final(&c, out);
}

// ----------------------------------------------------------- HMAC-SHA256 --
// RFC 2104。密钥先补/压到 64 字节（SHA-256 的块大小），
// 再分别与 ipad(0x36)/opad(0x5c) 异或后做内外两层哈希。
// 为什么不能直接 hash(key||data)？SHA-256 是 Merkle-Damgård 结构，
// 已知 H(key||msg) 可以不碰 key 直接续算出 H(key||msg||extra)——长度扩展攻击。
// HMAC 的双哈希切断了这条路。
inline void hmac_sha256(const uint8_t *key, size_t keyLen,
                        const void *data, size_t dataLen, uint8_t out[32])
{
    uint8_t k[64];
    if (keyLen > 64) sha256(key, keyLen, k), memset(k+32, 0, 32); // 长密钥→先哈希
    else { memcpy(k, key, keyLen); memset(k+keyLen, 0, 64-keyLen); }

    uint8_t inner[64], digest[32];
    for (int i = 0; i < 64; i++) inner[i] = k[i] ^ 0x36;
    Sha256Ctx c;
    sha256_init(&c); sha256_update(&c, inner, 64); sha256_update(&c, data, dataLen);
    sha256_final(&c, digest);

    uint8_t outer[64];
    for (int i = 0; i < 64; i++) outer[i] = k[i] ^ 0x5c;
    sha256_init(&c); sha256_update(&c, outer, 64); sha256_update(&c, digest, 32);
    sha256_final(&c, out);
}

// -------------------------------------------------------------- PBKDF2 --
// RFC 2898 的最小实现（只派生 32 字节 = 1 个块，RAR 只用 1 块）。
//   U1 = HMAC(password, salt || INT(1))          // INT(1) 是大端块序号
//   U2 = HMAC(password, U1)
//   ...
//   DK = U1 ^ U2 ^ ... ^ Uc                     // 异或链
inline void pbkdf2_hmac_sha256(const char *password, const uint8_t *salt, size_t saltLen,
                               uint32_t iterations, uint8_t out[32])
{
    size_t plen = strlen(password);
    uint8_t sdata[64 + 4];
    memcpy(sdata, salt, saltLen);
    sdata[saltLen+0]=0; sdata[saltLen+1]=0; sdata[saltLen+2]=0; sdata[saltLen+3]=1; // 块号 1
    uint8_t u[32], fn[32];
    hmac_sha256((const uint8_t*)password, plen, sdata, saltLen+4, u);
    memcpy(fn, u, 32);
    for (uint32_t i = 1; i < iterations; i++) {
        hmac_sha256((const uint8_t*)password, plen, u, 32, u);
        for (int j = 0; j < 32; j++) fn[j] ^= u[j];
    }
    memcpy(out, fn, 32);
}

} // namespace learnarc
