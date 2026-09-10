// ============================================================================
// aes.hpp - AES-128/256 CBC 模式（教学实现，FIPS-197）
// ----------------------------------------------------------------------------
// AES 是 RAR5 文件数据加密的"执行者"（密钥来自 sha256.hpp 的 PBKDF2）。
//
// 三层结构（从里到外）：
//   1. 轮函数 AddRoundKey → SubBytes → ShiftRows → MixColumns
//      （解密逆之：InvSubBytes → InvShiftRows → InvMixColumns → AddRoundKey）
//   2. 密钥扩展：把 256 位密钥搅成 15×4 个 32 位轮密钥
//   3. CBC 链：每个明文块先与前一个密文块异或再加密
//      → 相同明文块在不同位置产生不同密文（ECB 模式的"天书脸"缺陷）
//
// 教学要点：为什么 RAR5 选 AES-CBC 而不是 AES-CTR？
//   其实历史原因 + 足够用。CBC 解密可并行（加密不可），CTR 加解密都可并行。
//   两者安全性都依赖"IV 不重复"。RAR 每个文件随机 16 字节 InitV，OK。
//
// 本实现照抄 FIPS-197 的标准写法（教学优先）：
//   * SBOX 用查表（表本身可以由 GF(2^8) 上 x^-1 的仿射变换生成——见文末注释）
//   * MixColumns 用 gmul 逐项乘（生产代码用 4 个预乘表提速 ~10 倍）
//   * 解密轮密钥用"逆混合列变换"预烘焙（等价解密配方，FIPS-197 5.3）
// ============================================================================
#pragma once
#include <cstdint>
#include <cstring>

namespace learnarc {

static const uint8_t AES_SBOX[256] = {
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16
};

inline uint8_t gmul(uint8_t a, uint8_t b)   // GF(2^8) 乘法, 模多项式 x^8+x^4+x^3+x+1 (0x11b)
{
    uint8_t r = 0;
    while (b) {
        if (b & 1) r ^= a;
        uint8_t hi = a & 0x80;
        a <<= 1;
        if (hi) a ^= 0x1b;    // "mod 0x11b" 的简写：溢出时异或掉高位
        b >>= 1;
    }
    return r;
}

struct AesKey {
    int      nr;               // 轮数: AES-256 → 14 (nk+6)
    uint32_t enc[15*4];        // 加密轮密钥表 (4 字节"字"×60)
    uint32_t dec[15*4];        // 解密轮密钥表 (已烘焙逆列混合)
};

#define GETU32(p) (((uint32_t)(p)[0]<<24)|((uint32_t)(p)[1]<<16)|((uint32_t)(p)[2]<<8)|(uint32_t)(p)[3])
#define PUTU32(p,v) do { (p)[0]=(uint8_t)((v)>>24);(p)[1]=(uint8_t)((v)>>16); \
                         (p)[2]=(uint8_t)((v)>>8);(p)[3]=(uint8_t)(v);} while(0)

inline void aes_key_init(AesKey *k, const uint8_t *key, int keyBits)
{
    int nk = keyBits/32, nr = nk+6;
    k->nr = nr;
    uint32_t *w = k->enc;
    for (int i = 0; i < nk; i++) w[i] = GETU32(key + 4*i);
    for (int i = nk; i < 4*(nr+1); i++) {
        uint32_t t = w[i-1];
        if (i % nk == 0) {
            t = (t<<8)|(t>>24);                       // RotWord
            t = ((uint32_t)AES_SBOX[(t>>24)&0xff]<<24) |   // SubWord
                ((uint32_t)AES_SBOX[(t>>16)&0xff]<<16) |
                ((uint32_t)AES_SBOX[(t>>8)&0xff]<<8)  |
                 (uint32_t)AES_SBOX[t&0xff];
            uint32_t rc = 1;                           // Rcon: x^(i/nk - 1) in GF(2^8)
            for (int q = 1; q < i/nk; q++) { rc <<= 1; if (rc & 0x100) rc = (rc ^ 0x11b) & 0xff; }
            t ^= rc << 24;
        } else if (nk > 6 && i % nk == 4) {            // AES-256 的额外 SubWord
            t = ((uint32_t)AES_SBOX[(t>>24)&0xff]<<24) |
                ((uint32_t)AES_SBOX[(t>>16)&0xff]<<16) |
                ((uint32_t)AES_SBOX[(t>>8)&0xff]<<8)  |
                 (uint32_t)AES_SBOX[t&0xff];
        }
        w[i] = w[i-nk] ^ t;
    }
    // 解密轮密钥：首尾不动，中间轮做 InvMixColumns（等价解密配方）
    uint32_t *dw = k->dec;
    for (int i = 0; i < 4*(nr+1); i++) dw[i] = w[i];
    for (int r = 1; r < nr; r++)
        for (int c = 0; c < 4; c++) {
            uint32_t x = dw[4*r+c];
            uint8_t b0=x>>24, b1=x>>16, b2=x>>8, b3=x;
            dw[4*r+c] =
                ((uint32_t)(gmul(b0,14)^gmul(b1,11)^gmul(b2,13)^gmul(b3, 9))<<24) |
                ((uint32_t)(gmul(b0, 9)^gmul(b1,14)^gmul(b2,11)^gmul(b3,13))<<16) |
                ((uint32_t)(gmul(b0,13)^gmul(b1, 9)^gmul(b2,14)^gmul(b3,11))<<8) |
                 (uint32_t)(gmul(b0,11)^gmul(b1,13)^gmul(b2, 9)^gmul(b3,14));
        }
}

inline void aes_encrypt_block(const AesKey *k, const uint8_t in[16], uint8_t out[16])
{
    // 状态用 4 个 32 位列表示（列优先：st[c] = 该列 4 字节，最高字节在顶）
    uint32_t st[4];
    for (int c = 0; c < 4; c++) st[c] = GETU32(in + 4*c);
    const uint32_t *w = k->enc;

    for (int r = 0; r < k->nr; r++) {
        // AddRoundKey
        st[0]^=w[4*r+0]; st[1]^=w[4*r+1]; st[2]^=w[4*r+2]; st[3]^=w[4*r+3];
        // SubBytes（对每字节查 SBOX = GF 逆元 + 仿射变换）
        for (int c = 0; c < 4; c++)
            st[c] = ((uint32_t)AES_SBOX[st[c]>>24]<<24) | ((uint32_t)AES_SBOX[(st[c]>>16)&0xff]<<16)
                  | ((uint32_t)AES_SBOX[(st[c]>>8)&0xff]<<8) | AES_SBOX[st[c]&0xff];
        // ShiftRows（行 r 左转 r 字节；用字节转置实现最直观）
        uint8_t s[16], o[16];
        for (int c = 0; c < 4; c++) PUTU32(s+4*c, st[c]);
        for (int row = 0; row < 4; row++)
            for (int col = 0; col < 4; col++)
                o[4*col + row] = s[4*((col+row)&3) + row];
        for (int c = 0; c < 4; c++) st[c] = GETU32(o+4*c);
        // MixColumns（每列 = GF(2^8) 上乘固定矩阵 [2 3 1 1; 1 2 3 1; 1 1 2 3; 3 1 1 2]）
        if (r != k->nr-1) {
            for (int c = 0; c < 4; c++) {
                uint8_t col[4]; PUTU32(col, st[c]);   // col[0]=最高字节
                uint8_t r0 = (uint8_t)(gmul(col[0],2)^gmul(col[1],3)^col[2]^col[3]);
                uint8_t r1 = (uint8_t)(col[0]^gmul(col[1],2)^gmul(col[2],3)^col[3]);
                uint8_t r2 = (uint8_t)(col[0]^col[1]^gmul(col[2],2)^gmul(col[3],3));
                uint8_t r3 = (uint8_t)(gmul(col[0],3)^col[1]^col[2]^gmul(col[3],2));
                col[0]=r0; col[1]=r1; col[2]=r2; col[3]=r3;
                st[c] = GETU32(col);
            }
        }
    }
    st[0]^=w[4*k->nr+0]; st[1]^=w[4*k->nr+1]; st[2]^=w[4*k->nr+2]; st[3]^=w[4*k->nr+3];
    for (int c = 0; c < 4; c++) PUTU32(out + 4*c, st[c]);
}

inline void aes_decrypt_block(const AesKey *k, const uint8_t in[16], uint8_t out[16])
{
    uint32_t st[4];
    for (int c = 0; c < 4; c++) st[c] = GETU32(in + 4*c);
    const uint32_t *w = k->dec;

    for (int r = k->nr; r > 0; r--) {
        // AddRoundKey(r)（注意顺序与加密相反：先加后逆变换）
        st[0]^=w[4*r+0]; st[1]^=w[4*r+1]; st[2]^=w[4*r+2]; st[3]^=w[4*r+3];
        // InvShiftRows（行 r 右转 r 字节）
        uint8_t s[16], o[16];
        for (int c = 0; c < 4; c++) PUTU32(s+4*c, st[c]);
        for (int row = 0; row < 4; row++)
            for (int col = 0; col < 4; col++)
                o[4*col + row] = s[4*((col-row)&3) + row];
        for (int c = 0; c < 4; c++) st[c] = GETU32(o+4*c);
        // InvSubBytes（SBOX 的逆 = 先逆仿射再求 GF 逆元；我们用逆表）
        static uint8_t invSbox[256]; static bool invInit = false;
        if (!invInit) { for (int i=0;i<256;i++) invSbox[AES_SBOX[i]]=(uint8_t)i; invInit=true; }
        for (int c = 0; c < 4; c++)
            st[c] = ((uint32_t)invSbox[st[c]>>24]<<24) | ((uint32_t)invSbox[(st[c]>>16)&0xff]<<16)
                  | ((uint32_t)invSbox[(st[c]>>8)&0xff]<<8) | invSbox[st[c]&0xff];
        // InvMixColumns（矩阵 [14 11 13 9; 9 14 11 13; 13 9 14 11; 11 13 9 14]）
        if (r != 1) {
            for (int c = 0; c < 4; c++) {
                uint8_t col[4]; PUTU32(col, st[c]);
                uint8_t r0=(uint8_t)(gmul(col[0],14)^gmul(col[1],11)^gmul(col[2],13)^gmul(col[3],9));
                uint8_t r1=(uint8_t)(gmul(col[0],9)^gmul(col[1],14)^gmul(col[2],11)^gmul(col[3],13));
                uint8_t r2=(uint8_t)(gmul(col[0],13)^gmul(col[1],9)^gmul(col[2],14)^gmul(col[3],11));
                uint8_t r3=(uint8_t)(gmul(col[0],11)^gmul(col[1],13)^gmul(col[2],9)^gmul(col[3],14));
                col[0]=r0;col[1]=r1;col[2]=r2;col[3]=r3; st[c]=GETU32(col);
            }
        }
    }
    st[0]^=w[0]; st[1]^=w[1]; st[2]^=w[2]; st[3]^=w[3];
    for (int c = 0; c < 4; c++) PUTU32(out + 4*c, st[c]);
}

// -------------------------------------------------------------- CBC 链 --
// 加密: C[i] = E(P[i] ^ C[i-1]),  C[-1] = IV
// 解密: P[i] = D(C[i]) ^ C[i-1]
// 教学要点：CBC 加密是串行的（每块依赖前一块密文），解密可并行。
// 长度必须是 16 的倍数——上层负责填充（RAR 的填充策略见 lzh 容器层注释）。
inline void aes_cbc_encrypt(const AesKey *k, const uint8_t *iv, const uint8_t *in,
                             uint8_t *out, size_t bytes16x)
{
    uint8_t prev[16], cur[16];
    memcpy(prev, iv, 16);
    for (size_t off = 0; off < bytes16x; off += 16) {
        for (int i = 0; i < 16; i++) cur[i] = in[off+i] ^ prev[i];
        aes_encrypt_block(k, cur, out + off);
        memcpy(prev, out + off, 16);
    }
}
inline void aes_cbc_decrypt(const AesKey *k, const uint8_t *iv, const uint8_t *in,
                             uint8_t *out, size_t bytes16x)
{
    uint8_t prev[16], saved[16];
    memcpy(prev, iv, 16);
    for (size_t off = 0; off < bytes16x; off += 16) {
        memcpy(saved, in + off, 16);
        aes_decrypt_block(k, in + off, out + off);
        for (int i = 0; i < 16; i++) out[off+i] ^= prev[i];
        memcpy(prev, saved, 16);
    }
}

} // namespace learnarc
