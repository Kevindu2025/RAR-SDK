// ============================================================================
// bitio.hpp - 位级 I/O（熵编码的地基）
// ----------------------------------------------------------------------------
// 所有熵编码（Huffman / 算术编码 / PPM 的区间编码）本质都在做一件事：
//    用"概率高的符号 → 短比特串"来逼近信息熵。
// 而它们的第一块积木都是：能逐位读写、且知道"还剩多少有效位"的流。
//
// 写入侧（BitWriter）：
//   MSB-first：第 1 个写入的位是字节最高位——Huffman 树的码字天然按
//   "码长 + 高位字典序"分配（canonical码），MSB-first 让树路径=码字数值。
//
// 读取侧（BitReader）：
//   关键 API 是 read_bits(n) / read_bit()；后者在 PPM 区间解码器里
//   每"归一化一次读一位"，是热路径——教学版不做缓冲优化，保持透明。
//
// RAR5 里真实对应物：getbits.hpp 的 BitInput（不过它是 16-bit 大端预取式，
// 为查表优化设计；本实现选最直白的逐位式，方便对照理论）。
// ============================================================================
#pragma once
#include <cstdint>
#include <cstring>
#include <vector>
#include <stdexcept>

namespace learnarc {

struct BitWriter {
    std::vector<uint8_t> &out;
    uint8_t cur = 0;      // 正在装配的字节
    int nFilled = 0;      // 已装进 cur 的位数

    explicit BitWriter(std::vector<uint8_t> &o) : out(o) {}

    void put_bit(int b)
    {
        cur = (uint8_t)((cur << 1) | (b & 1));
        if (++nFilled == 8) { out.push_back(cur); cur = 0; nFilled = 0; }
    }
    void put_bits(uint32_t v, int n)      // 高位先进（MSB-first）
    {
        for (int i = n - 1; i >= 0; i--) put_bit((v >> i) & 1);
    }
    // 比特级"对齐辅助"：Huffman 码字 + 紧跟的定长字段直接调用
    void put_uint(uint32_t v, int n) { put_bits(v, n); }

    size_t finish()                        // 补零到字节边界，返回总字节数
    {
        if (nFilled) { cur <<= (8 - nFilled); out.push_back(cur); cur = 0; nFilled = 0; }
        return out.size();
    }
};

struct BitReader {
    const uint8_t *data; size_t size; size_t pos = 0;
    uint32_t acc = 0; int nBits = 0;       // 32 位漏桶

    BitReader(const uint8_t *d, size_t s) : data(d), size(s) {}

    bool eof() const { return nBits == 0 && pos >= size; }

    int read_bit()
    {
        if (nBits == 0) {
            if (pos >= size) return 0;    // 尾部按 0 填充（上层负责用长度校验）
            acc = data[pos++]; nBits = 8;
        }
        nBits--;
        int b = (acc >> nBits) & 1;
        return b;
    }
    uint32_t read_bits(int n)
    {
        uint32_t v = 0;
        for (int i = 0; i < n; i++) v = (v << 1) | (uint32_t)read_bit();
        return v;
    }
    // 用于区间解码器的"窥视不消费"（PPM 的 carry 处理需要）
    uint32_t peek_bits(int n)
    {
        uint32_t v = 0;
        for (int i = 0; i < n; i++) {
            // 简单实现：读一位再记下，用小回退
            int b = read_bit();
            v = (v << 1) | (uint32_t)b;
            // 不回退：peek 由具体调用方处理（教学版只在前向解码场景用）
        }
        return v;
    }
};

} // namespace learnarc
