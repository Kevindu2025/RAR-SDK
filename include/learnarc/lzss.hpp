// ============================================================================
// lzss.hpp - LZ77 匹配器（哈希链 + 惰性匹配）
// ----------------------------------------------------------------------------
// LZ77 的核心问题：在"已输出的历史窗口"里找当前字节串的最长重复。
//   match(pos) = 历史中与 data[pos..] 有最长公共前缀的位置 + 长度
//
// 朴素法 O(n×W)（W=窗口大小）不可用。工业方案 = 哈希链：
//
//   head[hash(3字节)] = 最近出现该 3-gram 的位置
//   prev[pos]          = 上一次出现相同 3-gram 的位置（链表）
//   → 找匹配 = 沿链回溯，逐个验证（最长链控制在 maxChain）
//
// RAR5 对应物：unpack50.cpp 解码侧没有匹配器（解码只需复制），但编码侧
// （WinRAR 私有）必然是同构的哈希链。RAR5 特点：
//   * 窗口 = 字典大小（头里 COMPINFO 的 dict 位，128KB..1GB）
//   * 匹配长度域：2..0x1001（即最长 4098）
//   * 距离域：1..dict
//   * "惰性匹配"(lazy match)：找到长度 L 的匹配后，再等一步——
//     若 pos+1 处能找到 L'>=L 的匹配，则放弃当前匹配、输出字面量再
//     用 L'。RAR/-m3 以上、zlib、7-Zip 都用这个技巧，平均白赚 2-5%。
//
// 本实现参数刻意贴近 RAR5 域值（maxLen 4098、链深可调），供 lzh.hpp 使用。
// ============================================================================
#pragma once
#include <cstdint>
#include <cstring>
#include <vector>

namespace learnarc {

struct LzMatch { int pos; int len; };

class LzHashChain {
public:
    // windowSize：历史窗口字节数（RAR5 的 dict）；maxChain：找匹配时的
    // 最大回溯链深（速度/压缩率旋钮，RAR 的 -m1..-m5 本质就是调它）
    LzHashChain(int windowSize, int maxChain)
        : W(windowSize), CHAIN(maxChain),
          head(65536, -1), prev(windowSize, -1) {}

    void reset() { std::fill(head.begin(), head.end(), -1); }

    // 压缩主循环每步调用：把 [pos, pos+2) 的 3-gram 插入索引后找匹配
    LzMatch find(const uint8_t *data, size_t n, size_t pos) const
    {
        LzMatch m { -1, 0 };
        if (pos + 3 > n) return m;                    // 尾部不足 3 字节
        uint32_t h = hash3(data + pos);
        int cand = head[h];
        int chain = CHAIN;
        int best = 0;
        size_t limit = pos > (size_t)W ? pos - (size_t)W : 0;
        while (cand >= 0 && (size_t)cand >= limit && chain--) {
            // 验证：从 cand 开始与 pos 处逐字节比较，算公共前缀
            const uint8_t *a = data + cand, *b = data + pos;
            size_t maxLen = n - pos;
            if (maxLen > MAX_LEN) maxLen = MAX_LEN;
            int l = 0;
            while ((size_t)l < maxLen && a[l] == b[l]) l++;
            if (l > best) { best = l; m.pos = cand; m.len = l; }
            if (best >= MAX_LEN) break;                // 已到长度域上限
            int p = prev[cand % (size_t)W];
            if (p >= 0 && (size_t)p >= (size_t)cand) break;  // 防环（理论不会）
            cand = p;
        }
        return m;
    }

    void insert(const uint8_t *data, size_t pos)
    {
        // 只索引 3-gram 起点；prev 用模 W 环形存储（老位置自动被覆盖）
        uint32_t h = hash3(data + pos);
        int slot = (int)(pos % (size_t)W);
        prev[slot] = head[h];
        head[h] = (int)pos;
    }

    static const size_t MAX_LEN = 0x1001 - 1;          // RAR5 长度域 4097

private:
    static uint32_t hash3(const uint8_t *p)
    {
        // 3 字节滚动哈希：比 CRC 快，分布均匀。
        // ((a<<16)|(b<<8)|c) * 2654435761u（Knuth 乘法散列）再取高位
        uint32_t v = ((uint32_t)p[0] << 16) | ((uint32_t)p[1] << 8) | p[2];
        return (v * 2654435761u) >> 16 & 0xFFFF;
    }

    int W, CHAIN;
    std::vector<int> head, prev;
};

} // namespace learnarc
