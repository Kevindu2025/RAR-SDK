// ============================================================================
// lzh.hpp - LZ77 + Huffman 组合编码器（RAR5 "-m0..m4" 家族的教学复刻）
// ----------------------------------------------------------------------------
// 数据流向（编码）：
//
//   原始字节 ──LZ77──▶ 符号流 ──Huffman──▶ 比特流
//              │         │
//              │         ├─ literal: (0..255)
//              │         ├─ match:   len符号(+附加位) + dist符号(+附加位)
//              │         └─ EOF      (EOB)
//              └─ 哈希链找 (dist, len)，惰性匹配择优
//
// 符号表（模仿 RAR5 解码器的表布局，教学版合并为一张表）：
//   0..255      字面量 literal
//   256..271    长度 1..16（直查）
//   272..287    长度指数段（段内附加位 4..19 位）
//   288..304    距离槽 17 个
//   305         EOB
//
// "槽 + 附加位"编码思想（RAR/DEFLATE 共用）：
//   小数值直接给符号；大数值用"槽符号（~log 值）+ 线性附加位"。
//   表小两个数量级且概率集中，Huffman 更有效。
// ============================================================================
#pragma once
#include "bitio.hpp"
#include "huffman.hpp"
#include "lzss.hpp"
#include <cstdint>
#include <cstring>
#include <vector>
#include <cstdio>

namespace learnarc {

// ---------------------------------------------------------- 符号常量 --
constexpr int SYM_LIT0    = 0;
constexpr int SYM_LEN0    = 256;           // 256..271 → len 1..16
constexpr int NLENDIRECT = 16;
constexpr int SYM_LEN17  = SYM_LEN0 + NLENDIRECT;  // 272..287 指数段
constexpr int NLENEXP    = 16;
constexpr int SYM_DIST0  = 288;            // 288..304 距离槽
constexpr int NDIST      = 17;
constexpr int SYM_EOB    = SYM_DIST0 + NDIST;   // 305
constexpr int NSYMS      = SYM_EOB + 1;

struct LenCodec {
    // 1..16 直查；17+：段 s 覆盖 [base, base+2^eb)，base=17<<s, eb=4+s
    static void encode(int len, int *sym, uint32_t *extra, int *extraBits)
    {
        if (len >= 1 && len <= NLENDIRECT) {
            *sym = SYM_LEN0 + len - 1; *extra = 0; *extraBits = 0; return;
        }
        int base = 17, eb = 4, seg = 0;
        while (len >= base + (1 << eb)) { base <<= 1; eb++; seg++; }
        *sym = SYM_LEN17 + seg;
        *extra = (uint32_t)(len - base);
        *extraBits = eb;
    }
    static int decode(int sym, uint32_t extra)
    {
        if (sym < SYM_LEN17) return sym - SYM_LEN0 + 1;
        int seg = sym - SYM_LEN17, base = 17, eb = 4;
        for (int i = 0; i < seg; i++) { base <<= 1; eb++; }
        return base + (int)extra;
    }
    static int extraBitsFor(int sym)
    {
        if (sym < SYM_LEN17) return 0;
        return 4 + (sym - SYM_LEN17);
    }
};

struct DistCodec {
    // dist 1 → 槽0；dist d(>=2): v=d-1, 槽 i=floor(log2(v))+1, 附加位 i 个
    static void encode(int dist, int *sym, uint32_t *extra, int *extraBits)
    {
        if (dist == 1) { *sym = 0; *extra = 0; *extraBits = 0; return; }
        int d = dist - 1;
        int i = 0; while ((1 << (i+1)) <= d) i++;
        *sym = i + 1;
        *extra = (uint32_t)(d - (1 << i));
        *extraBits = i;
    }
    static int decode(int sym, uint32_t extra)
    {
        if (sym == 0) return 1;
        int i = sym - 1;
        return (1 << i) + (int)extra + 1;
    }
    static int extraBitsFor(int sym)
    {
        if (sym == 0) return 0;
        return sym - 1;
    }
};

// Huffman 符号解码器（逐位版本——教学透明版；生产用一层查表）
inline int huf_decode_symbol(BitReader &br, const HuffmanTable &ht)
{
    uint32_t codev = 0;
    for (int len = 1; len <= ht.maxLen; len++) {
        codev = (codev << 1) | (uint32_t)br.read_bit();
        // 该层码字区间 [firstCode[len], firstCode[len] + lenCnt[len])
        if (ht.lenCnt[len] && codev >= ht.firstCode[len] &&
            codev < ht.firstCode[len] + ht.lenCnt[len])
            return ht.idxToSym[ht.firstIdx[len] + (codev - ht.firstCode[len])];
    }
    return -1;
}

struct LzhStats {
    uint32_t lit = 0, match = 0;
    size_t bytesSaved = 0;
};

class LzhEncoder {
public:
    // 返回 false = 无法获益（调用方回退 store 模式）
    static bool encode(const uint8_t *data, size_t n, int windowSize, int maxChain,
                       std::vector<uint8_t> &out, LzhStats *statsOut = nullptr)
    {
        // ---- 第一遍：LZ 解析 + 频次统计 ----
        struct Tok { int lit; int len; int dist; };
        std::vector<Tok> toks;
        LzHashChain hc(windowSize, maxChain);
        uint32_t freq[NSYMS] = {};
        LzhStats st;
        size_t pos = 0;
        const size_t minMatch = 4;
        while (pos < n) {
            LzMatch m = hc.find(data, n, pos);
            if (m.len >= (int)minMatch) {
                // 惰性匹配：探 pos+1 是否更长
                size_t save = pos; pos++;
                LzMatch m2 = hc.find(data, n, pos);
                pos = save;
                if (m2.len > m.len) {
                    toks.push_back({(int)data[pos], 0, 0});
                    freq[data[pos]]++;
                    st.lit++;
                    hc.insert(data, pos);
                    pos++;
                    continue;
                }
                int dist = (int)(pos - (size_t)m.pos);
                int s, eb; uint32_t ex;
                LenCodec::encode(m.len, &s, &ex, &eb);    freq[s]++;
                DistCodec::encode(dist, &s, &ex, &eb);     freq[s + SYM_DIST0]++;
                st.match++; st.bytesSaved += m.len;
                toks.push_back({-1, m.len, dist});
                for (size_t k = 0; k < (size_t)m.len && pos + k + 3 <= n; k++)
                    hc.insert(data, pos + k);
                pos += m.len;
            } else {
                toks.push_back({(int)data[pos], 0, 0});
                freq[data[pos]]++;
                st.lit++;
                hc.insert(data, pos);
                pos++;
            }
        }
        freq[SYM_EOB]++;
        if (statsOut) *statsOut = st;

        // ---- 建 canonical Huffman 表 ----
        int lens[NSYMS];
        if (!huffman_lengths_from_freq(freq, NSYMS, 15, lens)) return false;
        HuffmanTable ht;
        if (!ht.build(lens, NSYMS)) return false;

        // ---- 收益预估：表 + 码字 + 附加位 vs 原始 ----
        size_t tableBits = (size_t)NSYMS * 4;
        size_t dataBits = 0;
        for (int i = 0; i < NSYMS; i++)
            if (freq[i]) dataBits += (size_t)freq[i] * lens[i];
        for (auto &t : toks) if (t.lit < 0) {
            int s, eb; uint32_t ex;
            LenCodec::encode(t.len, &s, &ex, &eb);  dataBits += eb;
            DistCodec::encode(t.dist, &s, &ex, &eb); dataBits += eb;
        }
        if ((tableBits + dataBits + 7) / 8 >= n) return false;

        // ---- 第二遍：写比特流 ----
        BitWriter bw(out);
        for (int i = 0; i < NSYMS; i++) bw.put_bits((uint32_t)lens[i], 4);
        for (auto &t : toks) {
            if (t.lit >= 0) {
                bw.put_bits(ht.code[t.lit], ht.len[t.lit]);
            } else {
                int s, eb; uint32_t ex;
                LenCodec::encode(t.len, &s, &ex, &eb);
                bw.put_bits(ht.code[s], ht.len[s]);
                if (eb) bw.put_bits(ex, eb);
                DistCodec::encode(t.dist, &s, &ex, &eb);
                bw.put_bits(ht.code[s + SYM_DIST0], ht.len[s + SYM_DIST0]);
                if (eb) bw.put_bits(ex, eb);
            }
        }
        bw.put_bits(ht.code[SYM_EOB], ht.len[SYM_EOB]);
        bw.finish();
        return true;
    }
};

// -------------------------------------------------------------- 解码 --
inline bool lzh_decode(const uint8_t *in, size_t inSize, size_t originalLen,
                      int windowSize, std::vector<uint8_t> &out)
{
    (void)windowSize;
    // 表：NSYMS 个 4-bit 码长
    size_t tableBytes = (NSYMS * 4 + 7) / 8;
    if (inSize < tableBytes) return false;
    BitReader br(in, inSize);
    int lens[NSYMS];
    for (int i = 0; i < NSYMS; i++) lens[i] = (int)br.read_bits(4);
    HuffmanTable ht;
    if (!ht.build(lens, NSYMS)) return false;

    out.clear();
    out.reserve(originalLen);
    while (out.size() < originalLen) {
        int sym = huf_decode_symbol(br, ht);
        if (sym < 0 || sym == SYM_EOB) break;
        if (sym < 256) {
            out.push_back((uint8_t)sym);
        } else if (sym < SYM_DIST0) {
            int eb = LenCodec::extraBitsFor(sym);
            uint32_t extra = eb ? br.read_bits(eb) : 0;
            int len = LenCodec::decode(sym, extra);
            if (len < 1) return false;
            int dsym = huf_decode_symbol(br, ht);
            if (dsym < SYM_DIST0 || dsym >= SYM_DIST0 + NDIST) return false;
            int slot = dsym - SYM_DIST0;                 // 槽号 0..16
            int deb = DistCodec::extraBitsFor(slot);
            uint32_t dextra = deb ? br.read_bits(deb) : 0;
            int dist = DistCodec::decode(slot, dextra);
            if (dist < 1 || (size_t)dist > out.size()) return false;
            // 重叠复制：dist < len 时必须逐字节（教科书细节！）
            size_t src = out.size() - (size_t)dist;
            for (int k = 0; k < len && out.size() < originalLen; k++)
                out.push_back(out[src + k]);
        } else {
            return false;                          // 游离距离符号：非法
        }
    }
    return out.size() == originalLen;
}

} // namespace learnarc
