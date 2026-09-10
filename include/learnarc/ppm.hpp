// ============================================================================
// ppm.hpp - Simplified PPM (Prediction by Partial Matching) + range coder
// ----------------------------------------------------------------------------
// The shortest path to understanding RAR3 "-m5" (PPMd var.I). We implement
// the skeleton essence of PPM:
//
//   +------------------+ PPM core idea +---------------------------+
//   | Predict the next byte from its SUFFIX context (previous k      |
//   | bytes), not a tree walk:                                       |
//   |   context_k = the k bytes before current position              |
//   | Each context keeps a table "which successor bytes seen + count" |
//   | Encoding byte c:                                                |
//   |   hit at order K  -> range-encode with its counts               |
//   |   miss (escape)   -> drop one order down, retry                 |
//   |   still escaping at order 0 -> order -1: uniform 256 fallback   |
//   +----------------------------------------------------------------+
//
// Real PPMd (the RAR3 engine) adds on top of this skeleton:
//   * tree-structured shared memory (we use a hash map per order)
//   * SEE (Secondary Escape Estimation): adaptive escape probability -
//     the crown jewel; our simplified "esc = 1/count-weighted" hints at it
//   * bounded memory with resets (our nodes never expire - see LEARNING.md)
//
// Range coder (Subbotin style, 64-bit low + explicit carry):
//   Integer approximation of arithmetic coding. Maintain [low, low+range),
//   squeeze onto the symbol's probability slice each step, emit top bytes
//   when range < 2^24 (renormalization).
//   Why it beats Huffman: it can encode a probability of e.g. 0.99 in
//   ~0.02 bits - PPM compresses text far better than LZ because it models
//   probability itself, and a range coder can spend fractional bits on it.
//
//   Development war story (both bugs bit us, both are classic):
//   * 32-bit low without carry handling: one byte in 60000 diverged when
//     the interval crossed a 2^32 boundary. Fix: 64-bit low; when bit 32
//     sets, walk backwards through emitted bytes incrementing 0xFF runs.
//   * "range |= 0xFF" inflation on renorm: makes decoder range overshoot
//     the true interval. Fix: don't inflate - keep encoder/decoder range
//     arithmetic bit-identical.
// ============================================================================
#pragma once
#include <cstdint>
#include <cstring>
#include <vector>
#include <unordered_map>

namespace learnarc {

// --------------------------------------------------------- range coder --
class RangeEncoder {
public:
    std::vector<uint8_t> out;
    uint64_t low = 0;                    // 64-bit: carries visible in bit 32
    uint32_t range = 0xFFFFFFFFu;

    void encode(uint32_t cum, uint32_t cnt, uint32_t total)
    {
        uint32_t r = range / total;
        low += (uint64_t)r * cum;
        range = r * cnt;
        if (low >> 32) {                 // carry beyond 32 bits
            carry();
            low &= 0xFFFFFFFFull;
        }
        while (range < (1u << 24)) {     // renormalize
            out.push_back((uint8_t)(low >> 24));
            low = (low << 8) & 0xFFFFFFFFull;  // top byte was just emitted
            range <<= 8;
        }
    }
    void carry()                          // bump last emitted byte, cascade 0xFF
    {
        for (size_t i = out.size(); i-- > 0; )
            if (++out[i]) break;
    }
    void finish()
    {
        for (int i = 0; i < 4; i++) { out.push_back((uint8_t)(low >> 24)); low <<= 8; }
    }
};

class RangeDecoder {
public:
    const uint8_t *in; size_t inSize, pos = 0;
    uint64_t code = 0;                   // 40-bit window (32 + carry lookahead)
    uint32_t range = 0xFFFFFFFFu;

    RangeDecoder(const uint8_t *d, size_t n) : in(d), inSize(n)
    {
        for (int i = 0; i < 4; i++) code = (code << 8) | nextByte();
    }
    uint8_t nextByte() { return pos < inSize ? in[pos++] : 0; }

    uint32_t decodeCum(uint32_t total)
    {
        range /= total;
        return (uint32_t)(code / range);
    }
    void decode(uint32_t cum, uint32_t cnt)
    {
        code -= (uint64_t)range * cum;
        range *= cnt;
        while (range < (1u << 24)) {
            code = ((code << 8) | nextByte()) & 0xFFFFFFFFFFull;
            range <<= 8;
        }
    }
};

// ------------------------------------------------------------- PPM model --
struct PpmNode {
    uint32_t cnt[256] = {};
    uint32_t total = 0;      // sum of cnt, capped (see addHit)
    uint32_t esc = 1;        // escape experience counter

    // The range coder requires total < range (~2^24). Cap at 65535:
    // on overflow halve all counts - both numerically safe and a crude
    // "forgetting curve" (old evidence decays), mirroring what PPMd achieves
    // with count saturation and memory resets.
    void addHit(uint8_t c)
    {
        cnt[c]++; total++;
        if (total > 65535) rebalance();
    }
    void rebalance()
    {
        uint32_t t = 0;
        for (int i = 0; i < 256; i++) if (cnt[i]) {
            cnt[i] = (cnt[i] + 1) / 2;
            if (!cnt[i]) cnt[i] = 1;      // seen symbols keep weight 1
            t += cnt[i];
        }
        total = t;
        if (esc > 64) esc = (esc + 1) / 2;
    }
};

class PpmModel {
public:
    explicit PpmModel(int maxOrder) : K(maxOrder) {}

    // Encode one byte walking the escape chain order K..0:
    //   hit     -> encode (cum, cnt, total+esc)  (denominator reserves a
    //             slice for the escape symbol)
    //   miss    -> encode the escape event itself, drop one order
    //   escaped even order0 -> order -1 uniform 256 fallback
    void encodeByte(RangeEncoder &rc, uint8_t c, const uint8_t *hist, size_t histLen)
    {
        for (int ord = K; ord >= 0; ord--) {
            if ((size_t)ord > histLen) continue;       // not enough history
            PpmNode *node = getOrCreate(hist + (histLen - ord), (size_t)ord);
            uint32_t tot = node->total + node->esc;
            if (node->cnt[c]) {
                uint32_t cum = 0;
                for (int i = 0; i < c; i++) cum += node->cnt[i];
                rc.encode(cum, node->cnt[c], tot);     // hit: encode symbol
                node->addHit(c);
                return;
            }
            rc.encode(node->total, node->esc, tot);    // escape event
            node->esc++;
        }
        // order -1 fallback: uniform over 256 values
        rc.encode(c, 1, 256);
        // teach the new symbol to order-0 (simplified update policy:
        // real PPMd updates all nodes it walked through - "exclusion"
        // variants differ here; see LEARNING.md 6.3)
        PpmNode *o0 = getOrCreate(hist + histLen, 0);
        o0->addHit(c);
    }

    // Decode one byte (strict mirror of encodeByte).
    uint8_t decodeByte(RangeDecoder &rd, const uint8_t *hist, size_t histLen)
    {
        for (int ord = K; ord >= 0; ord--) {
            if ((size_t)ord > histLen) continue;
            PpmNode *node = getOrCreate(hist + (histLen - ord), (size_t)ord);
            uint32_t tot = node->total + node->esc;
            uint32_t cum = rd.decodeCum(tot);
            if (cum < node->total) {
                uint32_t acc = 0; int c = 0;
                for (c = 0; c < 256; c++) { acc += node->cnt[c]; if (acc > cum) break; }
                if (c >= 256) c = 255;
                uint32_t ccum = acc - node->cnt[c];
                rd.decode(ccum, node->cnt[c]);
                node->addHit((uint8_t)c);
                return (uint8_t)c;
            }
            rd.decode(node->total, node->esc);         // escape event
            node->esc++;
        }
        uint32_t cum = rd.decodeCum(256);
        rd.decode(cum, 1);
        PpmNode *o0 = getOrCreate(hist + histLen, 0);
        o0->addHit((uint8_t)cum);
        return (uint8_t)cum;
    }

    std::vector<uint8_t> history;                      // rolling history

    // exposed for diagnostic/teaching tools (see test harness)
    PpmNode *getOrCreateT(const uint8_t *p, size_t len) { return getOrCreate(p, len); }

private:
    int K;
    std::unordered_map<uint64_t, PpmNode*> map;

    static uint64_t key(const uint8_t *p, size_t len)
    {
        uint64_t h = 1469598103934665603ull;           // FNV-1a
        for (size_t i = 0; i < len; i++) { h ^= p[i]; h *= 1099511628211ull; }
        return h;
    }
    PpmNode *getOrCreate(const uint8_t *p, size_t len)
    {
        uint64_t k = key(p, len);
        auto it = map.find(k);
        if (it != map.end()) return it->second;
        PpmNode *n = new PpmNode();
        map[k] = n;
        return n;
    }
};

// -------------------------------------------------------- top-level API --
inline bool ppm_compress(const uint8_t *data, size_t n, int order,
                         std::vector<uint8_t> &out)
{
    RangeEncoder rc;
    PpmModel mdl(order);
    mdl.history.reserve(n);
    for (size_t i = 0; i < n; i++) {
        mdl.encodeByte(rc, data[i], mdl.history.data(), mdl.history.size());
        mdl.history.push_back(data[i]);
    }
    rc.finish();
    if (rc.out.size() >= n) return false;              // no gain
    out = std::move(rc.out);
    return true;
}

inline bool ppm_decompress(const uint8_t *in, size_t inSize, size_t originalLen,
                           int order, std::vector<uint8_t> &out)
{
    RangeDecoder rd(in, inSize);
    PpmModel mdl(order);
    mdl.history.reserve(originalLen);
    out.clear();
    for (size_t i = 0; i < originalLen; i++) {
        uint8_t c = mdl.decodeByte(rd, mdl.history.data(), mdl.history.size());
        out.push_back(c);
        mdl.history.push_back(c);
    }
    return out.size() == originalLen;
}

} // namespace learnarc
