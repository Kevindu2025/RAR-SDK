// ============================================================================
// huffman.hpp - 规范哈夫曼（Canonical Huffman）编解码器
// ----------------------------------------------------------------------------
// "标准 Huffman"：按符号频率建最优二叉树，树路径即码字。
// "规范 (Canonical)"：不存树！只存"每个符号的码长"。码字由规则生成：
//
//   1) 把符号按 (码长升序, 符号值升序) 排列
//   2) code = 0; 每进入下一码长组，code 左移一位；组内逐符号 +1
//
//   例：码长 A=1, B=2, C=2, D=3 →
//       A: 0        (len1: 0)
//       B: 10  C: 11 (len2: 10,11)
//       D: 100      (len3: 100)
//
// 教学要点（为什么全世界的压缩器都用 canonical）：
//   * 表头只需 ~n×log(maxLen) 位（RAR5 用"长度槽+游程"进一步压）
//   * 解码无需树：用 first_code[len] / first_index[len] 两张小数组，
//     读 maxLen 位后逐级判断（或一层查表）。
//   * 整数码字 MSB-first 与比特流天然吻合。
//
// 与 RAR5 的对应：unpack50.cpp ReadTables50() 读的正是"每符号码长"
// （分 20 个长度槽编码），建表用同思路的 canonical 解码。RAR3 (unpack30)
// 则是 20 长度槽 + 4 个游程位。本文件实现"长度数组 → canonical 码表"的
// 完整两方向（编码器建表 + 解码器建表），供 LZ 和容器层复用。
// ============================================================================
#pragma once
#include <cstdint>
#include <cstring>
#include <vector>
#include <algorithm>
#include <functional>

namespace learnarc {

constexpr int HUF_MAX_SYMS   = 512;   // RAR5 最大表 486；放宽到 512
constexpr int HUF_MAX_BITS  = 15;    // 码长上限（解码表规模与对齐性折中）

struct HuffmanTable {
    // 编码侧
    uint32_t code[HUF_MAX_SYMS] = {};
    int      len [HUF_MAX_SYMS] = {};      // 0 = 该符号不在表中
    // 解码侧
    uint32_t firstCode[HUF_MAX_BITS+1] = {};
    uint32_t firstIdx [HUF_MAX_BITS+1] = {};
    uint32_t lenCnt   [HUF_MAX_BITS+1] = {};   // 每层符号数（解码区间判断用）
    int      idxToSym[HUF_MAX_SYMS]   = {};
    int      maxLen = 0;

    // 从"每符号码长数组"构建 canonical 码表。
    // 这是本文件的灵魂 —— 建议对照上面的手算例子逐行读。
    bool build(const int *lens, int nSyms)
    {
        memset(code, 0, sizeof code);
        memset(len,  0, sizeof len);
        memset(firstCode, 0, sizeof firstCode);
        memset(firstIdx,  0, sizeof firstIdx);
        memset(lenCnt,    0, sizeof lenCnt);
        maxLen = 0;
        for (int i = 0; i < nSyms; i++) {
            if (lens[i] < 0 || lens[i] > HUF_MAX_BITS) return false;
            len[i] = lens[i];
            if (lens[i] > maxLen) maxLen = lens[i];
        }
        // 统计每个码长的符号数
        int cnt[HUF_MAX_BITS+1] = {};
        for (int i = 0; i < nSyms; i++) cnt[len[i]]++;
        cnt[0] = 0;
        // 校验 Kraft 不等式：Σ cnt[b]·2^-b ≤ 1，等价于逐层"先加后检再左移"
        // （每层 sum 先 +cnt[b] 再 ×2；任一时刻 sum > 2^b 即非法）
        uint32_t sum = 0;
        for (int b = 1; b <= HUF_MAX_BITS; b++) {
            sum += cnt[b];
            if (sum > (1u << b)) return false;      // 超界：非法码长集
            sum <<= 1;
        }
        // first_code[b]：码长 b 的第一个码字（前一长度组末尾 +1 再左移）
        uint32_t codev = 0, idx = 0;
        for (int b = 1; b <= HUF_MAX_BITS; b++) {
            codev = codev << 1;                      // 进入更深一层
            firstCode[b] = codev;
            firstIdx[b]  = idx;
            lenCnt[b]    = cnt[b];
            idx    += cnt[b];
            codev += cnt[b];
        }
        // 符号按 (len, sym) 排序后依序领码
        // （len[i] 已是排序键：直接两遍计数分配即可，无需真排序）
        uint32_t next[HUF_MAX_BITS+1] = {};
        for (int b = 1; b <= HUF_MAX_BITS; b++) next[b] = firstCode[b];
        for (int i = 0; i < nSyms; i++) {
            if (len[i]) {
                code[i] = next[len[i]]++;
                int slot = firstIdx[len[i]] + (int)(code[i] - firstCode[len[i]]);
                idxToSym[slot] = i;
            }
        }
        return true;
    }
};

// ---------------------------------------------------------- 建树（编码侧）--
// 教学核心：Huffman 树怎么来？
//   1. 每个符号一个节点，权重=频次，进最小堆
//   2. 取最小的两个合并（权重相加），新节点回堆
//   3. 重复直到只剩一棵树 → 树深 = 码长
// 贪心正确性的直觉：每次合并的都是"最便宜的"两个，被合并得越晚
// （离根越近）码越短——频率高的符号永远优先浮到浅层。
//
// 注意（常见坑，本文件第一版就踩过）：
//   std::make_heap/make_heap 系列按 comp 构造的是"comp 意义上的最大堆"，
//   即 comp(a,b)=a<b 时堆顶是【权重最大】的节点。要取最小权重，
//   比较器必须反过来写：comp(a,b) = w[b] < w[a]。
//
// 若贪心树深超过 maxBits（概率极倾斜时可能），用"位长调整"把码长集
// 拉回合法范围：clamp 到 maxBits 后，按 Kraft 值逐步
//   超订（Σ2^-len > 1）→ 把最深的可加深符号再加深一位（贡献减半）
//   欠订（Σ2^-len < 1）→ 把可变浅的符号变浅一位（贡献翻倍）
// 这是 JPEG/FLAC 使用的经典收敛法（DEFLATE 的 package-merge 更优，
// 但代码量翻倍——教学取舍）。
inline bool huffman_lengths_from_freq(const uint32_t *freq, int nSyms,
                                      int maxBits, int *lens /*out, nSyms*/)
{
    struct Node { uint64_t w; int sym; int a, b; };   // sym=-1: 内部节点
    std::vector<Node> nodes;
    nodes.reserve(nSyms * 2);
    for (int i = 0; i < nSyms; i++) {
        lens[i] = 0;
        if (freq[i]) nodes.push_back({freq[i], i, -1, -1});
    }
    if (nodes.empty()) return true;                   // 空表：全 0
    if ((int)nodes.size() == 1) { lens[nodes[0].sym] = 1; return true; }
    if ((int)nodes.size() > (1 << maxBits)) return false;  // 槽位不够，必然非法

    // ---- 最小堆（注意比较器方向：堆顶必须是最小权重）----
    auto cmp = [&nodes](int a, int b){ return nodes[b].w < nodes[a].w; };
    std::vector<int> heap;
    for (int i = 0; i < (int)nodes.size(); i++) heap.push_back(i);
    std::make_heap(heap.begin(), heap.end(), cmp);

    auto popMin = [&]() {
        std::pop_heap(heap.begin(), heap.end(), cmp);
        int v = heap.back(); heap.pop_back(); return v;
    };
    auto pushNode = [&](const Node &nd) {
        nodes.push_back(nd);
        heap.push_back((int)nodes.size()-1);
        std::push_heap(heap.begin(), heap.end(), cmp);
    };

    while (heap.size() > 1) {
        int a = popMin(), b = popMin();
        pushNode({ nodes[a].w + nodes[b].w, -1, a, b });
    }
    int root = heap.back();

    // ---- 非递归深度统计（BFS/DFS 均可；栈版防递归溢出）----
    std::vector<int> depth(nodes.size(), -1);
    std::vector<int> stack { root };
    depth[root] = 0;
    while (!stack.empty()) {
        int n = stack.back(); stack.pop_back();
        const Node &nd = nodes[n];
        if (nd.sym >= 0) lens[nd.sym] = depth[n];
        else {
            depth[nd.a] = depth[n] + 1; stack.push_back(nd.a);
            depth[nd.b] = depth[n] + 1; stack.push_back(nd.b);
        }
    }

    // ---- 限深调整（只在树深超限时进入）----
    bool over = false;
    for (int i = 0; i < nSyms; i++)
        if (lens[i] > maxBits) { lens[i] = maxBits; over = true; }
    if (!over) return true;

    // counts[b] = 码长 b 的符号数；Kraft 值以 2^maxBits 为单位：
    //   S = Σ counts[b] << (maxBits - b)，合法 ⇔ S == 1<<maxBits
    uint64_t counts[64] = {};
    for (int i = 0; i < nSyms; i++) if (lens[i]) counts[lens[i]]++;
    auto kraftSum = [&]() {
        uint64_t s = 0;
        for (int b = 1; b <= maxBits; b++) s += counts[b] << (maxBits - b);
        return s;
    };
    const uint64_t FULL = 1ull << maxBits;

    // 超订：把"最深且未达 maxBits"层的一个符号再加深一位。
    //   加深使该符号贡献减半（<< 的位数 +1），S 单调下降且不越 0。
    while (kraftSum() > FULL) {
        int b = maxBits - 1;
        while (b > 0 && counts[b] == 0) b--;
        if (b <= 0) return false;                     // 无符号可加深（不可达）
        // 选该层任意符号（确定性：取符号值最小者）
        for (int i = 0; i < nSyms; i++) if (lens[i] == b) {
            lens[i]++; counts[b]--; counts[b+1]++; break;
        }
    }
    // 欠订：把"最深可变浅"层（len>1 的最深）的一个符号变浅一位，
    //   变浅使贡献翻倍；若会越过 FULL 则换更浅层——但更浅翻倍更多，
    //   因此标准做法是：从 len=maxBits-1 往浅找第一个"翻倍后不超过
    //   剩余空间"的层；找不到即余量不可整分（此时剩余空间必然足够小，
    //   可安全地把最深符号逐步变浅填满）。
    while (kraftSum() < FULL) {
        uint64_t cur = kraftSum();
        uint64_t room = FULL - cur;
        int chosen = 0;
        for (int b = maxBits - 1; b >= 1; b--) {
            if (counts[b] && (1ull << (maxBits - b + 1)) <= room) { chosen = b; break; }
        }
        if (!chosen) {
            // 退化情形：剩余空间无 2 的幂可整分——把最深非 maxBits 符号
            // 逐步加深直到空间耗尽（每步减半，最终恰好收敛到 FULL）。
            int b = maxBits - 1;
            while (b > 0 && counts[b] == 0) b--;
            if (b <= 0) return false;
            for (int i = 0; i < nSyms; i++) if (lens[i] == b) {
                lens[i]++; counts[b]--; counts[b+1]++; break;
            }
            continue;
        }
        for (int i = 0; i < nSyms; i++) if (lens[i] == chosen) {
            lens[i]--; counts[chosen]--; counts[chosen-1]++; break;
        }
    }
    return kraftSum() == FULL;
}

} // namespace learnarc
