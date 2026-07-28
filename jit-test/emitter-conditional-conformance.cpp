#include <array>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <sys/mman.h>
#include <unistd.h>
#include <vector>

using uae_u32 = std::uint32_t;
using uae_s32 = std::int32_t;

static std::vector<uae_u32> emitted;
static void emit_long(uae_u32 word) { emitted.push_back(word); }

#include "../BasiliskII/src/uae_cpu_2026/compiler/codegen_arm64.h"

static void fail(const char *label, std::uint64_t expected, std::uint64_t found)
{
    std::fprintf(stderr, "CONDITIONAL_EMITTER_FAIL label=%s expected=%016llx found=%016llx\n",
        label, static_cast<unsigned long long>(expected),
        static_cast<unsigned long long>(found));
    std::exit(1);
}

static uae_u32 one_word(const char *label)
{
    if (emitted.size() != 1)
        fail(label, 1, emitted.size());
    const uae_u32 word = emitted.front();
    emitted.clear();
    return word;
}

static uae_u32 csel_w_word(unsigned d, unsigned n, unsigned m, unsigned cond)
{
    emitted.clear();
    CSEL_wwwc(d, n, m, cond);
    return one_word("CSEL_wwwc emission count");
}

static uae_u32 csel_x_word(unsigned d, unsigned n, unsigned m, unsigned cond)
{
    emitted.clear();
    CSEL_xxxc(d, n, m, cond);
    return one_word("CSEL_xxxc emission count");
}

static uae_u32 cset_x_word(unsigned d, unsigned cond)
{
    emitted.clear();
    CSET_xc(d, cond);
    return one_word("CSET_xc emission count");
}

static uae_u32 csetm_w_word(unsigned d, unsigned cond)
{
    emitted.clear();
    CSETM_wc(d, cond);
    return one_word("CSETM_wc emission count");
}

static void *executable_page(const std::vector<uae_u32> &words, long &page_size)
{
    page_size = sysconf(_SC_PAGESIZE);
    if (page_size <= 0 || words.size() * sizeof(uae_u32) > static_cast<std::size_t>(page_size))
        fail("executable page size", 1, 0);
    void *page = mmap(nullptr, static_cast<std::size_t>(page_size),
        PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (page == MAP_FAILED) {
        std::perror("mmap");
        std::exit(1);
    }
    std::memcpy(page, words.data(), words.size() * sizeof(uae_u32));
    if (mprotect(page, static_cast<std::size_t>(page_size), PROT_READ | PROT_EXEC) != 0) {
        std::perror("mprotect");
        std::exit(1);
    }
    __builtin___clear_cache(static_cast<char *>(page),
        static_cast<char *>(page) + words.size() * sizeof(uae_u32));
    return page;
}

static std::uint64_t run3(const std::vector<uae_u32> &words,
    std::uint64_t lhs, std::uint64_t rhs, std::uint64_t nzcv)
{
    long page_size = 0;
    void *page = executable_page(words, page_size);
    using Fn = std::uint64_t (*)(std::uint64_t, std::uint64_t, std::uint64_t);
    const auto result = reinterpret_cast<Fn>(page)(lhs, rhs, nzcv);
    if (munmap(page, static_cast<std::size_t>(page_size)) != 0) {
        std::perror("munmap");
        std::exit(1);
    }
    return result;
}

static bool condition_holds(unsigned cond, unsigned nzcv_nibble)
{
    const bool n = (nzcv_nibble & 8u) != 0;
    const bool z = (nzcv_nibble & 4u) != 0;
    const bool c = (nzcv_nibble & 2u) != 0;
    const bool v = (nzcv_nibble & 1u) != 0;
    switch (cond) {
    case 0: return z;
    case 1: return !z;
    case 2: return c;
    case 3: return !c;
    case 4: return n;
    case 5: return !n;
    case 6: return v;
    case 7: return !v;
    case 8: return c && !z;
    case 9: return !c || z;
    case 10: return n == v;
    case 11: return n != v;
    case 12: return !z && n == v;
    case 13: return z || n != v;
    case 14: return true;
    case 15: return true; // A64 ConditionHolds treats both 111x encodings as unconditional.
    default: fail("condition range", 15, cond);
    }
    return false;
}

static unsigned exact_words = 0;
static unsigned csel_w_vectors = 0;
static unsigned csel_x_vectors = 0;
static unsigned cset_x_vectors = 0;
static unsigned csetm_w_vectors = 0;

static void check_word(const char *label, uae_u32 expected, uae_u32 found)
{
    if (found != expected) fail(label, expected, found);
    ++exact_words;
}

static void check_native(const char *label, uae_u32 op, std::uint64_t lhs,
    std::uint64_t rhs, unsigned nzcv_nibble, std::uint64_t expected)
{
    constexpr uae_u32 msr_nzcv_x2 = 0xd51b4202u;
    constexpr uae_u32 ret = 0xd65f03c0u;
    const std::uint64_t found = run3(
        {msr_nzcv_x2, op, ret}, lhs, rhs,
        static_cast<std::uint64_t>(nzcv_nibble) << 28);
    if (found != expected) fail(label, expected, found);
}

int main()
{
#if !defined(__aarch64__)
    std::fprintf(stderr, "CONDITIONAL_EMITTER_FAIL native AArch64 host required\n");
    return 1;
#endif
    check_word("CSEL_wwwc EQ exact word", 0x1a8b0149u, csel_w_word(9, 10, 11, 0));
    check_word("CSEL_wwwc NV exact word", 0x1a9cf3beu, csel_w_word(30, 29, 28, 15));
    check_word("CSEL_xxxc MI exact word", 0x9a8e41acu, csel_x_word(12, 13, 14, 4));
    check_word("CSEL_xxxc AL exact word", 0x9a9ce3beu, csel_x_word(30, 29, 28, 14));
    check_word("CSET_xc NE exact word", 0x9a9f07efu, cset_x_word(15, 1));
    check_word("CSET_xc LE exact word", 0x9a9fc7feu, cset_x_word(30, 13));
    check_word("CSETM_wc CS exact word", 0x5a9f33f0u, csetm_w_word(16, 2));
    check_word("CSETM_wc GT exact word", 0x5a9fd3feu, csetm_w_word(30, 12));

    constexpr std::uint64_t lhs = 0x0123456789abcdefull;
    constexpr std::uint64_t rhs = 0xfedcba9876543210ull;
    for (unsigned cond = 0; cond < 16; ++cond) {
        for (unsigned nzcv = 0; nzcv < 16; ++nzcv) {
            const bool take = condition_holds(cond, nzcv);
            check_native("CSEL_wwwc native truth table/zero extension",
                csel_w_word(0, 0, 1, cond), lhs, rhs, nzcv,
                take ? static_cast<std::uint32_t>(lhs) : static_cast<std::uint32_t>(rhs));
            ++csel_w_vectors;
            check_native("CSEL_xxxc native truth table",
                csel_x_word(0, 0, 1, cond), lhs, rhs, nzcv, take ? lhs : rhs);
            ++csel_x_vectors;
        }
    }
    // CSET/CSETM are aliases that invert the encoded condition. Configured
    // callers use the 14 ordinary predicates only; AL/NV are rejected structurally.
    for (unsigned cond = 0; cond < 14; ++cond) {
        for (unsigned nzcv = 0; nzcv < 16; ++nzcv) {
            const bool take = condition_holds(cond, nzcv);
            check_native("CSET_xc native truth table",
                cset_x_word(0, cond), lhs, rhs, nzcv, take ? 1u : 0u);
            ++cset_x_vectors;
            check_native("CSETM_wc native truth table/zero extension",
                csetm_w_word(0, cond), lhs, rhs, nzcv,
                take ? std::uint64_t{0xffffffffu} : 0u);
            ++csetm_w_vectors;
        }
    }

    std::printf("METRIC emitter_conditional_apis=4\n");
    std::printf("METRIC emitter_conditional_exact_words=%u\n", exact_words);
    std::printf("METRIC emitter_conditional_csel_w_vectors=%u\n", csel_w_vectors);
    std::printf("METRIC emitter_conditional_csel_x_vectors=%u\n", csel_x_vectors);
    std::printf("METRIC emitter_conditional_cset_x_vectors=%u\n", cset_x_vectors);
    std::printf("METRIC emitter_conditional_csetm_w_vectors=%u\n", csetm_w_vectors);
    std::printf("METRIC emitter_conditional_native_vectors=%u\n",
        csel_w_vectors + csel_x_vectors + cset_x_vectors + csetm_w_vectors);
    std::printf("METRIC emitter_conditional_all_conditions=1\n");
    std::printf("METRIC emitter_conditional_width32_zero_extend=1\n");
    std::printf("METRIC emitter_conditional_width64=1\n");
    return exact_words == 8 && csel_w_vectors == 256 && csel_x_vectors == 256 &&
        cset_x_vectors == 224 && csetm_w_vectors == 224 ? 0 : 1;
}
