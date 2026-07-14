#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <sys/mman.h>
#include <tuple>
#include <unistd.h>
#include <vector>

using uae_u32 = std::uint32_t;
using uae_s32 = std::int32_t;

static std::vector<uae_u32> emitted;
static void emit_long(uae_u32 word) { emitted.push_back(word); }

#include "../BasiliskII/src/uae_cpu_2026/compiler/codegen_arm64.h"

static void fail(const char *label, std::uint64_t expected, std::uint64_t found)
{
    std::fprintf(stderr, "COMPARE_EMITTER_FAIL label=%s expected=%016llx found=%016llx\n",
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

static uae_u32 cmp_wi_word(unsigned n, unsigned immediate)
{
    emitted.clear();
    CMP_wi(n, immediate);
    return one_word("CMP_wi emission count");
}

static uae_u32 cmp_xi_word(unsigned n, unsigned immediate)
{
    emitted.clear();
    CMP_xi(n, immediate);
    return one_word("CMP_xi emission count");
}

static uae_u32 cmp_ww_word(unsigned n, unsigned m)
{
    emitted.clear();
    CMP_ww(n, m);
    return one_word("CMP_ww emission count");
}

static uae_u32 cmp_xx_word(unsigned n, unsigned m)
{
    emitted.clear();
    CMP_xx(n, m);
    return one_word("CMP_xx emission count");
}

static uae_u32 cmp_ww_lsl_word(unsigned n, unsigned m, unsigned shift)
{
    emitted.clear();
    CMP_wwLSLi(n, m, shift);
    return one_word("CMP_wwLSLi emission count");
}

static std::uint64_t expected_nzcv(std::uint64_t lhs, std::uint64_t rhs, unsigned bits)
{
    const std::uint64_t mask = bits == 64 ? ~std::uint64_t{0} : 0xffffffffu;
    const std::uint64_t sign = std::uint64_t{1} << (bits - 1);
    lhs &= mask;
    rhs &= mask;
    const std::uint64_t result = (lhs - rhs) & mask;
    std::uint64_t nzcv = 0;
    if (result & sign) nzcv |= 0x80000000u;
    if (result == 0) nzcv |= 0x40000000u;
    if (lhs >= rhs) nzcv |= 0x20000000u;
    if (((lhs ^ rhs) & (lhs ^ result) & sign) != 0) nzcv |= 0x10000000u;
    return nzcv;
}

static std::uint64_t run(const std::vector<uae_u32> &words, std::uint64_t lhs, std::uint64_t rhs)
{
    const long page_size = sysconf(_SC_PAGESIZE);
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
    using Fn = std::uint64_t (*)(std::uint64_t, std::uint64_t);
    const auto result = reinterpret_cast<Fn>(page)(lhs, rhs);
    if (munmap(page, static_cast<std::size_t>(page_size)) != 0) {
        std::perror("munmap");
        std::exit(1);
    }
    return result & 0xf0000000u;
}

static unsigned vectors = 0;

static void check(const char *label, const std::vector<uae_u32> &words,
    std::uint64_t lhs, std::uint64_t runtime_rhs, std::uint64_t expected_rhs,
    unsigned bits)
{
    const std::uint64_t expected = expected_nzcv(lhs, expected_rhs, bits);
    const std::uint64_t found = run(words, lhs, runtime_rhs);
    if (found != expected) fail(label, expected, found);
    ++vectors;
}

int main()
{
#if !defined(__aarch64__)
    std::fprintf(stderr, "COMPARE_EMITTER_FAIL native AArch64 host required\n");
    return 1;
#endif
    constexpr uae_u32 mrs_x0_nzcv = 0xd53b4200u;
    constexpr uae_u32 ret = 0xd65f03c0u;
    constexpr uae_u32 mov_w9_w0 = 0x2a0003e9u;
    constexpr uae_u32 mov_w10_w1 = 0x2a0103eau;
    constexpr uae_u32 mov_x11_x0 = 0xaa0003ebu;
    constexpr uae_u32 mov_x12_x1 = 0xaa0103ecu;

    if (cmp_wi_word(9, 0) != 0x7100013fu) fail("CMP_wi exact word", 0x7100013f, cmp_wi_word(9, 0));
    if (cmp_xi_word(11, 0xfff) != 0xf13ffd7fu) fail("CMP_xi exact word", 0xf13ffd7f, cmp_xi_word(11, 0xfff));
    if (cmp_ww_word(9, 10) != 0x6b0a013fu) fail("CMP_ww exact word", 0x6b0a013f, cmp_ww_word(9, 10));
    if (cmp_xx_word(11, 12) != 0xeb0c017fu) fail("CMP_xx exact word", 0xeb0c017f, cmp_xx_word(11, 12));
    if (cmp_ww_lsl_word(9, 10, 31) != 0x6b0a7d3fu) fail("CMP_wwLSLi exact word", 0x6b0a7d3f, cmp_ww_lsl_word(9, 10, 31));

    for (const auto &[label, lhs, immediate] : std::vector<std::tuple<const char *, std::uint64_t, unsigned>>{
        {"CMP_wi equal", 0, 0}, {"CMP_wi borrow", 0, 1},
        {"CMP_wi overflow", 0x80000000u, 1}, {"CMP_wi imm12-max", 0xffffffffu, 0xfff},
    }) check(label, {mov_w9_w0, cmp_wi_word(9, immediate), mrs_x0_nzcv, ret}, lhs, immediate, immediate, 32);

    for (const auto &[label, lhs, immediate] : std::vector<std::tuple<const char *, std::uint64_t, unsigned>>{
        {"CMP_xi equal", 0, 0}, {"CMP_xi borrow", 0, 1},
        {"CMP_xi overflow", 0x8000000000000000ull, 1},
        {"CMP_xi width64", 0x100000000ull, 0xfff},
    }) check(label, {mov_x11_x0, cmp_xi_word(11, immediate), mrs_x0_nzcv, ret}, lhs, immediate, immediate, 64);

    for (const auto &[label, lhs, rhs] : std::vector<std::tuple<const char *, std::uint64_t, std::uint64_t>>{
        {"CMP_ww equal", 0x100000001ull, 1}, {"CMP_ww borrow", 0, 1},
        {"CMP_ww overflow", 0x80000000u, 1}, {"CMP_ww carry", 0xffffffffu, 1},
    }) check(label, {mov_w9_w0, mov_w10_w1, cmp_ww_word(9, 10), mrs_x0_nzcv, ret}, lhs, rhs, rhs, 32);

    for (const auto &[label, lhs, rhs] : std::vector<std::tuple<const char *, std::uint64_t, std::uint64_t>>{
        {"CMP_xx equal", 0x100000001ull, 0x100000001ull}, {"CMP_xx borrow", 0, 1},
        {"CMP_xx overflow", 0x8000000000000000ull, 1},
        {"CMP_xx width64", 0x100000000ull, 1},
    }) check(label, {mov_x11_x0, mov_x12_x1, cmp_xx_word(11, 12), mrs_x0_nzcv, ret}, lhs, rhs, rhs, 64);

    for (const auto &[label, lhs, rhs, shift] : std::vector<std::tuple<const char *, std::uint64_t, std::uint64_t, unsigned>>{
        {"CMP_wwLSLi shift0", 7, 7, 0}, {"CMP_wwLSLi shift1", 6, 3, 1},
        {"CMP_wwLSLi shift16", 0x00010000u, 1, 16},
        {"CMP_wwLSLi shift31", 0x80000000u, 1, 31},
    }) {
        const std::uint64_t shifted = (rhs << shift) & 0xffffffffu;
        check(label, {mov_w9_w0, mov_w10_w1, cmp_ww_lsl_word(9, 10, shift), mrs_x0_nzcv, ret}, lhs, rhs, shifted, 32);
    }

    std::printf("METRIC emitter_compare_exact_words=5\n");
    std::printf("METRIC emitter_compare_native_vectors=%u\n", vectors);
    std::printf("METRIC emitter_compare_width32=1\n");
    std::printf("METRIC emitter_compare_width64=1\n");
    return vectors == 20 ? 0 : 1;
}
