#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <initializer_list>
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
    std::fprintf(stderr, "SUB_EMITTER_FAIL label=%s expected=%016llx found=%016llx\n",
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

static uae_u32 sub_wwi_word(unsigned d, unsigned n, unsigned immediate)
{
    emitted.clear();
    SUB_wwi(d, n, immediate);
    return one_word("SUB_wwi emission count");
}

static uae_u32 sub_xxi_word(unsigned d, unsigned n, unsigned immediate)
{
    emitted.clear();
    SUB_xxi(d, n, immediate);
    return one_word("SUB_xxi emission count");
}

static uae_u32 sub_www_word(unsigned d, unsigned n, unsigned m)
{
    emitted.clear();
    SUB_www(d, n, m);
    return one_word("SUB_www emission count");
}

static uae_u32 sub_xxx_word(unsigned d, unsigned n, unsigned m)
{
    emitted.clear();
    SUB_xxx(d, n, m);
    return one_word("SUB_xxx emission count");
}

static uae_u32 subs_wwi_word(unsigned d, unsigned n, unsigned immediate)
{
    emitted.clear();
    SUBS_wwi(d, n, immediate);
    return one_word("SUBS_wwi emission count");
}

static uae_u32 subs_www_word(unsigned d, unsigned n, unsigned m)
{
    emitted.clear();
    SUBS_www(d, n, m);
    return one_word("SUBS_www emission count");
}

static uae_u32 subs_www_lsl_word(unsigned d, unsigned n, unsigned m, unsigned shift)
{
    emitted.clear();
    SUBS_wwwLSLi(d, n, m, shift);
    return one_word("SUBS_wwwLSLi emission count");
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

static std::uint64_t run2(const std::vector<uae_u32> &words,
    std::uint64_t lhs, std::uint64_t rhs)
{
    long page_size = 0;
    void *page = executable_page(words, page_size);
    using Fn = std::uint64_t (*)(std::uint64_t, std::uint64_t);
    const auto result = reinterpret_cast<Fn>(page)(lhs, rhs);
    if (munmap(page, static_cast<std::size_t>(page_size)) != 0) {
        std::perror("munmap");
        std::exit(1);
    }
    return result;
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

static unsigned exact_words = 0;
static unsigned result_vectors = 0;
static unsigned preserve_vectors = 0;
static unsigned flag_vectors = 0;

static void check_word(const char *label, uae_u32 expected, uae_u32 found)
{
    if (found != expected) fail(label, expected, found);
    ++exact_words;
}

static void check_result(const char *label, const std::vector<uae_u32> &words,
    std::uint64_t lhs, std::uint64_t rhs, std::uint64_t expected)
{
    const std::uint64_t found = run2(words, lhs, rhs);
    if (found != expected) fail(label, expected, found);
    ++result_vectors;
}

static void check_preserves_flags(const char *label, uae_u32 sub_word,
    std::uint64_t lhs, std::uint64_t rhs)
{
    constexpr uae_u32 msr_nzcv_x2 = 0xd51b4202u;
    constexpr uae_u32 mrs_x0_nzcv = 0xd53b4200u;
    constexpr uae_u32 ret = 0xd65f03c0u;
    constexpr std::uint64_t initial_nzcv = 0xa0000000u;
    const std::uint64_t found = run3(
        {msr_nzcv_x2, sub_word, mrs_x0_nzcv, ret}, lhs, rhs, initial_nzcv) & 0xf0000000u;
    if (found != initial_nzcv) fail(label, initial_nzcv, found);
    ++preserve_vectors;
}

static std::uint64_t expected_subs_w_nzcv(std::uint64_t lhs64, std::uint64_t rhs64)
{
    const std::uint32_t lhs = static_cast<std::uint32_t>(lhs64);
    const std::uint32_t rhs = static_cast<std::uint32_t>(rhs64);
    const std::uint32_t result = lhs - rhs;
    const bool n = (result & 0x80000000u) != 0;
    const bool z = result == 0;
    const bool c = lhs >= rhs;
    const bool v = ((lhs ^ rhs) & (lhs ^ result) & 0x80000000u) != 0;
    return (static_cast<std::uint64_t>(n) << 31) |
        (static_cast<std::uint64_t>(z) << 30) |
        (static_cast<std::uint64_t>(c) << 29) |
        (static_cast<std::uint64_t>(v) << 28);
}

static void check_subs_flags(const char *label, uae_u32 subs_word,
    std::uint64_t lhs, std::uint64_t rhs_operand, std::uint64_t rhs_effective)
{
    constexpr uae_u32 msr_nzcv_x2 = 0xd51b4202u;
    constexpr uae_u32 mrs_x0_nzcv = 0xd53b4200u;
    constexpr uae_u32 ret = 0xd65f03c0u;
    constexpr std::uint64_t hostile_initial_nzcv = 0x50000000u;
    const std::uint64_t expected = expected_subs_w_nzcv(lhs, rhs_effective);
    const std::uint64_t found = run3(
        {msr_nzcv_x2, subs_word, mrs_x0_nzcv, ret},
        lhs, rhs_operand, hostile_initial_nzcv) & 0xf0000000u;
    if (found != expected) fail(label, expected, found);
    ++flag_vectors;
}

int main()
{
#if !defined(__aarch64__)
    std::fprintf(stderr, "SUB_EMITTER_FAIL native AArch64 host required\n");
    return 1;
#endif
    constexpr uae_u32 ret = 0xd65f03c0u;

    check_word("SUB_wwi imm0 exact word", 0x51000149u, sub_wwi_word(9, 10, 0));
    check_word("SUB_wwi imm12-max/max-register exact word", 0x513fffffu,
        sub_wwi_word(31, 31, 0xfff));
    check_word("SUB_xxi imm0 exact word", 0xd100018bu, sub_xxi_word(11, 12, 0));
    check_word("SUB_xxi imm12-max/max-register exact word", 0xd13fffffu,
        sub_xxi_word(31, 31, 0xfff));
    check_word("SUB_www max-register exact word", 0x4b1f03ffu, sub_www_word(31, 31, 31));
    check_word("SUB_xxx max-register exact word", 0xcb1f03ffu, sub_xxx_word(31, 31, 31));
    check_word("SUBS_wwi imm0 exact word", 0x71000149u, subs_wwi_word(9, 10, 0));
    check_word("SUBS_wwi imm12-max/max-register exact word", 0x713fffffu,
        subs_wwi_word(31, 31, 0xfff));
    check_word("SUBS_www max-register exact word", 0x6b1f03ffu,
        subs_www_word(31, 31, 31));
    check_word("SUBS_wwwLSLi shift0 exact word", 0x6b1b0359u,
        subs_www_lsl_word(25, 26, 27, 0));
    check_word("SUBS_wwwLSLi shift31/max-register exact word", 0x6b1f7fffu,
        subs_www_lsl_word(31, 31, 31, 31));

    for (const auto &v : std::initializer_list<std::uint64_t[3]>{
        {0, 0, 0}, {0, 1, 0xffffffffu}, {0xffffffffu, 1, 0xfffffffeu},
        {0x80000000u, 0xfff, 0x7ffff001u}, {0x100000001ull, 1, 0},
    }) check_result("SUB_wwi native result", {sub_wwi_word(0, 0, v[1]), ret}, v[0], 0, v[2]);

    for (const auto &v : std::initializer_list<std::uint64_t[3]>{
        {0, 0, 0}, {0, 1, ~std::uint64_t{0}},
        {~std::uint64_t{0}, 0xfff, 0xfffffffffffff000ull},
        {0x100000000ull, 0xfff, 0xfffff001ull},
        {0x8000000000000000ull, 0xfff, 0x7ffffffffffff001ull},
    }) check_result("SUB_xxi native result", {sub_xxi_word(0, 0, v[1]), ret}, v[0], 0, v[2]);

    for (const auto &v : std::initializer_list<std::uint64_t[3]>{
        {0, 0, 0}, {0, 1, 0xffffffffu}, {1, 2, 0xffffffffu},
        {0x80000000u, 1, 0x7fffffffu}, {0x100000001ull, 2, 0xffffffffu},
    }) check_result("SUB_www native result/destination-lhs alias",
        {sub_www_word(0, 0, 1), ret}, v[0], v[1], v[2]);
    check_result("SUB_www destination-rhs alias", {sub_www_word(1, 0, 1), 0x2a0103e0u, ret},
        9, 4, 5);

    for (const auto &v : std::initializer_list<std::uint64_t[3]>{
        {0, 0, 0}, {0, 1, ~std::uint64_t{0}}, {1, 2, ~std::uint64_t{0}},
        {0x8000000000000000ull, 1, 0x7fffffffffffffffull},
        {0x100000000ull, 2, 0xfffffffeull},
    }) check_result("SUB_xxx native result/destination-lhs alias",
        {sub_xxx_word(0, 0, 1), ret}, v[0], v[1], v[2]);
    check_result("SUB_xxx destination-rhs alias", {sub_xxx_word(1, 0, 1), 0xaa0103e0u, ret},
        0x100000000ull, 2, 0xfffffffeull);

    for (const auto &v : std::initializer_list<std::uint64_t[3]>{
        {0, 0, 0}, {0, 1, 0xffffffffu}, {1, 1, 0},
        {0xffffffffu, 1, 0xfffffffeu}, {0x80000000u, 1, 0x7fffffffu},
        {0x80000fffu, 0xfff, 0x80000000u},
    }) check_result("SUBS_wwi native result", {subs_wwi_word(0, 0, v[1]), ret}, v[0], 0, v[2]);

    for (const auto &v : std::initializer_list<std::uint64_t[3]>{
        {0, 0, 0}, {0, 1, 0xffffffffu}, {1, 1, 0},
        {0xffffffffu, 1, 0xfffffffeu}, {0x80000000u, 1, 0x7fffffffu},
        {0x7fffffffu, 0xffffffffu, 0x80000000u},
    }) check_result("SUBS_www native result/destination-lhs alias",
        {subs_www_word(0, 0, 1), ret}, v[0], v[1], v[2]);
    check_result("SUBS_www destination-rhs alias",
        {subs_www_word(1, 0, 1), 0x2a0103e0u, ret}, 9, 4, 5);

    for (const auto &v : std::initializer_list<std::uint64_t[4]>{
        {7, 3, 0, 4}, {6, 3, 1, 0}, {1, 1, 16, 0xffff0001u},
        {0, 1, 31, 0x80000000u}, {0xffffffffu, 3, 31, 0x7fffffffu},
        {0x80000000u, 1, 31, 0},
    }) check_result("SUBS_wwwLSLi native result/destination-lhs alias",
        {subs_www_lsl_word(0, 0, 1, v[2]), ret}, v[0], v[1], v[3]);
    check_result("SUBS_wwwLSLi destination-rhs alias",
        {subs_www_lsl_word(1, 0, 1, 1), 0x2a0103e0u, ret}, 14, 4, 6);

    check_preserves_flags("SUB_wwi preserves NZCV", sub_wwi_word(3, 0, 0xfff), 0, 0);
    check_preserves_flags("SUB_xxi preserves NZCV", sub_xxi_word(3, 0, 0xfff), 0, 0);
    check_preserves_flags("SUB_www preserves NZCV/destination-rhs alias",
        sub_www_word(1, 0, 1), 9, 4);
    check_preserves_flags("SUB_xxx preserves NZCV/destination-rhs alias",
        sub_xxx_word(1, 0, 1), 9, 4);

    for (const auto &v : std::initializer_list<std::uint64_t[2]>{
        {0, 0}, {0, 1}, {1, 1}, {0xffffffffu, 1},
        {0x80000000u, 1}, {0x80000fffu, 0xfff}, {0x7fffffffu, 0xfff}, {0x100000000ull, 1},
    }) check_subs_flags("SUBS_wwi native NZCV", subs_wwi_word(3, 0, v[1]),
        v[0], v[1], v[1]);

    for (const auto &v : std::initializer_list<std::uint64_t[2]>{
        {0, 0}, {0, 1}, {1, 1}, {0xffffffffu, 1},
        {0x80000000u, 1}, {0x7fffffffu, 0xffffffffu},
        {0x80000000u, 0xffffffffu}, {0x100000000ull, 1},
    }) check_subs_flags("SUBS_www native NZCV", subs_www_word(3, 0, 1),
        v[0], v[1], v[1]);

    for (const auto &v : std::initializer_list<std::uint64_t[3]>{
        {0, 0, 0}, {0, 1, 0}, {1, 1, 0}, {0xffffffffu, 1, 0},
        {0x80000000u, 1, 0}, {0x7fffffffu, 0xffffffffu, 0},
        {0x80000000u, 1, 31}, {0x7fffffffu, 1, 31},
    }) {
        const std::uint32_t effective = static_cast<std::uint32_t>(v[1]) << v[2];
        check_subs_flags("SUBS_wwwLSLi native NZCV", subs_www_lsl_word(3, 0, 1, v[2]),
            v[0], v[1], effective);
    }

    std::printf("METRIC emitter_sub_apis=7\n");
    std::printf("METRIC emitter_sub_exact_words=%u\n", exact_words);
    std::printf("METRIC emitter_sub_native_result_vectors=%u\n", result_vectors);
    std::printf("METRIC emitter_sub_native_preserve_vectors=%u\n", preserve_vectors);
    std::printf("METRIC emitter_sub_native_nzcv_vectors=%u\n", flag_vectors);
    std::printf("METRIC emitter_sub_native_vectors=%u\n", result_vectors + preserve_vectors + flag_vectors);
    std::printf("METRIC emitter_sub_width32=1\n");
    std::printf("METRIC emitter_sub_width64=1\n");
    return exact_words == 11 && result_vectors == 42 && preserve_vectors == 4 && flag_vectors == 24 ? 0 : 1;
}
