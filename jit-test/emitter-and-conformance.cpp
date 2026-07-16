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
    std::fprintf(stderr, "AND_EMITTER_FAIL label=%s expected=%016llx found=%016llx\n",
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

static uae_u32 and_ww3f_word(unsigned d, unsigned n)
{
    emitted.clear();
    AND_ww3f(d, n);
    return one_word("AND_ww3f emission count");
}

static uae_u32 and_www_word(unsigned d, unsigned n, unsigned m)
{
    emitted.clear();
    AND_www(d, n, m);
    return one_word("AND_www emission count");
}

static uae_u32 and_xxx_word(unsigned d, unsigned n, unsigned m)
{
    emitted.clear();
    AND_xxx(d, n, m);
    return one_word("AND_xxx emission count");
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

static std::uint64_t run1(const std::vector<uae_u32> &words, std::uint64_t value)
{
    long page_size = 0;
    void *page = executable_page(words, page_size);
    using Fn = std::uint64_t (*)(std::uint64_t);
    const auto result = reinterpret_cast<Fn>(page)(value);
    if (munmap(page, static_cast<std::size_t>(page_size)) != 0) {
        std::perror("munmap");
        std::exit(1);
    }
    return result;
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
static unsigned flag_vectors = 0;

static void check_word(const char *label, uae_u32 expected, uae_u32 found)
{
    if (found != expected) fail(label, expected, found);
    ++exact_words;
}

static void check_result1(const char *label, const std::vector<uae_u32> &words,
    std::uint64_t value, std::uint64_t expected)
{
    const std::uint64_t found = run1(words, value);
    if (found != expected) fail(label, expected, found);
    ++result_vectors;
}

static void check_result2(const char *label, const std::vector<uae_u32> &words,
    std::uint64_t lhs, std::uint64_t rhs, std::uint64_t expected)
{
    const std::uint64_t found = run2(words, lhs, rhs);
    if (found != expected) fail(label, expected, found);
    ++result_vectors;
}

static void check_flags(const char *label, uae_u32 and_word,
    std::uint64_t lhs, std::uint64_t rhs)
{
    constexpr uae_u32 msr_nzcv_x2 = 0xd51b4202u;
    constexpr uae_u32 mrs_x0_nzcv = 0xd53b4200u;
    constexpr uae_u32 ret = 0xd65f03c0u;
    constexpr std::uint64_t initial_nzcv = 0xa0000000u;
    const std::uint64_t found = run3(
        {msr_nzcv_x2, and_word, mrs_x0_nzcv, ret}, lhs, rhs, initial_nzcv) & 0xf0000000u;
    if (found != initial_nzcv) fail(label, initial_nzcv, found);
    ++flag_vectors;
}

int main()
{
#if !defined(__aarch64__)
    std::fprintf(stderr, "AND_EMITTER_FAIL native AArch64 host required\n");
    return 1;
#endif
    constexpr uae_u32 ret = 0xd65f03c0u;

    check_word("AND_ww3f exact word", 0x12001549u, and_ww3f_word(9, 10));
    check_word("AND_ww3f high register fields", 0x120017beu, and_ww3f_word(30, 29));
    check_word("AND_ww3f register field maximum", 0x120017ffu, and_ww3f_word(31, 31));
    check_word("AND_www exact word", 0x0a0b0149u, and_www_word(9, 10, 11));
    check_word("AND_www high register fields", 0x0a1c03beu, and_www_word(30, 29, 28));
    check_word("AND_www register field maximum", 0x0a1f03ffu, and_www_word(31, 31, 31));
    check_word("AND_xxx exact word", 0x8a0e01acu, and_xxx_word(12, 13, 14));
    check_word("AND_xxx high register fields", 0x8a1a037cu, and_xxx_word(28, 27, 26));
    check_word("AND_xxx register field maximum", 0x8a1f03ffu, and_xxx_word(31, 31, 31));

    for (const auto &v : std::initializer_list<std::uint64_t[2]>{
        {0, 0}, {0x3f, 0x3f}, {0x40, 0}, {0x7f, 0x3f},
        {0xffffffffu, 0x3f}, {0x10000003full, 0x3f},
    }) check_result1("AND_ww3f native alias result", {and_ww3f_word(0, 0), ret}, v[0], v[1]);
    check_result2("AND_ww3f native nonalias zero", {and_ww3f_word(0, 1), ret},
        0xaaaaaaaaaaaaaaaaull, 0x12345640ull, 0);
    check_result2("AND_ww3f native nonalias mask", {and_ww3f_word(0, 1), ret},
        0, 0xffffffffffffffd5ull, 0x15);

    for (const auto &v : std::initializer_list<std::uint64_t[3]>{
        {0, 0, 0}, {0xffffffffu, 0x0f0f0f0fu, 0x0f0f0f0fu},
        {0x12345678u, 0xff00ff00u, 0x12005600u},
        {0x100000001ull, 0x200000003ull, 1},
        {0x80000000u, 0x7fffffffu, 0},
        {0xffffffffffffffffull, 0x123456789abcdef0ull, 0x9abcdef0u},
    }) check_result2("AND_www native d=n alias", {and_www_word(0, 0, 1), ret},
        v[0], v[1], v[2]);
    check_result2("AND_www native d=m alias", {and_www_word(0, 1, 0), ret},
        0xff00ff00u, 0x0f0f0f0fu, 0x0f000f00u);
    check_result1("AND_www native all alias", {and_www_word(0, 0, 0), ret},
        0x123456789abcdef0ull, 0x9abcdef0u);

    for (const auto &v : std::initializer_list<std::uint64_t[3]>{
        {0, 0, 0}, {~std::uint64_t{0}, 0x0f0f0f0f0f0f0f0full, 0x0f0f0f0f0f0f0f0full},
        {0x123456789abcdef0ull, 0xff00ff00ff00ff00ull, 0x120056009a00de00ull},
        {0x100000001ull, 0x200000003ull, 1},
        {0x8000000000000000ull, 0x7fffffffffffffffull, 0},
        {0xffffffff00000000ull, 0x123456789abcdef0ull, 0x1234567800000000ull},
    }) check_result2("AND_xxx native d=n alias", {and_xxx_word(0, 0, 1), ret},
        v[0], v[1], v[2]);
    check_result2("AND_xxx native d=m alias", {and_xxx_word(0, 1, 0), ret},
        0xff00ff00ff00ff00ull, 0x0f0f0f0f0f0f0f0full, 0x0f000f000f000f00ull);
    check_result1("AND_xxx native all alias", {and_xxx_word(0, 0, 0), ret},
        0x123456789abcdef0ull, 0x123456789abcdef0ull);

    check_flags("AND_ww3f preserves NZCV", and_ww3f_word(3, 0), 0xffffffffu, 0);
    check_flags("AND_www preserves NZCV", and_www_word(3, 0, 1), 0xffffffffu, 0);
    check_flags("AND_xxx preserves NZCV", and_xxx_word(3, 0, 1), ~std::uint64_t{0}, 0);

    std::printf("METRIC emitter_and_apis=3\n");
    std::printf("METRIC emitter_and_exact_words=%u\n", exact_words);
    std::printf("METRIC emitter_and_native_result_vectors=%u\n", result_vectors);
    std::printf("METRIC emitter_and_native_flag_vectors=%u\n", flag_vectors);
    std::printf("METRIC emitter_and_native_vectors=%u\n", result_vectors + flag_vectors);
    std::printf("METRIC emitter_and_width32=1\n");
    std::printf("METRIC emitter_and_width64=1\n");
    std::printf("METRIC emitter_and_alias_dn=1\n");
    std::printf("METRIC emitter_and_alias_dm=1\n");
    std::printf("METRIC emitter_and_alias_all=1\n");
    return exact_words == 9 && result_vectors == 24 && flag_vectors == 3 ? 0 : 1;
}
