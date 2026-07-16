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
    std::fprintf(stderr, "EOR_EMITTER_FAIL label=%s expected=%016llx found=%016llx\n",
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

static uae_u32 eor_www_word(unsigned d, unsigned n, unsigned m)
{
    emitted.clear();
    EOR_www(d, n, m);
    return one_word("EOR_www emission count");
}

static uae_u32 eor_wwwlsli_word(unsigned d, unsigned n, unsigned m, unsigned shift)
{
    emitted.clear();
    EOR_wwwLSLi(d, n, m, shift);
    return one_word("EOR_wwwLSLi emission count");
}

static uae_u32 eor_xxcflag_word(unsigned d, unsigned n)
{
    emitted.clear();
    EOR_xxCflag(d, n);
    return one_word("EOR_xxCflag emission count");
}

static uae_u32 eor_xxbit_word(unsigned d, unsigned n, unsigned bit)
{
    emitted.clear();
    EOR_xxbit(d, n, bit);
    return one_word("EOR_xxbit emission count");
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
static unsigned constant_checks = 0;
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

static void check_flags(const char *label, uae_u32 eor_word,
    std::uint64_t lhs, std::uint64_t rhs)
{
    constexpr uae_u32 msr_nzcv_x2 = 0xd51b4202u;
    constexpr uae_u32 mrs_x0_nzcv = 0xd53b4200u;
    constexpr uae_u32 ret = 0xd65f03c0u;
    constexpr std::uint64_t initial_nzcv = 0xa0000000u;
    const std::uint64_t found = run3(
        {msr_nzcv_x2, eor_word, mrs_x0_nzcv, ret}, lhs, rhs, initial_nzcv) & 0xf0000000u;
    if (found != initial_nzcv) fail(label, initial_nzcv, found);
    ++flag_vectors;
}

int main()
{
#if !defined(__aarch64__)
    std::fprintf(stderr, "EOR_EMITTER_FAIL native AArch64 host required\n");
    return 1;
#endif
    constexpr uae_u32 ret = 0xd65f03c0u;
    constexpr std::uint64_t bit29 = std::uint64_t{1} << 29;
    constexpr std::uint64_t bit63 = std::uint64_t{1} << 63;

    if (static_cast<uae_u32>(immOP_EOR) != 0xd2000000u)
        fail("immOP_EOR exact base", 0xd2000000u, static_cast<uae_u32>(immOP_EOR));
    ++constant_checks;

    check_word("EOR_www exact word", 0x4a0b0149u, eor_www_word(9, 10, 11));
    check_word("EOR_www high register fields", 0x4a1c03beu, eor_www_word(30, 29, 28));
    check_word("EOR_www register field maximum", 0x4a1f03ffu, eor_www_word(31, 31, 31));
    check_word("EOR_wwwLSLi exact shift", 0x4a0b1d49u, eor_wwwlsli_word(9, 10, 11, 7));
    check_word("EOR_wwwLSLi shift maximum", 0x4a1c7fbeu, eor_wwwlsli_word(30, 29, 28, 31));
    check_word("EOR_wwwLSLi masked shift", 0x4a1f03ffu, eor_wwwlsli_word(31, 31, 31, 32));
    check_word("EOR_xxCflag exact word", 0xd2630149u, eor_xxcflag_word(9, 10));
    check_word("EOR_xxCflag high register fields", 0xd26303beu, eor_xxcflag_word(30, 29));
    check_word("EOR_xxCflag register field maximum", 0xd26303ffu, eor_xxcflag_word(31, 31));
    check_word("EOR_xxbit bit zero", 0xd2400149u, eor_xxbit_word(9, 10, 0));
    check_word("EOR_xxbit C bit", 0xd26301acu, eor_xxbit_word(12, 13, 29));
    check_word("EOR_xxbit high bit", 0xd24103beu, eor_xxbit_word(30, 29, 63));
    check_word("EOR_xxbit maximum fields", 0xd24103ffu, eor_xxbit_word(31, 31, 63));

    check_result2("EOR_www native d=n alias", {eor_www_word(0, 0, 1), ret},
        0xaaaaaaaa12345678ull, 0xff00ff00u, 0xed34a978u);
    check_result2("EOR_www native d=m alias", {eor_www_word(0, 1, 0), ret},
        0x0f0f0f0fu, 0x33333333u, 0x3c3c3c3cu);
    check_result1("EOR_www native all alias", {eor_www_word(0, 0, 0), ret},
        0x123456789abcdef0ull, 0);
    check_result2("EOR_www native zero extension", {eor_www_word(0, 0, 1), ret},
        0xffffffffffffffffull, 0, 0xffffffffu);

    check_result2("EOR_wwwLSLi native shift seven", {eor_wwwlsli_word(0, 0, 1, 7), ret},
        0x12345678u, 0x00123456u, 0x1b2e7d78u);
    check_result2("EOR_wwwLSLi native d=m alias", {eor_wwwlsli_word(0, 1, 0, 5), ret},
        0x00000003u, 0x00000100u, 0x00000160u);
    check_result1("EOR_wwwLSLi native all alias", {eor_wwwlsli_word(0, 0, 0, 1), ret},
        0x12345678u, 0x365cfa88u);
    check_result2("EOR_wwwLSLi native shift 31", {eor_wwwlsli_word(0, 0, 1, 31), ret},
        0x7fffffffu, 1, 0xffffffffu);
    check_result1("EOR_wwwLSLi native masked shift", {eor_wwwlsli_word(0, 0, 0, 32), ret},
        0xabcdef01u, 0);

    check_result1("EOR_xxCflag native alias set", {eor_xxcflag_word(0, 0), ret},
        0, bit29);
    check_result1("EOR_xxCflag native alias clear", {eor_xxcflag_word(0, 0), ret},
        bit29, 0);
    check_result2("EOR_xxCflag native distinct", {eor_xxcflag_word(0, 1), ret},
        0, 0x123456789abcdef0ull, 0x12345678babcdef0ull);
    check_result1("EOR_xxCflag preserves other bits", {eor_xxcflag_word(0, 0), ret},
        ~std::uint64_t{0}, ~bit29);

    check_result1("EOR_xxbit native bit zero", {eor_xxbit_word(0, 0, 0), ret},
        0x10, 0x11);
    check_result1("EOR_xxbit native bit 29", {eor_xxbit_word(0, 0, 29), ret},
        0x123456789abcdef0ull, 0x12345678babcdef0ull);
    check_result1("EOR_xxbit native bit 63 set", {eor_xxbit_word(0, 0, 63), ret},
        0x123456789abcdef0ull, 0x923456789abcdef0ull);
    check_result1("EOR_xxbit native bit 63 clear", {eor_xxbit_word(0, 0, 63), ret},
        bit63, 0);
    check_result2("EOR_xxbit native distinct", {eor_xxbit_word(0, 1, 5), ret},
        ~std::uint64_t{0}, 0x100, 0x120);

    check_flags("EOR_www preserves NZCV", eor_www_word(3, 0, 1), 0xffffffffu, 0);
    check_flags("EOR_wwwLSLi preserves NZCV", eor_wwwlsli_word(3, 0, 1, 31), 0, 1);
    check_flags("EOR_xxCflag preserves NZCV", eor_xxcflag_word(3, 0), bit29, 0);
    check_flags("EOR_xxbit preserves NZCV", eor_xxbit_word(3, 0, 63), bit63, 0);

    std::printf("METRIC emitter_eor_apis=5\n");
    std::printf("METRIC emitter_eor_exact_words=%u\n", exact_words);
    std::printf("METRIC emitter_eor_base_constants=%u\n", constant_checks);
    std::printf("METRIC emitter_eor_native_result_vectors=%u\n", result_vectors);
    std::printf("METRIC emitter_eor_native_flag_vectors=%u\n", flag_vectors);
    std::printf("METRIC emitter_eor_native_vectors=%u\n", result_vectors + flag_vectors);
    std::printf("METRIC emitter_eor_width32=1\n");
    std::printf("METRIC emitter_eor_width64=1\n");
    std::printf("METRIC emitter_eor_shift_mask=1\n");
    std::printf("METRIC emitter_eor_alias_dn=1\n");
    std::printf("METRIC emitter_eor_alias_dm=1\n");
    std::printf("METRIC emitter_eor_alias_all=1\n");
    return exact_words == 13 && constant_checks == 1 && result_vectors == 18 && flag_vectors == 4 ? 0 : 1;
}
