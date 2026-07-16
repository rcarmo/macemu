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
    std::fprintf(stderr, "ADD_EMITTER_FAIL label=%s expected=%016llx found=%016llx\n",
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

static uae_u32 add_wwi_word(unsigned d, unsigned n, unsigned immediate)
{
    emitted.clear();
    ADD_wwi(d, n, immediate);
    return one_word("ADD_wwi emission count");
}

static uae_u32 add_xxi_word(unsigned d, unsigned n, unsigned immediate)
{
    emitted.clear();
    ADD_xxi(d, n, immediate);
    return one_word("ADD_xxi emission count");
}

static uae_u32 add_www_ex_word(unsigned d, unsigned n, unsigned m, unsigned extend)
{
    emitted.clear();
    ADD_wwwEX(d, n, m, extend);
    return one_word("ADD_wwwEX emission count");
}

static uae_u32 add_xxw_ex_word(unsigned d, unsigned n, unsigned m, unsigned extend)
{
    emitted.clear();
    ADD_xxwEX(d, n, m, extend);
    return one_word("ADD_xxwEX emission count");
}

static uae_u32 add_www_word(unsigned d, unsigned n, unsigned m)
{
    emitted.clear();
    ADD_www(d, n, m);
    return one_word("ADD_www emission count");
}

static uae_u32 add_xxx_word(unsigned d, unsigned n, unsigned m)
{
    emitted.clear();
    ADD_xxx(d, n, m);
    return one_word("ADD_xxx emission count");
}

static uae_u32 add_www_lsl_word(unsigned d, unsigned n, unsigned m, unsigned shift)
{
    emitted.clear();
    ADD_wwwLSLi(d, n, m, shift);
    return one_word("ADD_wwwLSLi emission count");
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

static std::uint64_t extend32(std::uint64_t value, unsigned extend)
{
    const unsigned widths[] = {8, 16, 32, 64, 8, 16, 32, 64};
    const unsigned bits = widths[extend & 7];
    const std::uint64_t mask = bits == 64 ? ~std::uint64_t{0}
                                          : ((std::uint64_t{1} << bits) - 1);
    std::uint64_t result = value & mask;
    if ((extend & 4) != 0 && bits < 64 && (result & (std::uint64_t{1} << (bits - 1))) != 0)
        result |= ~mask;
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

static void check_result(const char *label, const std::vector<uae_u32> &words,
    std::uint64_t lhs, std::uint64_t rhs, std::uint64_t expected)
{
    const std::uint64_t found = run2(words, lhs, rhs);
    if (found != expected) fail(label, expected, found);
    ++result_vectors;
}

static void check_flags(const char *label, uae_u32 add_word,
    std::uint64_t lhs, std::uint64_t rhs)
{
    constexpr uae_u32 msr_nzcv_x2 = 0xd51b4202u;
    constexpr uae_u32 mrs_x0_nzcv = 0xd53b4200u;
    constexpr uae_u32 ret = 0xd65f03c0u;
    constexpr std::uint64_t initial_nzcv = 0xa0000000u;
    const std::uint64_t found = run3(
        {msr_nzcv_x2, add_word, mrs_x0_nzcv, ret}, lhs, rhs, initial_nzcv) & 0xf0000000u;
    if (found != initial_nzcv) fail(label, initial_nzcv, found);
    ++flag_vectors;
}

int main()
{
#if !defined(__aarch64__)
    std::fprintf(stderr, "ADD_EMITTER_FAIL native AArch64 host required\n");
    return 1;
#endif
    constexpr uae_u32 ret = 0xd65f03c0u;

    check_word("ADD_wwi imm0 exact word", 0x11000149u, add_wwi_word(9, 10, 0));
    check_word("ADD_wwi imm12-max exact word", 0x113ffd49u, add_wwi_word(9, 10, 0xfff));
    check_word("ADD_xxi imm0 exact word", 0x9100018bu, add_xxi_word(11, 12, 0));
    check_word("ADD_xxi imm12-max exact word", 0x913ffd8bu, add_xxi_word(11, 12, 0xfff));
    check_word("ADD_wwwEX UXTB exact word", 0x0b2f01cdu,
        add_www_ex_word(13, 14, 15, EX_UXTB));
    check_word("ADD_wwwEX SXTW exact word", 0x0b2fc1cdu,
        add_www_ex_word(13, 14, 15, EX_SXTW));
    check_word("ADD_xxwEX UXTW exact word", 0x8b324230u,
        add_xxw_ex_word(16, 17, 18, EX_UXTW));
    check_word("ADD_xxwEX SXTW exact word", 0x8b32c230u,
        add_xxw_ex_word(16, 17, 18, EX_SXTW));
    check_word("ADD_www exact word", 0x0b150293u, add_www_word(19, 20, 21));
    check_word("ADD_xxx exact word", 0x8b1802f6u, add_xxx_word(22, 23, 24));
    check_word("ADD_wwwLSLi shift0 exact word", 0x0b1b0359u,
        add_www_lsl_word(25, 26, 27, 0));
    check_word("ADD_wwwLSLi shift31 exact word", 0x0b1b7f59u,
        add_www_lsl_word(25, 26, 27, 31));

    for (const auto &v : std::initializer_list<std::uint64_t[3]>{
        {0, 0, 0}, {0xffffffffu, 1, 0}, {0x80000000u, 0xfff, 0x80000fffu},
        {0x100000001ull, 0xfff, 0x1000}, {0xfffffffeu, 0xfff, 0xffd},
    }) check_result("ADD_wwi native result", {add_wwi_word(0, 0, v[1]), ret}, v[0], 0, v[2]);

    for (const auto &v : std::initializer_list<std::uint64_t[3]>{
        {0, 0, 0}, {~std::uint64_t{0}, 1, 0},
        {0x100000000ull, 0xfff, 0x100000fffull},
        {0x8000000000000000ull, 0xfff, 0x8000000000000fffull},
        {0xfffffffffffffff0ull, 0xf, ~std::uint64_t{0}},
    }) check_result("ADD_xxi native result", {add_xxi_word(0, 0, v[1]), ret}, v[0], 0, v[2]);

    for (const auto &v : std::initializer_list<std::uint64_t[3]>{
        {0x100000001ull, 0x12345680ull, EX_UXTB},
        {1, 0x12348001ull, EX_UXTH}, {1, 0x80000001ull, EX_UXTW},
        {1, 0x12345680ull, EX_SXTB}, {1, 0x12348001ull, EX_SXTH},
        {1, 0x80000001ull, EX_SXTW}, {0xffffffffu, 1, EX_UXTB},
        {0xfeedface00000001ull, 0xffffffff000000ffull, EX_UXTB},
    }) {
        const std::uint64_t expected = static_cast<std::uint32_t>(
            static_cast<std::uint32_t>(v[0]) + static_cast<std::uint32_t>(extend32(v[1], v[2])));
        check_result("ADD_wwwEX native result", {add_www_ex_word(0, 0, 1, v[2]), ret},
            v[0], v[1], expected);
    }

    for (const auto &v : std::initializer_list<std::uint64_t[3]>{
        {0x100000000ull, 0x12345680ull, EX_UXTB},
        {0x100000000ull, 0x12348001ull, EX_UXTH},
        {0x100000000ull, 0x80000001ull, EX_UXTW},
        {0x100000000ull, 0x12345680ull, EX_SXTB},
        {0x100000000ull, 0x12348001ull, EX_SXTH},
        {0x100000000ull, 0x80000001ull, EX_SXTW},
        {~std::uint64_t{0}, 1, EX_UXTB},
        {0x7fffffffffffffffull, 0xffffffff000000ffull, EX_SXTB},
    }) {
        const std::uint64_t expected = v[0] + extend32(v[1], v[2]);
        check_result("ADD_xxwEX native result", {add_xxw_ex_word(0, 0, 1, v[2]), ret},
            v[0], v[1], expected);
    }

    for (const auto &v : std::initializer_list<std::uint64_t[3]>{
        {0, 0, 0}, {0xffffffffu, 1, 0},
        {0x100000001ull, 2, 3}, {0x80000000u, 0x80000000u, 0},
    }) check_result("ADD_www native result", {add_www_word(0, 0, 1), ret}, v[0], v[1], v[2]);

    for (const auto &v : std::initializer_list<std::uint64_t[3]>{
        {0, 0, 0}, {~std::uint64_t{0}, 1, 0},
        {0x100000000ull, 2, 0x100000002ull},
        {0x8000000000000000ull, 0x8000000000000000ull, 0},
    }) check_result("ADD_xxx native result", {add_xxx_word(0, 0, 1), ret}, v[0], v[1], v[2]);

    for (const auto &v : std::initializer_list<std::uint64_t[4]>{
        {7, 3, 0, 10}, {6, 3, 1, 12}, {1, 1, 16, 0x10001},
        {0, 1, 31, 0x80000000u}, {0xffffffffu, 3, 31, 0x7fffffffu},
    }) check_result("ADD_wwwLSLi native result", {add_www_lsl_word(0, 0, 1, v[2]), ret},
        v[0], v[1], v[3]);

    check_flags("ADD_wwi preserves NZCV", add_wwi_word(3, 0, 0xfff), 0xffffffffu, 1);
    check_flags("ADD_xxi preserves NZCV", add_xxi_word(3, 0, 0xfff), ~std::uint64_t{0}, 1);
    check_flags("ADD_wwwEX preserves NZCV", add_www_ex_word(3, 0, 1, EX_SXTH), 1, 0x8000);
    check_flags("ADD_xxwEX preserves NZCV", add_xxw_ex_word(3, 0, 1, EX_SXTW), 1, 0x80000000u);
    check_flags("ADD_www preserves NZCV", add_www_word(3, 0, 1), 0xffffffffu, 1);
    check_flags("ADD_xxx preserves NZCV", add_xxx_word(3, 0, 1), ~std::uint64_t{0}, 1);
    check_flags("ADD_wwwLSLi preserves NZCV", add_www_lsl_word(3, 0, 1, 31), 0, 1);

    std::printf("METRIC emitter_add_apis=7\n");
    std::printf("METRIC emitter_add_exact_words=%u\n", exact_words);
    std::printf("METRIC emitter_add_native_result_vectors=%u\n", result_vectors);
    std::printf("METRIC emitter_add_native_flag_vectors=%u\n", flag_vectors);
    std::printf("METRIC emitter_add_native_vectors=%u\n", result_vectors + flag_vectors);
    std::printf("METRIC emitter_add_width32=1\n");
    std::printf("METRIC emitter_add_width64=1\n");
    return exact_words == 12 && result_vectors == 39 && flag_vectors == 7 ? 0 : 1;
}
