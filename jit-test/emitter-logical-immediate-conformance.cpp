#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <sys/mman.h>
#include <unistd.h>
#include <vector>

using uae_u32 = std::uint32_t;
static std::vector<uae_u32> emitted;
static void emit_long(uae_u32 word) { emitted.push_back(word); }
#include "../BasiliskII/src/uae_cpu_2026/compiler/codegen_arm64.h"

static void fail(const char* label, std::uint64_t expected, std::uint64_t found)
{
    std::fprintf(stderr, "LOGIMM_EMITTER_FAIL %s expected=%016llx found=%016llx\n",
        label, static_cast<unsigned long long>(expected),
        static_cast<unsigned long long>(found));
    std::exit(1);
}

static uae_u32 one_word(const char* label)
{
    if (emitted.size() != 1) fail(label, 1, emitted.size());
    const auto word = emitted.front();
    emitted.clear();
    return word;
}

static uae_u32 clear_bit(unsigned d, unsigned n, unsigned bit)
{
    emitted.clear(); CLEAR_xxbit(d, n, bit); return one_word("CLEAR_xxbit count");
}
static uae_u32 set_bit(unsigned d, unsigned n, unsigned bit)
{
    emitted.clear(); SET_xxbit(d, n, bit); return one_word("SET_xxbit count");
}

enum class Fixed { ClearZ, ClearC, ClearV, SetZ, SetV };
static uae_u32 fixed_word(Fixed api, unsigned d, unsigned n)
{
    emitted.clear();
    switch (api) {
    case Fixed::ClearZ: CLEAR_xxZflag(d, n); break;
    case Fixed::ClearC: CLEAR_xxCflag(d, n); break;
    case Fixed::ClearV: CLEAR_xxVflag(d, n); break;
    case Fixed::SetZ: SET_xxZflag(d, n); break;
    case Fixed::SetV: SET_xxVflag(d, n); break;
    }
    return one_word("fixed flag count");
}

static void* executable_page(const std::vector<uae_u32>& words, long& page_size)
{
    page_size = sysconf(_SC_PAGESIZE);
    if (page_size <= 0 || words.size() * sizeof(uae_u32) > static_cast<std::size_t>(page_size))
        fail("page size", 1, 0);
    void* page = mmap(nullptr, static_cast<std::size_t>(page_size), PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (page == MAP_FAILED) { std::perror("mmap"); std::exit(1); }
    std::memcpy(page, words.data(), words.size() * sizeof(uae_u32));
    if (mprotect(page, static_cast<std::size_t>(page_size), PROT_READ | PROT_EXEC)) {
        std::perror("mprotect"); std::exit(1);
    }
    __builtin___clear_cache(static_cast<char*>(page),
        static_cast<char*>(page) + words.size() * sizeof(uae_u32));
    return page;
}

static std::uint64_t run1(uae_u32 word, std::uint64_t value)
{
    constexpr uae_u32 ret = 0xd65f03c0u;
    long page_size = 0; void* page = executable_page({word, ret}, page_size);
    using Fn = std::uint64_t (*)(std::uint64_t);
    const auto result = reinterpret_cast<Fn>(page)(value);
    munmap(page, static_cast<std::size_t>(page_size)); return result;
}
static std::uint64_t run2(uae_u32 word, std::uint64_t destination, std::uint64_t source)
{
    constexpr uae_u32 ret = 0xd65f03c0u;
    long page_size = 0; void* page = executable_page({word, ret}, page_size);
    using Fn = std::uint64_t (*)(std::uint64_t, std::uint64_t);
    const auto result = reinterpret_cast<Fn>(page)(destination, source);
    munmap(page, static_cast<std::size_t>(page_size)); return result;
}
static std::uint64_t run_flags(uae_u32 word)
{
    constexpr uae_u32 msr_nzcv_x2 = 0xd51b4202u;
    constexpr uae_u32 mrs_x0_nzcv = 0xd53b4200u;
    constexpr uae_u32 ret = 0xd65f03c0u;
    long page_size = 0;
    void* page = executable_page({msr_nzcv_x2, word, mrs_x0_nzcv, ret}, page_size);
    using Fn = std::uint64_t (*)(std::uint64_t, std::uint64_t, std::uint64_t);
    const auto result = reinterpret_cast<Fn>(page)(0x0123456789abcdefull,
        0xfedcba9876543210ull, 0xa0000000u);
    munmap(page, static_cast<std::size_t>(page_size)); return result & 0xf0000000u;
}

int main()
{
#if !defined(__aarch64__)
    std::fprintf(stderr, "LOGIMM_EMITTER_FAIL native AArch64 host required\n");
    return 1;
#endif
    constexpr std::uint32_t and_base = 0x92000000u;
    constexpr std::uint32_t orr_base = 0xb2000000u;
    unsigned encode_checks = 0, base_checks = 0, exact_words = 0;
    unsigned exhaustive_native = 0, alias_vectors = 0, distinct_vectors = 0, flag_vectors = 0;

    for (unsigned n = 0; n < 2; ++n)
        for (unsigned r = 0; r < 64; ++r)
            for (unsigned s = 0; s < 64; ++s) {
                const auto expected = (n << 22) | (r << 16) | (s << 10);
                const auto found = static_cast<uae_u32>(immEncode(n, r, s));
                if (found != expected) fail("immEncode", expected, found);
                ++encode_checks;
            }
    if (static_cast<uae_u32>(immOP_AND) != and_base) fail("immOP_AND", and_base, immOP_AND);
    if (static_cast<uae_u32>(immOP_ORR) != orr_base) fail("immOP_ORR", orr_base, immOP_ORR);
    base_checks = 2;

    for (unsigned bit = 0; bit < 64; ++bit) {
        const auto clear_expected = and_base | (1u << 22) |
            (((63u - bit) & 63u) << 16) | (62u << 10) | (10u << 5) | 9u;
        const auto set_expected = orr_base | (1u << 22) |
            (((64u - bit) & 63u) << 16) | (10u << 5) | 9u;
        if (clear_bit(9, 10, bit) != clear_expected) fail("CLEAR_xxbit word", clear_expected, clear_bit(9, 10, bit));
        if (set_bit(9, 10, bit) != set_expected) fail("SET_xxbit word", set_expected, set_bit(9, 10, bit));
        exact_words += 2;

        const auto mask = std::uint64_t{1} << bit;
        for (const auto input : {std::uint64_t{0}, ~std::uint64_t{0}}) {
            const auto cleared = run1(clear_bit(0, 0, bit), input);
            const auto set = run1(set_bit(0, 0, bit), input);
            if (cleared != (input & ~mask)) fail("CLEAR_xxbit native", input & ~mask, cleared);
            if (set != (input | mask)) fail("SET_xxbit native", input | mask, set);
            exhaustive_native += 2; alias_vectors += 2;
        }
    }
    for (const unsigned bit : {0u, 7u, 29u, 31u, 63u}) {
        const auto mask = std::uint64_t{1} << bit;
        const auto source = 0xa5a55a5af00f0ff0ull;
        const auto cleared = run2(clear_bit(0, 1, bit), 0xdeadbeefull, source);
        const auto set = run2(set_bit(0, 1, bit), 0xdeadbeefull, source);
        if (cleared != (source & ~mask)) fail("CLEAR_xxbit distinct", source & ~mask, cleared);
        if (set != (source | mask)) fail("SET_xxbit distinct", source | mask, set);
        distinct_vectors += 2;
    }
    for (const unsigned bit : {0u, 63u}) {
        const auto clear_max = and_base | (1u << 22) | (((63u - bit) & 63u) << 16) |
            (62u << 10) | (31u << 5) | 31u;
        const auto set_max = orr_base | (1u << 22) | (((64u - bit) & 63u) << 16) |
            (31u << 5) | 31u;
        if (clear_bit(31, 31, bit) != clear_max) fail("CLEAR_xxbit max fields", clear_max, clear_bit(31, 31, bit));
        if (set_bit(31, 31, bit) != set_max) fail("SET_xxbit max fields", set_max, set_bit(31, 31, bit));
        exact_words += 2;
    }

    struct FixedCase { Fixed api; std::uint64_t mask; bool set; std::uint32_t anchor; };
    const FixedCase fixed[] = {
        {Fixed::ClearZ, 1ull << 30, false, 0x9261f949u},
        {Fixed::ClearC, 1ull << 29, false, 0x9262f949u},
        {Fixed::ClearV, 1ull << 28, false, 0x9263f949u},
        {Fixed::SetZ, 1ull << 30, true, 0xb2620149u},
        {Fixed::SetV, 1ull << 28, true, 0xb2640149u},
    };
    for (const auto& test : fixed) {
        if (fixed_word(test.api, 9, 10) != test.anchor) fail("fixed anchor", test.anchor, fixed_word(test.api, 9, 10));
        const auto high_expected = (test.anchor & ~0x3ffu) | (29u << 5) | 30u;
        const auto max_expected = (test.anchor & ~0x3ffu) | (31u << 5) | 31u;
        if (fixed_word(test.api, 30, 29) != high_expected) fail("fixed high fields", high_expected, fixed_word(test.api, 30, 29));
        if (fixed_word(test.api, 31, 31) != max_expected) fail("fixed max fields", max_expected, fixed_word(test.api, 31, 31));
        exact_words += 3;
        for (const auto input : {std::uint64_t{0}, ~std::uint64_t{0}}) {
            const auto expected = test.set ? (input | test.mask) : (input & ~test.mask);
            const auto found = run1(fixed_word(test.api, 0, 0), input);
            if (found != expected) fail("fixed alias", expected, found);
            ++alias_vectors;
        }
        const auto source = 0x0123456789abcdefull;
        const auto expected = test.set ? (source | test.mask) : (source & ~test.mask);
        const auto found = run2(fixed_word(test.api, 0, 1), 0, source);
        if (found != expected) fail("fixed distinct", expected, found);
        ++distinct_vectors;
        if (run_flags(fixed_word(test.api, 3, 0)) != 0xa0000000u)
            fail("fixed preserves NZCV", 0xa0000000u, run_flags(fixed_word(test.api, 3, 0)));
        ++flag_vectors;
    }
    if (run_flags(clear_bit(3, 0, 63)) != 0xa0000000u) fail("clear bit preserves NZCV", 0xa0000000u, run_flags(clear_bit(3, 0, 63)));
    if (run_flags(set_bit(3, 0, 63)) != 0xa0000000u) fail("set bit preserves NZCV", 0xa0000000u, run_flags(set_bit(3, 0, 63)));
    flag_vectors += 2;

    std::printf("METRIC emitter_logimm_apis=10\n");
    std::printf("METRIC emitter_logimm_encode_checks=%u\n", encode_checks);
    std::printf("METRIC emitter_logimm_base_constants=%u\n", base_checks);
    std::printf("METRIC emitter_logimm_exact_words=%u\n", exact_words);
    std::printf("METRIC emitter_logimm_exhaustive_native=%u\n", exhaustive_native);
    std::printf("METRIC emitter_logimm_alias_vectors=%u\n", alias_vectors);
    std::printf("METRIC emitter_logimm_distinct_vectors=%u\n", distinct_vectors);
    const auto native_vectors = alias_vectors + distinct_vectors + flag_vectors;
    std::printf("METRIC emitter_logimm_flag_vectors=%u\n", flag_vectors);
    std::printf("METRIC emitter_logimm_native_vectors=%u\n", native_vectors);
    return encode_checks == 8192 && base_checks == 2 && exact_words == 147 &&
        exhaustive_native == 256 && alias_vectors == 266 && distinct_vectors == 15 &&
        flag_vectors == 7 && native_vectors == 288 ? 0 : 1;
}
