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
    std::fprintf(stderr, "MOV_L_RR_FAIL label=%s expected=%016llx found=%016llx\n",
        label, static_cast<unsigned long long>(expected),
        static_cast<unsigned long long>(found));
    std::exit(1);
}

static uae_u32 mov_xx_word(unsigned d, unsigned s)
{
    emitted.clear();
    MOV_xx(d, s);
    if (emitted.size() != 1) fail("MOV_xx emission count", 1, emitted.size());
    return emitted.front();
}

static std::uint64_t run(const std::vector<uae_u32> &words, std::uint64_t input)
{
    const long page_size = sysconf(_SC_PAGESIZE);
    if (page_size <= 0 || words.size() * sizeof(uae_u32) > static_cast<std::size_t>(page_size))
        fail("executable page size", 1, 0);
    void *page = mmap(nullptr, static_cast<std::size_t>(page_size),
        PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (page == MAP_FAILED) { std::perror("mmap"); std::exit(1); }
    std::memcpy(page, words.data(), words.size() * sizeof(uae_u32));
    if (mprotect(page, static_cast<std::size_t>(page_size), PROT_READ | PROT_EXEC) != 0) {
        std::perror("mprotect"); std::exit(1);
    }
    __builtin___clear_cache(static_cast<char *>(page),
        static_cast<char *>(page) + words.size() * sizeof(uae_u32));
    using Fn = std::uint64_t (*)(std::uint64_t);
    const auto result = reinterpret_cast<Fn>(page)(input);
    if (munmap(page, static_cast<std::size_t>(page_size)) != 0) {
        std::perror("munmap"); std::exit(1);
    }
    return result;
}

int main()
{
#if !defined(__aarch64__)
    std::fprintf(stderr, "MOV_L_RR_FAIL native AArch64 host required\n");
    return 1;
#endif
    struct Encoding { unsigned d; unsigned s; uae_u32 word; };
    const Encoding encodings[] = {
        {0, 0, 0xaa0003e0u}, {9, 0, 0xaa0003e9u},
        {0, 9, 0xaa0903e0u}, {28, 27, 0xaa1b03fcu},
    };
    unsigned exact_words = 0;
    for (const auto &item : encodings) {
        const auto found = mov_xx_word(item.d, item.s);
        if (found != item.word) fail("MOV_xx exact word", item.word, found);
        ++exact_words;
    }

    constexpr uae_u32 mov_x9_x0 = 0xaa0003e9u;
    constexpr uae_u32 mov_x0_x9 = 0xaa0903e0u;
    constexpr uae_u32 mov_x0_x0 = 0xaa0003e0u;
    constexpr uae_u32 ret = 0xd65f03c0u;
    unsigned native_vectors = 0;
    for (const std::uint64_t input : {
        0ull, 1ull, 0xffffffffull, 0x80000001ull,
        0x123456789abcdef0ull, 0xffffffffffffffffull,
    }) {
        const auto found = run({mov_x9_x0, mov_x0_x9, ret}, input);
        if (found != input) fail("distinct full-width copy", input, found);
        ++native_vectors;
    }
    const std::uint64_t aliasInput = 0xfedcba9876543210ull;
    const auto aliasFound = run({mov_x0_x0, ret}, aliasInput);
    if (aliasFound != aliasInput) fail("self alias", aliasInput, aliasFound);
    ++native_vectors;

    std::printf("METRIC mov_l_rr_exact_words=%u\n", exact_words);
    std::printf("METRIC mov_l_rr_native_vectors=%u\n", native_vectors);
    std::printf("METRIC mov_l_rr_full_width64=1\n");
    std::printf("METRIC mov_l_rr_self_alias=1\n");
    return exact_words == 4 && native_vectors == 7 ? 0 : 1;
}
