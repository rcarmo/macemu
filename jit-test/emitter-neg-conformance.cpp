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
    std::fprintf(stderr, "NEG_EMITTER_FAIL label=%s expected=%016llx found=%016llx\n",
        label, static_cast<unsigned long long>(expected),
        static_cast<unsigned long long>(found));
    std::exit(1);
}

static uae_u32 neg_ww_word(unsigned d, unsigned m)
{
    emitted.clear();
    NEG_ww(d, m);
    if (emitted.size() != 1)
        fail("NEG_ww emission count", 1, emitted.size());
    return emitted.front();
}

static std::uint64_t run(const std::vector<uae_u32> &words, std::uint64_t input)
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
    using Fn = std::uint64_t (*)(std::uint64_t);
    const auto result = reinterpret_cast<Fn>(page)(input);
    if (munmap(page, static_cast<std::size_t>(page_size)) != 0) {
        std::perror("munmap");
        std::exit(1);
    }
    return result;
}

int main()
{
#if !defined(__aarch64__)
    std::fprintf(stderr, "NEG_EMITTER_FAIL native AArch64 host required\n");
    return 1;
#endif
    constexpr uae_u32 mov_w9_w0 = 0x2a0003e9u;
    constexpr uae_u32 mov_w0_w10 = 0x2a0a03e0u;
    constexpr uae_u32 ret = 0xd65f03c0u;
    const uae_u32 neg = neg_ww_word(10, 9);
    if (neg != 0x4b0903eau)
        fail("NEG_ww exact word", 0x4b0903eau, neg);

    unsigned vectors = 0;
    for (const std::uint64_t input : {
        0ull, 1ull, 0x7fffffffull, 0x80000000ull, 0xffffffffull,
        0x12345678ull, 0xfeedface00000001ull,
    }) {
        const std::uint64_t expected = static_cast<std::uint32_t>(
            0u - static_cast<std::uint32_t>(input));
        const std::uint64_t found = run({mov_w9_w0, neg, mov_w0_w10, ret}, input);
        if (found != expected)
            fail("NEG_ww native result", expected, found);
        ++vectors;
    }

    std::printf("METRIC emitter_neg_exact_words=1\n");
    std::printf("METRIC emitter_neg_native_vectors=%u\n", vectors);
    std::printf("METRIC emitter_neg_width32=1\n");
    return vectors == 7 ? 0 : 1;
}
