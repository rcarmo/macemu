#include <algorithm>
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

static void fail(const char *label, std::uint64_t expected, std::uint64_t found)
{
    std::fprintf(stderr, "WORD_EMITTER_FAIL label=%s expected=%016llx found=%016llx\n",
        label, static_cast<unsigned long long>(expected),
        static_cast<unsigned long long>(found));
    std::exit(1);
}

static unsigned side_effect_calls;
static std::uint64_t side_effect_value()
{
    ++side_effect_calls;
    return 0x1d65f03c0ull;
}

static std::uint64_t run(const std::vector<uae_u32> &words, std::uint64_t input)
{
    const long page_size = sysconf(_SC_PAGESIZE);
    if (page_size <= 0 || words.size() * sizeof(uae_u32) > static_cast<std::size_t>(page_size))
        fail("executable page size", 1, 0);
    void *page = mmap(nullptr, static_cast<std::size_t>(page_size), PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (page == MAP_FAILED) { std::perror("mmap"); std::exit(1); }
    std::memcpy(page, words.data(), words.size() * sizeof(uae_u32));
    if (mprotect(page, static_cast<std::size_t>(page_size), PROT_READ | PROT_EXEC) != 0) {
        std::perror("mprotect"); std::exit(1);
    }
    __builtin___clear_cache(static_cast<char *>(page),
        static_cast<char *>(page) + words.size() * sizeof(uae_u32));
    using Fn = std::uint64_t (*)(std::uint64_t);
    const std::uint64_t result = reinterpret_cast<Fn>(page)(input);
    if (munmap(page, static_cast<std::size_t>(page_size)) != 0) {
        std::perror("munmap"); std::exit(1);
    }
    return result;
}

int main()
{
#if !defined(__aarch64__)
    std::fprintf(stderr, "WORD_EMITTER_FAIL native AArch64 host required\n");
    return 1;
#endif
    unsigned direct_vectors = 0;
    unsigned representative_words = 0;
    unsigned native_vectors = 0;

    emitted.clear();
    _W(0x11223344u);
    if (emitted != std::vector<uae_u32>{0x11223344u}) fail("direct u32", 0x11223344u, emitted.at(0));
    ++direct_vectors;

    emitted.clear();
    _W(0x1122334455667788ull);
    if (emitted != std::vector<uae_u32>{0x55667788u}) fail("unsigned truncation", 0x55667788u, emitted.at(0));
    ++direct_vectors;

    emitted.clear();
    _W(static_cast<std::int64_t>(-1));
    if (emitted != std::vector<uae_u32>{0xffffffffu}) fail("signed truncation", 0xffffffffu, emitted.at(0));
    ++direct_vectors;

    emitted.clear(); side_effect_calls = 0;
    _W(side_effect_value());
    if (side_effect_calls != 1 || emitted != std::vector<uae_u32>{0xd65f03c0u})
        fail("single evaluation", 1, side_effect_calls);
    ++direct_vectors;

    emitted.clear();
    _W(0xaa0003e0u); _W(0x11000400u); _W(0xd65f03c0u);
    if (emitted != std::vector<uae_u32>{0xaa0003e0u, 0x11000400u, 0xd65f03c0u})
        fail("sequence order/cardinality", 3, emitted.size());
    ++direct_vectors;

    emitted.clear();
    B_i(1); ADD_wwi(0, 0, 1); EOR_www(0, 0, 1); LDR_wXi(2, 3, 16);
    FMOV_dd(4, 5); RET;
    const std::vector<uae_u32> expected{
        0x14000001u, 0x11000400u, 0x4a010000u, 0xb9401062u, 0x1e6040a4u, 0xd65f03c0u,
    };
    if (emitted != expected) {
        const std::size_t at = emitted.size() == expected.size() ?
            static_cast<std::size_t>(std::mismatch(emitted.begin(), emitted.end(), expected.begin()).first - emitted.begin()) : 0;
        fail("representative encoder sequence", expected.size(), emitted.size() == expected.size() ? emitted.at(at) : emitted.size());
    }
    representative_words = static_cast<unsigned>(expected.size());

    const std::uint64_t found = run({0xaa0003e0u, 0x11000400u, 0xd65f03c0u}, 0x12345678ffffffffull);
    if (found != 0) fail("native mixed raw-word sequence", 0, found);
    ++native_vectors;

    std::printf("METRIC emitter_word_direct_vectors=%u\n", direct_vectors);
    std::printf("METRIC emitter_word_representative_words=%u\n", representative_words);
    std::printf("METRIC emitter_word_native_vectors=%u\n", native_vectors);
    std::printf("METRIC emitter_word_single_evaluation=1\n");
    std::printf("METRIC emitter_word_truncation32=1\n");
    return direct_vectors == 5 && representative_words == 6 && native_vectors == 1 ? 0 : 1;
}
