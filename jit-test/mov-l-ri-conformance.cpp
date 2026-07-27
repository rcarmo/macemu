#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <sys/mman.h>
#include <unistd.h>
#include <vector>

using uae_u8 = std::uint8_t;
using uae_s8 = std::int8_t;
using uae_u16 = std::uint16_t;
using uae_s16 = std::int16_t;
using uae_u32 = std::uint32_t;
using uae_s32 = std::int32_t;
using uae_u64 = std::uint64_t;
using uintptr = std::uintptr_t;

static std::vector<uae_u32> emitted;
static void emit_long(uae_u32 word) { emitted.push_back(word); }
#include "../BasiliskII/src/uae_cpu_2026/compiler/codegen_arm64.h"

static void materialise_u32(int reg, uae_u32 value)
{
    if ((value & 0xffff0000u) == 0xffff0000u) {
        MOVN_wi(reg, ~value);
    } else {
        MOV_wi(reg, value);
        if (value >> 16)
            MOVK_wish(reg, value >> 16, 16);
    }
}

static void materialise_u64(int reg, uae_u64 value)
{
    MOV_xi(reg, value);
    if ((value >> 16) & 0xffff)
        MOVK_xish(reg, value >> 16, 16);
    if ((value >> 32) & 0xffff)
        MOVK_xish(reg, value >> 32, 32);
    if (value >> 48)
        MOVK_xish(reg, value >> 48, 48);
}

static void fail(const char *label, std::uint64_t expected, std::uint64_t found)
{
    std::fprintf(stderr, "MOV_L_RI_FAIL label=%s expected=%016llx found=%016llx\n",
        label, static_cast<unsigned long long>(expected),
        static_cast<unsigned long long>(found));
    std::exit(1);
}

static std::uint64_t run(const std::vector<uae_u32> &words)
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
    using Fn = std::uint64_t (*)();
    const auto result = reinterpret_cast<Fn>(page)();
    if (munmap(page, static_cast<std::size_t>(page_size)) != 0) {
        std::perror("munmap");
        std::exit(1);
    }
    return result;
}

int main()
{
#if !defined(__aarch64__)
    std::fprintf(stderr, "MOV_L_RI_FAIL native AArch64 host required\n");
    return 1;
#endif
    constexpr uae_u32 mov_w0_w9 = 0x2a0903e0u;
    constexpr uae_u32 ret = 0xd65f03c0u;
    struct Case { uae_u32 value; std::vector<uae_u32> words; };
    const std::vector<Case> cases = {
        {0x00000000u, {0x52800009u}},
        {0x00000001u, {0x52800029u}},
        {0x12345678u, {0x528acf09u, 0x72a24689u}},
        {0xffff1234u, {0x129db969u}},
        {0xffffffffu, {0x12800009u}},
        {0x80000001u, {0x52800029u, 0x72b00009u}},
    };

    unsigned exact_words = 0;
    unsigned native_vectors = 0;
    for (const auto &item : cases) {
        emitted.clear();
        materialise_u32(9, item.value);
        if (emitted != item.words)
            fail("exact word sequence", item.words.size(), emitted.size());
        exact_words += static_cast<unsigned>(item.words.size());
        auto executable = emitted;
        executable.push_back(mov_w0_w9);
        executable.push_back(ret);
        const auto found = run(executable);
        if (found != item.value)
            fail("native zero-extended value", item.value, found);
        ++native_vectors;
    }

    emitted.clear();
    materialise_u64(9, 0x123456789abcdef0ull);
    const std::vector<uae_u32> pointerWords = {
        0xd29bde09u, 0xf2b35789u, 0xf2cacf09u, 0xf2e24689u,
    };
    if (emitted != pointerWords)
        fail("pointer exact word sequence", pointerWords.size(), emitted.size());
    exact_words += static_cast<unsigned>(pointerWords.size());
    auto pointerExecutable = emitted;
    pointerExecutable.push_back(0xaa0903e0u); // MOV X0,X9
    pointerExecutable.push_back(ret);
    const auto pointerFound = run(pointerExecutable);
    if (pointerFound != 0x123456789abcdef0ull)
        fail("native pointer value", 0x123456789abcdef0ull, pointerFound);
    ++native_vectors;

    std::printf("METRIC mov_l_ri_exact_words=%u\n", exact_words);
    std::printf("METRIC mov_l_ri_native_vectors=%u\n", native_vectors);
    std::printf("METRIC mov_l_ri_guest_width32=1\n");
    std::printf("METRIC mov_l_ri_pc_p_width64=1\n");
    return exact_words == 12 && native_vectors == 7 ? 0 : 1;
}
