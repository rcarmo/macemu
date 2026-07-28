#include <array>
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
using IMPTR = uintptr;

struct alignas(16) SyntheticRegs { std::array<uae_u8, 64> bytes{}; };
static SyntheticRegs regs;
static uintptr NATMEM_OFFSET;

static std::vector<uae_u32> emitted;
static void emit_long(uae_u32 word) { emitted.push_back(word); }
#include "codegen_arm64.h"

#define R_MEMSTART 27
#define R_REGSTRUCT 28
#define STATIC_INLINE static inline
#define LOWFUNC(flags,mem,nargs,func,args) static inline void func args
#define LENDFUNC(flags,mem,nargs,func,args)

#include "raw-init-regstruct.inc"

struct Output {
    std::uint64_t memstart;
    std::uint64_t regstruct;
    std::uint64_t nzcv;
};

[[noreturn]] static void fail(const char *label, std::uint64_t expected,
    std::uint64_t found)
{
    std::fprintf(stderr,
        "RAW_INIT_REGSTRUCT_FAIL label=%s expected=%016llx found=%016llx\n",
        label, static_cast<unsigned long long>(expected),
        static_cast<unsigned long long>(found));
    std::exit(1);
}

static Output execute(std::uint64_t hostile_nzcv)
{
    emitted.clear();
    STP_xxXpre(27, 28, 31, -16);
    MSR_NZCV_x(1);
    compemu_raw_init_r_regstruct(reinterpret_cast<uintptr>(&regs));
    MRS_NZCV_x(2);
    STR_xXi(27, 0, 0);
    STR_xXi(28, 0, 8);
    STR_xXi(2, 0, 16);
    LDP_xxXpost(27, 28, 31, 16);
    emitted.push_back(0xd65f03c0u); // RET

    const long page_size = sysconf(_SC_PAGESIZE);
    if (page_size <= 0 || emitted.size() * sizeof(uae_u32) >
        static_cast<std::size_t>(page_size))
        fail("executable page size", 1, emitted.size() * sizeof(uae_u32));
    void *page = mmap(nullptr, static_cast<std::size_t>(page_size),
        PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (page == MAP_FAILED) { std::perror("mmap code"); std::exit(1); }
    std::memcpy(page, emitted.data(), emitted.size() * sizeof(uae_u32));
    if (mprotect(page, static_cast<std::size_t>(page_size),
            PROT_READ | PROT_EXEC) != 0) {
        std::perror("mprotect code"); std::exit(1);
    }
    __builtin___clear_cache(static_cast<char *>(page),
        static_cast<char *>(page) + emitted.size() * sizeof(uae_u32));
    Output output{};
    using Fn = void (*)(Output *, std::uint64_t);
    reinterpret_cast<Fn>(page)(&output, hostile_nzcv);
    if (munmap(page, static_cast<std::size_t>(page_size)) != 0) {
        std::perror("munmap code"); std::exit(1);
    }
    return output;
}

int main()
{
#if !defined(__aarch64__)
    std::fprintf(stderr, "RAW_INIT_REGSTRUCT_FAIL native AArch64 host required\n");
    return 1;
#endif
    emitted.clear();
    compemu_raw_init_r_regstruct(reinterpret_cast<uintptr>(&regs));
    if (emitted.size() != 7)
        fail("production body exact word count", 7, emitted.size());
    const uae_u32 expected_terminal = 0xf9400000u | (27u << 5) | 27u;
    if (emitted.back() != expected_terminal)
        fail("terminal LDR X27,[X27]", expected_terminal, emitted.back());
    const unsigned exact_words = static_cast<unsigned>(emitted.size());

    constexpr std::array<std::uint64_t, 5> values{{
        0x0000000000000000ull,
        0x000000007fffffffull,
        0x0000000100000000ull,
        0x123456789abcdef0ull,
        0xffff000080000000ull,
    }};
    unsigned native_vectors = 0;
    unsigned index = 0;
    for (const auto value : values) {
        NATMEM_OFFSET = static_cast<uintptr>(value);
        const std::uint64_t hostile = (index++ & 1) ? 0xb0000000ull : 0x50000000ull;
        const auto output = execute(hostile);
        if (output.regstruct != reinterpret_cast<uintptr>(&regs))
            fail("native R_REGSTRUCT", reinterpret_cast<uintptr>(&regs),
                output.regstruct);
        if (output.memstart != value)
            fail("native R_MEMSTART", value, output.memstart);
        if ((output.nzcv & 0xf0000000ull) != hostile)
            fail("native NZCV", hostile, output.nzcv & 0xf0000000ull);
        ++native_vectors;
    }

    std::printf("METRIC raw_init_regstruct_boundaries=1\n");
    std::printf("METRIC raw_init_regstruct_body_words=%u\n", exact_words);
    std::printf("METRIC raw_init_regstruct_native_vectors=%u\n", native_vectors);
    std::printf("METRIC raw_init_regstruct_pointer_width=64\n");
    std::printf("METRIC raw_init_regstruct_nzcv_preserved=1\n");
    return native_vectors == values.size() ? 0 : 1;
}
