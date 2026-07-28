#include <array>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <sys/mman.h>
#include <unistd.h>

using uae_u8 = std::uint8_t;
using uae_s8 = std::int8_t;
using uae_u16 = std::uint16_t;
using uae_s16 = std::int16_t;
using uae_u32 = std::uint32_t;
using uae_s32 = std::int32_t;
using uae_u64 = std::uint64_t;
using uintptr = std::uintptr_t;
using IM32 = uae_s32;

struct SyntheticRegs {
    std::array<uae_u8, 32> prefix{};
    uae_u32 spcflags = 0;
    std::array<uae_u8, 32> suffix{};
};
static SyntheticRegs regs;
static uae_s32 countdown;

static std::array<uae_u32, 256> emitted{};
static std::size_t emitted_words = 0;
static void emit_long(uae_u32 word)
{
    if (emitted_words >= emitted.size()) {
        std::fprintf(stderr, "RAW_MAYBE_DO_NOTHING_FAIL emitted buffer overflow\n");
        std::exit(1);
    }
    emitted[emitted_words++] = word;
}
static uae_u8 *get_target()
{
    return reinterpret_cast<uae_u8 *>(emitted.data() + emitted_words);
}

#include "codegen_arm64.h"
#include "arm64_branch_patch.h"

#define REG_WORK1 2
#define REG_WORK2 3
#define REG_WORK3 4
#define REG_WORK4 5
#define R18_INDEX 18
#define R_REGSTRUCT 28
#define STATIC_INLINE static inline

[[maybe_unused]] static bool jit_test_dispatch_summary_enabled()
{
    return false;
}
[[maybe_unused]] static unsigned long jit_test_maybe_do_nothing_checks;
[[maybe_unused]] static unsigned long jit_test_maybe_do_nothing_taken;
[[maybe_unused]] static unsigned long jit_test_maybe_do_nothing_cycles;
[[maybe_unused]] static unsigned long jit_test_maybe_do_nothing_before;
[[maybe_unused]] static unsigned long jit_test_maybe_do_nothing_after;
static void *popall_do_nothing;

static inline void write_jmp_target(uae_u32 *address, uintptr target)
{
    const auto base = reinterpret_cast<uintptr>(address);
    const std::int64_t byte_offset = target >= base
        ? static_cast<std::int64_t>(target - base)
        : -static_cast<std::int64_t>(base - target);
    uae_u32 patched = 0;
    if (arm64_patch_branch_instruction(*address, byte_offset, &patched) !=
        ARM64_BRANCH_PATCH_OK) {
        std::fprintf(stderr,
            "RAW_MAYBE_DO_NOTHING_FAIL branch patch word=%08x offset=%lld\n",
            *address, static_cast<long long>(byte_offset));
        std::exit(1);
    }
    *address = patched;
}

#include "raw-maybe-do-nothing.inc"

struct Output {
    std::uint64_t terminal;
    std::uint64_t countdown;
};

[[noreturn]] static void fail(const char *label, std::uint64_t expected,
    std::uint64_t found)
{
    std::fprintf(stderr,
        "RAW_MAYBE_DO_NOTHING_FAIL label=%s expected=%016llx found=%016llx\n",
        label, static_cast<unsigned long long>(expected),
        static_cast<unsigned long long>(found));
    std::exit(1);
}

static void emit_result(unsigned terminal)
{
    MOV_wi(5, terminal);
    STR_xXi(5, 0, 0);
    LOAD_U64(6, reinterpret_cast<uintptr>(&countdown));
    LDR_wXi(7, 6, 0);
    STR_xXi(7, 0, 8);
    LDP_xxXpost(28, 30, 31, 16);
    emit_long(0xd65f03c0u); // RET
}

struct Shape {
    std::size_t words;
    bool has_imm_sub;
    bool has_reg_sub;
};

static Output execute(uae_u32 spcflags, uae_s32 cycles, uae_u32 seed,
    Shape *shape)
{
    emitted.fill(0xd503201fu); // NOP padding
    emitted_words = 0;
    regs.spcflags = spcflags;
    countdown = static_cast<uae_s32>(seed);

    STP_xxXpre(28, 30, 31, -16);
    LOAD_U64(R_REGSTRUCT, reinterpret_cast<uintptr>(&regs));
    const std::size_t body_start = emitted_words;
    constexpr std::size_t terminal_index = 128;
    popall_do_nothing = emitted.data() + terminal_index;
    compemu_raw_maybe_do_nothing(cycles);
    const std::size_t body_end = emitted_words;
    emit_result(0);
    if (emitted_words >= terminal_index)
        fail("body overlaps terminal", terminal_index - 1, emitted_words);
    emitted_words = terminal_index;
    emit_result(1);

    bool has_imm_sub = false;
    bool has_reg_sub = false;
    for (std::size_t i = body_start; i < body_end; ++i) {
        const uae_u32 word = emitted[i];
        if ((word & 0x7f000000u) == 0x51000000u)
            has_imm_sub = true;
        if ((word & 0x7fe0fc00u) == 0x4b000000u)
            has_reg_sub = true;
    }
    if (shape)
        *shape = {body_end - body_start, has_imm_sub, has_reg_sub};

    const long page_size = sysconf(_SC_PAGESIZE);
    if (page_size <= 0 || emitted_words * sizeof(uae_u32) >
        static_cast<std::size_t>(page_size))
        fail("executable page size", 1, emitted_words * sizeof(uae_u32));
    void *page = mmap(nullptr, static_cast<std::size_t>(page_size),
        PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (page == MAP_FAILED) { std::perror("mmap code"); std::exit(1); }
    std::memcpy(page, emitted.data(), emitted_words * sizeof(uae_u32));
    if (mprotect(page, static_cast<std::size_t>(page_size),
            PROT_READ | PROT_EXEC) != 0) {
        std::perror("mprotect code"); std::exit(1);
    }
    __builtin___clear_cache(static_cast<char *>(page),
        static_cast<char *>(page) + emitted_words * sizeof(uae_u32));
    Output output{};
    using Fn = void (*)(Output *);
    reinterpret_cast<Fn>(page)(&output);
    if (munmap(page, static_cast<std::size_t>(page_size)) != 0) {
        std::perror("munmap code"); std::exit(1);
    }
    return output;
}

int main()
{
#if !defined(__aarch64__)
    std::fprintf(stderr,
        "RAW_MAYBE_DO_NOTHING_FAIL native AArch64 host required\n");
    return 1;
#endif
    constexpr uae_u32 seed = 0x12345678u;
    unsigned native_vectors = 0;
    Shape imm_shape{}, reg_shape{};
    for (const auto cycles : {0xfff, 0x1000}) {
        for (const auto spcflags : {0u, 0x80000001u}) {
            Shape shape{};
            const auto output = execute(spcflags, cycles, seed, &shape);
            const auto expected_terminal = spcflags ? 1ull : 0ull;
            const auto expected_countdown = spcflags
                ? static_cast<uae_u32>(seed - static_cast<uae_u32>(cycles))
                : seed;
            if (output.terminal != expected_terminal)
                fail("native terminal outcome", expected_terminal,
                    output.terminal);
            if (output.countdown != expected_countdown)
                fail("native countdown", expected_countdown,
                    output.countdown);
            if (cycles == 0xfff)
                imm_shape = shape;
            else
                reg_shape = shape;
            ++native_vectors;
        }
    }
    if (!imm_shape.has_imm_sub || imm_shape.has_reg_sub)
        fail("imm12 subtraction shape", 1,
            imm_shape.has_imm_sub && !imm_shape.has_reg_sub);
    if (reg_shape.has_imm_sub || !reg_shape.has_reg_sub)
        fail("register subtraction shape", 1,
            !reg_shape.has_imm_sub && reg_shape.has_reg_sub);
    if (reg_shape.words != imm_shape.words + 1)
        fail("register body one-word expansion", imm_shape.words + 1,
            reg_shape.words);

    std::printf("METRIC raw_maybe_do_nothing_boundaries=1\n");
    std::printf("METRIC raw_maybe_do_nothing_native_vectors=%u\n",
        native_vectors);
    std::printf("METRIC raw_maybe_do_nothing_fallthrough=2\n");
    std::printf("METRIC raw_maybe_do_nothing_taken=2\n");
    std::printf("METRIC raw_maybe_do_nothing_imm12=1\n");
    std::printf("METRIC raw_maybe_do_nothing_register=1\n");
    std::printf("METRIC raw_maybe_do_nothing_once_only=1\n");
    return native_vectors == 4 ? 0 : 1;
}
