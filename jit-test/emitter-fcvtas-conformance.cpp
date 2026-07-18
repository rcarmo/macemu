#include <array>
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

struct Result {
    std::uint64_t value;
    std::uint64_t source;
    std::uint64_t nzcv;
    std::uint64_t fpcr;
    std::uint64_t fpsr;
};
struct Vector {
    const char *name;
    std::uint64_t source;
    std::uint32_t expected;
    bool inexact;
    bool invalid;
};
struct CallerState {
    std::uint64_t d8_d15[8];
    std::uint64_t fpcr;
    std::uint64_t fpsr;
};
using NativeFn = void (*)(Result *, std::uint64_t);
extern "C" void fcvtas_invoke_checked(NativeFn, Result *, std::uint64_t,
    CallerState *);

#if defined(__aarch64__)
asm(R"(
.text
.align 2
.global fcvtas_invoke_checked
.type fcvtas_invoke_checked, %function
fcvtas_invoke_checked:
    sub sp, sp, #144
    stp x29, x30, [sp, #0]
    mov x29, sp
    stp x19, x20, [sp, #16]
    stp x21, x22, [sp, #32]
    str d8,  [sp, #48]
    str d9,  [sp, #56]
    str d10, [sp, #64]
    str d11, [sp, #72]
    str d12, [sp, #80]
    str d13, [sp, #88]
    str d14, [sp, #96]
    str d15, [sp, #104]
    mrs x9, fpcr
    mrs x10, fpsr
    str x9, [sp, #112]
    str x10, [sp, #120]
    mov x19, x0
    mov x20, x1
    mov x21, x2
    mov x22, x3
    ldr d8,  [x22, #0]
    ldr d9,  [x22, #8]
    ldr d10, [x22, #16]
    ldr d11, [x22, #24]
    ldr d12, [x22, #32]
    ldr d13, [x22, #40]
    ldr d14, [x22, #48]
    ldr d15, [x22, #56]
    ldr x9, [x22, #64]
    ldr x10, [x22, #72]
    msr fpcr, x9
    msr fpsr, x10
    mov x0, x20
    mov x1, x21
    blr x19
    str d8,  [x22, #0]
    str d9,  [x22, #8]
    str d10, [x22, #16]
    str d11, [x22, #24]
    str d12, [x22, #32]
    str d13, [x22, #40]
    str d14, [x22, #48]
    str d15, [x22, #56]
    mrs x9, fpcr
    mrs x10, fpsr
    str x9, [x22, #64]
    str x10, [x22, #72]
    ldr x9, [sp, #112]
    ldr x10, [sp, #120]
    msr fpcr, x9
    msr fpsr, x10
    ldr d8,  [sp, #48]
    ldr d9,  [sp, #56]
    ldr d10, [sp, #64]
    ldr d11, [sp, #72]
    ldr d12, [sp, #80]
    ldr d13, [sp, #88]
    ldr d14, [sp, #96]
    ldr d15, [sp, #104]
    ldp x21, x22, [sp, #32]
    ldp x19, x20, [sp, #16]
    ldp x29, x30, [sp, #0]
    add sp, sp, #144
    ret
.size fcvtas_invoke_checked, .-fcvtas_invoke_checked
)");
#endif

static void fail(const char *label, std::uint64_t expected, std::uint64_t found)
{
    std::fprintf(stderr, "FCVTAS_EMITTER_FAIL label=%s expected=%016llx found=%016llx\n",
        label, static_cast<unsigned long long>(expected),
        static_cast<unsigned long long>(found));
    std::exit(1);
}

static uae_u32 word(unsigned w, unsigned d)
{
    emitted.clear();
    FCVTAS_wd(w, d);
    if (emitted.size() != 1) fail("FCVTAS_wd emission count", 1, emitted.size());
    return emitted.front();
}

static Result run(unsigned w, unsigned d, std::uint64_t source, unsigned rmode)
{
    emitted.clear();
    SUB_xxi(31, 31, 80);
    for (unsigned reg = 8; reg <= 15; ++reg) STR_dXi(reg, 31, (reg - 8) * 8);
    STR_xXi(30, 31, 64);
    MRS_FPCR_x(14);
    MRS_FPSR_x(15);
    MOV_xx(16, 0);
    FMOV_dx(d, 1);
    MOV_wi(3, 0);
    MOVK_wish(3, static_cast<unsigned>(rmode << 6), 16);
    MSR_FPCR_x(3);
    MOV_wi(5, 0);
    MOVK_wish(5, 0xb000u, 16);
    MSR_NZCV_x(5);
    MOV_wi(4, 0x0080u);
    MOVK_wish(4, 0x0800u, 16);
    MSR_FPSR_x(4);
    FCVTAS_wd(w, d);
    MOV_xi(12, 0);
    if (w != 31) MOV_ww(12, w);
    FMOV_xd(13, d);
    MRS_NZCV_x(9);
    MRS_FPCR_x(10);
    MRS_FPSR_x(11);
    STR_xXi(12, 16, 0);
    STR_xXi(13, 16, 8);
    STR_xXi(9, 16, 16);
    STR_xXi(10, 16, 24);
    STR_xXi(11, 16, 32);
    MSR_FPSR_x(15);
    MSR_FPCR_x(14);
    LDR_xXi(30, 31, 64);
    for (unsigned reg = 8; reg <= 15; ++reg) LDR_dXi(reg, 31, (reg - 8) * 8);
    ADD_xxi(31, 31, 80);
    emitted.push_back(0xd65f03c0u);

    const long page_size = sysconf(_SC_PAGESIZE);
    if (page_size <= 0 || emitted.size() * sizeof(uae_u32) > static_cast<std::size_t>(page_size))
        fail("executable page size", 1, 0);
    void *page = mmap(nullptr, static_cast<std::size_t>(page_size), PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (page == MAP_FAILED) { std::perror("mmap"); std::exit(1); }
    std::memcpy(page, emitted.data(), emitted.size() * sizeof(uae_u32));
    if (mprotect(page, static_cast<std::size_t>(page_size), PROT_READ | PROT_EXEC) != 0) {
        std::perror("mprotect"); std::exit(1);
    }
    __builtin___clear_cache(static_cast<char *>(page),
        static_cast<char *>(page) + emitted.size() * sizeof(uae_u32));
    Result result{};
    CallerState caller_state{{
        0x0808080808080808ull, 0x0909090909090909ull,
        0x0a0a0a0a0a0a0a0aull, 0x0b0b0b0b0b0b0b0bull,
        0x0c0c0c0c0c0c0c0cull, 0x0d0d0d0d0d0d0d0dull,
        0x0e0e0e0e0e0e0e0eull, 0x0f0f0f0f0f0f0f0full,
    }, 0x00c00000ull, 0x0800009full};
    const CallerState expected_caller_state = caller_state;
    fcvtas_invoke_checked(reinterpret_cast<NativeFn>(page), &result, source,
        &caller_state);
    for (unsigned reg = 0; reg < 8; ++reg) {
        if (caller_state.d8_d15[reg] != expected_caller_state.d8_d15[reg])
            fail("FCVTAS preserves caller D8-D15", expected_caller_state.d8_d15[reg],
                caller_state.d8_d15[reg]);
    }
    if (caller_state.fpcr != expected_caller_state.fpcr)
        fail("FCVTAS restores caller FPCR", expected_caller_state.fpcr, caller_state.fpcr);
    if (caller_state.fpsr != expected_caller_state.fpsr)
        fail("FCVTAS restores caller FPSR", expected_caller_state.fpsr, caller_state.fpsr);
    if (munmap(page, static_cast<std::size_t>(page_size)) != 0) {
        std::perror("munmap"); std::exit(1);
    }
    return result;
}

int main()
{
#if !defined(__aarch64__)
    std::fprintf(stderr, "FCVTAS_EMITTER_FAIL native AArch64 host required\n");
    return 1;
#endif
    unsigned exact_words = 0;
    for (unsigned w = 0; w < 32; ++w) for (unsigned d = 0; d < 32; ++d) {
        const uae_u32 expected = 0x1e640000u | (d << 5) | w;
        const uae_u32 found = word(w, d);
        if (found != expected) fail("FCVTAS_wd exact 32x32 word", expected, found);
        ++exact_words;
    }

    constexpr std::array<Vector, 16> vectors = {{
        {"positive zero", 0x0000000000000000ull, 0x00000000u, false, false},
        {"negative zero", 0x8000000000000000ull, 0x00000000u, false, false},
        {"positive half", 0x3fe0000000000000ull, 0x00000001u, true, false},
        {"negative half", 0xbfe0000000000000ull, 0xffffffffu, true, false},
        {"positive one half", 0x3ff8000000000000ull, 0x00000002u, true, false},
        {"negative one half", 0xbff8000000000000ull, 0xfffffffeu, true, false},
        {"positive fraction", 0x400199999999999aull, 0x00000002u, true, false},
        {"negative fraction", 0xc00199999999999aull, 0xfffffffeu, true, false},
        {"maximum signed", 0x41dfffffffc00000ull, 0x7fffffffu, false, false},
        {"minimum signed", 0xc1e0000000000000ull, 0x80000000u, false, false},
        {"positive overflow", 0x41e0000000000000ull, 0x7fffffffu, false, true},
        {"negative overflow", 0xc1e0000020000000ull, 0x80000000u, false, true},
        {"positive infinity", 0x7ff0000000000000ull, 0x7fffffffu, false, true},
        {"negative infinity", 0xfff0000000000000ull, 0x80000000u, false, true},
        {"quiet NaN", 0x7ff8deadbeef1234ull, 0x00000000u, false, true},
        {"signalling NaN", 0x7ff0000000000001ull, 0x00000000u, false, true},
    }};
    unsigned native_vectors = 0;
    unsigned fpcr_vectors = 0;
    unsigned discard_vectors = 0;
    constexpr std::array<std::array<unsigned, 2>, 4> routes = {{{{0, 0}}, {{30, 31}}, {{8, 15}}, {{31, 8}}}};
    for (const auto &item : vectors) for (const auto [w, d] : routes) for (unsigned mode = 0; mode < 4; ++mode) {
        const Result result = run(w, d, item.source, mode);
        const std::uint64_t expected_value = w == 31 ? 0 : item.expected;
        if (result.value != expected_value) fail(item.name, expected_value, result.value);
        if (result.source != item.source) fail("FCVTAS preserves source", item.source, result.source);
        if ((result.nzcv & 0xf0000000ull) != 0xb0000000ull)
            fail("FCVTAS preserves NZCV", 0xb0000000ull, result.nzcv & 0xf0000000ull);
        const std::uint64_t expected_fpcr = static_cast<std::uint64_t>(mode) << 22;
        if (result.fpcr != expected_fpcr) fail("FCVTAS preserves FPCR", expected_fpcr, result.fpcr);
        const std::uint64_t expected_fpsr = 0x08000080ull |
            (item.inexact ? 0x10ull : 0ull) | (item.invalid ? 1ull : 0ull);
        if (result.fpsr != expected_fpsr) fail(item.name, expected_fpsr, result.fpsr);
        ++native_vectors;
        ++fpcr_vectors;
        if (w == 31) ++discard_vectors;
    }

    std::printf("METRIC emitter_fcvtas_exact_words=%u\n", exact_words);
    std::printf("METRIC emitter_fcvtas_native_vectors=%u\n", native_vectors);
    std::printf("METRIC emitter_fcvtas_fpcr_vectors=%u\n", fpcr_vectors);
    std::printf("METRIC emitter_fcvtas_discard_vectors=%u\n", discard_vectors);
    return exact_words == 1024 && native_vectors == 256 && fpcr_vectors == 256 && discard_vectors == 64 ? 0 : 1;
}
