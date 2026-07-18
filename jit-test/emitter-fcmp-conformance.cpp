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
    std::uint64_t lhs;
    std::uint64_t rhs;
    std::uint64_t nzcv;
    std::uint64_t fpcr;
    std::uint64_t fpsr;
};

struct CompareCase {
    const char *name;
    std::uint64_t lhs;
    std::uint64_t rhs;
    std::uint64_t nzcv;
    bool invalid;
};

struct CallerState {
    std::uint64_t d8_d15[8];
    std::uint64_t fpcr;
    std::uint64_t fpsr;
};

using NativeFn = void (*)(Result *, std::uint64_t, std::uint64_t);
extern "C" void fcmp_invoke_checked(NativeFn, Result *, std::uint64_t,
    std::uint64_t, CallerState *);

#if defined(__aarch64__)
asm(R"(
.text
.align 2
.global fcmp_invoke_checked
.type fcmp_invoke_checked, %function
fcmp_invoke_checked:
    sub sp, sp, #160
    stp x29, x30, [sp, #0]
    mov x29, sp
    stp x19, x20, [sp, #16]
    stp x21, x22, [sp, #32]
    str x23, [sp, #48]
    str d8,  [sp, #56]
    str d9,  [sp, #64]
    str d10, [sp, #72]
    str d11, [sp, #80]
    str d12, [sp, #88]
    str d13, [sp, #96]
    str d14, [sp, #104]
    str d15, [sp, #112]
    mrs x9, fpcr
    mrs x10, fpsr
    str x9, [sp, #120]
    str x10, [sp, #128]
    mov x19, x0
    mov x20, x1
    mov x21, x2
    mov x22, x3
    mov x23, x4
    ldr d8,  [x23, #0]
    ldr d9,  [x23, #8]
    ldr d10, [x23, #16]
    ldr d11, [x23, #24]
    ldr d12, [x23, #32]
    ldr d13, [x23, #40]
    ldr d14, [x23, #48]
    ldr d15, [x23, #56]
    ldr x9, [x23, #64]
    ldr x10, [x23, #72]
    msr fpcr, x9
    msr fpsr, x10
    mov x0, x20
    mov x1, x21
    mov x2, x22
    blr x19
    str d8,  [x23, #0]
    str d9,  [x23, #8]
    str d10, [x23, #16]
    str d11, [x23, #24]
    str d12, [x23, #32]
    str d13, [x23, #40]
    str d14, [x23, #48]
    str d15, [x23, #56]
    mrs x9, fpcr
    mrs x10, fpsr
    str x9, [x23, #64]
    str x10, [x23, #72]
    ldr x9, [sp, #120]
    ldr x10, [sp, #128]
    msr fpcr, x9
    msr fpsr, x10
    ldr d8,  [sp, #56]
    ldr d9,  [sp, #64]
    ldr d10, [sp, #72]
    ldr d11, [sp, #80]
    ldr d12, [sp, #88]
    ldr d13, [sp, #96]
    ldr d14, [sp, #104]
    ldr d15, [sp, #112]
    ldr x23, [sp, #48]
    ldp x21, x22, [sp, #32]
    ldp x19, x20, [sp, #16]
    ldp x29, x30, [sp, #0]
    add sp, sp, #160
    ret
.size fcmp_invoke_checked, .-fcmp_invoke_checked
)");
#endif

static void fail(const char *label, std::uint64_t expected, std::uint64_t found)
{
    std::fprintf(stderr, "FCMP_EMITTER_FAIL label=%s expected=%016llx found=%016llx\n",
        label, static_cast<unsigned long long>(expected),
        static_cast<unsigned long long>(found));
    std::exit(1);
}

static uae_u32 fcmp_dd_word(unsigned n, unsigned m)
{
    emitted.clear();
    FCMP_dd(n, m);
    if (emitted.size() != 1) fail("FCMP_dd emission count", 1, emitted.size());
    return emitted.front();
}

static uae_u32 fcmp_d0_word(unsigned n)
{
    emitted.clear();
    FCMP_d0(n);
    if (emitted.size() != 1) fail("FCMP_d0 emission count", 1, emitted.size());
    return emitted.front();
}

static Result run(unsigned n, unsigned m, std::uint64_t lhs, std::uint64_t rhs,
    bool compare_zero)
{
    emitted.clear();
    SUB_xxi(31, 31, 64);
    for (unsigned reg = 8; reg <= 15; ++reg)
        STR_dXi(reg, 31, (reg - 8) * 8);
    MRS_FPCR_x(14);
    MRS_FPSR_x(15);
    FMOV_dx(n, 1);
    if (!compare_zero) FMOV_dx(m, 2);
    MOV_wi(3, 0);
    MSR_FPCR_x(3);
    MOV_wi(4, 0x0080u);
    MOVK_wish(4, 0x0800u, 16);
    MSR_FPSR_x(4);
    if (compare_zero) FCMP_d0(n); else FCMP_dd(n, m);
    MRS_NZCV_x(9);
    MRS_FPCR_x(10);
    MRS_FPSR_x(11);
    FMOV_xd(12, n);
    if (compare_zero) MOV_xi(13, 0); else FMOV_xd(13, m);
    STR_xXi(12, 0, 0);
    STR_xXi(13, 0, 8);
    STR_xXi(9, 0, 16);
    STR_xXi(10, 0, 24);
    STR_xXi(11, 0, 32);
    MSR_FPSR_x(15);
    MSR_FPCR_x(14);
    for (unsigned reg = 8; reg <= 15; ++reg)
        LDR_dXi(reg, 31, (reg - 8) * 8);
    ADD_xxi(31, 31, 64);
    emitted.push_back(0xd65f03c0u); // RET

    const long page_size = sysconf(_SC_PAGESIZE);
    if (page_size <= 0 || emitted.size() * sizeof(uae_u32) > static_cast<std::size_t>(page_size))
        fail("executable page size", 1, 0);
    void *page = mmap(nullptr, static_cast<std::size_t>(page_size),
        PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
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
    fcmp_invoke_checked(reinterpret_cast<NativeFn>(page), &result, lhs, rhs,
        &caller_state);
    for (unsigned reg = 0; reg < 8; ++reg) {
        if (caller_state.d8_d15[reg] != expected_caller_state.d8_d15[reg])
            fail("FCMP preserves caller D8-D15", expected_caller_state.d8_d15[reg],
                caller_state.d8_d15[reg]);
    }
    if (caller_state.fpcr != expected_caller_state.fpcr)
        fail("FCMP restores caller FPCR", expected_caller_state.fpcr, caller_state.fpcr);
    if (caller_state.fpsr != expected_caller_state.fpsr)
        fail("FCMP restores caller FPSR", expected_caller_state.fpsr, caller_state.fpsr);
    if (munmap(page, static_cast<std::size_t>(page_size)) != 0) {
        std::perror("munmap"); std::exit(1);
    }
    return result;
}

static void check_result(const CompareCase &item, const Result &result,
    std::uint64_t expected_lhs, std::uint64_t expected_rhs)
{
    constexpr std::uint64_t initial_fpsr = 0x08000080ull;
    if (result.lhs != expected_lhs) fail("FCMP preserves lhs", expected_lhs, result.lhs);
    if (result.rhs != expected_rhs) fail("FCMP preserves rhs", expected_rhs, result.rhs);
    if ((result.nzcv & 0xf0000000ull) != item.nzcv)
        fail(item.name, item.nzcv, result.nzcv & 0xf0000000ull);
    if (result.fpcr != 0) fail("FCMP preserves FPCR", 0, result.fpcr);
    const std::uint64_t expected_fpsr = initial_fpsr | (item.invalid ? 1ull : 0ull);
    if (result.fpsr != expected_fpsr)
        fail("FCMP FPSR invalid contract", expected_fpsr, result.fpsr);
}

int main()
{
#if !defined(__aarch64__)
    std::fprintf(stderr, "FCMP_EMITTER_FAIL native AArch64 host required\n");
    return 1;
#endif
    unsigned exact_words = 0;
    for (unsigned n = 0; n < 32; ++n) {
        for (unsigned m = 0; m < 32; ++m) {
            const uae_u32 expected = 0x1e602000u | (m << 16) | (n << 5);
            const uae_u32 found = fcmp_dd_word(n, m);
            if (found != expected) fail("FCMP_dd exact 32x32 word", expected, found);
            ++exact_words;
        }
        const uae_u32 expected_zero = 0x1e602008u | (n << 5);
        const uae_u32 found_zero = fcmp_d0_word(n);
        if (found_zero != expected_zero) fail("FCMP_d0 exact 32-word field", expected_zero, found_zero);
        ++exact_words;
    }

    constexpr std::array<CompareCase, 10> cases = {{
        {"FCMP less", 0xbff0000000000000ull, 0x3ff0000000000000ull, 0x80000000ull, false},
        {"FCMP equal", 0x4008000000000000ull, 0x4008000000000000ull, 0x60000000ull, false},
        {"FCMP greater", 0x4000000000000000ull, 0xbff0000000000000ull, 0x20000000ull, false},
        {"FCMP signed-zero equal", 0x8000000000000000ull, 0x0000000000000000ull, 0x60000000ull, false},
        {"FCMP infinity equal", 0x7ff0000000000000ull, 0x7ff0000000000000ull, 0x60000000ull, false},
        {"FCMP lhs qNaN", 0x7ff8deadbeef1234ull, 0x3ff0000000000000ull, 0x30000000ull, false},
        {"FCMP rhs qNaN", 0x3ff0000000000000ull, 0xfff8cafebabefeedull, 0x30000000ull, false},
        {"FCMP lhs sNaN", 0x7ff0000000000001ull, 0x3ff0000000000000ull, 0x30000000ull, true},
        {"FCMP rhs sNaN", 0x3ff0000000000000ull, 0xfff0000000000001ull, 0x30000000ull, true},
        {"FCMP subnormal greater", 0x0000000000000001ull, 0x0000000000000000ull, 0x20000000ull, false},
    }};
    unsigned dd_vectors = 0;
    unsigned alias_vectors = 0;
    for (const auto &item : cases) {
        for (const auto [n, m] : std::array<std::array<unsigned, 2>, 4>{{
            {{0, 1}}, {{31, 30}}, {{8, 15}}, {{7, 7}},
        }}) {
            const Result result = run(n, m, item.lhs, item.rhs, false);
            const std::uint64_t effective = n == m ? item.rhs : item.lhs;
            CompareCase expected = item;
            if (n == m) {
                const bool rhs_nan = (item.rhs & 0x7ff0000000000000ull) == 0x7ff0000000000000ull &&
                    (item.rhs & 0x000fffffffffffffull) != 0;
                const bool rhs_snan = (item.rhs & 0x7ff8000000000000ull) == 0x7ff0000000000000ull &&
                    (item.rhs & 0x0007ffffffffffffull) != 0;
                expected.nzcv = rhs_nan ? 0x30000000ull : 0x60000000ull;
                expected.invalid = rhs_snan;
            }
            check_result(expected, result, effective, n == m ? effective : item.rhs);
            ++dd_vectors;
            if (n == m) ++alias_vectors;
        }
    }

    constexpr std::array<CompareCase, 8> zero_cases = {{
        {"FCMP_d0 negative", 0xbff0000000000000ull, 0, 0x80000000ull, false},
        {"FCMP_d0 positive", 0x3ff0000000000000ull, 0, 0x20000000ull, false},
        {"FCMP_d0 positive zero", 0x0000000000000000ull, 0, 0x60000000ull, false},
        {"FCMP_d0 negative zero", 0x8000000000000000ull, 0, 0x60000000ull, false},
        {"FCMP_d0 positive infinity", 0x7ff0000000000000ull, 0, 0x20000000ull, false},
        {"FCMP_d0 negative infinity", 0xfff0000000000000ull, 0, 0x80000000ull, false},
        {"FCMP_d0 qNaN", 0x7ff8deadbeef1234ull, 0, 0x30000000ull, false},
        {"FCMP_d0 sNaN", 0x7ff0000000000001ull, 0, 0x30000000ull, true},
    }};
    unsigned d0_vectors = 0;
    for (const auto &item : zero_cases) {
        for (const unsigned n : {0u, 8u, 15u, 31u}) {
            const Result result = run(n, 0, item.lhs, 0, true);
            check_result(item, result, item.lhs, 0);
            ++d0_vectors;
        }
    }

    std::printf("METRIC emitter_fcmp_exact_words=%u\n", exact_words);
    std::printf("METRIC emitter_fcmp_dd_native_vectors=%u\n", dd_vectors);
    std::printf("METRIC emitter_fcmp_d0_native_vectors=%u\n", d0_vectors);
    std::printf("METRIC emitter_fcmp_alias_vectors=%u\n", alias_vectors);
    std::printf("METRIC emitter_fcmp_nan_classes=4\n");
    return exact_words == 1056 && dd_vectors == 40 && d0_vectors == 32 &&
        alias_vectors == 10 ? 0 : 1;
}
