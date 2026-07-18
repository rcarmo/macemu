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
struct CallerState {
    std::uint64_t d[8];
    std::uint64_t fpcr;
    std::uint64_t fpsr;
};
using NativeFn = void (*)(Result *, std::uint64_t);
extern "C" void fmov_sw_ws_invoke_checked(NativeFn, Result *, std::uint64_t, CallerState *);

#if defined(__aarch64__)
asm(R"(
.text
.align 2
.global fmov_sw_ws_invoke_checked
.type fmov_sw_ws_invoke_checked,%function
fmov_sw_ws_invoke_checked:
 sub sp,sp,#144
 stp x29,x30,[sp,#0]
 mov x29,sp
 stp x19,x20,[sp,#16]
 stp x21,x22,[sp,#32]
 str d8,[sp,#48]
 str d9,[sp,#56]
 str d10,[sp,#64]
 str d11,[sp,#72]
 str d12,[sp,#80]
 str d13,[sp,#88]
 str d14,[sp,#96]
 str d15,[sp,#104]
 mrs x9,fpcr
 mrs x10,fpsr
 str x9,[sp,#112]
 str x10,[sp,#120]
 mov x19,x0
 mov x20,x1
 mov x21,x2
 mov x22,x3
 ldr d8,[x22,#0]
 ldr d9,[x22,#8]
 ldr d10,[x22,#16]
 ldr d11,[x22,#24]
 ldr d12,[x22,#32]
 ldr d13,[x22,#40]
 ldr d14,[x22,#48]
 ldr d15,[x22,#56]
 ldr x9,[x22,#64]
 ldr x10,[x22,#72]
 msr fpcr,x9
 msr fpsr,x10
 mov x0,x20
 mov x1,x21
 blr x19
 str d8,[x22,#0]
 str d9,[x22,#8]
 str d10,[x22,#16]
 str d11,[x22,#24]
 str d12,[x22,#32]
 str d13,[x22,#40]
 str d14,[x22,#48]
 str d15,[x22,#56]
 mrs x9,fpcr
 mrs x10,fpsr
 str x9,[x22,#64]
 str x10,[x22,#72]
 ldr x9,[sp,#112]
 ldr x10,[sp,#120]
 msr fpcr,x9
 msr fpsr,x10
 ldr d8,[sp,#48]
 ldr d9,[sp,#56]
 ldr d10,[sp,#64]
 ldr d11,[sp,#72]
 ldr d12,[sp,#80]
 ldr d13,[sp,#88]
 ldr d14,[sp,#96]
 ldr d15,[sp,#104]
 ldp x21,x22,[sp,#32]
 ldp x19,x20,[sp,#16]
 ldp x29,x30,[sp,#0]
 add sp,sp,#144
 ret
.size fmov_sw_ws_invoke_checked,.-fmov_sw_ws_invoke_checked
)");
#endif

static void fail(const char *label, std::uint64_t expected, std::uint64_t found) {
    std::fprintf(stderr,
                 "FMOV_SW_WS_EMITTER_FAIL label=%s expected=%016llx found=%016llx\n",
                 label, static_cast<unsigned long long>(expected),
                 static_cast<unsigned long long>(found));
    std::exit(1);
}

static uae_u32 sw_word(unsigned s, unsigned w) {
    emitted.clear();
    FMOV_sw(s, w);
    if (emitted.size() != 1) fail("FMOV_sw count", 1, emitted.size());
    return emitted[0];
}

static uae_u32 ws_word(unsigned w, unsigned s) {
    emitted.clear();
    FMOV_ws(w, s);
    if (emitted.size() != 1) fail("FMOV_ws count", 1, emitted.size());
    return emitted[0];
}

static Result run(bool to_float, unsigned destination, unsigned source,
                  std::uint64_t bits) {
    emitted.clear();
    SUB_xxi(31, 31, 192);
    for (unsigned reg = 8; reg <= 15; ++reg) STR_dXi(reg, 31, (reg - 8) * 8);
    for (unsigned reg = 19; reg <= 30; ++reg) STR_xXi(reg, 31, 64 + (reg - 19) * 8);
    STR_xXi(0, 31, 160);
    MRS_FPCR_x(14);
    MRS_FPSR_x(15);
    STR_xXi(14, 31, 168);
    STR_xXi(15, 31, 176);
    MOV_wi(3, 0);
    MOVK_wish(3, 0x0080, 16);
    MSR_FPCR_x(3);
    MOV_wi(4, 0x9f);
    MOVK_wish(4, 0x0800, 16);
    MSR_FPSR_x(4);
    MOV_wi(5, 0);
    MOVK_wish(5, 0xb000, 16);
    MSR_NZCV_x(5);
    if (to_float) {
        MOV_xi(13, 0xa5a5a5a5a5a5a5a5ull);
        FMOV_dx(destination, 13);
        if (source != 31) MOV_ww(source, 1);
        FMOV_sw(destination, source);
        if (source != 31) MOV_ww(13, source);
        else MOV_wi(13, 0);
        FMOV_xd(12, destination);
    } else {
        FMOV_dx(source, 1);
        FMOV_ws(destination, source);
        if (destination != 31) MOV_ww(12, destination);
        else MOV_wi(12, 0);
        FMOV_xd(13, source);
    }
    LDR_xXi(16, 31, 160);
    MRS_NZCV_x(9);
    MRS_FPCR_x(10);
    MRS_FPSR_x(11);
    STR_xXi(12, 16, 0);
    STR_xXi(13, 16, 8);
    STR_xXi(9, 16, 16);
    STR_xXi(10, 16, 24);
    STR_xXi(11, 16, 32);
    LDR_xXi(14, 31, 168);
    LDR_xXi(15, 31, 176);
    MSR_FPSR_x(15);
    MSR_FPCR_x(14);
    for (unsigned reg = 19; reg <= 30; ++reg) LDR_xXi(reg, 31, 64 + (reg - 19) * 8);
    for (unsigned reg = 8; reg <= 15; ++reg) LDR_dXi(reg, 31, (reg - 8) * 8);
    ADD_xxi(31, 31, 192);
    emitted.push_back(0xd65f03c0u);

    const long page_size = sysconf(_SC_PAGESIZE);
    void *page = mmap(nullptr, static_cast<std::size_t>(page_size),
                      PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (page == MAP_FAILED) { std::perror("mmap"); std::exit(1); }
    std::memcpy(page, emitted.data(), emitted.size() * sizeof(uae_u32));
    if (mprotect(page, static_cast<std::size_t>(page_size), PROT_READ | PROT_EXEC)) {
        std::perror("mprotect"); std::exit(1);
    }
    __builtin___clear_cache(static_cast<char *>(page),
                            static_cast<char *>(page) + emitted.size() * sizeof(uae_u32));
    Result result{};
    CallerState state{{
        0x0808080808080808ull, 0x0909090909090909ull,
        0x0a0a0a0a0a0a0a0aull, 0x0b0b0b0b0b0b0b0bull,
        0x0c0c0c0c0c0c0c0cull, 0x0d0d0d0d0d0d0d0dull,
        0x0e0e0e0e0e0e0e0eull, 0x0f0f0f0f0f0f0f0full,
    }, 0x00800000ull, 0x0800009full};
    const CallerState expected = state;
    fmov_sw_ws_invoke_checked(reinterpret_cast<NativeFn>(page), &result, bits, &state);
    for (unsigned index = 0; index < 8; ++index) {
        if (state.d[index] != expected.d[index])
            fail("FMOV preserves caller D8-D15", expected.d[index], state.d[index]);
    }
    if (state.fpcr != expected.fpcr)
        fail("FMOV restores caller FPCR", expected.fpcr, state.fpcr);
    if (state.fpsr != expected.fpsr)
        fail("FMOV restores caller FPSR", expected.fpsr, state.fpsr);
    munmap(page, static_cast<std::size_t>(page_size));
    return result;
}

static void check_state(const Result &result) {
    if ((result.nzcv & 0xf0000000ull) != 0xb0000000ull)
        fail("FMOV preserves NZCV", 0xb0000000ull, result.nzcv & 0xf0000000ull);
    if (result.fpcr != 0x00800000ull)
        fail("FMOV preserves FPCR", 0x00800000ull, result.fpcr);
    if (result.fpsr != 0x0800009full)
        fail("FMOV preserves FPSR", 0x0800009full, result.fpsr);
}

int main() {
#if !defined(__aarch64__)
    std::fprintf(stderr, "FMOV_SW_WS_EMITTER_FAIL native AArch64 host required\n");
    return 1;
#endif
    unsigned exact_words = 0;
    for (unsigned a = 0; a < 32; ++a) {
        for (unsigned b = 0; b < 32; ++b) {
            const uae_u32 sw_expected = 0x1e270000u | (b << 5) | a;
            const uae_u32 ws_expected = 0x1e260000u | (b << 5) | a;
            const uae_u32 sw_found = sw_word(a, b);
            const uae_u32 ws_found = ws_word(a, b);
            if (sw_found != sw_expected) fail("FMOV_sw exact", sw_expected, sw_found);
            if (ws_found != ws_expected) fail("FMOV_ws exact", ws_expected, ws_found);
            exact_words += 2;
        }
    }

    constexpr std::array<std::uint64_t, 8> patterns{{
        0x0000000000000000ull, 0x0000000080000000ull,
        0xffffffff7fc12345ull, 0x123456787f812345ull,
        0xaaaaaaaa00000001ull, 0x555555557f800000ull,
        0xdeadbeefff800000ull, 0x012345673f800001ull,
    }};
    unsigned native_routes = 0;
    unsigned same_number_routes = 0;
    for (unsigned destination = 0; destination < 32; ++destination) {
        for (unsigned source = 0; source < 32; ++source) {
            const std::uint64_t bits = patterns[(destination * 32 + source) % patterns.size()];
            const Result sw = run(true, destination, source, bits);
            const std::uint32_t input_word = source == 31 ? 0u : static_cast<std::uint32_t>(bits);
            if (sw.value != input_word)
                fail("FMOV_sw low word and upper-lane zero", input_word, sw.value);
            if (sw.source != input_word)
                fail("FMOV_sw preserves W source", input_word, sw.source);
            check_state(sw);
            native_routes++;

            const Result ws = run(false, destination, source, bits);
            const std::uint32_t source_word = static_cast<std::uint32_t>(bits);
            const std::uint64_t expected_value = destination == 31 ? 0u : source_word;
            if (ws.value != expected_value)
                fail("FMOV_ws W result or WZR discard", expected_value, ws.value);
            if (ws.source != bits)
                fail("FMOV_ws preserves S source lane", bits, ws.source);
            check_state(ws);
            native_routes++;
            if (destination == source) same_number_routes += 2;
        }
    }

    std::printf("METRIC emitter_fmov_sw_ws_exact_words=%u\n", exact_words);
    std::printf("METRIC emitter_fmov_sw_ws_native_routes=%u\n", native_routes);
    std::printf("METRIC emitter_fmov_sw_ws_same_number_routes=%u\n", same_number_routes);
    return exact_words == 2048 && native_routes == 2048 && same_number_routes == 64 ? 0 : 1;
}
