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

struct Result { std::uint64_t value, source, nzcv, fpcr, fpsr; };
struct CallerState { std::uint64_t d[8], fpcr, fpsr; };
struct Vector {
    const char *name;
    std::uint64_t input;
    std::uint64_t away;
    std::uint64_t zero;
    std::array<std::uint64_t, 4> current;
    std::uint32_t flags;
};
using NativeFn = void (*)(Result *, std::uint64_t);
extern "C" void frint_invoke_checked(NativeFn, Result *, std::uint64_t, CallerState *);

#if defined(__aarch64__)
asm(R"(
.text
.align 2
.global frint_invoke_checked
.type frint_invoke_checked,%function
frint_invoke_checked:
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
.size frint_invoke_checked,.-frint_invoke_checked
)");
#endif

static void fail(const char *label, std::uint64_t expected, std::uint64_t found) {
    std::fprintf(stderr, "FRINT_EMITTER_FAIL label=%s expected=%016llx found=%016llx\n",
                 label, static_cast<unsigned long long>(expected),
                 static_cast<unsigned long long>(found));
    std::exit(1);
}

static uae_u32 word(unsigned kind, unsigned destination, unsigned source) {
    emitted.clear();
    if (kind == 0) FRINTA_dd(destination, source);
    else if (kind == 1) FRINTI_dd(destination, source);
    else FRINTZ_dd(destination, source);
    if (emitted.size() != 1) fail("FRINT word count", 1, emitted.size());
    return emitted[0];
}

static Result run(unsigned kind, unsigned destination, unsigned source,
                  std::uint64_t bits, unsigned mode) {
    emitted.clear();
    SUB_xxi(31, 31, 192);
    for (unsigned reg = 8; reg <= 15; ++reg) STR_dXi(reg, 31, (reg - 8) * 8);
    for (unsigned reg = 19; reg <= 30; ++reg) STR_xXi(reg, 31, 64 + (reg - 19) * 8);
    STR_xXi(0, 31, 160);
    MRS_FPCR_x(14); MRS_FPSR_x(15);
    STR_xXi(14, 31, 168); STR_xXi(15, 31, 176);
    MOV_wi(3, 0); MOVK_wish(3, mode << 6, 16); MSR_FPCR_x(3);
    MOV_wi(4, 0x80); MOVK_wish(4, 0x0800, 16); MSR_FPSR_x(4);
    MOV_wi(5, 0); MOVK_wish(5, 0xb000, 16); MSR_NZCV_x(5);
    FMOV_dx(source, 1);
    if (kind == 0) FRINTA_dd(destination, source);
    else if (kind == 1) FRINTI_dd(destination, source);
    else FRINTZ_dd(destination, source);
    FMOV_xd(12, destination);
    FMOV_xd(13, source);
    LDR_xXi(16, 31, 160);
    MRS_NZCV_x(9); MRS_FPCR_x(10); MRS_FPSR_x(11);
    STR_xXi(12, 16, 0); STR_xXi(13, 16, 8); STR_xXi(9, 16, 16);
    STR_xXi(10, 16, 24); STR_xXi(11, 16, 32);
    LDR_xXi(14, 31, 168); LDR_xXi(15, 31, 176);
    MSR_FPSR_x(15); MSR_FPCR_x(14);
    for (unsigned reg = 19; reg <= 30; ++reg) LDR_xXi(reg, 31, 64 + (reg - 19) * 8);
    for (unsigned reg = 8; reg <= 15; ++reg) LDR_dXi(reg, 31, (reg - 8) * 8);
    ADD_xxi(31, 31, 192);
    emitted.push_back(0xd65f03c0u);

    const long page_size = sysconf(_SC_PAGESIZE);
    void *page = mmap(nullptr, static_cast<std::size_t>(page_size), PROT_READ | PROT_WRITE,
                      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (page == MAP_FAILED) { std::perror("mmap"); std::exit(1); }
    std::memcpy(page, emitted.data(), emitted.size() * sizeof(uae_u32));
    if (mprotect(page, static_cast<std::size_t>(page_size), PROT_READ | PROT_EXEC)) {
        std::perror("mprotect"); std::exit(1);
    }
    __builtin___clear_cache(static_cast<char *>(page),
                            static_cast<char *>(page) + emitted.size() * sizeof(uae_u32));
    Result result{};
    CallerState state{{0x0808080808080808ull,0x0909090909090909ull,
        0x0a0a0a0a0a0a0a0aull,0x0b0b0b0b0b0b0b0bull,0x0c0c0c0c0c0c0c0cull,
        0x0d0d0d0d0d0d0d0dull,0x0e0e0e0e0e0e0e0eull,0x0f0f0f0f0f0f0f0full},
        0x00c00000ull, 0x0800009full};
    const CallerState expected = state;
    frint_invoke_checked(reinterpret_cast<NativeFn>(page), &result, bits, &state);
    for (unsigned index = 0; index < 8; ++index)
        if (state.d[index] != expected.d[index])
            fail("FRINT preserves caller D8-D15", expected.d[index], state.d[index]);
    if (state.fpcr != expected.fpcr) fail("FRINT restores caller FPCR", expected.fpcr, state.fpcr);
    if (state.fpsr != expected.fpsr) fail("FRINT restores caller FPSR", expected.fpsr, state.fpsr);
    munmap(page, static_cast<std::size_t>(page_size));
    return result;
}

int main() {
#if !defined(__aarch64__)
    std::fprintf(stderr, "FRINT_EMITTER_FAIL native AArch64 host required\n"); return 1;
#endif
    constexpr std::array<std::uint32_t, 3> bases{{0x1e664000u,0x1e67c000u,0x1e65c000u}};
    unsigned exact_words = 0;
    for (unsigned kind = 0; kind < 3; ++kind)
        for (unsigned destination = 0; destination < 32; ++destination)
            for (unsigned source = 0; source < 32; ++source) {
                const uae_u32 expected = bases[kind] | (source << 5) | destination;
                const uae_u32 found = word(kind, destination, source);
                if (found != expected) fail("FRINT exact", expected, found);
                exact_words++;
            }

    constexpr std::array<Vector, 14> vectors{{
      {"positive_half",0x3fe0000000000000ull,0x3ff0000000000000ull,0x0000000000000000ull,{0x0000000000000000ull,0x3ff0000000000000ull,0x0000000000000000ull,0x0000000000000000ull},0},
      {"negative_half",0xbfe0000000000000ull,0xbff0000000000000ull,0x8000000000000000ull,{0x8000000000000000ull,0x8000000000000000ull,0xbff0000000000000ull,0x8000000000000000ull},0},
      {"positive_one_half",0x3ff8000000000000ull,0x4000000000000000ull,0x3ff0000000000000ull,{0x4000000000000000ull,0x4000000000000000ull,0x3ff0000000000000ull,0x3ff0000000000000ull},0},
      {"negative_one_half",0xbff8000000000000ull,0xc000000000000000ull,0xbff0000000000000ull,{0xc000000000000000ull,0xbff0000000000000ull,0xc000000000000000ull,0xbff0000000000000ull},0},
      {"positive_two_half",0x4004000000000000ull,0x4008000000000000ull,0x4000000000000000ull,{0x4000000000000000ull,0x4008000000000000ull,0x4000000000000000ull,0x4000000000000000ull},0},
      {"negative_two_half",0xc004000000000000ull,0xc008000000000000ull,0xc000000000000000ull,{0xc000000000000000ull,0xc000000000000000ull,0xc008000000000000ull,0xc000000000000000ull},0},
      {"positive_subnormal",0x0000000000000001ull,0x0000000000000000ull,0x0000000000000000ull,{0x0000000000000000ull,0x3ff0000000000000ull,0x0000000000000000ull,0x0000000000000000ull},0},
      {"negative_subnormal",0x8000000000000001ull,0x8000000000000000ull,0x8000000000000000ull,{0x8000000000000000ull,0x8000000000000000ull,0xbff0000000000000ull,0x8000000000000000ull},0},
      {"positive_zero",0x0000000000000000ull,0x0000000000000000ull,0x0000000000000000ull,{0x0000000000000000ull,0x0000000000000000ull,0x0000000000000000ull,0x0000000000000000ull},0},
      {"negative_zero",0x8000000000000000ull,0x8000000000000000ull,0x8000000000000000ull,{0x8000000000000000ull,0x8000000000000000ull,0x8000000000000000ull,0x8000000000000000ull},0},
      {"positive_infinity",0x7ff0000000000000ull,0x7ff0000000000000ull,0x7ff0000000000000ull,{0x7ff0000000000000ull,0x7ff0000000000000ull,0x7ff0000000000000ull,0x7ff0000000000000ull},0},
      {"large_integral",0x432ffffffffffffeull,0x432ffffffffffffeull,0x432ffffffffffffeull,{0x432ffffffffffffeull,0x432ffffffffffffeull,0x432ffffffffffffeull,0x432ffffffffffffeull},0},
      {"quiet_nan",0x7ff82468a0000000ull,0x7ff82468a0000000ull,0x7ff82468a0000000ull,{0x7ff82468a0000000ull,0x7ff82468a0000000ull,0x7ff82468a0000000ull,0x7ff82468a0000000ull},0},
      {"signalling_nan",0x7ff02468a0000000ull,0x7ff82468a0000000ull,0x7ff82468a0000000ull,{0x7ff82468a0000000ull,0x7ff82468a0000000ull,0x7ff82468a0000000ull,0x7ff82468a0000000ull},1},
    }};
    unsigned native_routes = 0, alias_routes = 0;
    for (unsigned kind = 0; kind < 3; ++kind)
      for (unsigned destination = 0; destination < 32; ++destination)
        for (unsigned source = 0; source < 32; ++source)
          for (unsigned mode = 0; mode < 4; ++mode) {
            const Vector &vector = vectors[(kind + destination + source + mode) % vectors.size()];
            const std::uint64_t expected = kind == 0 ? vector.away : kind == 1 ? vector.current[mode] : vector.zero;
            const Result result = run(kind, destination, source, vector.input, mode);
            if (result.value != expected) fail(vector.name, expected, result.value);
            const std::uint64_t expected_source = destination == source ? expected : vector.input;
            if (result.source != expected_source) fail("FRINT source/alias semantics", expected_source, result.source);
            if ((result.nzcv & 0xf0000000ull) != 0xb0000000ull)
                fail("FRINT preserves NZCV",0xb0000000ull,result.nzcv&0xf0000000ull);
            if (result.fpcr != (static_cast<std::uint64_t>(mode) << 22))
                fail("FRINT preserves FPCR",static_cast<std::uint64_t>(mode)<<22,result.fpcr);
            const std::uint64_t expected_fpsr = 0x08000080ull | vector.flags;
            if (result.fpsr != expected_fpsr) fail("FRINT FPSR IOC without IXC",expected_fpsr,result.fpsr);
            native_routes++; if (destination == source) alias_routes++;
          }
    std::printf("METRIC emitter_frint_exact_words=%u\n", exact_words);
    std::printf("METRIC emitter_frint_native_routes=%u\n", native_routes);
    std::printf("METRIC emitter_frint_alias_routes=%u\n", alias_routes);
    return exact_words==3072 && native_routes==12288 && alias_routes==384 ? 0 : 1;
}
