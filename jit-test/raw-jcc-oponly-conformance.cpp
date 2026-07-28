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

static std::vector<uae_u32> emitted;
static void emit_long(uae_u32 word) { emitted.push_back(word); }
#include "flags_arm.h"
#include "codegen_arm64.h"

#define REG_WORK1 2
#define STATIC_INLINE static inline
static bool flags_carry_inverted;
#include "raw-jcc-oponly.inc"

struct Output { std::uint64_t taken; std::uint64_t nzcv; };

[[noreturn]] static void fail(const char *label, std::uint64_t expected,
    std::uint64_t found)
{
    std::fprintf(stderr,
        "RAW_JCC_OPONLY_FAIL label=%s expected=%016llx found=%016llx\n",
        label, static_cast<unsigned long long>(expected),
        static_cast<unsigned long long>(found));
    std::exit(1);
}

static unsigned base_words(int cc)
{
    switch (cc) {
    case NATIVE_CC_F_F: return 2;
    case NATIVE_CC_HI: return 2;
    case NATIVE_CC_LS: return 3;
    case NATIVE_CC_F_OGT: case NATIVE_CC_F_OGE:
    case NATIVE_CC_F_OLT: case NATIVE_CC_F_OLE:
    case NATIVE_CC_F_OGL: return 2;
    case NATIVE_CC_F_UEQ: case NATIVE_CC_F_UGT:
    case NATIVE_CC_F_UGE: case NATIVE_CC_F_ULT:
    case NATIVE_CC_F_ULE: return 3;
    default: return 1;
    }
}

static bool integer_holds(int cc, unsigned nzcv)
{
    const bool n = (nzcv & 8u) != 0;
    const bool z = (nzcv & 4u) != 0;
    const bool c = (nzcv & 2u) != 0;
    const bool v = (nzcv & 1u) != 0;
    switch (cc) {
    case NATIVE_CC_EQ: return z;
    case NATIVE_CC_NE: return !z;
    case NATIVE_CC_CS: return c;
    case NATIVE_CC_CC: return !c;
    case NATIVE_CC_MI: return n;
    case NATIVE_CC_PL: return !n;
    case NATIVE_CC_VS: return v;
    case NATIVE_CC_VC: return !v;
    case NATIVE_CC_HI: return !c && !z; // M68K unsigned higher
    case NATIVE_CC_LS: return c || z;   // M68K unsigned lower/same
    case NATIVE_CC_GE: return n == v;
    case NATIVE_CC_LT: return n != v;
    case NATIVE_CC_GT: return !z && n == v;
    case NATIVE_CC_LE: return z || n != v;
    case NATIVE_CC_AL: return true;
    default: fail("integer condition domain", 14, cc);
    }
}

enum class FpClass { Greater, Equal, Less, Unordered };
static unsigned fp_nzcv(FpClass value)
{
    switch (value) {
    case FpClass::Greater: return 0x2;   // 0010: C
    case FpClass::Equal: return 0x6;     // 0110: ZC
    case FpClass::Less: return 0x8;      // 1000: N
    case FpClass::Unordered: return 0x3; // 0011: CV
    }
    return 0;
}

static bool fp_holds(int cc, FpClass value)
{
    const bool gt = value == FpClass::Greater;
    const bool eq = value == FpClass::Equal;
    const bool lt = value == FpClass::Less;
    const bool un = value == FpClass::Unordered;
    switch (cc) {
    case NATIVE_CC_F_F: return false;
    case NATIVE_CC_F_EQ: return eq;
    case NATIVE_CC_F_OGT: return gt;
    case NATIVE_CC_F_OGE: return gt || eq;
    case NATIVE_CC_F_OLT: return lt;
    case NATIVE_CC_F_OLE: return lt || eq;
    case NATIVE_CC_F_OGL: return gt || lt;
    case NATIVE_CC_F_OR: return !un;
    case NATIVE_CC_F_UN: return un;
    case NATIVE_CC_F_UEQ: return un || eq;
    case NATIVE_CC_F_UGT: return un || gt;
    case NATIVE_CC_F_UGE: return un || gt || eq;
    case NATIVE_CC_F_ULT: return un || lt;
    case NATIVE_CC_F_ULE: return un || lt || eq;
    case NATIVE_CC_F_NE: return !eq;
    case NATIVE_CC_F_T: return true;
    default: fail("FP condition domain", NATIVE_CC_F_T, cc);
    }
}

static void patch_terminal(std::size_t branch_index, std::size_t target_index)
{
    const std::int64_t delta = static_cast<std::int64_t>(target_index) -
        static_cast<std::int64_t>(branch_index);
    uae_u32 &word = emitted[branch_index];
    if ((word & 0xfc000000u) == 0x14000000u) {
        word = (word & 0xfc000000u) |
            (static_cast<uae_u32>(delta) & 0x03ffffffu);
    } else if ((word & 0xff000010u) == 0x54000000u) {
        word = (word & ~0x00ffffe0u) |
            ((static_cast<uae_u32>(delta) & 0x7ffffu) << 5);
    } else {
        fail("terminal patch opcode", 0x14000000u, word);
    }
}

static Output execute(int cc, unsigned canonical_nzcv, bool inverted)
{
    emitted.clear();
    flags_carry_inverted = inverted;
    MSR_NZCV_x(1);
    const std::size_t body_start = emitted.size();
    compemu_raw_jcc_l_oponly(cc);
    const std::size_t body_words = emitted.size() - body_start;
    const unsigned expected_words = base_words(cc) + (inverted ? 3u : 0u);
    if (body_words != expected_words)
        fail("exact condition shape", expected_words, body_words);
    if (flags_carry_inverted)
        fail("carry state publication", 0, 1);

    const std::size_t terminal = emitted.size() - 1;
    MOV_wi(3, 0);
    STR_xXi(3, 0, 0);
    MRS_NZCV_x(2);
    STR_xXi(2, 0, 8);
    emitted.push_back(0xd65f03c0u); // RET
    const std::size_t taken_target = emitted.size();
    MOV_wi(3, 1);
    STR_xXi(3, 0, 0);
    MRS_NZCV_x(2);
    STR_xXi(2, 0, 8);
    emitted.push_back(0xd65f03c0u); // RET
    patch_terminal(terminal, taken_target);

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
    unsigned runtime_nzcv = canonical_nzcv;
    if (inverted) runtime_nzcv ^= 0x2u;
    reinterpret_cast<Fn>(page)(&output,
        static_cast<std::uint64_t>(runtime_nzcv) << 28);
    if (munmap(page, static_cast<std::size_t>(page_size)) != 0) {
        std::perror("munmap code"); std::exit(1);
    }
    return output;
}

int main()
{
#if !defined(__aarch64__)
    std::fprintf(stderr, "RAW_JCC_OPONLY_FAIL native AArch64 host required\n");
    return 1;
#endif
    unsigned integer_vectors = 0, fp_vectors = 0, inverted_vectors = 0;
    for (int cc = NATIVE_CC_EQ; cc <= NATIVE_CC_AL; ++cc) {
        for (unsigned nzcv = 0; nzcv < 16; ++nzcv) {
            for (const bool inverted : {false, true}) {
                const auto output = execute(cc, nzcv, inverted);
                const auto expected = integer_holds(cc, nzcv) ? 1ull : 0ull;
                if (output.taken != expected)
                    fail("integer native outcome", expected, output.taken);
                if ((output.nzcv >> 28) != nzcv)
                    fail("integer canonical NZCV", nzcv, output.nzcv >> 28);
                ++integer_vectors;
                if (inverted) ++inverted_vectors;
            }
        }
    }
    for (int cc = NATIVE_CC_F_F; cc <= NATIVE_CC_F_T; ++cc) {
        for (const auto value : {FpClass::Greater, FpClass::Equal,
                 FpClass::Less, FpClass::Unordered}) {
            const unsigned nzcv = fp_nzcv(value);
            for (const bool inverted : {false, true}) {
                const auto output = execute(cc, nzcv, inverted);
                const auto expected = fp_holds(cc, value) ? 1ull : 0ull;
                if (output.taken != expected)
                    fail("FP native outcome", expected, output.taken);
                if ((output.nzcv >> 28) != nzcv)
                    fail("FP canonical NZCV", nzcv, output.nzcv >> 28);
                ++fp_vectors;
                if (inverted) ++inverted_vectors;
            }
        }
    }
    std::printf("METRIC raw_jcc_oponly_boundaries=1\n");
    std::printf("METRIC raw_jcc_oponly_integer_vectors=%u\n", integer_vectors);
    std::printf("METRIC raw_jcc_oponly_fp_vectors=%u\n", fp_vectors);
    std::printf("METRIC raw_jcc_oponly_native_vectors=%u\n", integer_vectors + fp_vectors);
    std::printf("METRIC raw_jcc_oponly_inverted_carry_vectors=%u\n", inverted_vectors);
    std::printf("METRIC raw_jcc_oponly_condition_ids=31\n");
    return integer_vectors == 480 && fp_vectors == 128 &&
        inverted_vectors == 304 ? 0 : 1;
}
