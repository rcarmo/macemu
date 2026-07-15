#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <sys/mman.h>
#include <unistd.h>
#include <vector>

using uae_u32 = std::uint32_t;

/* AArch64 condition-code values consumed by codegen_arm64.h. */
enum {
    NATIVE_CC_EQ = 0, NATIVE_CC_NE = 1, NATIVE_CC_CS = 2, NATIVE_CC_CC = 3,
    NATIVE_CC_MI = 4, NATIVE_CC_PL = 5, NATIVE_CC_VS = 6, NATIVE_CC_VC = 7,
    NATIVE_CC_HI = 8, NATIVE_CC_LS = 9, NATIVE_CC_GE = 10, NATIVE_CC_LT = 11,
    NATIVE_CC_GT = 12, NATIVE_CC_LE = 13,
};

static std::vector<uae_u32> emitted;
static void emit_long(uae_u32 word) { emitted.push_back(word); }

#include "../BasiliskII/src/uae_cpu_2026/compiler/codegen_arm64.h"
#include "../BasiliskII/src/uae_cpu_2026/compiler/arm64_branch_patch.h"

static unsigned exact_words = 0;
static unsigned native_vectors = 0;
static unsigned patch_exact_words = 0;
static unsigned patch_rejections = 0;
static unsigned patch_native_vectors = 0;

[[noreturn]] static void fail(const char *label, std::uint64_t expected, std::uint64_t found)
{
    std::fprintf(stderr, "BRANCH_EMITTER_FAIL label=%s expected=%016llx found=%016llx\n",
        label, static_cast<unsigned long long>(expected),
        static_cast<unsigned long long>(found));
    std::exit(1);
}

static uae_u32 one_word(const char *label)
{
    if (emitted.size() != 1)
        fail(label, 1, emitted.size());
    const uae_u32 word = emitted.front();
    emitted.clear();
    return word;
}

static uae_u32 b_word(int immediate)
{
    emitted.clear();
    B_i(immediate);
    return one_word("B_i emission count");
}

static uae_u32 br_word(unsigned reg)
{
    emitted.clear();
    BR_x(reg);
    return one_word("BR_x emission count");
}

static uae_u32 cc_word(unsigned condition, int immediate)
{
    emitted.clear();
    CC_B_i(condition, immediate);
    return one_word("CC_B_i emission count");
}

static uae_u32 wrapper_word(unsigned condition, int immediate)
{
    emitted.clear();
    switch (condition) {
    case NATIVE_CC_EQ: BEQ_i(immediate); break;
    case NATIVE_CC_NE: BNE_i(immediate); break;
    case NATIVE_CC_CS: BCS_i(immediate); break;
    case NATIVE_CC_CC: BCC_i(immediate); break;
    case NATIVE_CC_MI: BMI_i(immediate); break;
    case NATIVE_CC_PL: BPL_i(immediate); break;
    case NATIVE_CC_VS: BVS_i(immediate); break;
    case NATIVE_CC_VC: BVC_i(immediate); break;
    case NATIVE_CC_HI: BHI_i(immediate); break;
    case NATIVE_CC_LS: BLS_i(immediate); break;
    case NATIVE_CC_GE: BGE_i(immediate); break;
    case NATIVE_CC_LT: BLT_i(immediate); break;
    case NATIVE_CC_GT: BGT_i(immediate); break;
    case NATIVE_CC_LE: BLE_i(immediate); break;
    default: fail("B.cond wrapper condition", 13, condition);
    }
    return one_word("B.cond wrapper emission count");
}

enum class CompareBranch { CbnzW, CbnzX, CbzW, CbzX };
static uae_u32 cb_word(CompareBranch kind, unsigned reg, int immediate)
{
    emitted.clear();
    switch (kind) {
    case CompareBranch::CbnzW: CBNZ_wi(reg, immediate); break;
    case CompareBranch::CbnzX: CBNZ_xi(reg, immediate); break;
    case CompareBranch::CbzW: CBZ_wi(reg, immediate); break;
    case CompareBranch::CbzX: CBZ_xi(reg, immediate); break;
    }
    return one_word("CBZ/CBNZ emission count");
}

enum class TestBranch { TbnzW, TbnzX, TbzW, TbzX };
static uae_u32 tb_word(TestBranch kind, unsigned reg, int bit, int immediate)
{
    emitted.clear();
    switch (kind) {
    case TestBranch::TbnzW: TBNZ_wii(reg, bit, immediate); break;
    case TestBranch::TbnzX: TBNZ_xii(reg, bit, immediate); break;
    case TestBranch::TbzW: TBZ_wii(reg, bit, immediate); break;
    case TestBranch::TbzX: TBZ_xii(reg, bit, immediate); break;
    }
    return one_word("TBZ/TBNZ emission count");
}

static void check_word(const char *label, uae_u32 found, uae_u32 expected)
{
    if (found != expected)
        fail(label, expected, found);
    ++exact_words;
}

static uae_u32 patched_word(const char *label, uae_u32 instruction,
    std::int64_t byte_offset)
{
    uae_u32 patched = 0xa5a5a5a5u;
    const arm64_branch_patch_status status =
        arm64_patch_branch_instruction(instruction, byte_offset, &patched);
    if (status != ARM64_BRANCH_PATCH_OK)
        fail(label, ARM64_BRANCH_PATCH_OK, status);
    return patched;
}

static void check_patch_word(const char *label, uae_u32 instruction,
    std::int64_t byte_offset, uae_u32 expected)
{
    const uae_u32 found = patched_word(label, instruction, byte_offset);
    if (found != expected)
        fail(label, expected, found);
    ++patch_exact_words;
}

static void check_patch_rejection(const char *label, uae_u32 instruction,
    std::int64_t byte_offset, arm64_branch_patch_status expected)
{
    constexpr uae_u32 sentinel = 0xa5a5a5a5u;
    uae_u32 patched = sentinel;
    const arm64_branch_patch_status found =
        arm64_patch_branch_instruction(instruction, byte_offset, &patched);
    if (found != expected)
        fail(label, expected, found);
    if (patched != sentinel)
        fail("rejected patch modified output", sentinel, patched);
    ++patch_rejections;
}

static uae_u32 expected_b(int immediate)
{
    return 0x14000000u | (static_cast<uae_u32>(immediate) & 0x03ffffffu);
}

static uae_u32 expected_cc(unsigned condition, int immediate)
{
    return 0x54000000u
        | ((static_cast<uae_u32>(immediate) & 0x0007ffffu) << 5)
        | condition;
}

static uae_u32 expected_cb(CompareBranch kind, unsigned reg, int immediate)
{
    uae_u32 base = 0;
    switch (kind) {
    case CompareBranch::CbnzW: base = 0x35000000u; break;
    case CompareBranch::CbnzX: base = 0xb5000000u; break;
    case CompareBranch::CbzW: base = 0x34000000u; break;
    case CompareBranch::CbzX: base = 0xb4000000u; break;
    }
    return base | ((static_cast<uae_u32>(immediate) & 0x0007ffffu) << 5) | reg;
}

static uae_u32 expected_tb(TestBranch kind, unsigned reg, unsigned bit, int immediate)
{
    const bool nonzero = kind == TestBranch::TbnzW || kind == TestBranch::TbnzX;
    const bool width64 = kind == TestBranch::TbnzX || kind == TestBranch::TbzX;
    const uae_u32 base = (nonzero ? 0x37000000u : 0x36000000u)
        | (width64 && (bit & 0x20u) ? 0x80000000u : 0u);
    return base | ((bit & 0x1fu) << 19)
        | ((static_cast<uae_u32>(immediate) & 0x3fffu) << 5) | reg;
}

static std::uint64_t run(const std::vector<uae_u32> &words, std::uint64_t argument)
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
    const std::uint64_t result = reinterpret_cast<Fn>(page)(argument);
    if (munmap(page, static_cast<std::size_t>(page_size)) != 0) {
        std::perror("munmap");
        std::exit(1);
    }
    return result;
}

static void check_native(const char *label, const std::vector<uae_u32> &words,
    std::uint64_t argument, std::uint64_t expected)
{
    const std::uint64_t found = run(words, argument);
    if (found != expected)
        fail(label, expected, found);
    ++native_vectors;
}

static void check_patch_native(const char *label, const std::vector<uae_u32> &words,
    std::uint64_t argument, std::uint64_t expected)
{
    const std::uint64_t found = run(words, argument);
    if (found != expected)
        fail(label, expected, found);
    ++patch_native_vectors;
}

static bool condition_holds(unsigned condition, unsigned nzcv)
{
    const bool n = (nzcv & 8u) != 0;
    const bool z = (nzcv & 4u) != 0;
    const bool c = (nzcv & 2u) != 0;
    const bool v = (nzcv & 1u) != 0;
    switch (condition) {
    case NATIVE_CC_EQ: return z;
    case NATIVE_CC_NE: return !z;
    case NATIVE_CC_CS: return c;
    case NATIVE_CC_CC: return !c;
    case NATIVE_CC_MI: return n;
    case NATIVE_CC_PL: return !n;
    case NATIVE_CC_VS: return v;
    case NATIVE_CC_VC: return !v;
    case NATIVE_CC_HI: return c && !z;
    case NATIVE_CC_LS: return !c || z;
    case NATIVE_CC_GE: return n == v;
    case NATIVE_CC_LT: return n != v;
    case NATIVE_CC_GT: return !z && n == v;
    case NATIVE_CC_LE: return z || n != v;
    default: return false;
    }
}

static std::uint64_t run_br_to_local_target()
{
    constexpr uae_u32 mov_w0_1234 = 0x52824680u;
    constexpr uae_u32 ret = 0xd65f03c0u;
    const std::vector<uae_u32> words{br_word(0), ret, mov_w0_1234, ret};
    const long page_size = sysconf(_SC_PAGESIZE);
    if (page_size <= 0)
        fail("BR executable page size", 1, 0);
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
    const auto target = reinterpret_cast<std::uint64_t>(static_cast<char *>(page) + 8);
    const std::uint64_t result = reinterpret_cast<Fn>(page)(target);
    if (munmap(page, static_cast<std::size_t>(page_size)) != 0) {
        std::perror("munmap");
        std::exit(1);
    }
    return result;
}

int main()
{
#if !defined(__aarch64__)
    std::fprintf(stderr, "BRANCH_EMITTER_FAIL native AArch64 host required\n");
    return 1;
#endif
    constexpr uae_u32 mov_w0_0 = 0x52800000u;
    constexpr uae_u32 mov_w0_1 = 0x52800020u;
    constexpr uae_u32 ret = 0xd65f03c0u;

    for (const int immediate : {0, 1, -1, 0x1ffffff, -0x2000000})
        check_word("B_i signed range", b_word(immediate), expected_b(immediate));
    for (const unsigned reg : {0u, 17u, 30u})
        check_word("BR_x register field", br_word(reg), 0xd61f0000u | (reg << 5));

    for (unsigned condition = 0; condition < 16; ++condition)
        check_word("CC_B_i condition field", cc_word(condition, -1), expected_cc(condition, -1));
    check_word("CC_B_i positive range edge", cc_word(NATIVE_CC_EQ, 0x3ffff), expected_cc(NATIVE_CC_EQ, 0x3ffff));
    check_word("CC_B_i negative range edge", cc_word(NATIVE_CC_LE, -0x40000), expected_cc(NATIVE_CC_LE, -0x40000));
    for (unsigned condition = 0; condition < 14; ++condition)
        check_word("B.cond wrapper exact", wrapper_word(condition, -1), expected_cc(condition, -1));

    for (const auto kind : {CompareBranch::CbnzW, CompareBranch::CbnzX,
             CompareBranch::CbzW, CompareBranch::CbzX}) {
        check_word("CBZ/CBNZ positive range edge", cb_word(kind, 31, 0x3ffff),
            expected_cb(kind, 31, 0x3ffff));
        check_word("CBZ/CBNZ negative range edge", cb_word(kind, 31, -0x40000),
            expected_cb(kind, 31, -0x40000));
    }

    for (const auto kind : {TestBranch::TbnzW, TestBranch::TbnzX,
             TestBranch::TbzW, TestBranch::TbzX}) {
        const unsigned bit = kind == TestBranch::TbnzX || kind == TestBranch::TbzX ? 63u : 31u;
        check_word("TBZ/TBNZ positive range edge", tb_word(kind, 31, bit, 0x1fff),
            expected_tb(kind, 31, bit, 0x1fff));
        check_word("TBZ/TBNZ negative range edge", tb_word(kind, 31, bit, -0x2000),
            expected_tb(kind, 31, bit, -0x2000));
    }

    check_patch_word("patch B positive edge", expected_b(-1), 0x7fffffc,
        expected_b(0x1ffffff));
    check_patch_word("patch B negative edge", expected_b(1), -0x8000000,
        expected_b(-0x2000000));
    check_patch_word("patch TBNZ imm14 positive edge",
        expected_tb(TestBranch::TbnzX, 31, 63, -1), 0x7ffc,
        expected_tb(TestBranch::TbnzX, 31, 63, 0x1fff));
    check_patch_word("patch TBZ imm14 negative edge",
        expected_tb(TestBranch::TbzW, 7, 31, 1), -0x8000,
        expected_tb(TestBranch::TbzW, 7, 31, -0x2000));
    check_patch_word("patch CBNZ imm19 positive edge",
        expected_cb(CompareBranch::CbnzX, 19, -1), 0xffffc,
        expected_cb(CompareBranch::CbnzX, 19, 0x3ffff));
    check_patch_word("patch CBZ imm19 negative edge",
        expected_cb(CompareBranch::CbzW, 5, 1), -0x100000,
        expected_cb(CompareBranch::CbzW, 5, -0x40000));
    check_patch_word("patch B.cond imm19 positive edge",
        expected_cc(NATIVE_CC_LE, -1), 0xffffc,
        expected_cc(NATIVE_CC_LE, 0x3ffff));
    check_patch_word("patch B.cond imm19 negative edge",
        expected_cc(NATIVE_CC_NE, 1), -0x100000,
        expected_cc(NATIVE_CC_NE, -0x40000));

    check_patch_rejection("patch unaligned", expected_b(0), 2,
        ARM64_BRANCH_PATCH_UNALIGNED);
    check_patch_rejection("patch B positive overflow", expected_b(0), 0x8000000,
        ARM64_BRANCH_PATCH_B_RANGE);
    check_patch_rejection("patch B negative overflow", expected_b(0), -0x8000004,
        ARM64_BRANCH_PATCH_B_RANGE);
    check_patch_rejection("patch TB positive overflow",
        expected_tb(TestBranch::TbzW, 0, 0, 0), 0x8000, ARM64_BRANCH_PATCH_TB_RANGE);
    check_patch_rejection("patch TB negative overflow",
        expected_tb(TestBranch::TbnzX, 0, 63, 0), -0x8004, ARM64_BRANCH_PATCH_TB_RANGE);
    check_patch_rejection("patch CB positive overflow",
        expected_cb(CompareBranch::CbzW, 0, 0), 0x100000, ARM64_BRANCH_PATCH_CB_RANGE);
    check_patch_rejection("patch CB negative overflow",
        expected_cb(CompareBranch::CbnzX, 0, 0), -0x100004, ARM64_BRANCH_PATCH_CB_RANGE);
    check_patch_rejection("patch B.cond positive overflow",
        expected_cc(NATIVE_CC_EQ, 0), 0x100000, ARM64_BRANCH_PATCH_BCOND_RANGE);
    check_patch_rejection("patch B.cond negative overflow",
        expected_cc(NATIVE_CC_VS, 0), -0x100004, ARM64_BRANCH_PATCH_BCOND_RANGE);
    check_patch_rejection("patch unsupported BR", br_word(0), 4,
        ARM64_BRANCH_PATCH_UNSUPPORTED);

    check_native("B_i forward/backward", {b_word(3), mov_w0_1, ret, b_word(-2)}, 0, 1);
    if (run_br_to_local_target() != 0x1234u)
        fail("BR_x local target", 0x1234, run_br_to_local_target());
    ++native_vectors;

    const uae_u32 msr_nzcv_x0 = [] {
        emitted.clear();
        MSR_NZCV_x(0);
        return one_word("MSR NZCV emission count");
    }();
    for (unsigned condition = 0; condition < 14; ++condition) {
        for (unsigned nzcv = 0; nzcv < 16; ++nzcv) {
            const std::uint64_t expected = condition_holds(condition, nzcv) ? 1 : 0;
            check_native("B.cond taken/not-taken",
                {msr_nzcv_x0, wrapper_word(condition, 3), mov_w0_0, ret, mov_w0_1, ret},
                static_cast<std::uint64_t>(nzcv) << 28, expected);
        }
    }

    constexpr uae_u32 mov_w1_0 = 0x52800001u;
    constexpr uae_u32 add_w1_w1_1 = 0x11000421u;
    constexpr uae_u32 cmp_w1_2 = 0x7100083fu;
    constexpr uae_u32 mov_w0_w1 = 0x2a0103e0u;
    check_native("BNE_i negative displacement",
        {mov_w1_0, add_w1_w1_1, cmp_w1_2, wrapper_word(NATIVE_CC_NE, -2), mov_w0_w1, ret},
        0, 2);

    check_patch_native("patched B native route",
        {patched_word("patch B native", b_word(0), 12), mov_w0_0, ret, mov_w0_1, ret},
        0, 1);
    check_patch_native("patched B.cond native loop",
        {mov_w1_0, add_w1_w1_1, cmp_w1_2,
         patched_word("patch B.cond native", wrapper_word(NATIVE_CC_NE, 0), -8),
         mov_w0_w1, ret}, 0, 2);
    check_patch_native("patched CBZ native route",
        {patched_word("patch CB native", cb_word(CompareBranch::CbzX, 0, 0), 12),
         mov_w0_0, ret, mov_w0_1, ret}, 0, 1);
    check_patch_native("patched TBNZ native route",
        {patched_word("patch TB native", tb_word(TestBranch::TbnzX, 0, 63, 0), 12),
         mov_w0_0, ret, mov_w0_1, ret}, 0x8000000000000000ull, 1);

    struct CbCase { CompareBranch kind; std::uint64_t value; bool taken; };
    for (const auto &test : std::vector<CbCase>{
        {CompareBranch::CbzW, 0, true}, {CompareBranch::CbzW, 1, false},
        {CompareBranch::CbzW, 0x100000000ull, true},
        {CompareBranch::CbnzW, 0, false}, {CompareBranch::CbnzW, 1, true},
        {CompareBranch::CbnzW, 0x100000000ull, false},
        {CompareBranch::CbzX, 0, true}, {CompareBranch::CbzX, 1, false},
        {CompareBranch::CbzX, 0x100000000ull, false},
        {CompareBranch::CbnzX, 0, false}, {CompareBranch::CbnzX, 1, true},
        {CompareBranch::CbnzX, 0x100000000ull, true},
    }) {
        check_native("CBZ/CBNZ width and route",
            {cb_word(test.kind, 0, 3), mov_w0_0, ret, mov_w0_1, ret},
            test.value, test.taken ? 1 : 0);
    }

    struct TbCase { TestBranch kind; unsigned bit; std::uint64_t value; bool taken; };
    for (const auto &test : std::vector<TbCase>{
        {TestBranch::TbzW, 31, 0, true}, {TestBranch::TbzW, 31, 0x80000000u, false},
        {TestBranch::TbzW, 31, 0x100000000ull, true},
        {TestBranch::TbnzW, 0, 0, false}, {TestBranch::TbnzW, 0, 1, true},
        {TestBranch::TbnzW, 0, 0x100000000ull, false},
        {TestBranch::TbzX, 32, 0, true}, {TestBranch::TbzX, 32, 0x100000000ull, false},
        {TestBranch::TbzX, 32, 1, true},
        {TestBranch::TbnzX, 63, 0, false}, {TestBranch::TbnzX, 63, 0x8000000000000000ull, true},
        {TestBranch::TbnzX, 63, 0x80000000u, false},
    }) {
        check_native("TBZ/TBNZ bit, width, and route",
            {tb_word(test.kind, 0, test.bit, 3), mov_w0_0, ret, mov_w0_1, ret},
            test.value, test.taken ? 1 : 0);
    }

    std::printf("METRIC emitter_branch_exact_words=%u\n", exact_words);
    std::printf("METRIC emitter_branch_native_vectors=%u\n", native_vectors);
    std::printf("METRIC emitter_branch_patch_exact_words=%u\n", patch_exact_words);
    std::printf("METRIC emitter_branch_patch_rejections=%u\n", patch_rejections);
    std::printf("METRIC emitter_branch_patch_native_vectors=%u\n", patch_native_vectors);
    std::printf("METRIC emitter_branch_condition_vectors=224\n");
    std::printf("METRIC emitter_branch_signed_range_edges=8\n");
    std::printf("METRIC emitter_branch_width32=1\n");
    std::printf("METRIC emitter_branch_width64=1\n");
    return exact_words == 56 && native_vectors == 251 &&
        patch_exact_words == 8 && patch_rejections == 10 && patch_native_vectors == 4 ? 0 : 1;
}
