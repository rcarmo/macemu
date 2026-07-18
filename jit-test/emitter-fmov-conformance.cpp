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
    std::uint64_t destination;
    std::uint64_t source;
    std::uint64_t nzcv;
    std::uint64_t fpcr;
    std::uint64_t fpsr;
};

static void fail(const char *label, std::uint64_t expected, std::uint64_t found)
{
    std::fprintf(stderr, "FMOV_EMITTER_FAIL label=%s expected=%016llx found=%016llx\n",
        label, static_cast<unsigned long long>(expected),
        static_cast<unsigned long long>(found));
    std::exit(1);
}

static uae_u32 fmov_dd_word(unsigned d, unsigned s)
{
    emitted.clear();
    FMOV_dd(d, s);
    if (emitted.size() != 1)
        fail("FMOV_dd emission count", 1, emitted.size());
    return emitted.front();
}

static Result run(unsigned d, unsigned s, std::uint64_t source,
    std::uint64_t initial_destination, std::uint64_t nzcv,
    std::uint64_t fpcr, std::uint64_t fpsr)
{
    emitted.clear();
    // d8-d15 are callee-saved low halves under AAPCS64. Preserve them so the
    // complete register-field sweep remains a valid C++ callable fixture.
    SUB_xxi(31, 31, 64);
    for (unsigned reg = 8; reg <= 15; ++reg)
        STR_dXi(reg, 31, (reg - 8) * 8);
    MRS_FPCR_x(14);
    MRS_FPSR_x(15);
    FMOV_dx(s, 1);
    FMOV_dx(d, 2);
    MSR_NZCV_x(3);
    MSR_FPCR_x(4);
    MSR_FPSR_x(5);
    FMOV_dd(d, s);
    FMOV_xd(9, d);
    FMOV_xd(10, s);
    MRS_NZCV_x(11);
    MRS_FPCR_x(12);
    MRS_FPSR_x(13);
    STR_xXi(9, 0, 0);
    STR_xXi(10, 0, 8);
    STR_xXi(11, 0, 16);
    STR_xXi(12, 0, 24);
    STR_xXi(13, 0, 32);
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
    if (page == MAP_FAILED) {
        std::perror("mmap");
        std::exit(1);
    }
    std::memcpy(page, emitted.data(), emitted.size() * sizeof(uae_u32));
    if (mprotect(page, static_cast<std::size_t>(page_size), PROT_READ | PROT_EXEC) != 0) {
        std::perror("mprotect");
        std::exit(1);
    }
    __builtin___clear_cache(static_cast<char *>(page),
        static_cast<char *>(page) + emitted.size() * sizeof(uae_u32));

    Result result{};
    using Fn = void (*)(Result *, std::uint64_t, std::uint64_t,
        std::uint64_t, std::uint64_t, std::uint64_t);
    reinterpret_cast<Fn>(page)(&result, source, initial_destination, nzcv, fpcr, fpsr);
    if (munmap(page, static_cast<std::size_t>(page_size)) != 0) {
        std::perror("munmap");
        std::exit(1);
    }
    return result;
}

int main()
{
#if !defined(__aarch64__)
    std::fprintf(stderr, "FMOV_EMITTER_FAIL native AArch64 host required\n");
    return 1;
#endif
    unsigned exact_words = 0;
    for (unsigned d = 0; d < 32; ++d) {
        for (unsigned s = 0; s < 32; ++s) {
            const uae_u32 expected = 0x1e604000u | (s << 5) | d;
            const uae_u32 found = fmov_dd_word(d, s);
            if (found != expected)
                fail("FMOV_dd exact 32x32 word", expected, found);
            ++exact_words;
        }
    }

    constexpr std::array<std::uint64_t, 10> values = {{
        0x0000000000000000ull, // +0
        0x8000000000000000ull, // -0
        0x0000000000000001ull, // minimum subnormal
        0x7fefffffffffffffull, // maximum finite
        0x7ff0000000000000ull, // +infinity
        0xfff0000000000000ull, // -infinity
        0x7ff0000000000001ull, // signalling NaN payload
        0xfff8deadbeef1234ull, // negative quiet NaN payload
        0x0123456789abcdefull,
        0xfedcba9876543210ull,
    }};
    constexpr std::uint64_t initial_destination = 0x55aa33cc0f0ff0f0ull;
    constexpr std::uint64_t initial_nzcv = 0xb0000000ull;
    constexpr std::uint64_t initial_fpcr = 0x00c00000ull;
    constexpr std::uint64_t initial_fpsr = 0x0800009full;
    unsigned native_vectors = 0;
    unsigned self_alias_vectors = 0;
    for (unsigned d = 0; d < 32; ++d) {
        for (unsigned s = 0; s < 32; ++s) {
            for (const std::uint64_t value : values) {
                const Result result = run(d, s, value, initial_destination,
                    initial_nzcv, initial_fpcr, initial_fpsr);
                const std::uint64_t expected = d == s ? initial_destination : value;
                if (result.destination != expected)
                    fail("FMOV_dd native destination bits", expected, result.destination);
                if (result.source != expected)
                    fail("FMOV_dd native source bits", expected, result.source);
                if ((result.nzcv & 0xf0000000ull) != initial_nzcv)
                    fail("FMOV_dd preserves NZCV", initial_nzcv, result.nzcv & 0xf0000000ull);
                if (result.fpcr != initial_fpcr)
                    fail("FMOV_dd preserves FPCR", initial_fpcr, result.fpcr);
                if (result.fpsr != initial_fpsr)
                    fail("FMOV_dd preserves FPSR", initial_fpsr, result.fpsr);
                ++native_vectors;
                if (d == s) ++self_alias_vectors;
            }
        }
    }

    std::printf("METRIC emitter_fmov_exact_words=%u\n", exact_words);
    std::printf("METRIC emitter_fmov_native_vectors=%u\n", native_vectors);
    std::printf("METRIC emitter_fmov_self_alias_vectors=%u\n", self_alias_vectors);
    std::printf("METRIC emitter_fmov_bit_classes=%zu\n", values.size());
    return exact_words == 1024 && native_vectors == 10240 &&
        self_alias_vectors == 320 && values.size() == 10 ? 0 : 1;
}
