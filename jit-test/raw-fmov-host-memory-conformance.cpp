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
using MEMW = uintptr;
using MEMR = uintptr;
using FW = uae_u32;
using FR = uae_u32;

struct alignas(16) SyntheticRegs { std::array<uae_u8, 32776> bytes{}; };
static SyntheticRegs regs;

static std::vector<uae_u32> emitted;
static void emit_long(uae_u32 word) { emitted.push_back(word); }
#include "codegen_arm64.h"

#define R_REGSTRUCT 28
#define REG_WORK1 2
#define STATIC_INLINE static inline
#define LOWFUNC(flags,mem,nargs,func,args) static inline void func args
#define LENDFUNC(flags,mem,nargs,func,args)

#include "raw-fmov-host-memory.inc"

struct Output { std::uint64_t bits; std::uint64_t nzcv; };
enum class Direction { Store, Load };

[[noreturn]] static void fail(const char *label, std::uint64_t expected, std::uint64_t found)
{
    std::fprintf(stderr, "RAW_FMOV_HOST_MEMORY_FAIL label=%s expected=%016llx found=%016llx\n",
        label, static_cast<unsigned long long>(expected),
        static_cast<unsigned long long>(found));
    std::exit(1);
}

static bool direct_address(uintptr address)
{
    const uintptr base = reinterpret_cast<uintptr>(&regs);
    return address >= base && address < base + 32760 && ((address - base) & 7) == 0;
}

static uae_u32 expected_memory_word(Direction direction, unsigned fpreg,
    unsigned base, unsigned offset)
{
    const uae_u32 opcode = direction == Direction::Store ? 0xfd000000u : 0xfd400000u;
    return opcode | ((offset / 8) << 10) | (base << 5) | fpreg;
}

static void emit_boundary(Direction direction, uintptr address, unsigned fpreg)
{
    if (direction == Direction::Store)
        compemu_raw_fmov_mr_drop(address, fpreg);
    else
        compemu_raw_fmov_rm(fpreg, address);
}

static void emit_prologue()
{
    STP_xxXpre(28, 30, 31, -16);
    SUB_xxi(31, 31, 64);
    for (unsigned reg = 8; reg <= 15; ++reg)
        STR_dXi(reg, 31, (reg - 8) * 8);
    MOV_xx(28, 1);
}

static void emit_epilogue()
{
    for (unsigned reg = 8; reg <= 15; ++reg)
        LDR_dXi(reg, 31, (reg - 8) * 8);
    ADD_xxi(31, 31, 64);
    LDP_xxXpost(28, 30, 31, 16);
    emitted.push_back(0xd65f03c0u); // RET
}

static Output execute(Direction direction, uintptr address, unsigned fpreg,
    std::uint64_t input, std::uint64_t hostile_nzcv)
{
    emitted.clear();
    emit_prologue();
    if (direction == Direction::Store)
        FMOV_dx(fpreg, 0);
    MSR_NZCV_x(2);
    emit_boundary(direction, address, fpreg);
    if (direction == Direction::Load)
        FMOV_xd(4, fpreg);
    MRS_NZCV_x(5);
    if (direction == Direction::Load)
        STR_xXi(4, 3, 0);
    STR_xXi(5, 3, 8);
    emit_epilogue();

    const long page_size = sysconf(_SC_PAGESIZE);
    if (page_size <= 0 || emitted.size() * sizeof(uae_u32) > static_cast<std::size_t>(page_size))
        fail("executable page size", 1, emitted.size() * sizeof(uae_u32));
    void *page = mmap(nullptr, static_cast<std::size_t>(page_size),
        PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (page == MAP_FAILED) { std::perror("mmap code"); std::exit(1); }
    std::memcpy(page, emitted.data(), emitted.size() * sizeof(uae_u32));
    if (mprotect(page, static_cast<std::size_t>(page_size), PROT_READ | PROT_EXEC) != 0) {
        std::perror("mprotect code"); std::exit(1);
    }
    __builtin___clear_cache(static_cast<char *>(page),
        static_cast<char *>(page) + emitted.size() * sizeof(uae_u32));
    Output output{};
    using Fn = void (*)(std::uint64_t, void *, std::uint64_t, Output *);
    reinterpret_cast<Fn>(page)(input, &regs, hostile_nzcv, &output);
    if (munmap(page, static_cast<std::size_t>(page_size)) != 0) {
        std::perror("munmap code"); std::exit(1);
    }
    return output;
}

int main()
{
#if !defined(__aarch64__)
    std::fprintf(stderr, "RAW_FMOV_HOST_MEMORY_FAIL native AArch64 host required\n");
    return 1;
#endif
    const uintptr base = reinterpret_cast<uintptr>(&regs);
    const std::array<unsigned, 2> offsets{{0, 32752}};
    unsigned direct_exact_words = 0;
    for (const auto direction : {Direction::Store, Direction::Load}) {
        for (const unsigned offset : offsets) {
            for (unsigned fpreg = 0; fpreg < 32; ++fpreg) {
                emitted.clear();
                emit_boundary(direction, base + offset, fpreg);
                if (emitted.size() != 1) fail("direct emission count", 1, emitted.size());
                const auto expected = expected_memory_word(direction, fpreg, 28, offset);
                if (emitted[0] != expected) fail("direct exact word", expected, emitted[0]);
                ++direct_exact_words;
            }
        }
    }

    const long page_size = sysconf(_SC_PAGESIZE);
    void *external_page = mmap(nullptr, static_cast<std::size_t>(page_size),
        PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (external_page == MAP_FAILED) { std::perror("mmap data"); return 1; }
    const uintptr external = reinterpret_cast<uintptr>(external_page) + 64;
    if (direct_address(external)) fail("external address classified direct", 0, 1);

    unsigned fallback_shapes = 0;
    for (const auto direction : {Direction::Store, Direction::Load}) {
        for (const uintptr address : {external, base + 1, base + 32760}) {
            for (const unsigned fpreg : {0u, 7u, 8u, 15u, 31u}) {
                emitted.clear(); emit_boundary(direction, address, fpreg);
                if (emitted.size() < 2 || emitted.size() > 5)
                    fail("fallback emission count", 2, emitted.size());
                const auto expected = expected_memory_word(direction, fpreg, 2, 0);
                if (emitted.back() != expected) fail("fallback terminal word", expected, emitted.back());
                ++fallback_shapes;
            }
        }
    }

    constexpr std::array<std::uint64_t, 10> values{{
        0x0000000000000000ull, 0x8000000000000000ull,
        0x0000000000000001ull, 0x7fefffffffffffffull,
        0x7ff0000000000000ull, 0xfff0000000000000ull,
        0x7ff0000000000001ull, 0xfff8deadbeef1234ull,
        0x0123456789abcdefull, 0xfedcba9876543210ull,
    }};
    struct RuntimeCase { uintptr address; unsigned fpreg; };
    const std::array<RuntimeCase, 6> runtime_cases{{
        {base, 0}, {base + 32752, 7}, {base + 8, 8},
        {external, 15}, {base + 32760, 31}, {base + 1, 6},
    }};
    unsigned store_vectors = 0, load_vectors = 0;
    unsigned caller_saved_fp = 0, callee_saved_fp = 0;
    unsigned index = 0;
    for (const auto &test : runtime_cases) {
        for (const auto bits : values) {
            const std::uint64_t hostile = (index++ & 1) ? 0xb0000000ull : 0x50000000ull;
            std::uint64_t poison = ~bits;
            std::memcpy(reinterpret_cast<void *>(test.address), &poison, sizeof(poison));
            const auto stored = execute(Direction::Store, test.address, test.fpreg, bits, hostile);
            std::uint64_t found = 0;
            std::memcpy(&found, reinterpret_cast<const void *>(test.address), sizeof(found));
            if (found != bits) fail("native store payload", bits, found);
            if ((stored.nzcv & 0xf0000000ull) != hostile)
                fail("native store NZCV", hostile, stored.nzcv & 0xf0000000ull);
            ++store_vectors;

            std::memcpy(reinterpret_cast<void *>(test.address), &bits, sizeof(bits));
            const auto loaded = execute(Direction::Load, test.address, test.fpreg, 0, hostile);
            if (loaded.bits != bits) fail("native load payload", bits, loaded.bits);
            if ((loaded.nzcv & 0xf0000000ull) != hostile)
                fail("native load NZCV", hostile, loaded.nzcv & 0xf0000000ull);
            ++load_vectors;
            if (test.fpreg >= 8 && test.fpreg <= 15) ++callee_saved_fp;
            else ++caller_saved_fp;
        }
    }
    if (munmap(external_page, static_cast<std::size_t>(page_size)) != 0) {
        std::perror("munmap data"); return 1;
    }

    std::printf("METRIC raw_fmov_host_memory_boundaries=2\n");
    std::printf("METRIC raw_fmov_host_memory_direct_exact_words=%u\n", direct_exact_words);
    std::printf("METRIC raw_fmov_host_memory_fallback_shapes=%u\n", fallback_shapes);
    std::printf("METRIC raw_fmov_host_memory_store_vectors=%u\n", store_vectors);
    std::printf("METRIC raw_fmov_host_memory_load_vectors=%u\n", load_vectors);
    std::printf("METRIC raw_fmov_host_memory_bit_classes=%zu\n", values.size());
    std::printf("METRIC raw_fmov_host_memory_caller_saved_fp_vectors=%u\n", caller_saved_fp);
    std::printf("METRIC raw_fmov_host_memory_callee_saved_fp_vectors=%u\n", callee_saved_fp);
    return direct_exact_words == 128 && fallback_shapes == 30 &&
        store_vectors == 60 && load_vectors == 60 &&
        caller_saved_fp == 40 && callee_saved_fp == 20 ? 0 : 1;
}
