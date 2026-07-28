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
using IMPTR = uintptr;
using RR4 = unsigned;
using W4 = unsigned;

struct alignas(16) SyntheticRegs {
    uae_u8 *pc_p;
    uae_u8 *pc_oldp;
    std::array<uae_u8, 16400 - 16> bytes{};
};
static SyntheticRegs regs;

static std::vector<uae_u32> emitted;
static void emit_long(uae_u32 word) { emitted.push_back(word); }
#include "codegen_arm64.h"

#define R_REGSTRUCT 28
#define REG_WORK1 2
#define REG_WORK2 3
#define STATIC_INLINE static inline
#define LOWFUNC(flags,mem,nargs,func,args) static inline void func args
#define LENDFUNC(flags,mem,nargs,func,args)
#include "raw-mov-host-memory.inc"

struct Output { std::uint64_t value; std::uint64_t nzcv; };
enum class Op { ImmediateStore, RegisterStore, Load };

[[noreturn]] static void fail(const char *label, std::uint64_t expected,
    std::uint64_t found)
{
    std::fprintf(stderr,
        "RAW_MOV_HOST_MEMORY_FAIL label=%s expected=%016llx found=%016llx\n",
        label, static_cast<unsigned long long>(expected),
        static_cast<unsigned long long>(found));
    std::exit(1);
}

static bool pointer_address(uintptr address)
{
    return address == reinterpret_cast<uintptr>(&regs.pc_p) ||
        address == reinterpret_cast<uintptr>(&regs.pc_oldp);
}

static void emit_boundary(Op op, uintptr address, std::uint64_t value,
    unsigned reg)
{
    switch (op) {
    case Op::ImmediateStore:
        compemu_raw_mov_l_mi(address, static_cast<uintptr>(value));
        break;
    case Op::RegisterStore:
        compemu_raw_mov_l_mr(address, reg);
        break;
    case Op::Load:
        compemu_raw_mov_l_rm(reg, address);
        break;
    }
}

static void emit_prologue()
{
    STP_xxXpre(19, 20, 31, -16);
    STP_xxXpre(28, 30, 31, -16);
    MOV_xx(19, 0); // output survives production scratch-register use
    MOV_xx(20, 3); // synthetic regs base survives production scratch use
    MOV_xx(28, 3);
}

static void emit_epilogue()
{
    LDP_xxXpost(28, 30, 31, 16);
    LDP_xxXpost(19, 20, 31, 16);
    emitted.push_back(0xd65f03c0u); // RET
}

static Output execute(Op op, uintptr address, std::uint64_t value,
    std::uint64_t hostile_nzcv, unsigned reg)
{
    emitted.clear();
    emit_prologue();
    MSR_NZCV_x(2);
    if (op == Op::RegisterStore && reg != 1)
        MOV_xx(reg, 1);
    emit_boundary(op, address, value, reg);
    if (op == Op::Load) {
        STR_xXi(reg, 19, 0);
    } else {
        if (pointer_address(address))
            LDR_xXi(4, 20, address - reinterpret_cast<uintptr>(&regs));
        else
            LOAD_U64(4, address), LDR_wXi(4, 4, 0);
        STR_xXi(4, 19, 0);
    }
    MRS_NZCV_x(5);
    STR_xXi(5, 19, 8);
    emit_epilogue();

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
    using Fn = void (*)(Output *, std::uint64_t, std::uint64_t, void *);
    reinterpret_cast<Fn>(page)(&output, value, hostile_nzcv, &regs);
    if (munmap(page, static_cast<std::size_t>(page_size)) != 0) {
        std::perror("munmap code"); std::exit(1);
    }
    return output;
}

static void poison(uintptr address, std::uint64_t value, bool pointer)
{
    if (pointer)
        std::memcpy(reinterpret_cast<void *>(address), &value, sizeof(value));
    else {
        const auto word = static_cast<uae_u32>(value);
        std::memcpy(reinterpret_cast<void *>(address), &word, sizeof(word));
    }
}

int main()
{
#if !defined(__aarch64__)
    std::fprintf(stderr,
        "RAW_MOV_HOST_MEMORY_FAIL native AArch64 host required\n");
    return 1;
#endif
    const uintptr base = reinterpret_cast<uintptr>(&regs);
    const long page_size = sysconf(_SC_PAGESIZE);
    void *external_page = mmap(nullptr, static_cast<std::size_t>(page_size),
        PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (external_page == MAP_FAILED) { std::perror("mmap data"); return 1; }
    const uintptr external = reinterpret_cast<uintptr>(external_page) + 64;
    struct AddressCase { uintptr address; bool pointer; bool direct32; };
    const std::array<AddressCase, 6> addresses{{
        {reinterpret_cast<uintptr>(&regs.pc_p), true, false},
        {reinterpret_cast<uintptr>(&regs.pc_oldp), true, false},
        {base + 16, false, true}, {base + 16380, false, true},
        {base + 17, false, false}, {external, false, false},
    }};
    constexpr std::array<std::uint64_t, 5> values{{
        0x0000000000000000ull, 0x00000000ffffffffull,
        0x0000000100000001ull, 0x123456789abcdef0ull,
        0xffff000080000001ull,
    }};

    unsigned exact_shapes = 0, immediate_vectors = 0, register_vectors = 0;
    unsigned load_vectors = 0, pointer_vectors = 0, direct32_vectors = 0;
    unsigned absolute_vectors = 0, hostile_index = 0;
    for (const auto &target : addresses) {
        for (const auto value : values) {
            const std::uint64_t hostile = (hostile_index++ & 1)
                ? 0xb0000000ull : 0x50000000ull;
            const std::uint64_t expected = target.pointer
                ? value : static_cast<uae_u32>(value);
            poison(target.address, ~value, target.pointer);
            const auto immediate = execute(Op::ImmediateStore, target.address,
                value, hostile, 6);
            if (immediate.value != expected)
                fail("native immediate-store payload", expected, immediate.value);
            if ((immediate.nzcv & 0xf0000000ull) != hostile)
                fail("native immediate-store NZCV", hostile,
                    immediate.nzcv & 0xf0000000ull);
            ++immediate_vectors;
            for (const unsigned reg : {1u, 2u, 6u}) {
                poison(target.address, ~value, target.pointer);
                const auto stored = execute(Op::RegisterStore, target.address,
                    value, hostile, reg);
                if (stored.value != expected)
                    fail("native register-store payload", expected, stored.value);
                if ((stored.nzcv & 0xf0000000ull) != hostile)
                    fail("native register-store NZCV", hostile,
                        stored.nzcv & 0xf0000000ull);
                ++register_vectors;
            }
            poison(target.address, value, target.pointer);
            const auto loaded = execute(Op::Load, target.address, 0, hostile, 6);
            if (loaded.value != expected)
                fail("native load payload", expected, loaded.value);
            if ((loaded.nzcv & 0xf0000000ull) != hostile)
                fail("native load NZCV", hostile,
                    loaded.nzcv & 0xf0000000ull);
            ++load_vectors;
            if (target.pointer) ++pointer_vectors;
            else if (target.direct32) ++direct32_vectors;
            else ++absolute_vectors;
        }
    }

    for (const auto &target : addresses) {
        for (const auto op : {Op::ImmediateStore, Op::RegisterStore, Op::Load}) {
            emitted.clear();
            emit_boundary(op, target.address, 0x123456789abcdef0ull, 6);
            const bool direct = target.pointer || target.direct32;
            if (direct && emitted.size() > 5)
                fail("direct exact shape maximum", 5, emitted.size());
            if (!direct && emitted.size() < 2)
                fail("absolute exact shape minimum", 2, emitted.size());
            const uae_u32 terminal = emitted.back();
            const uae_u32 expected_class = op == Op::Load
                ? (target.pointer ? 0xf9400000u : 0xb9400000u)
                : (target.pointer ? 0xf9000000u : 0xb9000000u);
            const uae_u32 class_mask = target.pointer ? 0xffc00000u : 0xffc00000u;
            if ((terminal & class_mask) != expected_class)
                fail("terminal load/store width", expected_class,
                    terminal & class_mask);
            ++exact_shapes;
        }
    }
    if (munmap(external_page, static_cast<std::size_t>(page_size)) != 0) {
        std::perror("munmap data"); return 1;
    }

    std::printf("METRIC raw_mov_host_memory_boundaries=3\n");
    std::printf("METRIC raw_mov_host_memory_exact_shapes=%u\n", exact_shapes);
    std::printf("METRIC raw_mov_host_memory_immediate_vectors=%u\n", immediate_vectors);
    std::printf("METRIC raw_mov_host_memory_register_vectors=%u\n", register_vectors);
    std::printf("METRIC raw_mov_host_memory_load_vectors=%u\n", load_vectors);
    std::printf("METRIC raw_mov_host_memory_pointer_vectors=%u\n", pointer_vectors);
    std::printf("METRIC raw_mov_host_memory_direct32_vectors=%u\n", direct32_vectors);
    std::printf("METRIC raw_mov_host_memory_absolute_vectors=%u\n", absolute_vectors);
    std::printf("METRIC raw_mov_host_memory_nzcv_preserved=1\n");
    return exact_shapes == 18 && immediate_vectors == 30 &&
        register_vectors == 90 && load_vectors == 30 &&
        pointer_vectors == 10 && direct32_vectors == 10 &&
        absolute_vectors == 10 ? 0 : 1;
}
