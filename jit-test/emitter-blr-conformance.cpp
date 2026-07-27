#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <sys/mman.h>
#include <unistd.h>
#include <vector>

using uae_u32 = std::uint32_t;
static std::vector<uae_u32> emitted;
static void emit_long(uae_u32 word) { emitted.push_back(word); }
#include "../BasiliskII/src/uae_cpu_2026/compiler/codegen_arm64.h"

struct Out {
    std::uint64_t link;
    std::uint64_t nzcv;
};

static void fail(const char* label, std::uint64_t expected, std::uint64_t found)
{
    std::fprintf(stderr, "BLR_EMITTER_FAIL %s expected=%016llx found=%016llx\n",
        label, static_cast<unsigned long long>(expected),
        static_cast<unsigned long long>(found));
    std::exit(1);
}

static uae_u32 blr(unsigned reg)
{
    emitted.clear();
    BLR_x(reg);
    if (emitted.size() != 1)
        fail("count", 1, emitted.size());
    return emitted[0];
}

static uae_u32 adr(unsigned reg, std::int64_t displacement)
{
    const auto imm = static_cast<std::uint64_t>(displacement) & 0x1fffffu;
    return 0x10000000u | static_cast<uae_u32>((imm & 3u) << 29) |
        static_cast<uae_u32>(((imm >> 2) & 0x7ffffu) << 5) | reg;
}

int main()
{
#if !defined(__aarch64__)
    return 1;
#endif
    unsigned exact = 0;
    unsigned native = 0;
    for (unsigned reg = 0; reg < 32; ++reg) {
        const auto expected = 0xd63f0000u | (reg << 5);
        const auto found = blr(reg);
        if (expected != found)
            fail("field", expected, found);
        ++exact;
    }

    for (unsigned target : {9u, 16u, 17u, 18u}) {
        const unsigned decoy = target == 16 ? 9u : 16u;
        std::vector<uae_u32> code {
            0xd51b4201u,             // msr nzcv,x1
            0xa9bf7bfdu,             // stp x29,x30,[sp,#-16]!
            adr(target, 28),          // target = actual callee at word 9
            adr(decoy, 32),           // distinct register = decoy at word 11
            blr(target),
            0xd53b4202u,             // mrs x2,nzcv
            0xf9000402u,             // str x2,[x0,#8]
            0xa8c17bfdu,             // ldp x29,x30,[sp],#16
            0xd65f03c0u,             // ret
            0xf900001eu,             // actual: str x30,[x0]
            0xd65f03c0u,             // ret
            0xf900001fu,             // decoy: str xzr,[x0]
            0xd65f03c0u,             // ret
        };

        const long page_size = sysconf(_SC_PAGESIZE);
        void* mapping = mmap(nullptr, page_size, PROT_READ | PROT_WRITE,
            MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (mapping == MAP_FAILED) {
            std::perror("mmap");
            return 1;
        }
        std::memcpy(mapping, code.data(), code.size() * sizeof(code[0]));
        if (mprotect(mapping, page_size, PROT_READ | PROT_EXEC)) {
            std::perror("mprotect");
            munmap(mapping, page_size);
            return 1;
        }
        __builtin___clear_cache(static_cast<char*>(mapping),
            static_cast<char*>(mapping) + code.size() * sizeof(code[0]));

        Out out {};
        using Function = void (*)(Out*, std::uint64_t);
        reinterpret_cast<Function>(mapping)(&out, 0xa0000000u);
        const auto expected_link = reinterpret_cast<std::uint64_t>(mapping) + 20;
        if (out.link != expected_link)
            fail("target-link", expected_link, out.link);
        if ((out.nzcv & 0xf0000000u) != 0xa0000000u)
            fail("nzcv", 0xa0000000u, out.nzcv & 0xf0000000u);
        munmap(mapping, page_size);
        ++native;
    }

    std::printf(
        "METRIC emitter_blr_api=1\n"
        "METRIC emitter_blr_exact_words=%u\n"
        "METRIC emitter_blr_native_vectors=%u\n"
        "METRIC emitter_blr_target_decoys=%u\n"
        "METRIC emitter_blr_link_semantics=1\n"
        "METRIC emitter_blr_preserves_nzcv=1\n",
        exact, native, native);
    return exact == 32 && native == 4 ? 0 : 1;
}
