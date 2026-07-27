#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <initializer_list>
#include <limits>
#include <sys/mman.h>
#include <unistd.h>
#include <utility>
#include <vector>

using uae_u32 = std::uint32_t;
static std::vector<uae_u32> emitted;
static void emit_long(uae_u32 word) { emitted.push_back(word); }
#include "../BasiliskII/src/uae_cpu_2026/compiler/codegen_arm64.h"

struct Output { std::uint32_t result; std::uint32_t pad; std::uint64_t nzcv; };

static void fail(const char *label, std::uint64_t expected, std::uint64_t found)
{
    std::fprintf(stderr, "CARRY_EMITTER_FAIL label=%s expected=%016llx found=%016llx\n",
        label, static_cast<unsigned long long>(expected),
        static_cast<unsigned long long>(found));
    std::exit(1);
}

static uae_u32 one_word(const char *label)
{
    if (emitted.size() != 1) fail(label, 1, emitted.size());
    const uae_u32 word = emitted.front(); emitted.clear(); return word;
}
static uae_u32 adcs_word(unsigned d, unsigned n, unsigned m)
{ emitted.clear(); ADCS_www(d,n,m); return one_word("ADCS_www count"); }
static uae_u32 sbcs_word(unsigned d, unsigned n, unsigned m)
{ emitted.clear(); SBCS_www(d,n,m); return one_word("SBCS_www count"); }

static Output run(uae_u32 op, unsigned alias, std::uint32_t lhs,
    std::uint32_t rhs, std::uint64_t initial_nzcv)
{
    /* x0=lhs, x1=rhs, x2=NZCV, x3=Output*. Rotate destination ownership. */
    const unsigned d = alias == 0 ? 4 : alias == 1 ? 0 : 1;
    const uae_u32 word = op == 0 ? adcs_word(d,0,1) : sbcs_word(d,0,1);
    const std::vector<uae_u32> words{
        0xd51b4202u, word, 0xd53b4205u,
        static_cast<uae_u32>(0xb9000060u | d), 0xf9000465u, 0xd65f03c0u,
    };
    const long page_size = sysconf(_SC_PAGESIZE);
    if (page_size <= 0 || words.size()*sizeof(uae_u32) > static_cast<std::size_t>(page_size))
        fail("page size", 1, 0);
    void *page = mmap(nullptr, static_cast<std::size_t>(page_size), PROT_READ|PROT_WRITE,
        MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
    if (page == MAP_FAILED) { std::perror("mmap"); std::exit(1); }
    std::memcpy(page, words.data(), words.size()*sizeof(uae_u32));
    if (mprotect(page, static_cast<std::size_t>(page_size), PROT_READ|PROT_EXEC) != 0) {
        std::perror("mprotect"); std::exit(1);
    }
    __builtin___clear_cache(static_cast<char*>(page), static_cast<char*>(page)+words.size()*sizeof(uae_u32));
    Output out{};
    using Fn = void (*)(std::uint64_t,std::uint64_t,std::uint64_t,Output*);
    reinterpret_cast<Fn>(page)(lhs,rhs,initial_nzcv,&out);
    if (munmap(page, static_cast<std::size_t>(page_size)) != 0) { std::perror("munmap"); std::exit(1); }
    return out;
}

static std::uint64_t pack_nzcv(bool n, bool z, bool c, bool v)
{
    return (std::uint64_t(n)<<31)|(std::uint64_t(z)<<30)|
        (std::uint64_t(c)<<29)|(std::uint64_t(v)<<28);
}

static Output expected_add(std::uint32_t lhs, std::uint32_t rhs, bool carry)
{
    const std::uint64_t wide = std::uint64_t(lhs)+std::uint64_t(rhs)+carry;
    const std::uint32_t result = static_cast<std::uint32_t>(wide);
    const std::int64_t signed_wide = std::int64_t(std::int32_t(lhs))+
        std::int64_t(std::int32_t(rhs))+carry;
    const bool overflow = signed_wide > std::numeric_limits<std::int32_t>::max() ||
        signed_wide < std::numeric_limits<std::int32_t>::min();
    return {result,0,pack_nzcv((result>>31)!=0,result==0,(wide>>32)!=0,overflow)};
}

static Output expected_sub(std::uint32_t lhs, std::uint32_t rhs, bool carry)
{
    const std::uint64_t borrow = carry ? 0 : 1;
    const std::uint32_t result = static_cast<std::uint32_t>(std::uint64_t(lhs)-rhs-borrow);
    const std::int64_t signed_wide = std::int64_t(std::int32_t(lhs))-
        std::int64_t(std::int32_t(rhs))-std::int64_t(borrow);
    const bool overflow = signed_wide > std::numeric_limits<std::int32_t>::max() ||
        signed_wide < std::numeric_limits<std::int32_t>::min();
    const bool no_borrow = std::uint64_t(lhs) >= std::uint64_t(rhs)+borrow;
    return {result,0,pack_nzcv((result>>31)!=0,result==0,no_borrow,overflow)};
}

int main()
{
#if !defined(__aarch64__)
    std::fprintf(stderr,"CARRY_EMITTER_FAIL native AArch64 host required\n"); return 1;
#endif
    unsigned exact_words=0, adcs_vectors=0, sbcs_vectors=0, alias_vectors=0;
    for (const auto &c : std::initializer_list<std::pair<uae_u32,uae_u32>>{
        {0x3a0b0149u,adcs_word(9,10,11)}, {0x3a1f03ffu,adcs_word(31,31,31)},
        {0x7a0b0149u,sbcs_word(9,10,11)}, {0x7a1f03ffu,sbcs_word(31,31,31)},
    }) { if(c.first!=c.second) fail("exact word",c.first,c.second); ++exact_words; }

    const std::pair<std::uint32_t,std::uint32_t> pairs[] = {
        {0,0},{0,1},{1,0},{1,1},{0xffffffffu,0},{0xffffffffu,1},
        {0x7fffffffu,0},{0x7fffffffu,1},{0x80000000u,0},{0x80000000u,1},
        {0x80000000u,0xffffffffu},{0x7fffffffu,0xffffffffu},
    };
    unsigned index=0;
    for (const auto &p : pairs) for (unsigned carry=0; carry<2; ++carry,++index) {
        const unsigned alias=index%3;
        const std::uint64_t hostile=(carry?0x20000000u:0)|((index&1)?0xd0000000u:0x40000000u);
        const Output add=run(0,alias,p.first,p.second,hostile), exp_add=expected_add(p.first,p.second,carry);
        if(add.result!=exp_add.result) fail("ADCS result",exp_add.result,add.result);
        if((add.nzcv&0xf0000000u)!=exp_add.nzcv) fail("ADCS NZCV",exp_add.nzcv,add.nzcv&0xf0000000u);
        ++adcs_vectors; ++alias_vectors;
        const Output sub=run(1,alias,p.first,p.second,hostile), exp_sub=expected_sub(p.first,p.second,carry);
        if(sub.result!=exp_sub.result) fail("SBCS result",exp_sub.result,sub.result);
        if((sub.nzcv&0xf0000000u)!=exp_sub.nzcv) fail("SBCS NZCV",exp_sub.nzcv,sub.nzcv&0xf0000000u);
        ++sbcs_vectors; ++alias_vectors;
    }
    std::printf("METRIC emitter_carry_apis=2\nMETRIC emitter_carry_exact_words=%u\n",exact_words);
    std::printf("METRIC emitter_adcs_native_vectors=%u\nMETRIC emitter_sbcs_native_vectors=%u\n",adcs_vectors,sbcs_vectors);
    std::printf("METRIC emitter_carry_alias_vectors=%u\nMETRIC emitter_carry_native_vectors=%u\n",alias_vectors,adcs_vectors+sbcs_vectors);
    return exact_words==4 && adcs_vectors==24 && sbcs_vectors==24 && alias_vectors==48 ? 0:1;
}
