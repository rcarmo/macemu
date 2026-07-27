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
    std::fprintf(stderr,"ADDS_EMITTER_FAIL label=%s expected=%016llx found=%016llx\n",label,
        static_cast<unsigned long long>(expected),static_cast<unsigned long long>(found));
    std::exit(1);
}
static uae_u32 one_word(const char *label)
{
    if(emitted.size()!=1) fail(label,1,emitted.size());
    const auto word=emitted.front(); emitted.clear(); return word;
}
static uae_u32 adds_imm(unsigned d,unsigned n,unsigned i)
{ emitted.clear(); ADDS_wwi(d,n,i); return one_word("ADDS_wwi count"); }
static uae_u32 adds_reg(unsigned d,unsigned n,unsigned m)
{ emitted.clear(); ADDS_www(d,n,m); return one_word("ADDS_www count"); }
static uae_u32 adds_shift(unsigned d,unsigned n,unsigned m,unsigned sh)
{ emitted.clear(); ADDS_wwwLSLi(d,n,m,sh); return one_word("ADDS_wwwLSLi count"); }

static Output execute(uae_u32 word,unsigned d,std::uint32_t lhs,std::uint32_t rhs,std::uint64_t hostile)
{
    const std::vector<uae_u32> words{0xd51b4202u,word,0xd53b4205u,
        static_cast<uae_u32>(0xb9000060u|d),0xf9000465u,0xd65f03c0u};
    const long page_size=sysconf(_SC_PAGESIZE);
    if(page_size<=0||words.size()*sizeof(uae_u32)>static_cast<std::size_t>(page_size)) fail("page",1,0);
    void *page=mmap(nullptr,static_cast<std::size_t>(page_size),PROT_READ|PROT_WRITE,
        MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
    if(page==MAP_FAILED){std::perror("mmap");std::exit(1);}
    std::memcpy(page,words.data(),words.size()*sizeof(uae_u32));
    if(mprotect(page,static_cast<std::size_t>(page_size),PROT_READ|PROT_EXEC)!=0){std::perror("mprotect");std::exit(1);}
    __builtin___clear_cache(static_cast<char*>(page),static_cast<char*>(page)+words.size()*sizeof(uae_u32));
    Output out{}; using Fn=void(*)(std::uint64_t,std::uint64_t,std::uint64_t,Output*);
    reinterpret_cast<Fn>(page)(lhs,rhs,hostile,&out);
    if(munmap(page,static_cast<std::size_t>(page_size))!=0){std::perror("munmap");std::exit(1);}
    return out;
}
static std::uint64_t pack(bool n,bool z,bool c,bool v)
{ return (std::uint64_t(n)<<31)|(std::uint64_t(z)<<30)|(std::uint64_t(c)<<29)|(std::uint64_t(v)<<28); }
static Output expected(std::uint32_t lhs,std::uint32_t rhs)
{
    const std::uint64_t wide=std::uint64_t(lhs)+rhs;
    const std::uint32_t result=static_cast<std::uint32_t>(wide);
    const std::int64_t signed_wide=std::int64_t(std::int32_t(lhs))+std::int64_t(std::int32_t(rhs));
    const bool v=signed_wide>std::numeric_limits<std::int32_t>::max()||signed_wide<std::numeric_limits<std::int32_t>::min();
    return {result,0,pack((result>>31)!=0,result==0,(wide>>32)!=0,v)};
}
static void check(const char *label,uae_u32 word,unsigned d,std::uint32_t lhs,
    std::uint32_t rhs_operand,std::uint32_t rhs_effective,unsigned &count)
{
    const Output found=execute(word,d,lhs,rhs_operand,(count&1)?0xf0000000u:0x50000000u), exp=expected(lhs,rhs_effective);
    if(found.result!=exp.result) fail(label,exp.result,found.result);
    if((found.nzcv&0xf0000000u)!=exp.nzcv) fail(label,exp.nzcv,found.nzcv&0xf0000000u);
    ++count;
}
int main()
{
#if !defined(__aarch64__)
    std::fprintf(stderr,"ADDS_EMITTER_FAIL native AArch64 host required\n"); return 1;
#endif
    unsigned exact=0,imm_vectors=0,reg_vectors=0,shift_vectors=0,alias_vectors=0;
    for(const auto &c:std::initializer_list<std::pair<uae_u32,uae_u32>>{
        {0x31000149u,adds_imm(9,10,0)},{0x313ffd49u,adds_imm(9,10,0xfff)},
        {0x313fffffu,adds_imm(31,31,0xfff)},{0x2b0b0149u,adds_reg(9,10,11)},
        {0x2b1f03ffu,adds_reg(31,31,31)},{0x2b0b7d49u,adds_shift(9,10,11,31)},
        {0x2b1f7fffu,adds_shift(31,31,31,31)},
    }){if(c.first!=c.second)fail("exact",c.first,c.second);++exact;}

    struct Imm {std::uint32_t lhs,imm;};
    const Imm imms[]={{0,0},{0,1},{1,0xfff},{0xffffffffu,1},{0x7fffffffu,1},{0x80000000u,0xffffffffu&0xfff},
        {0xfffff001u,0xfff},{0x7ffff001u,0xfff},{0x80000000u,0},{0xffffffffu,0},{0x100,0xf00},{0xfffff000u,0x100}};
    for(unsigned i=0;i<std::size(imms);++i){const unsigned d=(i&1)?0:4;check("ADDS_wwi",adds_imm(d,0,imms[i].imm),d,imms[i].lhs,0,imms[i].imm,imm_vectors);if(d==0)++alias_vectors;}

    const std::pair<std::uint32_t,std::uint32_t> pairs[]={{0,0},{0,1},{1,0xffffffffu},{0xffffffffu,1},
        {0x7fffffffu,1},{0x80000000u,0xffffffffu},{0x80000000u,0x80000000u},{0x7fffffffu,0x7fffffffu},
        {0xffffffffu,0xffffffffu},{0x40000000u,0x40000000u},{0x12345678u,0x87654321u},{1,1}};
    for(unsigned i=0;i<std::size(pairs);++i){const unsigned alias=i%3,d=alias==0?4:alias==1?0:1;
        check("ADDS_www",adds_reg(d,0,1),d,pairs[i].first,pairs[i].second,pairs[i].second,reg_vectors);if(alias)++alias_vectors;}

    const unsigned shifts[]={0,1,16,24,31};
    unsigned index=0;
    for(unsigned sh:shifts)for(const auto &p:std::initializer_list<std::pair<std::uint32_t,std::uint32_t>>{{0,1},{0xffffffffu,1},{0x7fffffffu,0xffffffffu}}){
        const unsigned alias=index++%3,d=alias==0?4:alias==1?0:1; const std::uint32_t rhs=p.second<<sh;
        check("ADDS_wwwLSLi",adds_shift(d,0,1,sh),d,p.first,p.second,rhs,shift_vectors);if(alias)++alias_vectors;
    }
    std::printf("METRIC emitter_adds_apis=3\nMETRIC emitter_adds_exact_words=%u\n",exact);
    std::printf("METRIC emitter_adds_immediate_vectors=%u\nMETRIC emitter_adds_register_vectors=%u\n",imm_vectors,reg_vectors);
    std::printf("METRIC emitter_adds_shift_vectors=%u\nMETRIC emitter_adds_alias_vectors=%u\n",shift_vectors,alias_vectors);
    std::printf("METRIC emitter_adds_native_vectors=%u\n",imm_vectors+reg_vectors+shift_vectors);
    return exact==7&&imm_vectors==12&&reg_vectors==12&&shift_vectors==15&&alias_vectors==24?0:1;
}
