#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <initializer_list>
#include <sys/mman.h>
#include <unistd.h>
#include <utility>
#include <vector>

using uae_u32 = std::uint32_t;
static std::vector<uae_u32> emitted;
static void emit_long(uae_u32 word) { emitted.push_back(word); }
#include "../BasiliskII/src/uae_cpu_2026/compiler/codegen_arm64.h"

struct Output { std::uint64_t result; std::uint64_t nzcv; };
static void fail(const char *label, std::uint64_t expected, std::uint64_t found)
{
    std::fprintf(stderr,"ANDS_EMITTER_FAIL label=%s expected=%016llx found=%016llx\n",label,
        static_cast<unsigned long long>(expected),static_cast<unsigned long long>(found));
    std::exit(1);
}
static uae_u32 one_word(const char *label)
{
    if(emitted.size()!=1) fail(label,1,emitted.size());
    const auto word=emitted.front(); emitted.clear(); return word;
}
static uae_u32 ands_reg(unsigned d,unsigned n,unsigned m)
{ emitted.clear(); ANDS_www(d,n,m); return one_word("ANDS_www count"); }
static uae_u32 ands_3f(unsigned d,unsigned n)
{ emitted.clear(); ANDS_ww3f(d,n); return one_word("ANDS_ww3f count"); }
static uae_u32 ands_7fff(unsigned d,unsigned n)
{ emitted.clear(); ANDS_xx7fff(d,n); return one_word("ANDS_xx7fff count"); }

static Output execute(uae_u32 word,unsigned d,std::uint64_t lhs,std::uint64_t rhs,std::uint64_t hostile)
{
    const std::vector<uae_u32> words{0xd51b4202u,word,0xd53b4205u,
        static_cast<uae_u32>(0xf9000060u|d),0xf9000465u,0xd65f03c0u};
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
static std::uint64_t logical_nzcv(std::uint64_t result,unsigned width)
{
    const std::uint64_t mask=width==32?0xffffffffull:~std::uint64_t{0};
    result&=mask;
    return ((result>>(width-1))&1)<<31 | std::uint64_t(result==0)<<30;
}
static void check(const char *label,uae_u32 word,unsigned d,std::uint64_t lhs,
    std::uint64_t rhs,std::uint64_t effective,unsigned width,unsigned &count)
{
    const Output found=execute(word,d,lhs,rhs,(count&1)?0xf0000000u:0x30000000u);
    const std::uint64_t expected_result=width==32?static_cast<std::uint32_t>(effective):effective;
    if(found.result!=expected_result) fail(label,expected_result,found.result);
    const std::uint64_t expected_flags=logical_nzcv(expected_result,width);
    if((found.nzcv&0xf0000000u)!=expected_flags) fail(label,expected_flags,found.nzcv&0xf0000000u);
    ++count;
}
int main()
{
#if !defined(__aarch64__)
    std::fprintf(stderr,"ANDS_EMITTER_FAIL native AArch64 host required\n"); return 1;
#endif
    unsigned exact=0,reg_vectors=0,mask3f_vectors=0,mask7fff_vectors=0,alias_vectors=0;
    for(const auto &c:std::initializer_list<std::pair<uae_u32,uae_u32>>{
        {0x6a0b0149u,ands_reg(9,10,11)},{0x6a1f03ffu,ands_reg(31,31,31)},
        {0x72001549u,ands_3f(9,10)},{0x720017ffu,ands_3f(31,31)},
        {0xf2403949u,ands_7fff(9,10)},{0xf2403bffu,ands_7fff(31,31)},
    }){if(c.first!=c.second)fail("exact",c.first,c.second);++exact;}

    const std::pair<std::uint32_t,std::uint32_t> pairs[]={{0,0},{0,0xffffffffu},{0xffffffffu,0xffffffffu},
        {0x80000000u,0xffffffffu},{0x7fffffffu,0xffffffffu},{0xaaaaaaaau,0x55555555u},
        {0xf0f0f0f0u,0xff00ff00u},{1,1},{0x10000001u,0x10000000u},{0x80000000u,0x7fffffffu},
        {0x12345678u,0xffffffffu},{0xffffffffu,1}};
    for(unsigned i=0;i<std::size(pairs);++i){const unsigned alias=i%3,d=alias==0?4:alias==1?0:1;
        const auto effective=static_cast<std::uint32_t>(pairs[i].first & pairs[i].second);
        check("ANDS_www",ands_reg(d,0,1),d,pairs[i].first,pairs[i].second,effective,32,reg_vectors);if(alias)++alias_vectors;}

    const std::uint64_t values3f[]={0,1,0x3f,0x40,0x7f,0xffffffffull,0x80000000ull,
        0x123456789abcdef0ull,0x100000000ull,0x10000003full,0x20,0x60};
    for(unsigned i=0;i<std::size(values3f);++i){const unsigned d=(i&1)?0:4;
        check("ANDS_ww3f",ands_3f(d,0),d,values3f[i],0,static_cast<std::uint32_t>(values3f[i])&0x3fu,32,mask3f_vectors);if(d==0)++alias_vectors;}

    const std::uint64_t values7fff[]={0,1,0x7fff,0x8000,0xffff,0xffffffffffffffffull,
        0x8000000000000000ull,0x123456789abcdef0ull,0x1000000000007fffull,
        0x1000000000008000ull,0x4000,0xc000};
    for(unsigned i=0;i<std::size(values7fff);++i){const unsigned d=(i&1)?0:4;
        check("ANDS_xx7fff",ands_7fff(d,0),d,values7fff[i],0,values7fff[i]&0x7fffull,64,mask7fff_vectors);if(d==0)++alias_vectors;}

    std::printf("METRIC emitter_ands_apis=3\nMETRIC emitter_ands_exact_words=%u\n",exact);
    std::printf("METRIC emitter_ands_register_vectors=%u\nMETRIC emitter_ands_mask3f_vectors=%u\n",reg_vectors,mask3f_vectors);
    std::printf("METRIC emitter_ands_mask7fff_vectors=%u\nMETRIC emitter_ands_alias_vectors=%u\n",mask7fff_vectors,alias_vectors);
    std::printf("METRIC emitter_ands_native_vectors=%u\nMETRIC emitter_ands_cv_clear=1\n",reg_vectors+mask3f_vectors+mask7fff_vectors);
    return exact==6&&reg_vectors==12&&mask3f_vectors==12&&mask7fff_vectors==12&&alias_vectors==20?0:1;
}
