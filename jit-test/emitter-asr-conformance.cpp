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
static void fail(const char *label,std::uint64_t expected,std::uint64_t found)
{
    std::fprintf(stderr,"ASR_EMITTER_FAIL label=%s expected=%016llx found=%016llx\n",label,
        static_cast<unsigned long long>(expected),static_cast<unsigned long long>(found));
    std::exit(1);
}
static uae_u32 one_word(const char *label)
{ if(emitted.size()!=1)fail(label,1,emitted.size());const auto w=emitted.front();emitted.clear();return w; }
static uae_u32 asr_w_imm(unsigned d,unsigned n,unsigned c)
{ emitted.clear();ASR_wwi(d,n,c);return one_word("ASR_wwi count"); }
static uae_u32 asr_x_imm(unsigned d,unsigned n,unsigned c)
{ emitted.clear();ASR_xxi(d,n,c);return one_word("ASR_xxi count"); }
static uae_u32 asr_x_reg(unsigned d,unsigned n,unsigned m)
{ emitted.clear();ASR_xxx(d,n,m);return one_word("ASR_xxx count"); }

static Output execute(uae_u32 word,unsigned d,std::uint64_t value,std::uint64_t count,std::uint64_t hostile)
{
    const std::vector<uae_u32> words{0xd51b4202u,word,0xd53b4205u,
        static_cast<uae_u32>(0xf9000060u|d),0xf9000465u,0xd65f03c0u};
    const long ps=sysconf(_SC_PAGESIZE);if(ps<=0||words.size()*4>static_cast<std::size_t>(ps))fail("page",1,0);
    void *page=mmap(nullptr,static_cast<std::size_t>(ps),PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
    if(page==MAP_FAILED){std::perror("mmap");std::exit(1);}std::memcpy(page,words.data(),words.size()*4);
    if(mprotect(page,static_cast<std::size_t>(ps),PROT_READ|PROT_EXEC)!=0){std::perror("mprotect");std::exit(1);}
    __builtin___clear_cache(static_cast<char*>(page),static_cast<char*>(page)+words.size()*4);
    Output out{};using Fn=void(*)(std::uint64_t,std::uint64_t,std::uint64_t,Output*);
    reinterpret_cast<Fn>(page)(value,count,hostile,&out);
    if(munmap(page,static_cast<std::size_t>(ps))!=0){std::perror("munmap");std::exit(1);}return out;
}
static std::uint64_t arithmetic_right(std::uint64_t value,unsigned count,unsigned width)
{
    const std::uint64_t mask=width==64?~std::uint64_t{0}:0xffffffffull;
    value&=mask;count%=width;if(!count)return value;
    std::uint64_t result=value>>count;
    if((value>>(width-1))&1){const std::uint64_t fill=~std::uint64_t{0}<<(width-count);result|=fill;}
    return result&mask;
}
static void check(const char *label,uae_u32 word,unsigned d,std::uint64_t value,
    std::uint64_t machine_count,unsigned effective_count,unsigned width,unsigned &count)
{
    const std::uint64_t hostile=(count&1)?0xf0000000u:0x50000000u;
    const Output found=execute(word,d,value,machine_count,hostile);
    const std::uint64_t expected=arithmetic_right(value,effective_count,width);
    if(found.result!=expected)fail(label,expected,found.result);
    if((found.nzcv&0xf0000000u)!=hostile)fail(label,hostile,found.nzcv&0xf0000000u);
    ++count;
}
int main()
{
#if !defined(__aarch64__)
    std::fprintf(stderr,"ASR_EMITTER_FAIL native AArch64 host required\n");return 1;
#endif
    unsigned exact=0,wimm=0,ximm=0,xreg=0,aliases=0;
    for(const auto &c:std::initializer_list<std::pair<uae_u32,uae_u32>>{
        {0x13007d49u,asr_w_imm(9,10,0)},{0x131f7d49u,asr_w_imm(9,10,31)},
        {0x131f7fffu,asr_w_imm(31,31,31)},{0x9340fd49u,asr_x_imm(9,10,0)},
        {0x937ffd49u,asr_x_imm(9,10,63)},{0x937fffffu,asr_x_imm(31,31,63)},
        {0x9acb2949u,asr_x_reg(9,10,11)},{0x9adf2bffu,asr_x_reg(31,31,31)},
    }){if(c.first!=c.second)fail("exact",c.first,c.second);++exact;}

    struct I{std::uint64_t value;unsigned shift;};
    const I wi[]={{0,0},{1,1},{0xffffffffu,1},{0x80000000u,1},{0x7fffffffu,31},{0x80000000u,31},
        {0x12345678abcdef01ull,0},{0x12345678abcdef01ull,15},{0xffffffffu,32},{0x80000000u,63},{0x40000000u,30},{0xc0000000u,30}};
    for(unsigned i=0;i<std::size(wi);++i){const unsigned d=(i&1)?0:4;check("ASR_wwi",asr_w_imm(d,0,wi[i].shift),d,wi[i].value,0,wi[i].shift&31,32,wimm);if(d==0)++aliases;}
    const I xi[]={{0,0},{1,1},{~std::uint64_t{0},1},{0x8000000000000000ull,1},{0x7fffffffffffffffull,63},
        {0x8000000000000000ull,63},{0x123456789abcdef0ull,32},{0xf23456789abcdef0ull,32},
        {~std::uint64_t{0},64},{0x8000000000000000ull,127},{0x4000000000000000ull,62},{0xc000000000000000ull,62}};
    for(unsigned i=0;i<std::size(xi);++i){const unsigned d=(i&1)?0:4;check("ASR_xxi",asr_x_imm(d,0,xi[i].shift),d,xi[i].value,0,xi[i].shift&63,64,ximm);if(d==0)++aliases;}
    const std::uint64_t values[]={0,1,~std::uint64_t{0},0x8000000000000000ull,0x7fffffffffffffffull,0xf23456789abcdef0ull};
    const std::uint64_t counts[]={0,1,31,32,63,64,65,127};unsigned index=0;
    for(auto value:values)for(auto shift:counts){const unsigned alias=index++%3,d=alias==0?4:alias==1?0:1;
        check("ASR_xxx",asr_x_reg(d,0,1),d,value,shift,shift&63,64,xreg);if(alias)++aliases;}
    std::printf("METRIC emitter_asr_apis=3\nMETRIC emitter_asr_exact_words=%u\n",exact);
    std::printf("METRIC emitter_asr_w_immediate_vectors=%u\nMETRIC emitter_asr_x_immediate_vectors=%u\n",wimm,ximm);
    std::printf("METRIC emitter_asr_x_register_vectors=%u\nMETRIC emitter_asr_alias_vectors=%u\n",xreg,aliases);
    std::printf("METRIC emitter_asr_native_vectors=%u\nMETRIC emitter_asr_preserves_nzcv=1\n",wimm+ximm+xreg);
    return exact==8&&wimm==12&&ximm==12&&xreg==48&&aliases==44?0:1;
}
