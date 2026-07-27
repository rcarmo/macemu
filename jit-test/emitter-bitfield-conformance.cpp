#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <sys/mman.h>
#include <unistd.h>
#include <utility>
#include <vector>

using uae_u32 = std::uint32_t;
static std::vector<uae_u32> emitted;
static void emit_long(uae_u32 word) { emitted.push_back(word); }
#include "../BasiliskII/src/uae_cpu_2026/compiler/codegen_arm64.h"

enum class Api { BFI, BFXIL, UBFIZ, UBFX };
struct Case { std::size_t word_offset; Api api; unsigned bits, lsb, width; bool alias; };
struct Output { std::uint64_t result; std::uint64_t nzcv; };

static void fail(const char *label, std::uint64_t expected, std::uint64_t found)
{
    std::fprintf(stderr,"BITFIELD_EMITTER_FAIL label=%s expected=%016llx found=%016llx\n",label,
        static_cast<unsigned long long>(expected),static_cast<unsigned long long>(found));
    std::exit(1);
}
static uae_u32 one_word(const char *label)
{ if(emitted.size()!=1)fail(label,1,emitted.size());const auto w=emitted.front();emitted.clear();return w; }

static uae_u32 emit_api(Api api,unsigned bits,unsigned d,unsigned n,unsigned lsb,unsigned width)
{
    emitted.clear();
    if(bits==32){
        if(api==Api::BFI) BFI_wwii(d,n,lsb,width);
        else if(api==Api::BFXIL) BFXIL_wwii(d,n,lsb,width);
        else if(api==Api::UBFIZ) UBFIZ_wwii(d,n,lsb,width);
        else UBFX_wwii(d,n,lsb,width);
    }else{
        if(api==Api::BFI) BFI_xxii(d,n,lsb,width);
        else if(api==Api::BFXIL) BFXIL_xxii(d,n,lsb,width);
        else if(api==Api::UBFIZ) UBFIZ_xxii(d,n,lsb,width);
        else UBFX_xxii(d,n,lsb,width);
    }
    return one_word("one-word emission");
}
static uae_u32 expected_word(Api api,unsigned bits,unsigned d,unsigned n,unsigned lsb,unsigned width)
{
    const uae_u32 base = api==Api::BFI||api==Api::BFXIL ? (bits==32?0x33000000u:0xb3400000u)
                                                           : (bits==32?0x53000000u:0xd3400000u);
    const unsigned immr = api==Api::BFI||api==Api::UBFIZ ? (bits-lsb)&(bits-1) : lsb&(bits-1);
    const unsigned imms = api==Api::BFI||api==Api::UBFIZ ? (width-1)&(bits-1) : (lsb+width-1)&(bits-1);
    return base|(immr<<16)|(imms<<10)|(n<<5)|d;
}
static std::uint64_t width_mask(unsigned width)
{ return width==64?~std::uint64_t{0}:((std::uint64_t{1}<<width)-1); }
static std::uint64_t expected_result(Api api,unsigned bits,unsigned lsb,unsigned width,
    std::uint64_t dst,std::uint64_t src)
{
    const std::uint64_t full=width_mask(bits), field=width_mask(width);
    dst&=full;src&=full;
    if(api==Api::BFI){const std::uint64_t placed=(src&field)<<lsb;return ((dst&~(field<<lsb))|placed)&full;}
    if(api==Api::BFXIL)return ((dst&~field)|((src>>lsb)&field))&full;
    if(api==Api::UBFIZ)return ((src&field)<<lsb)&full;
    return (src>>lsb)&field;
}
static const char *api_name(Api api)
{
    if(api==Api::BFI)return "BFI";
    if(api==Api::BFXIL)return "BFXIL";
    if(api==Api::UBFIZ)return "UBFIZ";
    return "UBFX";
}
static void append_case(std::vector<uae_u32>& code,std::vector<Case>& cases,Api api,
    unsigned bits,unsigned lsb,unsigned width,bool alias)
{
    const unsigned d=0,n=alias?0:1;
    const uae_u32 word=emit_api(api,bits,d,n,lsb,width);
    const uae_u32 expected=expected_word(api,bits,d,n,lsb,width);
    if(word!=expected)fail("exhaustive encoding",expected,word);
    const std::size_t offset=code.size();
    code.push_back(0xd51b4202u); code.push_back(word); code.push_back(0xd53b4205u);
    code.push_back(0xf9000060u); code.push_back(0xf9000465u); code.push_back(0xd65f03c0u);
    cases.push_back({offset,api,bits,lsb,width,alias});
}
int main()
{
#if !defined(__aarch64__)
    std::fprintf(stderr,"BITFIELD_EMITTER_FAIL native AArch64 host required\n");return 1;
#endif
    unsigned anchor_words=0;
    struct Anchor{Api api;unsigned bits,d,n,lsb,width;uae_u32 word;};
    const Anchor anchors[]={
        {Api::BFI,32,9,10,31,1,0x33010149u},{Api::BFI,32,31,31,31,1,0x330103ffu},
        {Api::BFI,64,9,10,63,1,0xb3410149u},{Api::BFI,64,31,31,63,1,0xb34103ffu},
        {Api::BFXIL,32,9,10,31,1,0x331f7d49u},{Api::BFXIL,32,31,31,31,1,0x331f7fffu},
        {Api::BFXIL,64,9,10,63,1,0xb37ffd49u},{Api::BFXIL,64,31,31,63,1,0xb37fffffu},
        {Api::UBFIZ,32,9,10,31,1,0x53010149u},{Api::UBFIZ,32,31,31,31,1,0x530103ffu},
        {Api::UBFIZ,64,9,10,63,1,0xd3410149u},{Api::UBFIZ,64,31,31,63,1,0xd34103ffu},
        {Api::UBFX,32,9,10,31,1,0x531f7d49u},{Api::UBFX,32,31,31,31,1,0x531f7fffu},
        {Api::UBFX,64,9,10,63,1,0xd37ffd49u},{Api::UBFX,64,31,31,63,1,0xd37fffffu},
    };
    for(const auto &a:anchors){const auto found=emit_api(a.api,a.bits,a.d,a.n,a.lsb,a.width);
        if(found!=a.word)fail("assembler anchor",a.word,found);
        ++anchor_words;}

    std::vector<uae_u32> code;std::vector<Case> cases;
    code.reserve(11000*6);cases.reserve(11000);
    for(Api api:{Api::BFI,Api::BFXIL,Api::UBFIZ,Api::UBFX})for(unsigned bits:{32u,64u})
        for(unsigned lsb=0;lsb<bits;++lsb)for(unsigned width=1;width<=bits-lsb;++width)
            append_case(code,cases,api,bits,lsb,width,false);
    for(Api api:{Api::BFI,Api::BFXIL,Api::UBFIZ,Api::UBFX})for(unsigned bits:{32u,64u})
        for(const auto &f:std::vector<std::pair<unsigned,unsigned>>{{0,1},{bits/2,bits/2},{bits-1,1}})
            append_case(code,cases,api,bits,f.first,f.second,true);

    const long ps=sysconf(_SC_PAGESIZE);const std::size_t bytes=code.size()*sizeof(uae_u32);
    const std::size_t mapped=(bytes+static_cast<std::size_t>(ps)-1)&~(static_cast<std::size_t>(ps)-1);
    void *page=mmap(nullptr,mapped,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
    if(page==MAP_FAILED){std::perror("mmap");return 1;}std::memcpy(page,code.data(),bytes);
    if(mprotect(page,mapped,PROT_READ|PROT_EXEC)!=0){std::perror("mprotect");return 1;}
    __builtin___clear_cache(static_cast<char*>(page),static_cast<char*>(page)+bytes);
    using Fn=void(*)(std::uint64_t,std::uint64_t,std::uint64_t,Output*);
    const std::uint64_t dst=0xa55aa55adeadbeefull,src=0x936cc63912345678ull,hostile=0xf0000000u;
    unsigned native=0,aliases=0;
    for(const auto &c:cases){Output out{};const std::uint64_t actual_src=c.alias?dst:src;
        auto fn=reinterpret_cast<Fn>(static_cast<char*>(page)+c.word_offset*sizeof(uae_u32));
        fn(dst,src,hostile,&out);const auto expected=expected_result(c.api,c.bits,c.lsb,c.width,dst,actual_src);
        if(out.result!=expected){std::fprintf(stderr,"BITFIELD_CASE api=%s bits=%u lsb=%u width=%u alias=%u\n",
            api_name(c.api),c.bits,c.lsb,c.width,c.alias);fail("native result",expected,out.result);}
        if((out.nzcv&0xf0000000u)!=hostile)fail("NZCV preservation",hostile,out.nzcv&0xf0000000u);
        ++native;if(c.alias)++aliases;}
    if(munmap(page,mapped)!=0){std::perror("munmap");return 1;}
    const unsigned exhaustive=native-aliases;
    std::printf("METRIC emitter_bitfield_apis=8\nMETRIC emitter_bitfield_anchor_words=%u\n",anchor_words);
    std::printf("METRIC emitter_bitfield_exhaustive_encodings=%u\n",exhaustive);
    std::printf("METRIC emitter_bitfield_native_vectors=%u\nMETRIC emitter_bitfield_alias_vectors=%u\n",native,aliases);
    std::printf("METRIC emitter_bitfield_preserves_nzcv=1\n");
    return anchor_words==16&&exhaustive==10432&&native==10456&&aliases==24?0:1;
}
