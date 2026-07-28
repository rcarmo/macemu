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

static void fail(const char *label, std::uint64_t expected, std::uint64_t found)
{
    std::fprintf(stderr, "MEMORY_EMITTER_FAIL label=%s expected=%016llx found=%016llx\n",
        label, static_cast<unsigned long long>(expected), static_cast<unsigned long long>(found));
    std::exit(1);
}
static uae_u32 one(const char *label) { if (emitted.size()!=1) fail(label,1,emitted.size()); auto w=emitted[0]; emitted.clear(); return w; }
#define WORD4(fn, macro) static uae_u32 fn(unsigned a,unsigned b,unsigned c,int i){emitted.clear();macro(a,b,c,i);return one(#macro);}
#define WORD3(fn, macro) static uae_u32 fn(unsigned a,unsigned b,int i){emitted.clear();macro(a,b,i);return one(#macro);}
#define WORDR(fn, macro) static uae_u32 fn(unsigned a,unsigned b,unsigned c){emitted.clear();macro(a,b,c);return one(#macro);}
WORD4(ldp_x, LDP_xxXi) WORD4(ldp_xpost, LDP_xxXpost)
WORD3(ldr_wi, LDR_wXi) WORDR(ldr_wr, LDR_wXx) WORD4(ldr_wrs, LDR_wXxLSLi)
WORD3(ldr_xi, LDR_xXi) WORD3(ldr_xpost, LDR_xXpost) WORD4(ldr_xrs, LDR_xXxLSLi)
WORDR(ldrb_r, LDRB_wXx) WORD3(ldrh_i, LDRH_wXi) WORDR(ldrh_r, LDRH_wXx)
WORD4(stp_w, STP_wwXi) WORD4(stp_x, STP_xxXi) WORD4(stp_xpre, STP_xxXpre)
WORD3(str_wi, STR_wXi) WORDR(str_wr, STR_wXx) WORD4(str_wrs, STR_wXxLSLi)
WORD3(str_xi, STR_xXi) WORD3(str_xpre, STR_xXpre)
WORDR(strb_r, STRB_wXx) WORD3(strh_i, STRH_wXi) WORDR(strh_r, STRH_wXx)
#undef WORD4
#undef WORD3
#undef WORDR

static void *page_for(const std::vector<uae_u32>& words,long& ps){
    ps=sysconf(_SC_PAGESIZE); if(ps<=0||words.size()*4>static_cast<size_t>(ps)) fail("page",1,0);
    void* p=mmap(nullptr,ps,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
    if(p==MAP_FAILED){std::perror("mmap");std::exit(1);} std::memcpy(p,words.data(),words.size()*4);
    if(mprotect(p,ps,PROT_READ|PROT_EXEC)){std::perror("mprotect");std::exit(1);}
    __builtin___clear_cache(static_cast<char*>(p),static_cast<char*>(p)+words.size()*4); return p;
}
static std::uint64_t run4(const std::vector<uae_u32>& words,std::uint64_t a=0,std::uint64_t b=0,std::uint64_t c=0,std::uint64_t d=0){
    long ps=0;void* p=page_for(words,ps);using Fn=std::uint64_t(*)(std::uint64_t,std::uint64_t,std::uint64_t,std::uint64_t);
    auto r=reinterpret_cast<Fn>(p)(a,b,c,d);if(munmap(p,ps)){std::perror("munmap");std::exit(1);}return r;
}
static constexpr uae_u32 ret=0xd65f03c0u, msr_x3=0xd51b4203u, mrs_x0=0xd53b4200u;
static unsigned exact_words=0,native_values=0,nzcv_vectors=0,uxtw_vectors=0;
static void word(const char*l,uae_u32 e,uae_u32 f){if(e!=f)fail(l,e,f);++exact_words;}
static void value(const char*l,std::uint64_t e,std::uint64_t f){if(e!=f)fail(l,e,f);++native_values;}
static void flags(const char*l,uae_u32 op,std::uint64_t a,std::uint64_t b,std::uint64_t c){
    constexpr std::uint64_t nzcv=0xa0000000u; auto f=run4({msr_x3,op,mrs_x0,ret},a,b,c,nzcv)&0xf0000000u;
    if(f!=nzcv) fail(l,nzcv,f);
    ++nzcv_vectors;
}
static void put64(std::uint8_t*p,std::uint64_t v){std::memcpy(p,&v,8);} static std::uint64_t get64(const std::uint8_t*p){std::uint64_t v;std::memcpy(&v,p,8);return v;}
static void put32(std::uint8_t*p,std::uint32_t v){std::memcpy(p,&v,4);} static std::uint32_t get32(const std::uint8_t*p){std::uint32_t v;std::memcpy(&v,p,4);return v;}
static void put16(std::uint8_t*p,std::uint16_t v){std::memcpy(p,&v,2);} static std::uint16_t get16(const std::uint8_t*p){std::uint16_t v;std::memcpy(&v,p,2);return v;}

int main(){
#if !defined(__aarch64__)
    std::fprintf(stderr,"MEMORY_EMITTER_FAIL native AArch64 host required\n");return 1;
#endif
    word("LDP_xxXi",0xa9602969u,ldp_x(9,10,11,-512));
    word("LDP_xxXpost",0xa8dfb5ccu,ldp_xpost(12,13,14,504));
    word("LDR_wXi",0xb97ffd49u,ldr_wi(9,10,16380));
    word("LDR_wXx reversed guest/base",0xb86d498bu,ldr_wr(11,13,12));
    word("LDR_wXxLSLi",0xb87079eeu,ldr_wrs(14,15,16,1));
    word("LDR_xXi",0xf97ffd49u,ldr_xi(9,10,32760));
    word("LDR_xXpost",0xf850058bu,ldr_xpost(11,12,-256));
    word("LDR_xXxLSLi",0xf86f79cdu,ldr_xrs(13,14,15,1));
    word("LDRB_wXx reversed guest/base",0x386b4949u,ldrb_r(9,11,10));
    word("LDRH_wXi",0x797ffdacu,ldrh_i(12,13,8190));
    word("LDRH_wXx reversed guest/base",0x787049eeu,ldrh_r(14,16,15));
    word("STP_wwXi",0x29202969u,stp_w(9,10,11,-256));
    word("STP_xxXi",0xa91fb5ccu,stp_x(12,13,14,504));
    word("STP_xxXpre",0xa9a0422fu,stp_xpre(15,16,17,-512));
    word("STR_wXi",0xb93ffd49u,str_wi(9,10,16380));
    word("STR_wXx reversed guest/base",0xb82d498bu,str_wr(11,13,12));
    word("STR_wXxLSLi",0xb83079eeu,str_wrs(14,15,16,1));
    word("STR_xXi",0xf93ffd49u,str_xi(9,10,32760));
    word("STR_xXpre",0xf8100d8bu,str_xpre(11,12,-256));
    word("STRB_wXx reversed guest/base",0x382f49cdu,strb_r(13,15,14));
    word("STRH_wXi",0x793ffe30u,strh_i(16,17,8190));
    word("STRH_wXx reversed guest/base",0x78344a72u,strh_r(18,20,19));

    alignas(16) std::array<std::uint8_t,65536> m{}; auto* b=m.data()+1024;
    constexpr std::uint64_t a=0x0123456789abcdefull,z=0xfedcba9876543210ull;
    put64(b-16,a);put64(b-8,z);std::array<std::uint64_t,3> out{};
    run4({ldp_x(2,3,0,-16),str_xi(2,1,0),str_xi(3,1,8),ret},reinterpret_cast<uintptr_t>(b),reinterpret_cast<uintptr_t>(out.data()));
    value("LDP first",a,out[0]);value("LDP second",z,out[1]);
    put64(b,a);put64(b+8,z);out={};run4({ldp_xpost(2,3,0,16),str_xi(2,1,0),str_xi(3,1,8),str_xi(0,1,16),ret},reinterpret_cast<uintptr_t>(b),reinterpret_cast<uintptr_t>(out.data()));
    value("LDP post first",a,out[0]);value("LDP post second",z,out[1]);value("LDP post base",reinterpret_cast<uintptr_t>(b+16),out[2]);
    put32(b+16380,0x89abcdefu);value("LDR W immediate",0x89abcdefu,run4({ldr_wi(0,0,16380),ret},reinterpret_cast<uintptr_t>(b)));
    put32(b+12,0x76543210u);value("LDR W register LSL",0x76543210u,run4({ldr_wrs(0,0,1,1),ret},reinterpret_cast<uintptr_t>(b),3));
    put64(b+32760,a);value("LDR X immediate",a,run4({ldr_xi(0,0,32760),ret},reinterpret_cast<uintptr_t>(b)));
    put64(b,z);out={};run4({ldr_xpost(2,0,8),str_xi(2,1,0),str_xi(0,1,8),ret},reinterpret_cast<uintptr_t>(b),reinterpret_cast<uintptr_t>(out.data()));value("LDR X post value",z,out[0]);value("LDR X post base",reinterpret_cast<uintptr_t>(b+8),out[1]);
    put64(b+16,a);value("LDR X register LSL",a,run4({ldr_xrs(0,0,1,1),ret},reinterpret_cast<uintptr_t>(b),2));
    put16(b+8190,0xbeefu);value("LDRH immediate",0xbeefu,run4({ldrh_i(0,0,8190),ret},reinterpret_cast<uintptr_t>(b)));

    std::memset(b-32,0,128);run4({stp_w(1,2,0,-8),ret},reinterpret_cast<uintptr_t>(b),0xaaaa555512345678ull,0xbbbb666589abcdefull);value("STP W first",0x12345678u,get32(b-8));value("STP W second",0x89abcdefu,get32(b-4));
    run4({stp_x(1,2,0,16),ret},reinterpret_cast<uintptr_t>(b),a,z);value("STP X first",a,get64(b+16));value("STP X second",z,get64(b+24));
    run4({stp_xpre(1,2,0,-16),str_xi(0,3,0),ret},reinterpret_cast<uintptr_t>(b),a,z,reinterpret_cast<uintptr_t>(out.data()));value("STP pre first",a,get64(b-16));value("STP pre second",z,get64(b-8));value("STP pre base",reinterpret_cast<uintptr_t>(b-16),out[0]);
    run4({str_wi(1,0,16380),ret},reinterpret_cast<uintptr_t>(b),0x1234567889abcdefull);value("STR W immediate",0x89abcdefu,get32(b+16380));
    run4({str_wrs(2,0,1,1),ret},reinterpret_cast<uintptr_t>(b),4,0xcafebabeu);value("STR W register LSL",0xcafebabeu,get32(b+16));
    run4({str_xi(1,0,32760),ret},reinterpret_cast<uintptr_t>(b),z);value("STR X immediate",z,get64(b+32760));
    out={};run4({str_xpre(1,0,-8),str_xi(0,2,0),ret},reinterpret_cast<uintptr_t>(b),a,reinterpret_cast<uintptr_t>(out.data()));value("STR X pre value",a,get64(b-8));value("STR X pre base",reinterpret_cast<uintptr_t>(b-8),out[0]);
    run4({strh_i(1,0,8190),ret},reinterpret_cast<uintptr_t>(b),0x1234beefu);value("STRH immediate",0xbeefu,get16(b+8190));

    const size_t span=0x80002000ull;void* reserve=mmap(nullptr,span,PROT_NONE,MAP_PRIVATE|MAP_ANONYMOUS|MAP_NORESERVE,-1,0);if(reserve==MAP_FAILED){std::perror("mmap high offset");return 1;}auto* high=static_cast<std::uint8_t*>(reserve)+0x80000000ull;if(mprotect(high,4096,PROT_READ|PROT_WRITE)){std::perror("mprotect high offset");return 1;}
    high[0]=0x5a;put16(high+2,0xbeef);put32(high+4,0x89abcdefu);
    value("LDRB UXTW high bit",0x5au,run4({ldrb_r(0,0,1),ret},0x80000000u,reinterpret_cast<uintptr_t>(reserve)));++uxtw_vectors;
    value("LDRH UXTW high bit",0xbeefu,run4({ldrh_r(0,0,1),ret},0x80000002u,reinterpret_cast<uintptr_t>(reserve)));++uxtw_vectors;
    value("LDR W UXTW high bit",0x89abcdefu,run4({ldr_wr(0,0,1),ret},0x80000004u,reinterpret_cast<uintptr_t>(reserve)));++uxtw_vectors;
    run4({strb_r(2,0,1),ret},0x80000008u,reinterpret_cast<uintptr_t>(reserve),0xa5);value("STRB UXTW high bit",0xa5,high[8]);++uxtw_vectors;
    run4({strh_r(2,0,1),ret},0x8000000au,reinterpret_cast<uintptr_t>(reserve),0xface);value("STRH UXTW high bit",0xface,get16(high+10));++uxtw_vectors;
    run4({str_wr(2,0,1),ret},0x8000000cu,reinterpret_cast<uintptr_t>(reserve),0x76543210u);value("STR W UXTW high bit",0x76543210u,get32(high+12));++uxtw_vectors;
    if(munmap(reserve,span)){std::perror("munmap high offset");return 1;}

    // Every audited memory instruction must preserve NZCV. Use safe operands and
    // non-overlapping destinations; value/writeback semantics were checked above.
    put64(b,a);put64(b+8,z);const std::array<uae_u32,22> ops={
      ldp_x(4,5,0,0),ldp_xpost(4,5,0,16),ldr_wi(4,0,0),ldr_wr(4,1,0),ldr_wrs(4,0,1,0),
      ldr_xi(4,0,0),ldr_xpost(4,0,8),ldr_xrs(4,0,1,0),ldrb_r(4,1,0),ldrh_i(4,0,0),ldrh_r(4,1,0),
      stp_w(1,2,0,0),stp_x(1,2,0,0),stp_xpre(1,2,0,-16),str_wi(2,0,0),str_wr(2,1,0),str_wrs(2,0,1,0),
      str_xi(2,0,0),str_xpre(2,0,-8),strb_r(2,1,0),strh_i(2,0,0),strh_r(2,1,0)};
    for(unsigned i=0;i<ops.size();++i)
      flags("memory op preserves NZCV",ops[i],reinterpret_cast<uintptr_t>(b),0,3);

    std::printf("METRIC emitter_memory_apis=22\nMETRIC emitter_memory_exact_words=%u\n",exact_words);
    std::printf("METRIC emitter_memory_native_value_vectors=%u\nMETRIC emitter_memory_nzcv_vectors=%u\n",native_values,nzcv_vectors);
    std::printf("METRIC emitter_memory_uxtw_highbit_vectors=%u\n",uxtw_vectors);
    std::printf("METRIC emitter_memory_pair_order=1\nMETRIC emitter_memory_writeback=1\nMETRIC emitter_memory_widths_8_16_32_64=1\n");
    return exact_words==22&&native_values==31&&nzcv_vectors==22&&uxtw_vectors==6?0:1;
}
