#include <array>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <sys/mman.h>
#include <unistd.h>
#include <vector>
using uae_u32=std::uint32_t; using uae_s32=std::int32_t;
static std::vector<uae_u32> emitted; static void emit_long(uae_u32 w){emitted.push_back(w);}
#include "../BasiliskII/src/uae_cpu_2026/compiler/codegen_arm64.h"
struct Result{std::uint64_t value,source,nzcv,fpcr,fpsr;};
struct Narrow{const char*name;std::uint64_t in;std::array<std::uint32_t,4> out;std::uint32_t flags;};
struct Widen{const char*name;std::uint32_t in;std::uint64_t out;std::uint32_t flags;};
struct CallerState{std::uint64_t d[8],fpcr,fpsr;}; using NativeFn=void(*)(Result*,std::uint64_t);
extern "C" void fcvt_invoke_checked(NativeFn,Result*,std::uint64_t,CallerState*);
#if defined(__aarch64__)
asm(R"(
.text
.align 2
.global fcvt_invoke_checked
.type fcvt_invoke_checked,%function
fcvt_invoke_checked:
 sub sp,sp,#144
 stp x29,x30,[sp,#0]
 mov x29,sp
 stp x19,x20,[sp,#16]
 stp x21,x22,[sp,#32]
 str d8,[sp,#48]
 str d9,[sp,#56]
 str d10,[sp,#64]
 str d11,[sp,#72]
 str d12,[sp,#80]
 str d13,[sp,#88]
 str d14,[sp,#96]
 str d15,[sp,#104]
 mrs x9,fpcr
 mrs x10,fpsr
 str x9,[sp,#112]
 str x10,[sp,#120]
 mov x19,x0
 mov x20,x1
 mov x21,x2
 mov x22,x3
 ldr d8,[x22,#0]
 ldr d9,[x22,#8]
 ldr d10,[x22,#16]
 ldr d11,[x22,#24]
 ldr d12,[x22,#32]
 ldr d13,[x22,#40]
 ldr d14,[x22,#48]
 ldr d15,[x22,#56]
 ldr x9,[x22,#64]
 ldr x10,[x22,#72]
 msr fpcr,x9
 msr fpsr,x10
 mov x0,x20
 mov x1,x21
 blr x19
 str d8,[x22,#0]
 str d9,[x22,#8]
 str d10,[x22,#16]
 str d11,[x22,#24]
 str d12,[x22,#32]
 str d13,[x22,#40]
 str d14,[x22,#48]
 str d15,[x22,#56]
 mrs x9,fpcr
 mrs x10,fpsr
 str x9,[x22,#64]
 str x10,[x22,#72]
 ldr x9,[sp,#112]
 ldr x10,[sp,#120]
 msr fpcr,x9
 msr fpsr,x10
 ldr d8,[sp,#48]
 ldr d9,[sp,#56]
 ldr d10,[sp,#64]
 ldr d11,[sp,#72]
 ldr d12,[sp,#80]
 ldr d13,[sp,#88]
 ldr d14,[sp,#96]
 ldr d15,[sp,#104]
 ldp x21,x22,[sp,#32]
 ldp x19,x20,[sp,#16]
 ldp x29,x30,[sp,#0]
 add sp,sp,#144
 ret
.size fcvt_invoke_checked,.-fcvt_invoke_checked
)");
#endif
static void fail(const char*l,std::uint64_t e,std::uint64_t f){std::fprintf(stderr,"FCVT_EMITTER_FAIL label=%s expected=%016llx found=%016llx\n",l,(unsigned long long)e,(unsigned long long)f);std::exit(1);}
static uae_u32 sdword(unsigned s,unsigned d){emitted.clear();FCVT_sd(s,d);if(emitted.size()!=1)fail("FCVT_sd count",1,emitted.size());return emitted[0];}
static uae_u32 dsword(unsigned d,unsigned s){emitted.clear();FCVT_ds(d,s);if(emitted.size()!=1)fail("FCVT_ds count",1,emitted.size());return emitted[0];}
static Result run(bool narrow,unsigned out,unsigned in,std::uint64_t bits,unsigned mode){
 emitted.clear();SUB_xxi(31,31,80);for(unsigned r=8;r<=15;r++)STR_dXi(r,31,(r-8)*8);STR_xXi(30,31,64);MRS_FPCR_x(14);MRS_FPSR_x(15);MOV_xx(16,0);
 MOV_wi(3,0);MOVK_wish(3,mode<<6,16);MSR_FPCR_x(3);MOV_wi(4,0x80);MOVK_wish(4,0x0800,16);MSR_FPSR_x(4);MOV_wi(5,0);MOVK_wish(5,0xb000,16);MSR_NZCV_x(5);
 if(narrow){FMOV_dx(in,1);FCVT_sd(out,in);FMOV_ws(12,out);FMOV_xd(13,in);}else{FMOV_sw(in,1);FCVT_ds(out,in);FMOV_xd(12,out);FMOV_ws(13,in);}
 MRS_NZCV_x(9);MRS_FPCR_x(10);MRS_FPSR_x(11);STR_xXi(12,16,0);STR_xXi(13,16,8);STR_xXi(9,16,16);STR_xXi(10,16,24);STR_xXi(11,16,32);
 MSR_FPSR_x(15);MSR_FPCR_x(14);LDR_xXi(30,31,64);for(unsigned r=8;r<=15;r++)LDR_dXi(r,31,(r-8)*8);ADD_xxi(31,31,80);emitted.push_back(0xd65f03c0u);
 long ps=sysconf(_SC_PAGESIZE);void*p=mmap(nullptr,ps,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);if(p==MAP_FAILED){perror("mmap");exit(1);}memcpy(p,emitted.data(),emitted.size()*4);if(mprotect(p,ps,PROT_READ|PROT_EXEC)){perror("mprotect");exit(1);}__builtin___clear_cache((char*)p,(char*)p+emitted.size()*4);Result r{};CallerState cs{{0x0808080808080808ull,0x0909090909090909ull,0x0a0a0a0a0a0a0a0aull,0x0b0b0b0b0b0b0b0bull,0x0c0c0c0c0c0c0c0cull,0x0d0d0d0d0d0d0d0dull,0x0e0e0e0e0e0e0e0eull,0x0f0f0f0f0f0f0f0full},0x00c00000ull,0x0800009full},want=cs;fcvt_invoke_checked(reinterpret_cast<NativeFn>(p),&r,bits,&cs);for(unsigned i=0;i<8;i++)if(cs.d[i]!=want.d[i])fail("FCVT preserves caller D8-D15",want.d[i],cs.d[i]);if(cs.fpcr!=want.fpcr)fail("FCVT restores caller FPCR",want.fpcr,cs.fpcr);if(cs.fpsr!=want.fpsr)fail("FCVT restores caller FPSR",want.fpsr,cs.fpsr);munmap(p,ps);return r;
}
static void state(const char*n,const Result&r,std::uint64_t source,unsigned mode,std::uint32_t flags){if(r.source!=source)fail("FCVT preserves source",source,r.source);if((r.nzcv&0xf0000000ull)!=0xb0000000ull)fail("FCVT preserves NZCV",0xb0000000,r.nzcv&0xf0000000ull);if(r.fpcr!=(std::uint64_t(mode)<<22))fail("FCVT preserves FPCR",std::uint64_t(mode)<<22,r.fpcr);std::uint64_t ef=0x08000080ull|flags;if(r.fpsr!=ef)fail(n,ef,r.fpsr);}
int main(){
#if !defined(__aarch64__)
 std::fprintf(stderr,"FCVT_EMITTER_FAIL native AArch64 host required\n");return 1;
#endif
 unsigned exact=0;for(unsigned a=0;a<32;a++)for(unsigned b=0;b<32;b++){uae_u32 sd=0x1e624000u|(b<<5)|a,ds=0x1e22c000u|(b<<5)|a;if(sdword(a,b)!=sd)fail("FCVT_sd exact",sd,sdword(a,b));if(dsword(a,b)!=ds)fail("FCVT_ds exact",ds,dsword(a,b));exact+=2;}
 constexpr std::array<Narrow,9> ns={{{"one",0x3ff0000000000000ull,{0x3f800000,0x3f800000,0x3f800000,0x3f800000},0},{"negative_zero",0x8000000000000000ull,{0x80000000,0x80000000,0x80000000,0x80000000},0},{"inexact_normal",0x3ff0000010000000ull,{0x3f800000,0x3f800001,0x3f800000,0x3f800000},0x10},{"half_min_subnormal",0x3690000000000000ull,{0,1,0,0},0x18},{"negative_half_min_subnormal",0xb690000000000000ull,{0x80000000,0x80000000,0x80000001,0x80000000},0x18},{"positive_overflow",0x7fefffffffffffffull,{0x7f800000,0x7f800000,0x7f7fffff,0x7f7fffff},0x14},{"negative_overflow",0xffefffffffffffffull,{0xff800000,0xff7fffff,0xff800000,0xff7fffff},0x14},{"quiet_nan",0x7ff82468a0000000ull,{0x7fc12345,0x7fc12345,0x7fc12345,0x7fc12345},0},{"signalling_nan",0x7ff02468a0000000ull,{0x7fc12345,0x7fc12345,0x7fc12345,0x7fc12345},1}}};
 constexpr std::array<Widen,7> ws={{{"single_one",0x3f800000,0x3ff0000000000000ull,0},{"single_negative_zero",0x80000000,0x8000000000000000ull,0},{"single_low_bit",0x3f800001,0x3ff0000020000000ull,0},{"single_min_subnormal",1,0x36a0000000000000ull,0},{"single_infinity",0x7f800000,0x7ff0000000000000ull,0},{"single_qnan",0x7fc12345,0x7ff82468a0000000ull,0},{"single_snan",0x7f812345,0x7ff82468a0000000ull,1}}};
 constexpr std::array<std::array<unsigned,2>,4> routes={{{{0,1}},{{31,30}},{{8,15}},{{7,7}}}};unsigned nv=0,wv=0,av=0;
 for(auto&v:ns)for(auto rt:routes)for(unsigned m=0;m<4;m++){Result r=run(true,rt[0],rt[1],v.in,m);bool alias=rt[0]==rt[1];std::uint64_t src=alias?std::uint64_t(v.out[m]):v.in;if(r.value!=v.out[m])fail(v.name,v.out[m],r.value);state(v.name,r,src,m,v.flags);nv++;if(alias)av++;}
 for(auto&v:ws)for(auto rt:routes)for(unsigned m=0;m<4;m++){Result r=run(false,rt[0],rt[1],v.in,m);bool alias=rt[0]==rt[1];std::uint64_t src=alias?std::uint32_t(v.out):v.in;if(r.value!=v.out)fail(v.name,v.out,r.value);state(v.name,r,src,m,v.flags);wv++;if(alias)av++;}
 std::printf("METRIC emitter_fcvt_exact_words=%u\n",exact);std::printf("METRIC emitter_fcvt_narrow_vectors=%u\n",nv);std::printf("METRIC emitter_fcvt_widen_vectors=%u\n",wv);std::printf("METRIC emitter_fcvt_alias_fields=%u\n",av);return exact==2048&&nv==144&&wv==112&&av==64?0:1;
}
