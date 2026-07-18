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
struct Result{std::uint64_t value,n,m,a,nzcv,fpcr,fpsr;};
struct CallerState{std::uint64_t d[8],fpcr,fpsr;};
struct Vector{const char*name;std::uint64_t n,m,a;std::array<std::uint64_t,4> out;std::uint32_t flags;};
struct Route{unsigned d,n,m,a;};
using NativeFn=void(*)(Result*,std::uint64_t,std::uint64_t,std::uint64_t);
extern "C" void fmsub_invoke_checked(NativeFn,Result*,std::uint64_t,std::uint64_t,std::uint64_t,CallerState*);
#if defined(__aarch64__)
asm(R"(
.text
.align 2
.global fmsub_invoke_checked
.type fmsub_invoke_checked,%function
fmsub_invoke_checked:
 sub sp,sp,#176
 stp x29,x30,[sp,#0]
 mov x29,sp
 stp x19,x20,[sp,#16]
 stp x21,x22,[sp,#32]
 stp x23,x24,[sp,#48]
 stp x25,x26,[sp,#64]
 str d8,[sp,#80]
 str d9,[sp,#88]
 str d10,[sp,#96]
 str d11,[sp,#104]
 str d12,[sp,#112]
 str d13,[sp,#120]
 str d14,[sp,#128]
 str d15,[sp,#136]
 mrs x9,fpcr
 mrs x10,fpsr
 str x9,[sp,#144]
 str x10,[sp,#152]
 mov x19,x0
 mov x20,x1
 mov x21,x2
 mov x22,x3
 mov x23,x4
 mov x24,x5
 ldr d8,[x24,#0]
 ldr d9,[x24,#8]
 ldr d10,[x24,#16]
 ldr d11,[x24,#24]
 ldr d12,[x24,#32]
 ldr d13,[x24,#40]
 ldr d14,[x24,#48]
 ldr d15,[x24,#56]
 ldr x9,[x24,#64]
 ldr x10,[x24,#72]
 msr fpcr,x9
 msr fpsr,x10
 mov x0,x20
 mov x1,x21
 mov x2,x22
 mov x3,x23
 blr x19
 str d8,[x24,#0]
 str d9,[x24,#8]
 str d10,[x24,#16]
 str d11,[x24,#24]
 str d12,[x24,#32]
 str d13,[x24,#40]
 str d14,[x24,#48]
 str d15,[x24,#56]
 mrs x9,fpcr
 mrs x10,fpsr
 str x9,[x24,#64]
 str x10,[x24,#72]
 ldr x9,[sp,#144]
 ldr x10,[sp,#152]
 msr fpcr,x9
 msr fpsr,x10
 ldr d8,[sp,#80]
 ldr d9,[sp,#88]
 ldr d10,[sp,#96]
 ldr d11,[sp,#104]
 ldr d12,[sp,#112]
 ldr d13,[sp,#120]
 ldr d14,[sp,#128]
 ldr d15,[sp,#136]
 ldp x25,x26,[sp,#64]
 ldp x23,x24,[sp,#48]
 ldp x21,x22,[sp,#32]
 ldp x19,x20,[sp,#16]
 ldp x29,x30,[sp,#0]
 add sp,sp,#176
 ret
.size fmsub_invoke_checked,.-fmsub_invoke_checked
)");
#endif
static void fail(const char*l,std::uint64_t e,std::uint64_t f){std::fprintf(stderr,"FMSUB_EMITTER_FAIL label=%s expected=%016llx found=%016llx\n",l,(unsigned long long)e,(unsigned long long)f);std::exit(1);}
static uae_u32 encoded(unsigned d,unsigned n,unsigned m,unsigned a){emitted.clear();FMSUB_dddd(d,n,m,a);if(emitted.size()!=1)fail("FMSUB word count",1,emitted.size());return emitted[0];}
static Result run(const Route&r,std::uint64_t nb,std::uint64_t mb,std::uint64_t ab,unsigned mode){
 emitted.clear();SUB_xxi(31,31,112);for(unsigned x=8;x<=15;x++)STR_dXi(x,31,(x-8)*8);STR_xXi(30,31,64);STR_xXi(0,31,72);MRS_FPCR_x(14);MRS_FPSR_x(15);STR_xXi(14,31,80);STR_xXi(15,31,88);
 MOV_wi(4,0);MOVK_wish(4,mode<<6,16);MSR_FPCR_x(4);MOV_wi(5,0x80);MOVK_wish(5,0x0800,16);MSR_FPSR_x(5);MOV_wi(6,0);MOVK_wish(6,0xb000,16);MSR_NZCV_x(6);
 FMOV_dx(r.n,1);FMOV_dx(r.m,2);FMOV_dx(r.a,3);FMSUB_dddd(r.d,r.n,r.m,r.a);FMOV_xd(12,r.d);FMOV_xd(13,r.n);FMOV_xd(14,r.m);FMOV_xd(15,r.a);LDR_xXi(16,31,72);MRS_NZCV_x(9);MRS_FPCR_x(10);MRS_FPSR_x(11);
 STR_xXi(12,16,0);STR_xXi(13,16,8);STR_xXi(14,16,16);STR_xXi(15,16,24);STR_xXi(9,16,32);STR_xXi(10,16,40);STR_xXi(11,16,48);
 LDR_xXi(14,31,80);LDR_xXi(15,31,88);MSR_FPSR_x(15);MSR_FPCR_x(14);LDR_xXi(30,31,64);for(unsigned x=8;x<=15;x++)LDR_dXi(x,31,(x-8)*8);ADD_xxi(31,31,112);emitted.push_back(0xd65f03c0u);
 long ps=sysconf(_SC_PAGESIZE);void*p=mmap(nullptr,ps,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);if(p==MAP_FAILED){perror("mmap");exit(1);}memcpy(p,emitted.data(),emitted.size()*4);if(mprotect(p,ps,PROT_READ|PROT_EXEC)){perror("mprotect");exit(1);}__builtin___clear_cache((char*)p,(char*)p+emitted.size()*4);
 Result result{};CallerState state{{0x0808080808080808ull,0x0909090909090909ull,0x0a0a0a0a0a0a0a0aull,0x0b0b0b0b0b0b0b0bull,0x0c0c0c0c0c0c0c0cull,0x0d0d0d0d0d0d0d0dull,0x0e0e0e0e0e0e0e0eull,0x0f0f0f0f0f0f0f0full},0x00c00000ull,0x0800009full},want=state;fmsub_invoke_checked(reinterpret_cast<NativeFn>(p),&result,nb,mb,ab,&state);for(unsigned i=0;i<8;i++)if(state.d[i]!=want.d[i])fail("FMSUB preserves caller D8-D15",want.d[i],state.d[i]);if(state.fpcr!=want.fpcr)fail("FMSUB restores caller FPCR",want.fpcr,state.fpcr);if(state.fpsr!=want.fpsr)fail("FMSUB restores caller FPSR",want.fpsr,state.fpsr);munmap(p,ps);return result;
}
static void state(const Result&r,unsigned mode,std::uint32_t flags){if((r.nzcv&0xf0000000ull)!=0xb0000000ull)fail("FMSUB preserves NZCV",0xb0000000ull,r.nzcv&0xf0000000ull);if(r.fpcr!=(std::uint64_t(mode)<<22))fail("FMSUB preserves FPCR",std::uint64_t(mode)<<22,r.fpcr);std::uint64_t ef=0x08000080ull|flags;if(r.fpsr!=ef)fail("FMSUB FPSR",ef,r.fpsr);}
int main(){
#if !defined(__aarch64__)
 std::fprintf(stderr,"FMSUB_EMITTER_FAIL native AArch64 host required\n");return 1;
#endif
 unsigned exact=0;for(unsigned d=0;d<32;d++)for(unsigned n=0;n<32;n++)for(unsigned m=0;m<32;m++)for(unsigned a=0;a<32;a++){uae_u32 want=0x1f408000u|(m<<16)|(a<<10)|(n<<5)|d,found=encoded(d,n,m,a);if(found!=want)fail("FMSUB exact",want,found);exact++;}
 constexpr std::array<Vector,16> vectors{{
  {"fused_cancellation",0x3ff0000000000001ull,0x3feffffffffffffeull,0x3ff0000000000000ull,{0x3970000000000000ull,0x3970000000000000ull,0x3970000000000000ull,0x3970000000000000ull},0},
  {"exact_positive",0x4000000000000000ull,0x4008000000000000ull,0x4024000000000000ull,{0x4010000000000000ull,0x4010000000000000ull,0x4010000000000000ull,0x4010000000000000ull},0},
  {"positive_midpoint",0x3c90000000000000ull,0x3ff0000000000000ull,0x3ff0000000000000ull,{0x3ff0000000000000ull,0x3ff0000000000000ull,0x3fefffffffffffffull,0x3fefffffffffffffull},0x10},
  {"negative_midpoint",0xbc90000000000000ull,0x3ff0000000000000ull,0xbff0000000000000ull,{0xbff0000000000000ull,0xbfefffffffffffffull,0xbff0000000000000ull,0xbfefffffffffffffull},0x10},
  {"positive_overflow",0xffefffffffffffffull,0x3ff0000000000000ull,0x7fefffffffffffffull,{0x7ff0000000000000ull,0x7ff0000000000000ull,0x7fefffffffffffffull,0x7fefffffffffffffull},0x14},
  {"negative_overflow",0x7fefffffffffffffull,0x3ff0000000000000ull,0xffefffffffffffffull,{0xfff0000000000000ull,0xffefffffffffffffull,0xfff0000000000000ull,0xffefffffffffffffull},0x14},
  {"positive_half_min_subnormal",0x0000000000000001ull,0x3fe0000000000000ull,0x0000000000000001ull,{0,1,0,0},0x18},
  {"negative_half_min_subnormal",0x8000000000000001ull,0x3fe0000000000000ull,0x8000000000000001ull,{0x8000000000000000ull,0x8000000000000000ull,0x8000000000000001ull,0x8000000000000000ull},0x18},
  {"zero_times_infinity",0,0x7ff0000000000000ull,0x3ff0000000000000ull,{0x7ff8000000000000ull,0x7ff8000000000000ull,0x7ff8000000000000ull,0x7ff8000000000000ull},1},
  {"infinity_cancellation",0x7ff0000000000000ull,0x3ff0000000000000ull,0x7ff0000000000000ull,{0x7ff8000000000000ull,0x7ff8000000000000ull,0x7ff8000000000000ull,0x7ff8000000000000ull},1},
  {"n_quiet_nan",0x7ff82468a0000000ull,0x3ff0000000000000ull,0x4000000000000000ull,{0xfff82468a0000000ull,0xfff82468a0000000ull,0xfff82468a0000000ull,0xfff82468a0000000ull},0},
  {"m_quiet_nan",0x3ff0000000000000ull,0x7ff82468a0000000ull,0x4000000000000000ull,{0x7ff82468a0000000ull,0x7ff82468a0000000ull,0x7ff82468a0000000ull,0x7ff82468a0000000ull},0},
  {"a_quiet_nan",0x3ff0000000000000ull,0x4000000000000000ull,0x7ff82468a0000000ull,{0x7ff82468a0000000ull,0x7ff82468a0000000ull,0x7ff82468a0000000ull,0x7ff82468a0000000ull},0},
  {"n_signalling_nan",0x7ff02468a0000000ull,0x3ff0000000000000ull,0x4000000000000000ull,{0xfff82468a0000000ull,0xfff82468a0000000ull,0xfff82468a0000000ull,0xfff82468a0000000ull},1},
  {"m_signalling_nan",0x3ff0000000000000ull,0x7ff02468a0000000ull,0x4000000000000000ull,{0x7ff82468a0000000ull,0x7ff82468a0000000ull,0x7ff82468a0000000ull,0x7ff82468a0000000ull},1},
  {"a_signalling_nan",0x3ff0000000000000ull,0x4000000000000000ull,0x7ff02468a0000000ull,{0x7ff82468a0000000ull,0x7ff82468a0000000ull,0x7ff82468a0000000ull,0x7ff82468a0000000ull},1}
 }};
 constexpr std::array<Route,6> routes{{{0,1,2,3},{7,7,8,9},{10,11,10,12},{13,14,15,13},{31,30,29,28},{8,9,10,11}}};
 unsigned native=0,aliases=0;for(const auto&r:routes)for(const auto&v:vectors)for(unsigned mode=0;mode<4;mode++){Result x=run(r,v.n,v.m,v.a,mode);if(x.value!=v.out[mode])fail(v.name,v.out[mode],x.value);std::uint64_t en=r.d==r.n?v.out[mode]:v.n,em=r.d==r.m?v.out[mode]:v.m,ea=r.d==r.a?v.out[mode]:v.a;if(x.n!=en)fail("FMSUB N source/alias semantics",en,x.n);if(x.m!=em)fail("FMSUB M source/alias semantics",em,x.m);if(x.a!=ea)fail("FMSUB A source/alias semantics",ea,x.a);state(x,mode,v.flags);native++;if(r.d==r.n||r.d==r.m||r.d==r.a)aliases++;}
 constexpr std::array<Route,4> sourceAliases{{{16,17,17,18},{19,20,21,20},{22,23,24,24},{25,25,25,25}}};
 constexpr std::array<std::uint64_t,4> aliasOut{{0x3ff0000000000000ull,0xc034000000000000ull,0xc024000000000000ull,0xc056800000000000ull}};
 for(unsigned i=0;i<sourceAliases.size();i++)for(unsigned mode=0;mode<4;mode++){const Route&r=sourceAliases[i];Result x=run(r,0x4000000000000000ull,0x4008000000000000ull,0x4024000000000000ull,mode);if(x.value!=aliasOut[i])fail("FMSUB source-alias load order",aliasOut[i],x.value);state(x,mode,0);native++;aliases++;}
 std::printf("METRIC emitter_fmsub_exact_words=%u\n",exact);std::printf("METRIC emitter_fmsub_native_routes=%u\n",native);std::printf("METRIC emitter_fmsub_alias_routes=%u\n",aliases);return exact==1048576&&native==400&&aliases==208?0:1;
}
