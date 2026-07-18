#include <array>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <sys/mman.h>
#include <unistd.h>
#include <vector>

using uae_u32=std::uint32_t; using uae_s32=std::int32_t;
static std::vector<uae_u32> emitted;
static void emit_long(uae_u32 word){emitted.push_back(word);}
#include "../BasiliskII/src/uae_cpu_2026/compiler/codegen_arm64.h"

struct Result{std::uint64_t value,source,nzcv,fpcr,fpsr;};
struct CallerState{std::uint64_t d[8],fpcr,fpsr;};
struct Vector{const char*name;std::uint64_t input;std::array<std::uint64_t,4> output;std::uint32_t flags;};
using NativeFn=void(*)(Result*,std::uint64_t);
extern "C" void fsqrt_invoke_checked(NativeFn,Result*,std::uint64_t,CallerState*);

#if defined(__aarch64__)
asm(R"(
.text
.align 2
.global fsqrt_invoke_checked
.type fsqrt_invoke_checked,%function
fsqrt_invoke_checked:
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
.size fsqrt_invoke_checked,.-fsqrt_invoke_checked
)");
#endif

static void fail(const char*l,std::uint64_t e,std::uint64_t f){
 std::fprintf(stderr,"FSQRT_EMITTER_FAIL label=%s expected=%016llx found=%016llx\n",l,(unsigned long long)e,(unsigned long long)f);std::exit(1);
}
static uae_u32 encoded(unsigned d,unsigned s){emitted.clear();FSQRT_dd(d,s);if(emitted.size()!=1)fail("FSQRT word count",1,emitted.size());return emitted[0];}

static Result run(unsigned d,unsigned s,std::uint64_t bits,unsigned mode){
 emitted.clear();SUB_xxi(31,31,80);for(unsigned r=8;r<=15;r++)STR_dXi(r,31,(r-8)*8);STR_xXi(30,31,64);
 MRS_FPCR_x(14);MRS_FPSR_x(15);MOV_xx(16,0);
 MOV_wi(3,0);MOVK_wish(3,mode<<6,16);MSR_FPCR_x(3);MOV_wi(4,0x80);MOVK_wish(4,0x0800,16);MSR_FPSR_x(4);MOV_wi(5,0);MOVK_wish(5,0xb000,16);MSR_NZCV_x(5);
 FMOV_dx(s,1);FSQRT_dd(d,s);FMOV_xd(12,d);FMOV_xd(13,s);MRS_NZCV_x(9);MRS_FPCR_x(10);MRS_FPSR_x(11);
 STR_xXi(12,16,0);STR_xXi(13,16,8);STR_xXi(9,16,16);STR_xXi(10,16,24);STR_xXi(11,16,32);
 MSR_FPSR_x(15);MSR_FPCR_x(14);LDR_xXi(30,31,64);for(unsigned r=8;r<=15;r++)LDR_dXi(r,31,(r-8)*8);ADD_xxi(31,31,80);emitted.push_back(0xd65f03c0u);
 long ps=sysconf(_SC_PAGESIZE);void*p=mmap(nullptr,ps,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);if(p==MAP_FAILED){perror("mmap");exit(1);}memcpy(p,emitted.data(),emitted.size()*4);if(mprotect(p,ps,PROT_READ|PROT_EXEC)){perror("mprotect");exit(1);}__builtin___clear_cache((char*)p,(char*)p+emitted.size()*4);
 Result result{};CallerState state{{0x0808080808080808ull,0x0909090909090909ull,0x0a0a0a0a0a0a0a0aull,0x0b0b0b0b0b0b0b0bull,0x0c0c0c0c0c0c0c0cull,0x0d0d0d0d0d0d0d0dull,0x0e0e0e0e0e0e0e0eull,0x0f0f0f0f0f0f0f0full},0x00c00000ull,0x0800009full},want=state;
 fsqrt_invoke_checked(reinterpret_cast<NativeFn>(p),&result,bits,&state);for(unsigned i=0;i<8;i++)if(state.d[i]!=want.d[i])fail("FSQRT preserves caller D8-D15",want.d[i],state.d[i]);if(state.fpcr!=want.fpcr)fail("FSQRT restores caller FPCR",want.fpcr,state.fpcr);if(state.fpsr!=want.fpsr)fail("FSQRT restores caller FPSR",want.fpsr,state.fpsr);munmap(p,ps);return result;
}

int main(){
#if !defined(__aarch64__)
 std::fprintf(stderr,"FSQRT_EMITTER_FAIL native AArch64 host required\n");return 1;
#endif
 unsigned exact=0;for(unsigned d=0;d<32;d++)for(unsigned s=0;s<32;s++){uae_u32 want=0x1e61c000u|(s<<5)|d,found=encoded(d,s);if(found!=want)fail("FSQRT exact",want,found);exact++;}
 constexpr std::array<Vector,11> vectors{{
  {"positive_zero",0x0000000000000000ull,{0,0,0,0},0},
  {"negative_zero",0x8000000000000000ull,{0x8000000000000000ull,0x8000000000000000ull,0x8000000000000000ull,0x8000000000000000ull},0},
  {"one",0x3ff0000000000000ull,{0x3ff0000000000000ull,0x3ff0000000000000ull,0x3ff0000000000000ull,0x3ff0000000000000ull},0},
  {"four",0x4010000000000000ull,{0x4000000000000000ull,0x4000000000000000ull,0x4000000000000000ull,0x4000000000000000ull},0},
  {"sqrt_two",0x4000000000000000ull,{0x3ff6a09e667f3bcdull,0x3ff6a09e667f3bcdull,0x3ff6a09e667f3bccull,0x3ff6a09e667f3bccull},0x10},
  {"minimum_subnormal",0x0000000000000001ull,{0x1e60000000000000ull,0x1e60000000000000ull,0x1e60000000000000ull,0x1e60000000000000ull},0},
  {"positive_infinity",0x7ff0000000000000ull,{0x7ff0000000000000ull,0x7ff0000000000000ull,0x7ff0000000000000ull,0x7ff0000000000000ull},0},
  {"negative_one",0xbff0000000000000ull,{0x7ff8000000000000ull,0x7ff8000000000000ull,0x7ff8000000000000ull,0x7ff8000000000000ull},1},
  {"negative_infinity",0xfff0000000000000ull,{0x7ff8000000000000ull,0x7ff8000000000000ull,0x7ff8000000000000ull,0x7ff8000000000000ull},1},
  {"quiet_nan",0x7ff82468a0000000ull,{0x7ff82468a0000000ull,0x7ff82468a0000000ull,0x7ff82468a0000000ull,0x7ff82468a0000000ull},0},
  {"signalling_nan",0x7ff02468a0000000ull,{0x7ff82468a0000000ull,0x7ff82468a0000000ull,0x7ff82468a0000000ull,0x7ff82468a0000000ull},1}
 }};
 unsigned routes=0,aliases=0;for(unsigned d=0;d<32;d++)for(unsigned s=0;s<32;s++)for(unsigned mode=0;mode<4;mode++){
  const auto&v=vectors[(d+s+mode)%vectors.size()];Result r=run(d,s,v.input,mode);if(r.value!=v.output[mode])fail(v.name,v.output[mode],r.value);std::uint64_t source=d==s?v.output[mode]:v.input;if(r.source!=source)fail("FSQRT source/alias semantics",source,r.source);if((r.nzcv&0xf0000000ull)!=0xb0000000ull)fail("FSQRT preserves NZCV",0xb0000000ull,r.nzcv&0xf0000000ull);if(r.fpcr!=(std::uint64_t(mode)<<22))fail("FSQRT preserves FPCR",std::uint64_t(mode)<<22,r.fpcr);std::uint64_t fpsr=0x08000080ull|v.flags;if(r.fpsr!=fpsr)fail("FSQRT FPSR",fpsr,r.fpsr);routes++;if(d==s)aliases++;
 }
 std::printf("METRIC emitter_fsqrt_exact_words=%u\n",exact);std::printf("METRIC emitter_fsqrt_native_routes=%u\n",routes);std::printf("METRIC emitter_fsqrt_alias_routes=%u\n",aliases);return exact==1024&&routes==4096&&aliases==128?0:1;
}
