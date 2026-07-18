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
struct Result{std::uint64_t value,n,m,nzcv,fpcr,fpsr;};
struct CallerState{std::uint64_t d[8],fpcr,fpsr;};
struct Vector{const char*name;std::uint64_t n,m;std::array<std::uint64_t,4> out;std::uint32_t flags;};
struct Route{unsigned d,n,m;bool equal_sources;};
using NativeFn=void(*)(Result*,std::uint64_t,std::uint64_t);
extern "C" void fsub_invoke_checked(NativeFn,Result*,std::uint64_t,std::uint64_t,CallerState*);
#if defined(__aarch64__)
asm(R"(
.text
.align 2
.global fsub_invoke_checked
.type fsub_invoke_checked,%function
fsub_invoke_checked:
 sub sp,sp,#160
 stp x29,x30,[sp,#0]
 mov x29,sp
 stp x19,x20,[sp,#16]
 stp x21,x22,[sp,#32]
 stp x23,x24,[sp,#48]
 str d8,[sp,#64]
 str d9,[sp,#72]
 str d10,[sp,#80]
 str d11,[sp,#88]
 str d12,[sp,#96]
 str d13,[sp,#104]
 str d14,[sp,#112]
 str d15,[sp,#120]
 mrs x9,fpcr
 mrs x10,fpsr
 str x9,[sp,#128]
 str x10,[sp,#136]
 mov x19,x0
 mov x20,x1
 mov x21,x2
 mov x22,x3
 mov x23,x4
 ldr d8,[x23,#0]
 ldr d9,[x23,#8]
 ldr d10,[x23,#16]
 ldr d11,[x23,#24]
 ldr d12,[x23,#32]
 ldr d13,[x23,#40]
 ldr d14,[x23,#48]
 ldr d15,[x23,#56]
 ldr x9,[x23,#64]
 ldr x10,[x23,#72]
 msr fpcr,x9
 msr fpsr,x10
 mov x0,x20
 mov x1,x21
 mov x2,x22
 blr x19
 str d8,[x23,#0]
 str d9,[x23,#8]
 str d10,[x23,#16]
 str d11,[x23,#24]
 str d12,[x23,#32]
 str d13,[x23,#40]
 str d14,[x23,#48]
 str d15,[x23,#56]
 mrs x9,fpcr
 mrs x10,fpsr
 str x9,[x23,#64]
 str x10,[x23,#72]
 ldr x9,[sp,#128]
 ldr x10,[sp,#136]
 msr fpcr,x9
 msr fpsr,x10
 ldr d8,[sp,#64]
 ldr d9,[sp,#72]
 ldr d10,[sp,#80]
 ldr d11,[sp,#88]
 ldr d12,[sp,#96]
 ldr d13,[sp,#104]
 ldr d14,[sp,#112]
 ldr d15,[sp,#120]
 ldp x23,x24,[sp,#48]
 ldp x21,x22,[sp,#32]
 ldp x19,x20,[sp,#16]
 ldp x29,x30,[sp,#0]
 add sp,sp,#160
 ret
.size fsub_invoke_checked,.-fsub_invoke_checked
)");
#endif
static void fail(const char*l,std::uint64_t e,std::uint64_t f){std::fprintf(stderr,"FSUB_EMITTER_FAIL label=%s expected=%016llx found=%016llx\n",l,(unsigned long long)e,(unsigned long long)f);std::exit(1);}
static uae_u32 encoded(unsigned d,unsigned n,unsigned m){emitted.clear();FSUB_ddd(d,n,m);if(emitted.size()!=1)fail("FSUB word count",1,emitted.size());return emitted[0];}
static Result run(const Route&r,std::uint64_t nbits,std::uint64_t mbits,unsigned mode){
 emitted.clear();SUB_xxi(31,31,96);for(unsigned x=8;x<=15;x++)STR_dXi(x,31,(x-8)*8);STR_xXi(30,31,64);STR_xXi(0,31,72);MRS_FPCR_x(14);MRS_FPSR_x(15);STR_xXi(14,31,80);STR_xXi(15,31,88);
 MOV_wi(3,0);MOVK_wish(3,mode<<6,16);MSR_FPCR_x(3);MOV_wi(4,0x80);MOVK_wish(4,0x0800,16);MSR_FPSR_x(4);MOV_wi(5,0);MOVK_wish(5,0xb000,16);MSR_NZCV_x(5);
 FMOV_dx(r.n,1);FMOV_dx(r.m,2);FSUB_ddd(r.d,r.n,r.m);FMOV_xd(12,r.d);FMOV_xd(13,r.n);FMOV_xd(14,r.m);MRS_NZCV_x(9);MRS_FPCR_x(10);MRS_FPSR_x(11);
 LDR_xXi(16,31,72);STR_xXi(12,16,0);STR_xXi(13,16,8);STR_xXi(14,16,16);STR_xXi(9,16,24);STR_xXi(10,16,32);STR_xXi(11,16,40);
 LDR_xXi(14,31,80);LDR_xXi(15,31,88);MSR_FPSR_x(15);MSR_FPCR_x(14);LDR_xXi(30,31,64);for(unsigned x=8;x<=15;x++)LDR_dXi(x,31,(x-8)*8);ADD_xxi(31,31,96);emitted.push_back(0xd65f03c0u);
 long ps=sysconf(_SC_PAGESIZE);void*p=mmap(nullptr,ps,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);if(p==MAP_FAILED){perror("mmap");exit(1);}memcpy(p,emitted.data(),emitted.size()*4);if(mprotect(p,ps,PROT_READ|PROT_EXEC)){perror("mprotect");exit(1);}__builtin___clear_cache((char*)p,(char*)p+emitted.size()*4);
 Result result{};CallerState state{{0x0808080808080808ull,0x0909090909090909ull,0x0a0a0a0a0a0a0a0aull,0x0b0b0b0b0b0b0b0bull,0x0c0c0c0c0c0c0c0cull,0x0d0d0d0d0d0d0d0dull,0x0e0e0e0e0e0e0e0eull,0x0f0f0f0f0f0f0f0full},0x00c00000ull,0x0800009full},want=state;fsub_invoke_checked(reinterpret_cast<NativeFn>(p),&result,nbits,mbits,&state);for(unsigned i=0;i<8;i++)if(state.d[i]!=want.d[i])fail("FSUB preserves caller D8-D15",want.d[i],state.d[i]);if(state.fpcr!=want.fpcr)fail("FSUB restores caller FPCR",want.fpcr,state.fpcr);if(state.fpsr!=want.fpsr)fail("FSUB restores caller FPSR",want.fpsr,state.fpsr);munmap(p,ps);return result;
}
int main(){
#if !defined(__aarch64__)
 std::fprintf(stderr,"FSUB_EMITTER_FAIL native AArch64 host required\n");return 1;
#endif
 unsigned exact=0;for(unsigned d=0;d<32;d++)for(unsigned n=0;n<32;n++)for(unsigned m=0;m<32;m++){uae_u32 want=0x1e603800u|(m<<16)|(n<<5)|d,found=encoded(d,n,m);if(found!=want)fail("FSUB exact",want,found);exact++;}
 constexpr std::array<Vector,16> vectors{{
  {"exact_positive",0x4008000000000000ull,0x3ff0000000000000ull,{0x4000000000000000ull,0x4000000000000000ull,0x4000000000000000ull,0x4000000000000000ull},0},
  {"exact_negative",0xc008000000000000ull,0x3ff0000000000000ull,{0xc010000000000000ull,0xc010000000000000ull,0xc010000000000000ull,0xc010000000000000ull},0},
  {"positive_midpoint",0x3ff0000000000000ull,0x3c90000000000000ull,{0x3ff0000000000000ull,0x3ff0000000000000ull,0x3fefffffffffffffull,0x3fefffffffffffffull},0x10},
  {"negative_midpoint",0xbff0000000000000ull,0xbc90000000000000ull,{0xbff0000000000000ull,0xbfefffffffffffffull,0xbff0000000000000ull,0xbfefffffffffffffull},0x10},
  {"positive_overflow",0x7fefffffffffffffull,0xffefffffffffffffull,{0x7ff0000000000000ull,0x7ff0000000000000ull,0x7fefffffffffffffull,0x7fefffffffffffffull},0x14},
  {"negative_overflow",0xffefffffffffffffull,0x7fefffffffffffffull,{0xfff0000000000000ull,0xffefffffffffffffull,0xfff0000000000000ull,0xffefffffffffffffull},0x14},
  {"exact_cancel",0x3ff0000000000000ull,0x3ff0000000000000ull,{0,0,0x8000000000000000ull,0},0},
  {"positive_zero_minus_negative_zero",0,0x8000000000000000ull,{0,0,0,0},0},
  {"negative_zero_minus_positive_zero",0x8000000000000000ull,0,{0x8000000000000000ull,0x8000000000000000ull,0x8000000000000000ull,0x8000000000000000ull},0},
  {"infinity_minus_finite",0x7ff0000000000000ull,0x3ff0000000000000ull,{0x7ff0000000000000ull,0x7ff0000000000000ull,0x7ff0000000000000ull,0x7ff0000000000000ull},0},
  {"finite_minus_infinity",0x3ff0000000000000ull,0x7ff0000000000000ull,{0xfff0000000000000ull,0xfff0000000000000ull,0xfff0000000000000ull,0xfff0000000000000ull},0},
  {"infinity_minus_infinity",0x7ff0000000000000ull,0x7ff0000000000000ull,{0x7ff8000000000000ull,0x7ff8000000000000ull,0x7ff8000000000000ull,0x7ff8000000000000ull},1},
  {"left_quiet_nan",0x7ff82468a0000000ull,0x3ff0000000000000ull,{0x7ff82468a0000000ull,0x7ff82468a0000000ull,0x7ff82468a0000000ull,0x7ff82468a0000000ull},0},
  {"right_quiet_nan",0x3ff0000000000000ull,0x7ff82468a0000000ull,{0x7ff82468a0000000ull,0x7ff82468a0000000ull,0x7ff82468a0000000ull,0x7ff82468a0000000ull},0},
  {"left_signalling_nan",0x7ff02468a0000000ull,0x3ff0000000000000ull,{0x7ff82468a0000000ull,0x7ff82468a0000000ull,0x7ff82468a0000000ull,0x7ff82468a0000000ull},1},
  {"right_signalling_nan",0x3ff0000000000000ull,0x7ff02468a0000000ull,{0x7ff82468a0000000ull,0x7ff82468a0000000ull,0x7ff82468a0000000ull,0x7ff82468a0000000ull},1}
 }};
 constexpr std::array<Route,7> routes{{{0,1,2,false},{7,7,8,false},{9,10,9,false},{11,12,12,true},{13,13,13,true},{31,30,29,false},{8,15,14,false}}};
 unsigned native=0,aliases=0;for(unsigned ri=0;ri<routes.size();ri++)for(unsigned vi=0;vi<vectors.size();vi++)for(unsigned mode=0;mode<4;mode++){
  const Route&r=routes[ri];const Vector&v=vectors[vi];std::uint64_t nb=r.equal_sources?0x4008000000000000ull:v.n,mb=r.equal_sources?0x4008000000000000ull:v.m;std::array<std::uint64_t,4> out=r.equal_sources?std::array<std::uint64_t,4>{0,0,0x8000000000000000ull,0}:v.out;std::uint32_t flags=r.equal_sources?0:v.flags;Result x=run(r,nb,mb,mode);if(x.value!=out[mode])fail(r.equal_sources?"finite_equal_sources":v.name,out[mode],x.value);std::uint64_t loadedn=r.n==r.m?mb:nb;std::uint64_t en=r.d==r.n?out[mode]:loadedn,em=r.d==r.m?out[mode]:mb;if(x.n!=en)fail("FSUB N source/alias semantics",en,x.n);if(x.m!=em)fail("FSUB M source/alias semantics",em,x.m);if((x.nzcv&0xf0000000ull)!=0xb0000000ull)fail("FSUB preserves NZCV",0xb0000000ull,x.nzcv&0xf0000000ull);if(x.fpcr!=(std::uint64_t(mode)<<22))fail("FSUB preserves FPCR",std::uint64_t(mode)<<22,x.fpcr);std::uint64_t ef=0x08000080ull|flags;if(x.fpsr!=ef)fail("FSUB FPSR",ef,x.fpsr);native++;if(r.d==r.n||r.d==r.m||r.n==r.m)aliases++;
 }
 for(unsigned i=0;i<32;i++)for(unsigned mode=0;mode<4;mode++){Route r{i,(i+1)%32,(i+2)%32,false};const Vector&v=vectors[(i+mode)%vectors.size()];Result x=run(r,v.n,v.m,mode);if(x.value!=v.out[mode])fail(v.name,v.out[mode],x.value);native++;}
 std::printf("METRIC emitter_fsub_exact_words=%u\n",exact);std::printf("METRIC emitter_fsub_native_routes=%u\n",native);std::printf("METRIC emitter_fsub_alias_routes=%u\n",aliases);return exact==32768&&native==576&&aliases==256?0:1;
}
