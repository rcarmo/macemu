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

struct Result { std::uint64_t value, nzcv, fpcr, fpsr; };
struct CallerState { std::uint64_t d[8], fpcr, fpsr; };
using NativeFn = void (*)(Result *);
extern "C" void fmov_di_invoke_checked(NativeFn, Result *, CallerState *);

#if defined(__aarch64__)
asm(R"(
.text
.align 2
.global fmov_di_invoke_checked
.type fmov_di_invoke_checked,%function
fmov_di_invoke_checked:
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
 ldr d8,[x21,#0]
 ldr d9,[x21,#8]
 ldr d10,[x21,#16]
 ldr d11,[x21,#24]
 ldr d12,[x21,#32]
 ldr d13,[x21,#40]
 ldr d14,[x21,#48]
 ldr d15,[x21,#56]
 ldr x9,[x21,#64]
 ldr x10,[x21,#72]
 msr fpcr,x9
 msr fpsr,x10
 mov x0,x20
 blr x19
 str d8,[x21,#0]
 str d9,[x21,#8]
 str d10,[x21,#16]
 str d11,[x21,#24]
 str d12,[x21,#32]
 str d13,[x21,#40]
 str d14,[x21,#48]
 str d15,[x21,#56]
 mrs x9,fpcr
 mrs x10,fpsr
 str x9,[x21,#64]
 str x10,[x21,#72]
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
.size fmov_di_invoke_checked,.-fmov_di_invoke_checked
)");
#endif

static void fail(const char *label, std::uint64_t expected, std::uint64_t found) {
    std::fprintf(stderr, "FMOV_DI_EMITTER_FAIL label=%s expected=%016llx found=%016llx\n",
                 label, static_cast<unsigned long long>(expected),
                 static_cast<unsigned long long>(found));
    std::exit(1);
}

static uae_u32 encoded(unsigned destination, unsigned immediate) {
    emitted.clear();
    FMOV_di(destination, immediate);
    if (emitted.size() != 1) fail("FMOV_di word count", 1, emitted.size());
    return emitted[0];
}

static std::uint64_t expand_imm8(unsigned immediate) {
    const std::uint64_t sign = static_cast<std::uint64_t>((immediate >> 7) & 1) << 63;
    const unsigned b6 = (immediate >> 6) & 1;
    const unsigned exponent = ((b6 ^ 1) << 10) | ((b6 ? 0xffu : 0u) << 2) |
                              ((immediate >> 4) & 3);
    const std::uint64_t fraction = static_cast<std::uint64_t>(immediate & 0xf) << 48;
    return sign | (static_cast<std::uint64_t>(exponent) << 52) | fraction;
}

static Result run(unsigned destination, unsigned immediate, unsigned mode) {
    emitted.clear();
    SUB_xxi(31,31,80);
    for (unsigned reg=8; reg<=15; ++reg) STR_dXi(reg,31,(reg-8)*8);
    STR_xXi(30,31,64);
    MRS_FPCR_x(14); MRS_FPSR_x(15); MOV_xx(16,0);
    MOV_wi(3,0); MOVK_wish(3,mode<<6,16); MSR_FPCR_x(3);
    MOV_wi(4,0x9f); MOVK_wish(4,0x0800,16); MSR_FPSR_x(4);
    MOV_wi(5,0); MOVK_wish(5,0xb000,16); MSR_NZCV_x(5);
    FMOV_di(destination,immediate);
    FMOV_xd(12,destination);
    MRS_NZCV_x(9); MRS_FPCR_x(10); MRS_FPSR_x(11);
    STR_xXi(12,16,0); STR_xXi(9,16,8); STR_xXi(10,16,16); STR_xXi(11,16,24);
    MSR_FPSR_x(15); MSR_FPCR_x(14); LDR_xXi(30,31,64);
    for (unsigned reg=8; reg<=15; ++reg) LDR_dXi(reg,31,(reg-8)*8);
    ADD_xxi(31,31,80); emitted.push_back(0xd65f03c0u);

    const long page_size=sysconf(_SC_PAGESIZE);
    void *page=mmap(nullptr,static_cast<std::size_t>(page_size),PROT_READ|PROT_WRITE,
                    MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
    if(page==MAP_FAILED){std::perror("mmap");std::exit(1);}
    std::memcpy(page,emitted.data(),emitted.size()*sizeof(uae_u32));
    if(mprotect(page,static_cast<std::size_t>(page_size),PROT_READ|PROT_EXEC)){
        std::perror("mprotect");std::exit(1);
    }
    __builtin___clear_cache(static_cast<char*>(page),static_cast<char*>(page)+emitted.size()*sizeof(uae_u32));
    Result result{};
    CallerState state{{0x0808080808080808ull,0x0909090909090909ull,
      0x0a0a0a0a0a0a0a0aull,0x0b0b0b0b0b0b0b0bull,0x0c0c0c0c0c0c0c0cull,
      0x0d0d0d0d0d0d0d0dull,0x0e0e0e0e0e0e0e0eull,0x0f0f0f0f0f0f0f0full},
      0x00c00000ull,0x0800009full};
    const CallerState expected=state;
    fmov_di_invoke_checked(reinterpret_cast<NativeFn>(page),&result,&state);
    for(unsigned index=0;index<8;++index)
      if(state.d[index]!=expected.d[index]) fail("FMOV_di preserves caller D8-D15",expected.d[index],state.d[index]);
    if(state.fpcr!=expected.fpcr) fail("FMOV_di restores caller FPCR",expected.fpcr,state.fpcr);
    if(state.fpsr!=expected.fpsr) fail("FMOV_di restores caller FPSR",expected.fpsr,state.fpsr);
    munmap(page,static_cast<std::size_t>(page_size));
    return result;
}

int main(){
#if !defined(__aarch64__)
    std::fprintf(stderr,"FMOV_DI_EMITTER_FAIL native AArch64 host required\n");return 1;
#endif
    unsigned exact_words=0,native_routes=0;
    for(unsigned destination=0;destination<32;++destination){
      for(unsigned immediate=0;immediate<256;++immediate){
        const uae_u32 expected_word=0x1e601000u|(immediate<<13)|destination;
        const uae_u32 found=encoded(destination,immediate);
        if(found!=expected_word) fail("FMOV_di exact",expected_word,found);
        exact_words++;
        const std::uint64_t expected_bits=expand_imm8(immediate);
        for(unsigned mode=0;mode<4;++mode){
          const Result result=run(destination,immediate,mode);
          if(result.value!=expected_bits) fail("FMOV_di VFPExpandImm",expected_bits,result.value);
          if((result.nzcv&0xf0000000ull)!=0xb0000000ull)
            fail("FMOV_di preserves NZCV",0xb0000000ull,result.nzcv&0xf0000000ull);
          if(result.fpcr!=(static_cast<std::uint64_t>(mode)<<22))
            fail("FMOV_di preserves FPCR",static_cast<std::uint64_t>(mode)<<22,result.fpcr);
          if(result.fpsr!=0x0800009full)
            fail("FMOV_di preserves FPSR",0x0800009full,result.fpsr);
          native_routes++;
        }
      }
    }
    std::printf("METRIC emitter_fmov_di_exact_words=%u\n",exact_words);
    std::printf("METRIC emitter_fmov_di_native_routes=%u\n",native_routes);
    std::printf("METRIC emitter_fmov_di_immediates=%u\n",256u);
    return exact_words==8192&&native_routes==32768?0:1;
}
