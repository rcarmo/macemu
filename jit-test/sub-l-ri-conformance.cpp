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

static void fail(const char *label, std::uint64_t expected, std::uint64_t found) {
  std::fprintf(stderr, "SUB_L_RI_FAIL label=%s expected=%016llx found=%016llx\n", label,
    static_cast<unsigned long long>(expected), static_cast<unsigned long long>(found));
  std::exit(1);
}
static std::uint64_t run(const std::vector<uae_u32> &words, std::uint64_t input) {
  const long n = sysconf(_SC_PAGESIZE); void *p = mmap(nullptr, n, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
  if (p == MAP_FAILED) { std::perror("mmap"); std::exit(1); }
  std::memcpy(p, words.data(), words.size()*4); mprotect(p,n,PROT_READ|PROT_EXEC);
  __builtin___clear_cache(static_cast<char*>(p), static_cast<char*>(p)+words.size()*4);
  using Fn=std::uint64_t(*)(std::uint64_t); auto out=reinterpret_cast<Fn>(p)(input); munmap(p,n); return out;
}
int main() {
#if !defined(__aarch64__)
  return 1;
#endif
  emitted.clear(); SUB_wwi(9,9,1); if (emitted.size()!=1 || emitted[0]!=0x51000529u) fail("SUB_wwi exact",0x51000529u,emitted.empty()?0:emitted[0]);
  constexpr uae_u32 mov_w9_w0=0x2a0003e9u, mov_w0_w9=0x2a0903e0u, ret=0xd65f03c0u;
  unsigned vectors=0;
  for (const std::uint64_t in : {0ull,1ull,2ull,0xffffffffull,0x80000000ull,0xdeadbeef00000000ull}) {
    const auto expected=static_cast<std::uint32_t>(static_cast<std::uint32_t>(in)-1u);
    const auto found=run({mov_w9_w0,0x51000529u,mov_w0_w9,ret},in);
    if (found != expected) fail("native modulo32", expected, found);
    vectors++;
  }
  std::printf("METRIC sub_l_ri_exact_words=1\nMETRIC sub_l_ri_native_vectors=%u\nMETRIC sub_l_ri_modulo32=1\n",vectors);
  return vectors==6?0:1;
}
