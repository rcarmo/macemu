#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <sys/mman.h>
#include <unistd.h>
#include <utility>
#include <vector>
using uae_u32=std::uint32_t;
static std::vector<uae_u32> emitted; static void emit_long(uae_u32 w){emitted.push_back(w);}
#include "../BasiliskII/src/uae_cpu_2026/compiler/codegen_arm64.h"
struct Out{std::uint64_t result,nzcv;};
static void fail(const char*l,std::uint64_t e,std::uint64_t f){std::fprintf(stderr,"LOGICAL_EMITTER_FAIL %s expected=%016llx found=%016llx\n",l,(unsigned long long)e,(unsigned long long)f);std::exit(1);}
static uae_u32 one(){if(emitted.size()!=1)fail("count",1,emitted.size());auto w=emitted[0];emitted.clear();return w;}
enum class Api{BICW,ORRW,ORRWLSR,ORRX,ORRXLSL,TSTW,TSTX};
static uae_u32 word(Api a,unsigned d,unsigned n,unsigned m,unsigned sh=0){emitted.clear();switch(a){case Api::BICW:BIC_www(d,n,m);break;case Api::ORRW:ORR_www(d,n,m);break;case Api::ORRWLSR:ORR_wwwLSRi(d,n,m,sh);break;case Api::ORRX:ORR_xxx(d,n,m);break;case Api::ORRXLSL:ORR_xxxLSLi(d,n,m,sh);break;case Api::TSTW:TST_ww(n,m);break;case Api::TSTX:TST_xx(n,m);break;}return one();}
static Out run(uae_u32 op,unsigned d,std::uint64_t a,std::uint64_t b,std::uint64_t nz){std::vector<uae_u32> c{0xd51b4202u,op,0xd53b4205u,(uae_u32)(0xf9000060u|d),0xf9000465u,0xd65f03c0u};long ps=sysconf(_SC_PAGESIZE);void*p=mmap(nullptr,ps,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);if(p==MAP_FAILED){perror("mmap");exit(1);}memcpy(p,c.data(),c.size()*4);if(mprotect(p,ps,PROT_READ|PROT_EXEC)){perror("mprotect");exit(1);}__builtin___clear_cache((char*)p,(char*)p+c.size()*4);Out o{};using F=void(*)(std::uint64_t,std::uint64_t,std::uint64_t,Out*);((F)p)(a,b,nz,&o);munmap(p,ps);return o;}
static std::uint64_t mask(unsigned bits){return bits==64?~0ull:0xffffffffull;}
static std::uint64_t shifted(Api api,std::uint64_t b,unsigned sh,unsigned bits){if(api==Api::ORRWLSR)return (b&mask(bits))>>sh;if(api==Api::ORRXLSL)return (b<<sh)&mask(bits);return b&mask(bits);}
static void check(Api api,unsigned bits,unsigned alias,unsigned sh,std::uint64_t a,std::uint64_t b,unsigned&total,unsigned&aliases){bool tst=api==Api::TSTW||api==Api::TSTX;unsigned d=tst?31:(alias==0?4:alias==1?0:1);auto op=word(api,d,0,1,sh);auto rhs=shifted(api,b,sh,bits),m=mask(bits);auto result=(api==Api::BICW?(a&~rhs):(a|rhs))&m;if(tst)result=(a&b)&m;std::uint64_t hostile=(total&1)?0xf0000000u:0x30000000u;auto o=run(op,d,a,b,hostile);if(!tst&&o.result!=result)fail("result",result,o.result);auto flags=tst?(((result>>(bits-1))&1)<<31 | std::uint64_t(result==0)<<30):hostile;if((o.nzcv&0xf0000000u)!=flags)fail("flags",flags,o.nzcv&0xf0000000u);++total;if(!tst&&alias)++aliases;}
int main(){
#if !defined(__aarch64__)
return 1;
#endif
struct A{Api a;unsigned bits;uae_u32 w1,w2;};A as[]={{Api::BICW,32,0x0a2b0149u,0x0a3f03ffu},{Api::ORRW,32,0x2a0b0149u,0x2a1f03ffu},{Api::ORRWLSR,32,0x2a4b7d49u,0x2a5f7fffu},{Api::ORRX,64,0xaa0b0149u,0xaa1f03ffu},{Api::ORRXLSL,64,0xaa0bfd49u,0xaa1fffffu},{Api::TSTW,32,0x6a0b015fu,0x6a1f03ffu},{Api::TSTX,64,0xea0b015fu,0xea1f03ffu}};unsigned anchors=0,total=0,aliases=0;for(auto&a:as){unsigned sh=(a.a==Api::ORRWLSR?31:a.a==Api::ORRXLSL?63:0);auto x=word(a.a,9,10,11,sh),y=word(a.a,31,31,31,sh);if(x!=a.w1)fail("anchor",a.w1,x);if(y!=a.w2)fail("anchor",a.w2,y);anchors+=2;}
std::pair<std::uint64_t,std::uint64_t> p[]={{0,0},{0,~0ull},{~0ull,0},{~0ull,~0ull},{0x8000000080000000ull,~0ull},{0x7fffffff7fffffffull,1},{0xaaaaaaaaaaaaaaaaull,0x5555555555555555ull},{0xf0f0f0f0f0f0f0f0ull,0xff00ff00ff00ff00ull}};
for(Api a:{Api::BICW,Api::ORRW,Api::ORRX}){unsigned bits=a==Api::ORRX?64:32;unsigned i=0;for(auto&v:p){check(a,bits,i++%3,0,v.first,v.second,total,aliases);}}
for(unsigned sh:{0u,1u,16u,31u})for(auto&v:p)check(Api::ORRWLSR,32,total%3,sh,v.first,v.second,total,aliases);
for(unsigned sh:{0u,1u,32u,63u})for(auto&v:p)check(Api::ORRXLSL,64,total%3,sh,v.first,v.second,total,aliases);
for(Api a:{Api::TSTW,Api::TSTX})for(auto&v:p)check(a,a==Api::TSTW?32:64,0,0,v.first,v.second,total,aliases);
std::printf("METRIC emitter_logical_apis=7\nMETRIC emitter_logical_anchor_words=%u\nMETRIC emitter_logical_native_vectors=%u\nMETRIC emitter_logical_alias_vectors=%u\nMETRIC emitter_logical_flag_vectors=16\n",anchors,total,aliases);return anchors==14&&total==104&&aliases==57?0:1;}
