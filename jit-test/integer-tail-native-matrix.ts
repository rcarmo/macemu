#!/usr/bin/env bun
import {mkdtempSync,rmSync,writeFileSync} from "node:fs";import{tmpdir}from"node:os";import{join}from"node:path";import{spawnSync}from"node:child_process";
const root=new URL("..",import.meta.url).pathname,bin=`${root}/BasiliskII/src/Unix/BasiliskII`,rom=process.env.ROM??"/workspace/projects/rpi-basilisk2-sdl2-nox/Quadra800.ROM",diskSource=process.env.DISK??"/workspace/fixtures/basilisk/images/HD200MB",display=process.env.DISPLAY??":99",cowLib=process.env.COW_LIB??"/workspace/scripts/lib/cow-disk.sh",dd=mkdtempSync(join(tmpdir(),"integer-tail-disk-")),cl=spawnSync("bash",["-c",'set -euo pipefail\nsource "$1"\ncow_clone "$2" "$3/disk.img" integer-tail',"bash",cowLib,diskSource,dd],{encoding:"utf8"});if(cl.status!==0){console.error(cl.stderr||"INTEGER_TAIL_FAIL clone");process.exit(1)}const disk=cl.stdout.trim().split("\n").at(-1)!;
type C={name:string,stream:string,d?:Record<number,string>,a?:Record<number,string>,sr?:string,memory?:string,memdump?:string,want:Record<string,string>,wantmem?:string,alias?:number,scratch?:number,pin?:boolean};
const C=(name:string,stream:string,want:Record<string,string>,x:Partial<C>={}):C=>({name,stream,want,...x});
const cases:C[]=[
C("muls_neg_neg","c1c1 2c7c a6c8 0001",{D0:"0000000f",D1:"fffffffb",SR:"2710"},{d:{0:"fffffffd",1:"fffffffb"}}),
C("muls_min_times_minus1","c1c1 2c7c a6c8 0002",{D0:"00008000",SR:"2710"},{d:{0:"00008000",1:"ffffffff"}}),
C("muls_same_reg","c1c0 2c7c a6c8 0003",{D0:"00000009",SR:"2710"},{d:{0:"fffffffd"}}),
C("muls_d16","c1e8 0002 2c7c a6c8 0004",{D0:"fffffff1",A0:"00008ffe",SR:"2718"},{d:{0:"00000003"},a:{0:"00008ffe"},memory:"9000 ff 9001 fb"}),
C("mulu_max","c0c1 2c7c a6c8 0005",{D0:"fffe0001",SR:"2718"},{d:{0:"0000ffff",1:"0000ffff"}}),
C("mulu_same_reg","c0c0 2c7c a6c8 0006",{D0:"fffe0001",SR:"2718"},{d:{0:"0000ffff"}}),
C("mulu_zero","c0c1 2c7c a6c8 0007",{D0:"00000000",SR:"2714"},{d:{0:"00000000",1:"0000ffff"}}),
C("mulu_d16","c0e8 0002 2c7c a6c8 0008",{D0:"0000000f",A0:"00008ffe",SR:"2710"},{d:{0:"00000003"},a:{0:"00008ffe"},memory:"9000 00 9001 05"}),
C("not_b_d7","4607 2c7c a6c8 0009",{D7:"12345687",SR:"2718"},{d:{7:"12345678"}}),
C("not_w_d0","4640 2c7c a6c8 000a",{D0:"1234a987",SR:"2718"},{d:{0:"12345678"}}),
C("not_l_d0","4680 2c7c a6c8 000b",{D0:"edcba987",SR:"2718"},{d:{0:"12345678"}}),
C("not_l_zero","4680 2c7c a6c8 001e",{D0:"00000000",SR:"2714"},{d:{0:"ffffffff"}}),
C("not_b_postinc","4618 2c7c a6c8 000c",{A0:"00009001",SR:"2718"},{a:{0:"00009000"},memory:"8fff a5 9000 55 9001 5a",memdump:"0x8fff:3",wantmem:"a5 aa 5a"}),
C("not_b_d16_pressure","4628 0004 2c7c a6c8 000d",{A0:"00008ffc",SR:"2710"},{a:{0:"00008ffc"},memory:"8fff a5 9000 aa 9001 5a",memdump:"0x8fff:3",wantmem:"a5 55 5a",alias:20,scratch:22,pin:true}),
C("suba_w_negative_imm","90fc ffff 2c7c a6c8 000e",{A0:"00001001",SR:"271f"},{a:{0:"00001000"}}),
C("suba_l_wrap_imm","91fc 0000 1001 2c7c a6c8 000f",{A0:"ffffffff",SR:"271f"},{a:{0:"00001000"}}),
C("suba_w_dreg","90c0 2c7c a6c8 0010",{A0:"00001001",D0:"0000ffff",SR:"271f"},{d:{0:"0000ffff"},a:{0:"00001000"}}),
C("suba_w_postinc_alias","90d8 2c7c a6c8 0011",{A0:"00008fff",SR:"271f"},{a:{0:"00009000"},memory:"9000 00 9001 03",alias:22,scratch:23,pin:true}),
C("suba_l_postinc_alias","91d8 2c7c a6c8 0012",{A0:"00009001",SR:"271f"},{a:{0:"00009000"},memory:"9000 00 9001 00 9002 00 9003 03"}),
C("swap_negative","4840 2c7c a6c8 0013",{D0:"ccddaabb",SR:"2718"},{d:{0:"aabbccdd"}}),
C("swap_d7_positive","4847 2c7c a6c8 0014",{D7:"00020001",SR:"2710"},{d:{7:"00010002"}}),
C("swap_zero","4840 2c7c a6c8 001f",{D0:"00000000",SR:"2714"},{d:{0:"00000000"}}),
C("swap_noflags","4840 7200 2c7c a6c8 0015",{D0:"56781234",D1:"00000000",SR:"2714"},{d:{0:"12345678"}}),
C("tst_b_d7_negative","4a07 2c7c a6c8 0016",{D7:"12345680",SR:"2718"},{d:{7:"12345680"}}),
C("tst_w_zero","4a40 2c7c a6c8 0017",{D0:"12340000",SR:"2714"},{d:{0:"12340000"}}),
C("tst_l_positive","4a80 2c7c a6c8 0018",{D0:"00010000",SR:"2710"},{d:{0:"00010000"}}),
C("tst_b_d16_negative","4a28 0004 2c7c a6c8 0019",{A0:"00008ffc",SR:"2718"},{a:{0:"00008ffc"},memory:"9000 80"}),
C("tst_b_immediate_negative","4a3c 0080 2c7c a6c8 001a",{SR:"2718"}),
C("tst_w_immediate_zero","4a7c 0000 2c7c a6c8 001b",{SR:"2714"}),
C("tst_l_immediate_negative","4abc 8000 0000 2c7c a6c8 001c",{SR:"2718"}),
C("tst_l_noflags","4a80 7200 2c7c a6c8 001d",{D0:"80000000",D1:"00000000",SR:"2714"},{d:{0:"80000000"}}),
C("tst_b_postinc_noflags","4a18 7200 2c7c a6c8 0020",{A0:"00009001",D1:"00000000",SR:"2714"},{a:{0:"00009000"},memory:"9000 80"}),
];
function prefs(p:string,j:boolean){writeFileSync(p,[`rom ${rom}`,`disk ${disk}`,"ramsize 8388608","modelid 14","cpu 4","fpu false",`jit ${j}`,"jitfpu false","jitcachesize 8192","screen win/640/480","nosound true","nocdrom true","nogui true","ignoresegv true",""].join("\n"))}
function init(c:C){const r=Array(16).fill("00000000");r[15]="007fe000";for(const[k,v]of Object.entries(c.d??{}))r[+k]=v;for(const[k,v]of Object.entries(c.a??{}))r[8+(+k)]=v;return`${r.join(" ")} ${c.sr??"271f"}`}
function fields(d?:string){const o:Record<string,string>={};for(const m of d?.matchAll(/\b(D[0-7]|A[0-7]|SR)=([0-9a-f]+)/gi)??[])o[m[1].toUpperCase()]=m[2].toLowerCase();return o}
function run(c:C,j:boolean){const td=mkdtempSync(join(tmpdir(),`integer-tail-${j?"jit":"int"}-`));try{const p=join(td,"prefs");prefs(p,j);const e:NodeJS.ProcessEnv={...process.env,SDL_VIDEODRIVER:"x11",DISPLAY:display,HOME:td,B2_TEST_HEX:c.stream,B2_TEST_INIT:init(c),B2_TEST_DUMP:"1"};if(c.memory){e.B2_TEST_MEMORY_BYTES=c.memory;e.B2_TEST_REPLAY_BYTES=c.memory}if(c.memdump)e.B2_TEST_MEMDUMP=c.memdump;if(j)Object.assign(e,{B2_JIT_FORCE_TRANSLATE:"1",B2_TEST_TWO_PASS:"1",B2_TEST_SECOND_PC:"0x1000",B2_TEST_REPLAY_COUNT:"2",B2_TEST_FORCE_L2_RAM:"1",B2_JIT_STRICT_FULL:"1",B2_NATIVE_ASSERT_PC:"0x1000",...(c.alias===undefined?{}:{B2_FORCE_SCRATCH_ALIAS_VREG:String(c.alias),B2_FORCE_SCRATCH_VREG:String(c.scratch)})});const q=spawnSync("timeout",["-k","5s","35s",bin,"--config",p],{encoding:"utf8",timeout:40000,env:e}),out=`${q.stdout??""}${q.stderr??""}`,ds=[...out.matchAll(/^REGDUMP:.*$/gm)].map(m=>m[0]),md=[...out.matchAll(/^MEMDUMP [^:]+:(.*)$/gm)].map(m=>m[1].trim().toLowerCase());return{rc:q.status,out,dump:ds.at(-1),f:fields(ds.at(-1)),mem:md.at(-1)}}finally{rmSync(td,{recursive:true,force:true})}}
let pass=0,fail=0;try{const selected=process.env.CASE?cases.filter(c=>c.name===process.env.CASE):cases;if(!selected.length)throw Error(`unknown CASE=${process.env.CASE}`);for(const c of selected){const i=run(c,false),j=run(c,true),exact=Object.entries(c.want).every(([k,v])=>i.f[k]===v&&j.f[k]===v),equiv=i.dump!==undefined&&i.dump===j.dump,memok=!c.wantmem||(i.mem===c.wantmem&&j.mem===c.wantmem),native=j.out.includes("NATEXEC pc=00001000"),strict=j.out.includes("JIT_STRICT_SUMMARY ")&&!j.out.includes("strict full-JIT:")&&!j.out.includes("JIT_FALLBACK"),pin=!c.pin||j.out.includes("REGPRESSURE_PIN_HIT")||j.out.includes("REGPRESSURE_PIN_SKIP");if(i.rc===0&&j.rc===0&&exact&&equiv&&memok&&native&&strict&&pin)pass++;else{fail++;console.error(`INTEGER_TAIL_FAIL case=${c.name} int=${i.rc} jit=${j.rc} exact=${+exact} equiv=${+equiv} mem=${+memok} native=${+native} strict=${+strict} pin=${+pin}`);console.error(`interp=${i.dump??"missing"} mem=${i.mem??""}`);console.error(`jit=${j.dump??"missing"} mem=${j.mem??""}`);for(const l of j.out.split("\n").filter(x=>/Caught|strict full-JIT|JIT_FALLBACK|NATEXEC|REGPRESSURE/.test(x)).slice(-12))console.error(l)}}}finally{spawnSync("bash",["-c",'source "$1"; cow_release "$2"',"bash",cowLib,disk]);rmSync(dd,{recursive:true,force:true})}console.log(`INTEGER_TAIL_NATIVE_MATRIX pass=${pass} fail=${fail} total=${pass+fail}`);process.exit(fail?1:0);
