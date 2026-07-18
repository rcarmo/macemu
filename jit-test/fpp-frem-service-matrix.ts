#!/usr/bin/env bun

import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { spawnSync } from "node:child_process";

const root = new URL("..", import.meta.url).pathname;
const bin = `${root}/BasiliskII/src/Unix/BasiliskII`;
const rom = process.env.ROM ?? "/workspace/projects/rpi-basilisk2-sdl2-nox/Quadra800.ROM";
const diskSource = process.env.DISK ?? "/workspace/fixtures/basilisk/images/HD200MB";
const display = process.env.DISPLAY ?? ":99";
const cowLib = process.env.COW_LIB ?? "/workspace/scripts/lib/cow-disk.sh";
const zeroInit = "0 0 0 0 0 0 0 0 0000a000 0 0 0 0 0 0 007fe000 271f";
const x = {
  pz: "00 00 00 00 00 00 00 00 00 00 00 00", nz: "80 00 00 00 00 00 00 00 00 00 00 00",
  p1: "3f ff 00 00 80 00 00 00 00 00 00 00", n1: "bf ff 00 00 80 00 00 00 00 00 00 00",
  p2: "40 00 00 00 80 00 00 00 00 00 00 00", n2: "c0 00 00 00 80 00 00 00 00 00 00 00",
  p3: "40 00 00 00 c0 00 00 00 00 00 00 00", p6: "40 01 00 00 c0 00 00 00 00 00 00 00",
  p7: "40 01 00 00 e0 00 00 00 00 00 00 00", n7: "c0 01 00 00 e0 00 00 00 00 00 00 00",
  p125: "3f ff 00 00 a0 00 00 00 00 00 00 00", quarter: "3f fd 00 00 80 00 00 00 00 00 00 00", nTiny: "bf c0 00 00 80 00 00 00 00 00 00 00",
  p391: "40 07 00 00 c3 80 00 00 00 00 00 00", p195: "40 06 00 00 c3 00 00 00 00 00 00 00",
  pinf: "7f ff 00 00 00 00 00 00 00 00 00 00", ninf: "ff ff 00 00 00 00 00 00 00 00 00 00",
  max: "7f fe 00 00 ff ff ff ff ff ff ff ff", hugeModulus: "7f fd 00 00 80 00 00 00 00 00 00 00",
  minNormal: "00 01 00 00 80 00 00 00 00 00 00 00", twiceMinNormal: "00 02 00 00 80 00 00 00 00 00 00 00",
  onePlusUlp: "3f ff 00 00 80 00 00 00 00 00 00 01", oneMinusUlp: "3f fe 00 00 ff ff ff ff ff ff ff ff",
  halfPlusTiny: "3f fe 00 00 80 00 00 00 00 00 00 01", half: "3f fe 00 00 80 00 00 00 00 00 00 00",
  halfMinusTiny: "3f fd 00 00 ff ff ff ff ff ff ff fe",
  prevHalfSingle: "3f fd 00 00 ff ff ff 00 00 00 00 00", prevHalfDouble: "3f fd 00 00 ff ff ff ff ff ff f8 00",
  prevQuarterSingle: "3f fc 00 00 ff ff ff 00 00 00 00 00", prevQuarterDouble: "3f fc 00 00 ff ff ff ff ff ff f8 00",
  tiny: "3f c0 00 00 80 00 00 00 00 00 00 00", halfTiny: "3f bf 00 00 80 00 00 00 00 00 00 00",
  qnanA: "7f ff 00 00 c0 00 12 34 56 78 9a bc", nqnanB: "ff ff 00 00 c0 00 de ad be ef 12 34",
  snanA: "7f ff 00 00 80 00 12 34 56 78 9a bc", nsnanB: "ff ff 00 00 80 00 de ad be ef 12 34",
  quietA: "7f ff 00 00 c0 00 12 34 56 78 9a bc",
  canonical: "7f ff 00 00 ff ff ff ff ff ff ff ff",
} as const;

type C = { name:string; destination:string; source:string; output:string; operationFpsr:string; fpsr:string; fpcr?:string; replayFpsr?:string; destinationSnan?:boolean; aliasFp7?:boolean; destinationFp7?:boolean; ea?:"postinc"|"predec"; expectedA0?:string };
const cases:C[] = [
  {name:"frem_positive_7_by_3",destination:x.p7,source:x.p3,output:x.p1,operationFpsr:"00020000",fpsr:"00020000"},
  {name:"frem_negative_7_by_3",destination:x.n7,source:x.p3,output:x.n1,operationFpsr:"08820000",fpsr:"08820000"},
  {name:"frem_positive_7_by_negative_3",destination:x.p7,source:"c0 00 00 00 c0 00 00 00 00 00 00 00",output:x.p1,operationFpsr:"00820000",fpsr:"00820000"},
  {name:"frem_negative_7_by_negative_3",destination:x.n7,source:"c0 00 00 00 c0 00 00 00 00 00 00 00",output:x.n1,operationFpsr:"08020000",fpsr:"08020000"},
  {name:"frem_quotient_low_seven_wrap",destination:x.p195,source:x.p3,output:x.pz,operationFpsr:"04410000",fpsr:"04410000"},
  {name:"frem_nearest_not_truncating",destination:x.p7,source:"40 01 00 00 80 00 00 00 00 00 00 00",output:x.n1,operationFpsr:"08020000",fpsr:"08020000"},
  {name:"frem_tie_even_2p5",destination:"40 00 00 00 a0 00 00 00 00 00 00 00",source:x.p1,output:x.half,operationFpsr:"00020000",fpsr:"00020000"},
  {name:"frem_tie_even_3p5",destination:"40 00 00 00 e0 00 00 00 00 00 00 00",source:x.p1,output:"bf fe 00 00 80 00 00 00 00 00 00 00",operationFpsr:"08040000",fpsr:"08040000"},
  {name:"frem_extended_destination_low_bit",destination:x.onePlusUlp,source:x.p1,output:x.tiny,operationFpsr:"00010000",fpsr:"00010000"},
  {name:"frem_extended_source_low_bit",destination:x.p1,source:x.oneMinusUlp,output:x.halfTiny,operationFpsr:"00010000",fpsr:"00010000"},
  {name:"frem_single_nearest",destination:x.p125,source:x.halfPlusTiny,output:x.quarter,fpcr:"40",operationFpsr:"00020208",fpsr:"00020008"},
  {name:"frem_single_zero",destination:x.p125,source:x.halfPlusTiny,output:x.prevQuarterSingle,fpcr:"50",operationFpsr:"00020208",fpsr:"00020008"},
  {name:"frem_single_minus",destination:x.p125,source:x.halfPlusTiny,output:x.prevQuarterSingle,fpcr:"60",operationFpsr:"00020208",fpsr:"00020008"},
  {name:"frem_single_plus",destination:x.p125,source:x.halfPlusTiny,output:x.quarter,fpcr:"70",operationFpsr:"00020208",fpsr:"00020008"},
  {name:"frem_double_nearest",destination:x.p125,source:x.halfPlusTiny,output:x.quarter,fpcr:"80",operationFpsr:"00020208",fpsr:"00020008"},
  {name:"frem_double_zero",destination:x.p125,source:x.halfPlusTiny,output:x.prevQuarterDouble,fpcr:"90",operationFpsr:"00020208",fpsr:"00020008"},
  {name:"frem_single_overflow",destination:x.max,source:x.hugeModulus,output:x.ninf,fpcr:"40",operationFpsr:"0a041248",fpsr:"0a040048"},
  {name:"frem_single_underflow",destination:x.minNormal,source:x.twiceMinNormal,output:x.pz,fpcr:"40",operationFpsr:"04000a28",fpsr:"04000028"},
  {name:"frem_negative_zero_quotient_sign",destination:x.nz,source:x.p3,output:x.nz,operationFpsr:"0c800000",fpsr:"0c800000"},
  {name:"frem_zero_by_negative_source",destination:x.pz,source:"c0 00 00 00 c0 00 00 00 00 00 00 00",output:x.pz,operationFpsr:"04800000",fpsr:"04800000"},
  {name:"frem_finite_by_positive_infinity",destination:x.n7,source:x.pinf,output:x.n7,operationFpsr:"08800000",fpsr:"08800000"},
  {name:"frem_finite_by_negative_infinity",destination:x.p7,source:x.ninf,output:x.p7,operationFpsr:"00800000",fpsr:"00800000"},
  {name:"frem_source_zero_invalid_preserves_quotient",destination:x.p7,source:x.pz,output:x.canonical,replayFpsr:"0055ff00",operationFpsr:"01552080",fpsr:"01550080"},
  {name:"frem_destination_infinity_invalid_preserves_quotient",destination:x.pinf,source:x.p3,output:x.canonical,replayFpsr:"002aff00",operationFpsr:"012a2080",fpsr:"012a0080"},
  {name:"frem_destination_qnan_precedence",destination:x.qnanA,source:x.nqnanB,output:x.qnanA,replayFpsr:"00330000",operationFpsr:"01330000",fpsr:"01330000"},
  {name:"frem_source_snan_quiet_then_destination_precedence",destination:x.qnanA,source:x.nsnanB,output:x.qnanA,operationFpsr:"01004080",fpsr:"01000080"},
  {name:"frem_destination_snan_quiet_then_destination_precedence",destination:x.snanA,source:x.nqnanB,output:x.quietA,operationFpsr:"01004080",fpsr:"01000080",destinationSnan:true},
  {name:"frem_source_only_snan",destination:x.p7,source:x.nsnanB,output:"ff ff 00 00 c0 00 de ad be ef 12 34",operationFpsr:"09004080",fpsr:"09000080"},
  {name:"frem_fp7_self_alias",destination:x.n7,source:x.n7,output:x.nz,operationFpsr:"0c010000",fpsr:"0c010000",aliasFp7:true},
  {name:"frem_fp7_destination_reseed",destination:x.p7,source:x.p3,output:x.p1,operationFpsr:"00020000",fpsr:"00020000",destinationFp7:true},
  {name:"frem_postincrement_source",destination:x.p7,source:x.p3,output:x.p1,operationFpsr:"00020000",fpsr:"00020000",ea:"postinc",expectedA0:"0000902c"},
  {name:"frem_predecrement_source",destination:x.p7,source:x.p3,output:x.p1,operationFpsr:"00020000",fpsr:"00020000",ea:"predec",expectedA0:"00009020"},
  {name:"frem_quotient_replaced_accrued_preserved",destination:x.p7,source:x.p3,output:x.p1,replayFpsr:"0055ff08",operationFpsr:"00020008",fpsr:"00020008"},
];
const strict=[{name:"frem_strict",extra:"1fa5"}] as const;
function B(a:number,v:string){return v.split(/\s+/).map((b,i)=>`${(a+i).toString(16)} ${b}`).join(" ")}
function P(p:string,d:string){writeFileSync(p,[`rom ${rom}`,`disk ${d}`,"ramsize 8388608","modelid 14","cpu 4","fpu true","jit true","jitfpu true","jitcachesize 8192","screen win/640/480","nosound true","nocdrom true","nogui true","ignoresegv true",""].join("\n"))}
const dd=mkdtempSync(join(tmpdir(),"fpp-frem-disk-")),cl=spawnSync("bash",["-c","set -euo pipefail\nsource \"$1\"\ncow_clone \"$2\" \"$3/disk.img\" fpp-frem","bash",cowLib,diskSource,dd],{encoding:"utf8"});if(cl.status!==0){console.error(cl.stderr||"FPP_FREM_FAIL clone");rmSync(dd,{recursive:true,force:true});process.exit(1)}const disk=cl.stdout.trim().split("\n").at(-1)!,sc=process.env.CASE?cases.filter(a=>a.name===process.env.CASE):cases,ss=process.env.CASE?strict.filter(a=>a.name===process.env.CASE):strict;let sp=0,st=0,fail=0;
try{if(!sc.length&&!ss.length)throw Error(`unknown CASE=${process.env.CASE}`);for(const a of sc){const td=mkdtempSync(join(tmpdir(),"fpp-frem-service-"));try{P(join(td,"prefs"),disk);const fp7=a.aliasFp7||a.destinationFp7,load=a.destinationSnan?"F239 D080":fp7?"F239 4B80":"F239 4800",extra=(0x4825+(fp7?0x380:0)).toString(16),op=a.aliasFp7?"F200 1FA5":`${a.ea==="postinc"?"F218":a.ea==="predec"?"F220":"F239"} ${extra}${a.ea?"":" 0000 9010"}`,store=fp7?"F239 6B80 0000 A000":"F239 6800 0000 A000",stream=`${load} 0000 9000 ${op} F200 A800 ${store} 2C7C A6C2 0000`,sourceAddr=a.ea?0x9020:0x9010,init=a.ea==="postinc"?zeroInit.replace("0000a000","00009020"):a.ea==="predec"?zeroInit.replace("0000a000","0000902c"):zeroInit,guard=`${B(0x9ffe,"a5 5a")} ${B(0xa000,x.pz)} ${B(0xa00c,"3c c3")}`,seed=a.destination.replaceAll(" ","").match(/.{8}/g)!.join(" "),r=spawnSync("timeout",["-k","5s","30s",bin,"--config",join(td,"prefs")],{encoding:"utf8",timeout:35000,env:{...process.env,SDL_VIDEODRIVER:"x11",DISPLAY:display,HOME:td,B2_TEST_HEX:stream,B2_TEST_INIT:init,B2_TEST_MEMORY_BYTES:`${B(0x9000,a.destination)} ${B(sourceAddr,a.source)} ${guard}`,B2_TEST_MEMDUMP:"0x9ffe:16",B2_TEST_DUMP:"1",B2_TEST_DUMP_FP:"1",B2_JIT_FORCE_TRANSLATE:"1",B2_TEST_TWO_PASS:"1",B2_TEST_SECOND_PC:"0x1008",B2_TEST_REPLAY_COUNT:"2",B2_TEST_FORCE_L2_RAM:"1",B2_TEST_REPLAY_FPCR:a.fpcr??"0",B2_TEST_REPLAY_FPSR:a.replayFpsr??"0",[fp7?"B2_TEST_REPLAY_FP7_EXT":"B2_TEST_REPLAY_FP0_EXT"]:seed,B2_NATIVE_ASSERT_PC:"0x1008"}}),o=`${r.stdout??""}${r.stderr??""}`,d=o.match(/^REGDUMP:.*$/m)?.[0],m=o.match(/^MEMDUMP [^:]+:(.*)$/m)?.[1].trim().toLowerCase(),want=`a5 5a ${a.output} 3c c3`,d0=d?.match(/ D0=([0-9a-f]+)/i)?.[1].toLowerCase(),fpsr=d?.match(/ FPSR=([0-9a-f]+)/i)?.[1].toLowerCase(),a0=d?.match(/ A0=([0-9a-f]+)/i)?.[1].toLowerCase(),sr=d?.match(/ SR=([0-9a-f]+)/i)?.[1].toLowerCase(),fc=(o.match(/JIT_FALLBACK/g)??[]).length,wfc=a.destinationSnan?6:7;if(r.status===0&&m===want&&d0===a.operationFpsr&&fpsr===a.fpsr&&a0===(a.expectedA0??"0000a000")&&sr==="271f"&&fc===wfc&&o.includes("NATEXEC pc=00001008")&&!o.includes("Caught SIGSEGV"))sp++;else{fail++;console.error(`FPP_FREM_FAIL case=${a.name} rc=${r.status} mem=${m} want=${want} d0=${d0} want_d0=${a.operationFpsr} fpsr=${fpsr} want_fpsr=${a.fpsr} a0=${a0} sr=${sr} fallbacks=${fc} want_fallbacks=${wfc}`)}}finally{rmSync(td,{recursive:true,force:true})}}for(const a of ss){const td=mkdtempSync(join(tmpdir(),"fpp-frem-strict-"));try{P(join(td,"prefs"),disk);const r=spawnSync("timeout",["-k","5s","30s",bin,"--config",join(td,"prefs")],{encoding:"utf8",timeout:35000,env:{...process.env,SDL_VIDEODRIVER:"x11",DISPLAY:display,HOME:td,B2_TEST_HEX:`F200 ${a.extra} 2C7C A6C3 0000`,B2_TEST_INIT:zeroInit,B2_TEST_DUMP:"1",B2_JIT_FORCE_TRANSLATE:"1",B2_TEST_FORCE_L2_RAM:"1",B2_JIT_STRICT_FULL:"1"}}),o=`${r.stdout??""}${r.stderr??""}`;if(r.status!==0&&o.includes("strict full-JIT: opcode fallback pc=00001000 op=f200")&&!o.includes("NATEXEC pc=00001000")&&!o.includes("JIT_STRICT_SUMMARY ")&&!o.includes("Caught SIGSEGV"))st++;else{fail++;console.error(`FPP_FREM_FAIL strict=${a.name} rc=${r.status}`)}}finally{rmSync(td,{recursive:true,force:true})}}}finally{spawnSync("bash",["-c","source \"$1\"; cow_release \"$2\"","bash",cowLib,disk]);rmSync(dd,{recursive:true,force:true})}console.log(`FPP_FREM_MATRIX service_pass=${sp} strict_pass=${st} fail=${fail} total=${sp+st+fail}`);process.exit(fail===0&&sp===(process.env.CASE?sc.length:33)&&st===(process.env.CASE?ss.length:1)?0:1);
