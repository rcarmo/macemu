#!/usr/bin/env bun

import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { spawnSync } from "node:child_process";

const root = new URL("..", import.meta.url).pathname;
const bin = `${root}/BasiliskII/src/Unix/BasiliskII`;
const rom = process.env.ROM ?? "/workspace/projects/rpi-basilisk2-sdl2-nox/Quadra800.ROM";
const diskSource = process.env.DISK ?? "/workspace/fixtures/basilisk/images/HD200MB";
const cowLib = process.env.COW_LIB ?? "/workspace/scripts/lib/cow-disk.sh";
const display = process.env.DISPLAY ?? ":99";
const nops = "4E71 4E71 4E71 4E71";
const base = ["11111111", "22222222", "33333333", "44444444", "55555555", "66666666", "77777777", "88888888", "0000a000", "99999999", "0000a100", "bbbbbbbb", "cccccccc", "dddddddd", "eeeeeeee", "00009000"];
const x = {
  pz: "00 00 00 00 00 00 00 00 00 00 00 00", nz: "80 00 00 00 00 00 00 00 00 00 00 00",
  p1: "3f ff 00 00 80 00 00 00 00 00 00 00", n1: "bf ff 00 00 80 00 00 00 00 00 00 00",
  p15: "3f ff 00 00 c0 00 00 00 00 00 00 00",
  half: "3f ff 00 00 80 00 00 00 00 00 04 00", nhalf: "bf ff 00 00 80 00 00 00 00 00 04 00",
  maxDouble: "43 fe 00 00 ff ff ff ff ff ff f8 00", overflow: "43 ff 00 00 80 00 00 00 00 00 00 00",
  noverflow: "c3 ff 00 00 80 00 00 00 00 00 00 00", minNormal: "3c 01 00 00 80 00 00 00 00 00 00 00",
  minSubnormal: "3b cd 00 00 80 00 00 00 00 00 00 00", halfMinSubnormal: "3b cc 00 00 80 00 00 00 00 00 00 00",
  negativeHalfMinSubnormal: "bb cc 00 00 80 00 00 00 00 00 00 00",
  pinf: "7f ff 00 00 00 00 00 00 00 00 00 00", ninf: "ff ff 00 00 00 00 00 00 00 00 00 00",
  qnan: "7f ff 00 00 c0 00 12 34 56 78 9a bc", nqnan: "ff ff 00 00 c0 00 12 34 56 78 9a bc",
  snan: "7f ff 00 00 80 00 12 34 56 78 9a bc",
} as const;

type Case = {
  name: string; source: string; want: string; fpsr: string; fpcr?: string; opcode?: string; extension?: string;
  effective?: number; regs?: Record<number, number>; aregs?: Record<number, number>; extraMemory?: string;
  finalA0?: string; finalA7?: string; fpreg?: 0 | 7; preserveSource?: boolean;
};
const cases: Case[] = [
  { name: "double_positive_zero", source: x.pz, want: "00 00 00 00 00 00 00 00", fpsr: "0c550008" },
  { name: "double_negative_zero", source: x.nz, want: "80 00 00 00 00 00 00 00", fpsr: "0c550008" },
  { name: "double_positive_infinity", source: x.pinf, want: "7f f0 00 00 00 00 00 00", fpsr: "0c550008" },
  { name: "double_negative_infinity", source: x.ninf, want: "ff f0 00 00 00 00 00 00", fpsr: "0c550008" },
  { name: "double_half_nearest_even", source: x.half, want: "3f f0 00 00 00 00 00 00", fpsr: "0c550208" },
  { name: "double_half_plus_infinity", source: x.half, want: "3f f0 00 00 00 00 00 01", fpsr: "0c550208", fpcr: "30" },
  { name: "double_negative_half_minus_infinity", source: x.nhalf, want: "bf f0 00 00 00 00 00 01", fpsr: "0c550208", fpcr: "20" },
  { name: "double_maximum_finite_exact", source: x.maxDouble, want: "7f ef ff ff ff ff ff ff", fpsr: "0c550008" },
  { name: "double_positive_overflow_nearest", source: x.overflow, want: "7f f0 00 00 00 00 00 00", fpsr: "0c551248" },
  { name: "double_positive_overflow_zero", source: x.overflow, want: "7f ef ff ff ff ff ff ff", fpsr: "0c551248", fpcr: "10" },
  { name: "double_negative_overflow_minus", source: x.noverflow, want: "ff f0 00 00 00 00 00 00", fpsr: "0c551248", fpcr: "20" },
  { name: "double_minimum_normal_exact", source: x.minNormal, want: "00 10 00 00 00 00 00 00", fpsr: "0c550008" },
  { name: "double_minimum_subnormal_exact", source: x.minSubnormal, want: "00 00 00 00 00 00 00 01", fpsr: "0c550808" },
  { name: "double_half_minimum_subnormal_nearest", source: x.halfMinSubnormal, want: "00 00 00 00 00 00 00 00", fpsr: "0c550a28" },
  { name: "double_half_minimum_subnormal_plus", source: x.halfMinSubnormal, want: "00 00 00 00 00 00 00 01", fpsr: "0c550a28", fpcr: "30" },
  { name: "double_negative_half_minimum_subnormal_minus", source: x.negativeHalfMinSubnormal, want: "80 00 00 00 00 00 00 01", fpsr: "0c550a28", fpcr: "20" },
  { name: "double_quiet_nan_payload", source: x.qnan, want: "7f f8 00 02 46 8a cf 13", fpsr: "0c550008" },
  { name: "double_negative_quiet_nan_payload_fp7", source: x.nqnan, want: "ff f8 00 02 46 8a cf 13", fpsr: "0c550008", fpreg: 7, extension: "7780" },
  { name: "double_signalling_nan_quiets_without_source_mutation", source: x.snan, want: "7f f8 00 02 46 8a cf 13", fpsr: "0c554088", preserveSource: true },
  { name: "double_a7_postincrement", source: x.p15, want: "3f f8 00 00 00 00 00 00", fpsr: "0c550008", opcode: "F21F", effective: 0x9000, finalA7: "00009008" },
  { name: "double_a7_predecrement", source: x.p15, want: "3f f8 00 00 00 00 00 00", fpsr: "0c550008", opcode: "F227", effective: 0x9000, aregs: { 7: 0x9008 }, finalA7: "00009000" },
  { name: "double_d16_a0", source: x.p15, want: "3f f8 00 00 00 00 00 00", fpsr: "0c550008", opcode: "F228", extension: "7400 0010", effective: 0xa010 },
  { name: "double_brief_a0_d1", source: x.p15, want: "3f f8 00 00 00 00 00 00", fpsr: "0c550008", opcode: "F230", extension: "7400 1AFC", effective: 0xa00c, regs: { 1: 8 } },
  { name: "double_full_direct", source: x.p15, want: "3f f8 00 00 00 00 00 00", fpsr: "0c550008", opcode: "F230", extension: "7400 1920 FFF0", effective: 0xa000, regs: { 1: 0 }, aregs: { 0: 0xa010 } },
  { name: "double_full_preindexed", source: x.p15, want: "3f f8 00 00 00 00 00 00", fpsr: "0c550008", opcode: "F230", extension: "7400 1922 FFFC 0010", effective: 0xa000, regs: { 1: 4 }, aregs: { 0: 0xa100 }, extraMemory: "a100 00 a101 00 a102 9f a103 f0" },
  { name: "double_full_postindexed", source: x.p15, want: "3f f8 00 00 00 00 00 00", fpsr: "0c550008", opcode: "F230", extension: "7400 1926 FFFC 0000", effective: 0xa000, regs: { 1: 4 }, aregs: { 0: 0xa104 }, extraMemory: "a100 00 a101 00 a102 9f a103 fc" },
  { name: "double_absolute_short", source: x.p15, want: "3f f8 00 00 00 00 00 00", fpsr: "0c550008", opcode: "F238", extension: "7400 6000", effective: 0x6000 },
  { name: "double_absolute_long", source: x.p15, want: "3f f8 00 00 00 00 00 00", fpsr: "0c550008", opcode: "F239", extension: "7400 0000 A000", effective: 0xa000 },
];
const strict = [
  { name: "double_aind_strict", stream: "F210 7400 2C7C A6C5 0001", opcode: "f210" },
  { name: "double_predecrement_strict", stream: "F227 7400 2C7C A6C5 0002", opcode: "f227" },
  { name: "double_indexed_strict", stream: "F230 7400 1000 2C7C A6C5 0003", opcode: "f230" },
] as const;

function bytes(address: number, value: string) { return value.trim().split(/\s+/).map((byte, i) => `${(address + i).toString(16)} ${byte}`).join(" "); }
function words(value: string) { return value.replaceAll(" ", "").match(/.{8}/g)!.join(" "); }
function hex(value: number) { return (value >>> 0).toString(16).padStart(8, "0"); }
function field(dump: string | undefined, name: string) { return dump?.match(new RegExp(` ${name}=([0-9a-f]+)`, "i"))?.[1].toLowerCase(); }
function prefs(path: string, disk: string) { writeFileSync(path, [`rom ${rom}`, `disk ${disk}`, "ramsize 8388608", "modelid 14", "cpu 4", "fpu true", "jit true", "jitfpu true", "jitcachesize 8192", "screen win/640/480", "nosound true", "nocdrom true", "nogui true", "ignoresegv true", ""].join("\n")); }

const diskDir = mkdtempSync(join(tmpdir(), "fpp-double-dest-disk-"));
const clone = spawnSync("bash", ["-c", "set -euo pipefail\nsource \"$1\"\ncow_clone \"$2\" \"$3/disk.img\" fpp-double-dest", "bash", cowLib, diskSource, diskDir], { encoding: "utf8" });
if (clone.status !== 0) throw new Error(clone.stderr || "CoW clone failed");
const disk = clone.stdout.trim().split("\n").at(-1)!;
const selectedCases = process.env.CASE ? cases.filter((item) => item.name === process.env.CASE) : cases;
const selectedStrict = process.env.CASE ? strict.filter((item) => item.name === process.env.CASE) : strict;
let servicePass = 0, strictPass = 0, fail = 0;
try {
  if (!selectedCases.length && !selectedStrict.length) throw new Error(`unknown CASE=${process.env.CASE}`);
  for (const item of selectedCases) {
    const td = mkdtempSync(join(tmpdir(), "fpp-double-dest-service-"));
    try {
      prefs(join(td, "prefs"), disk);
      const init = [...base];
      for (const [reg, value] of Object.entries(item.regs ?? {})) init[+reg] = hex(value);
      for (const [reg, value] of Object.entries(item.aregs ?? {})) init[8 + +reg] = hex(value);
      const effective = item.effective ?? 0xa000;
      const start = effective - 2;
      const expected = `a5 5a ${item.want} 3c c3`;
      const memory = `${bytes(start, "a5 5a 00 00 00 00 00 00 00 00 3c c3")} ${item.extraMemory ?? ""}`.trim();
      const opcode = item.opcode ?? "F210";
      const extension = item.extension ?? (item.fpreg === 7 ? "7780" : "7400");
      const preserveStream = item.preserveSource ? "F206 A800 F239 6800 0000 A020" : "";
      const sourceDump = item.preserveSource ? " 0xa020:12" : "";
      const run = spawnSync("timeout", ["-k", "5s", "30s", bin, "--config", join(td, "prefs")], {
        encoding: "utf8", timeout: 35_000,
        env: {
          ...process.env, SDL_VIDEODRIVER: "x11", DISPLAY: display, HOME: td,
          B2_TEST_HEX: `${nops} ${opcode} ${extension} ${preserveStream} 2C7C A6C5 1000`, B2_TEST_INIT: `${init.join(" ")} 271f`,
          B2_TEST_MEMORY_BYTES: memory, B2_TEST_MEMDUMP: `0x${start.toString(16)}:12${sourceDump}`, B2_TEST_DUMP: "1", B2_TEST_DUMP_FP: "1",
          B2_JIT_FORCE_TRANSLATE: "1", B2_TEST_TWO_PASS: "1", B2_TEST_SECOND_PC: "0x1008", B2_TEST_REPLAY_COUNT: "2", B2_TEST_FORCE_L2_RAM: "1",
          B2_TEST_REPLAY_FPCR: item.fpcr ?? "0", B2_TEST_REPLAY_FPSR: "0c55ff08",
          [item.fpreg === 7 ? "B2_TEST_REPLAY_FP7_EXT" : "B2_TEST_REPLAY_FP0_EXT"]: words(item.source), B2_NATIVE_ASSERT_PC: "0x1008",
        },
      });
      const output = `${run.stdout ?? ""}${run.stderr ?? ""}`;
      const dump = output.match(/^REGDUMP:.*$/m)?.[0];
      const memdumps = [...output.matchAll(/^MEMDUMP [^:]+:(.*)$/gm)].map((match) => match[1].trim().toLowerCase());
      const mem = memdumps[0];
      const sourcePreserved = !item.preserveSource || memdumps[1] === item.source;
      const conversionFpsrPreserved = !item.preserveSource || field(dump, "D6") === item.fpsr;
      const finalFpsr = item.preserveSource ? "0c550088" : item.fpsr;
      const regsPreserved = Object.entries(item.regs ?? {}).every(([reg, value]) => field(dump, `D${reg}`) === hex(value));
      const aregsPreserved = Object.entries(item.aregs ?? {}).every(([reg, value]) => reg === "7" && item.finalA7 ? true : field(dump, `A${reg}`) === hex(value));
      const native = output.includes("NATEXEC pc=00001008");
      const fallback = output.includes(`JIT_FALLBACK op=${opcode.toLowerCase()} pc=00001008`);
      const ok = run.status === 0 && mem === expected && field(dump, "FPSR") === finalFpsr && field(dump, "SR") === "271f" &&
        regsPreserved && aregsPreserved && field(dump, "A0") === (item.finalA0 ?? hex(item.aregs?.[0] ?? 0xa000)) &&
        field(dump, "A7") === (item.finalA7 ?? hex(item.aregs?.[7] ?? 0x9000)) && sourcePreserved && conversionFpsrPreserved && native && fallback && !output.includes("Caught SIGSEGV");
      if (ok) servicePass++;
      else {
        fail++;
        console.error(`FPP_DOUBLE_DEST_FAIL case=${item.name} rc=${run.status} mem=${mem} want=${expected} fpsr=${field(dump, "FPSR")} want_fpsr=${item.fpsr} a0=${field(dump, "A0")} a7=${field(dump, "A7")} regs=${regsPreserved ? 1 : 0} aregs=${aregsPreserved ? 1 : 0} source=${sourcePreserved ? 1 : 0} snap=${conversionFpsrPreserved ? 1 : 0} native=${native ? 1 : 0} fallback=${fallback ? 1 : 0}`);
        for (const line of output.split("\n").filter((text) => /REGDUMP|MEMDUMP|NATEXEC|fallback|Caught/.test(text)).slice(-20)) console.error(line);
      }
    } finally { rmSync(td, { recursive: true, force: true }); }
  }
  for (const item of selectedStrict) {
    const td = mkdtempSync(join(tmpdir(), "fpp-double-dest-strict-"));
    try {
      prefs(join(td, "prefs"), disk);
      const run = spawnSync("timeout", ["-k", "5s", "30s", bin, "--config", join(td, "prefs")], { encoding: "utf8", timeout: 35_000, env: { ...process.env, SDL_VIDEODRIVER: "x11", DISPLAY: display, HOME: td, B2_TEST_HEX: item.stream, B2_TEST_INIT: `${base.join(" ")} 271f`, B2_TEST_DUMP: "1", B2_JIT_FORCE_TRANSLATE: "1", B2_TEST_FORCE_L2_RAM: "1", B2_JIT_STRICT_FULL: "1" } });
      const output = `${run.stdout ?? ""}${run.stderr ?? ""}`;
      if (run.status !== 0 && output.includes(`strict full-JIT: opcode fallback pc=00001000 op=${item.opcode}`) && !output.includes("NATEXEC pc=00001000")) strictPass++;
      else { fail++; console.error(`FPP_DOUBLE_DEST_FAIL strict=${item.name}`); }
    } finally { rmSync(td, { recursive: true, force: true }); }
  }
} finally {
  spawnSync("bash", ["-c", "source \"$1\"; cow_release \"$2\"", "bash", cowLib, disk]);
  rmSync(diskDir, { recursive: true, force: true });
}
const expectedService = process.env.CASE ? selectedCases.length : 28;
const expectedStrict = process.env.CASE ? selectedStrict.length : 3;
console.log(`FPP_DOUBLE_DEST_MATRIX service_pass=${servicePass} strict_pass=${strictPass} fail=${fail} total=${servicePass + strictPass + fail}`);
process.exit(fail === 0 && servicePass === expectedService && strictPass === expectedStrict ? 0 : 1);
