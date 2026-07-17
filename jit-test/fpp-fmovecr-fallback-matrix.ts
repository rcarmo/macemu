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

type Case = { name: string; selector: number; output: string; fpcr?: string; fpsr?: string };
const defined: Array<[number, string, string]> = [
  [0, "pi", "40 00 00 00 c9 0f da a2 21 68 c2 35"],
  [11, "log10_2", "3f fd 00 00 9a 20 9a 84 fb cf f7 98"],
  [12, "e", "40 00 00 00 ad f8 54 58 a2 bb 4a 9a"],
  [13, "log2_e", "3f ff 00 00 b8 aa 3b 29 5c 17 f0 bc"],
  [14, "log10_e", "3f fd 00 00 de 5b d8 a9 37 28 71 95"],
  [15, "zero", "00 00 00 00 00 00 00 00 00 00 00 00"],
  [48, "ln_2", "3f fe 00 00 b1 72 17 f7 d1 cf 79 ac"],
  [49, "ln_10", "40 00 00 00 93 5d 8d dd aa a8 ac 17"],
  [50, "ten_pow_0", "3f ff 00 00 80 00 00 00 00 00 00 00"],
  [51, "ten_pow_1", "40 02 00 00 a0 00 00 00 00 00 00 00"],
  [52, "ten_pow_2", "40 05 00 00 c8 00 00 00 00 00 00 00"],
  [53, "ten_pow_4", "40 0c 00 00 9c 40 00 00 00 00 00 00"],
  [54, "ten_pow_8", "40 19 00 00 be bc 20 00 00 00 00 00"],
  [55, "ten_pow_16", "40 34 00 00 8e 1b c9 bf 04 00 00 00"],
  [56, "ten_pow_32", "40 69 00 00 9d c5 ad a8 2b 70 b5 9e"],
  [57, "ten_pow_64", "40 d3 00 00 c2 78 1f 49 ff cf a6 d5"],
  [58, "ten_pow_128", "41 a8 00 00 93 ba 47 c9 80 e9 8c e0"],
  [59, "ten_pow_256", "43 51 00 00 aa 7e eb fb 9d f9 de 8e"],
  [60, "ten_pow_512", "46 a3 00 00 e3 19 a0 ae a6 0e 91 c7"],
  [61, "ten_pow_1024", "4d 48 00 00 c9 76 75 86 81 75 0c 17"],
  [62, "ten_pow_2048", "5a 92 00 00 9e 8b 3b 5d c5 3d 5d e5"],
  [63, "ten_pow_4096", "75 25 00 00 c4 60 52 02 8a 20 97 9b"],
];
const serviceCases: Case[] = defined.map(([selector, name, output]) => ({
  name: `selector_${selector}_${name}`, selector, output,
  fpsr: selector === 15 ? "04000000" : "00000000",
}));
for (const [fpcr, suffix, output] of [
  ["40", "single_nearest", "40 00 00 00 c9 0f db 00 00 00 00 00"],
  ["50", "single_zero", "40 00 00 00 c9 0f da 00 00 00 00 00"],
  ["60", "single_minus", "40 00 00 00 c9 0f da 00 00 00 00 00"],
  ["70", "single_plus", "40 00 00 00 c9 0f db 00 00 00 00 00"],
  ["80", "double_nearest", "40 00 00 00 c9 0f da a2 21 68 c0 00"],
  ["90", "double_zero", "40 00 00 00 c9 0f da a2 21 68 c0 00"],
  ["a0", "double_minus", "40 00 00 00 c9 0f da a2 21 68 c0 00"],
  ["b0", "double_plus", "40 00 00 00 c9 0f da a2 21 68 c8 00"],
] as const) serviceCases.push({ name: `pi_${suffix}`, selector: 0, output, fpcr, fpsr: "00000008" });
for (const selector of [1, 10, 16, 47, 64, 127]) serviceCases.push({
  name: `undefined_selector_${selector}_zero`, selector,
  output: "00 00 00 00 00 00 00 00 00 00 00 00", fpsr: "04000000",
});
const strictCases = [
  { name: "pi_fp7_max_destination", selector: 0 },
  { name: "ten_pow_4096_fp7_max_destination", selector: 63 },
  { name: "undefined_127_fp7_max_destination", selector: 127 },
] as const;

function writePrefs(path: string, disk: string) {
  writeFileSync(path, [
    `rom ${rom}`, `disk ${disk}`, "ramsize 8388608", "modelid 14", "cpu 4",
    "fpu true", "jit true", "jitfpu true", "jitcachesize 8192",
    "screen win/640/480", "nosound true", "nocdrom true", "nogui true", "ignoresegv true", "",
  ].join("\n"));
}
const diskDir = mkdtempSync(join(tmpdir(), "fpp-fmovecr-fallback-disk-"));
const clone = spawnSync("bash", ["-c", ["set -euo pipefail", "source \"$1\"", "cow_clone \"$2\" \"$3/disk.img\" fpp-fmovecr-fallback"].join("\n"), "bash", cowLib, diskSource, diskDir], { encoding: "utf8" });
if (clone.status !== 0) { console.error(clone.stderr || "FPP_FMOVECR_FALLBACK_FAIL unable to create isolated disk clone"); process.exit(1); }
const disk = clone.stdout.trim().split("\n").at(-1)!;
const selectedService = process.env.CASE ? serviceCases.filter((item) => item.name === process.env.CASE) : serviceCases;
const selectedStrict = process.env.CASE ? strictCases.filter((item) => item.name === process.env.CASE) : strictCases;
if (selectedService.length + selectedStrict.length === 0) throw new Error(`unknown CASE=${process.env.CASE}`);
let servicePass = 0, strictPass = 0, fail = 0;
try {
  for (const item of selectedService) {
    const td = mkdtempSync(join(tmpdir(), "fpp-fmovecr-service-"));
    try {
      const pref = join(td, "prefs"); writePrefs(pref, disk);
      const extra = (0x5c00 | item.selector).toString(16).padStart(4, "0");
      const guard = "9ffe a5 9fff 5a a000 00 a001 00 a002 00 a003 00 a004 00 a005 00 a006 00 a007 00 a008 00 a009 00 a00a 00 a00b 00 a00c 3c a00d c3";
      const run = spawnSync("timeout", ["-k", "5s", "30s", bin, "--config", pref], { encoding: "utf8", timeout: 35_000, env: {
        ...process.env, SDL_VIDEODRIVER: "x11", DISPLAY: display, HOME: td,
        B2_TEST_HEX: `F200 ${extra} F210 6800 2C7C A6FD 0000`, B2_TEST_INIT: zeroInit,
        B2_TEST_MEMORY_BYTES: guard, B2_TEST_MEMDUMP: "0x9ffe:16", B2_TEST_DUMP: "1", B2_TEST_DUMP_FP: "1",
        B2_JIT_FORCE_TRANSLATE: "1", B2_TEST_TWO_PASS: "1", B2_TEST_SECOND_PC: "0x1000", B2_TEST_REPLAY_COUNT: "2", B2_TEST_FORCE_L2_RAM: "1", B2_TEST_REPLAY_FPCR: item.fpcr ?? "0",
      }});
      const output = `${run.stdout ?? ""}${run.stderr ?? ""}`, dump = output.match(/^REGDUMP:.*$/m)?.[0];
      const mem = output.match(/^MEMDUMP [^:]+:(.*)$/m)?.[1].trim().toLowerCase();
      const expected = `a5 5a ${item.output} 3c c3`, a0 = dump?.match(/ A0=([0-9a-f]+)/i)?.[1].toLowerCase();
      const fpsr = dump?.match(/ FPSR=([0-9a-f]+)/i)?.[1].toLowerCase(), sr = dump?.match(/ SR=([0-9a-f]+)/i)?.[1].toLowerCase();
      const serviced = output.includes("JIT_FALLBACK op=f200 pc=00001000") && !output.includes("Caught SIGSEGV");
      if (run.status === 0 && mem === expected && a0 === "0000a000" && fpsr === item.fpsr && sr === "271f" && serviced) servicePass++;
      else { fail++; console.error(`FPP_FMOVECR_FALLBACK_FAIL case=${item.name} phase=service rc=${run.status} mem=${mem} want_mem=${expected} a0=${a0} fpsr=${fpsr} want_fpsr=${item.fpsr} sr=${sr} serviced=${serviced ? 1 : 0}`); }
    } finally { rmSync(td, { recursive: true, force: true }); }
  }
  for (const item of selectedStrict) {
    const td = mkdtempSync(join(tmpdir(), "fpp-fmovecr-strict-"));
    try {
      const pref = join(td, "prefs"); writePrefs(pref, disk);
      const extra = (0x5c00 | (7 << 7) | item.selector).toString(16).padStart(4, "0");
      const run = spawnSync("timeout", ["-k", "5s", "30s", bin, "--config", pref], { encoding: "utf8", timeout: 35_000, env: {
        ...process.env, SDL_VIDEODRIVER: "x11", DISPLAY: display, HOME: td,
        B2_TEST_HEX: `F200 ${extra} 2C7C A6FE 0000`, B2_TEST_INIT: zeroInit, B2_TEST_DUMP: "1", B2_TEST_DUMP_FP: "1",
        B2_JIT_FORCE_TRANSLATE: "1", B2_TEST_TWO_PASS: "1", B2_TEST_SECOND_PC: "0x1000", B2_TEST_REPLAY_COUNT: "2", B2_TEST_FORCE_L2_RAM: "1", B2_JIT_STRICT_FULL: "1",
      }});
      const output = `${run.stdout ?? ""}${run.stderr ?? ""}`;
      const rejected = output.includes("strict full-JIT: opcode fallback");
      const noNative = !output.includes("NATEXEC pc=00001000") && !output.includes("JIT_STRICT_SUMMARY ");
      const noSegv = !output.includes("Caught SIGSEGV");
      if (run.status !== 0 && rejected && noNative && noSegv) strictPass++;
      else { fail++; console.error(`FPP_FMOVECR_FALLBACK_FAIL case=${item.name} phase=strict rc=${run.status} rejected=${rejected ? 1 : 0} no_native=${noNative ? 1 : 0} no_segv=${noSegv ? 1 : 0}`); }
    } finally { rmSync(td, { recursive: true, force: true }); }
  }
} finally {
  spawnSync("bash", ["-c", "source \"$1\"; cow_release \"$2\"", "bash", cowLib, disk]); rmSync(diskDir, { recursive: true, force: true });
}
console.log(`FPP_FMOVECR_FALLBACK_MATRIX service_pass=${servicePass} strict_pass=${strictPass} fail=${fail} total=${servicePass + strictPass + fail}`);
const expectedService = process.env.CASE ? selectedService.length : 36, expectedStrict = process.env.CASE ? selectedStrict.length : 3;
process.exit(fail === 0 && servicePass === expectedService && strictPass === expectedStrict ? 0 : 1);
