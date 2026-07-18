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
  positiveZero: "00 00 00 00 00 00 00 00 00 00 00 00",
  negativeZero: "80 00 00 00 00 00 00 00 00 00 00 00",
  positiveOne: "3f ff 00 00 80 00 00 00 00 00 00 00",
  negativeOne: "bf ff 00 00 80 00 00 00 00 00 00 00",
  positiveTwo: "40 00 00 00 80 00 00 00 00 00 00 00",
  positiveInfinity: "7f ff 00 00 00 00 00 00 00 00 00 00",
  quietNan: "7f ff 00 00 c0 00 12 34 56 78 9a bc",
  signallingNan: "7f ff 00 00 80 00 12 34 56 78 9a bc",
  canonicalPositiveNan: "7f ff 00 00 ff ff ff ff ff ff ff ff",
  canonicalNegativeNan: "ff ff 00 00 ff ff ff ff ff ff ff ff",
  maximumExtended: "7f fe 00 00 ff ff ff ff ff ff ff ff",
  sqrtMaximumExtended: "5f fe 00 00 ff ff ff ff ff ff ff ff",
  minimumNormalExtended: "00 01 00 00 80 00 00 00 00 00 00 00",
  sqrtMinimumNormalExtended: "20 00 00 00 80 00 00 00 00 00 00 00",
  onePlusExtendedUlp: "3f ff 00 00 80 00 00 00 00 00 00 01",
  singleHalfSquare: "3f ff 00 00 80 00 01 00 00 00 80 00",
  doubleHalfSquare: "3f ff 00 00 80 00 00 00 00 00 08 00",
  positiveSingleNext: "3f ff 00 00 80 00 01 00 00 00 00 00",
  positiveDoubleNext: "3f ff 00 00 80 00 00 00 00 00 08 00",
  sqrtTwo: "3f ff 00 00 b5 04 f3 33 f9 de 64 84",
  sqrtTwoUp: "3f ff 00 00 b5 04 f3 33 f9 de 64 85",
  sqrtTwoSingle: "3f ff 00 00 b5 04 f3 00 00 00 00 00",
  sqrtTwoDouble: "3f ff 00 00 b5 04 f3 33 f9 de 68 00",
  sqrtSingleHalfExtended: "3f ff 00 00 80 00 00 80 00 00 00 00",
  sqrtDoubleHalfExtended: "3f ff 00 00 80 00 00 00 00 00 04 00",
  fssqrtExtendedRangeSource: "40 fd 00 00 80 00 00 00 00 00 00 00",
  fssqrtExtendedRangeResult: "40 7e 00 00 80 00 00 00 00 00 00 00",
  fdsqrtExtendedRangeSource: "47 fd 00 00 80 00 00 00 00 00 00 00",
  fdsqrtExtendedRangeResult: "43 fe 00 00 80 00 00 00 00 00 00 00",
} as const;

type ServiceCase = {
  name: string;
  selector: "0404" | "0441" | "0445" | "1f84";
  input: string;
  output: string;
  fpsr: string;
  fpcr?: string;
  replayFpsr?: string;
  fp7?: boolean;
};

const serviceCases: ServiceCase[] = [
  { name: "fsqrt_positive_zero", selector: "0404", input: x.positiveZero, output: x.positiveZero, fpsr: "04000000" },
  { name: "fsqrt_negative_zero", selector: "0404", input: x.negativeZero, output: x.negativeZero, fpsr: "0c000000" },
  { name: "fsqrt_one", selector: "0404", input: x.positiveOne, output: x.positiveOne, fpsr: "00000000" },
  { name: "fsqrt_negative_invalid", selector: "0404", input: x.negativeOne, output: x.canonicalNegativeNan, fpsr: "09000080" },
  { name: "fsqrt_infinity", selector: "0404", input: x.positiveInfinity, output: x.positiveInfinity, fpsr: "02000000" },
  { name: "fsqrt_quiet_nan_payload", selector: "0404", input: x.quietNan, output: x.quietNan, fpsr: "01000000" },
  { name: "fsqrt_signalling_nan_quiet", selector: "0404", input: x.signallingNan, output: x.quietNan, fpsr: "01000080" },
  { name: "fsqrt_maximum_extended", selector: "0404", input: x.maximumExtended, output: x.sqrtMaximumExtended, fpsr: "00000008" },
  { name: "fsqrt_minimum_normal_extended", selector: "0404", input: x.minimumNormalExtended, output: x.sqrtMinimumNormalExtended, fpsr: "00000000" },
  { name: "fsqrt_wide_low_bit", selector: "0404", input: x.onePlusExtendedUlp, output: x.positiveOne, fpsr: "00000008" },
  { name: "fsqrt_single_half_extended", selector: "0404", input: x.singleHalfSquare, output: x.sqrtSingleHalfExtended, fpsr: "00000000" },
  { name: "fsqrt_double_half_extended", selector: "0404", input: x.doubleHalfSquare, output: x.sqrtDoubleHalfExtended, fpsr: "00000008" },
];
for (const [fpcr, suffix, output] of [
  ["0", "nearest", x.sqrtTwo], ["10", "zero", x.sqrtTwo],
  ["20", "minus", x.sqrtTwo], ["30", "plus", x.sqrtTwoUp],
] as const) serviceCases.push({ name: `fsqrt_extended_${suffix}`, selector: "0404", input: x.positiveTwo, output, fpcr, fpsr: "00000008" });
for (const [fpcr, suffix, output] of [
  ["40", "nearest", x.positiveOne], ["50", "zero", x.positiveOne],
  ["60", "minus", x.positiveOne], ["70", "plus", x.positiveSingleNext],
] as const) serviceCases.push({ name: `fsqrt_single_${suffix}`, selector: "0404", input: x.singleHalfSquare, output, fpcr, fpsr: "00000008" });
for (const [fpcr, suffix, output] of [
  ["80", "nearest", x.positiveOne], ["90", "zero", x.positiveOne],
  ["a0", "minus", x.positiveOne], ["b0", "plus", x.positiveDoubleNext],
] as const) serviceCases.push({ name: `fsqrt_double_${suffix}`, selector: "0404", input: x.doubleHalfSquare, output, fpcr, fpsr: "00000008" });
for (const [fpcr, suffix, output] of [
  ["0", "nearest", x.positiveOne], ["10", "zero", x.positiveOne],
  ["20", "minus", x.positiveOne], ["30", "plus", x.positiveSingleNext],
] as const) serviceCases.push({ name: `fssqrt_${suffix}`, selector: "0441", input: x.singleHalfSquare, output, fpcr, fpsr: "00000008" });
for (const [fpcr, suffix, output] of [
  ["0", "nearest", x.positiveOne], ["10", "zero", x.positiveOne],
  ["20", "minus", x.positiveOne], ["30", "plus", x.positiveDoubleNext],
] as const) serviceCases.push({ name: `fdsqrt_${suffix}`, selector: "0445", input: x.doubleHalfSquare, output, fpcr, fpsr: "00000008" });
serviceCases.push(
  { name: "fsqrt_fp7_self_max_fields", selector: "1f84", input: x.positiveTwo, output: x.sqrtTwo, fpsr: "00000008", fp7: true },
  { name: "fsqrt_accrued_preserve", selector: "0404", input: x.positiveTwo, output: x.sqrtTwo, fpsr: "00550008", replayFpsr: "0455ff00" },
  { name: "fssqrt_extended_source_range", selector: "0441", input: x.fssqrtExtendedRangeSource, output: x.fssqrtExtendedRangeResult, fpsr: "00000000" },
  { name: "fdsqrt_extended_source_range", selector: "0445", input: x.fdsqrtExtendedRangeSource, output: x.fdsqrtExtendedRangeResult, fpsr: "00000000" },
);
for (const [prefix, selector, oppositePrecision, sqrtTwo] of [
  ["fssqrt", "0441", "80", x.sqrtTwoSingle],
  ["fdsqrt", "0445", "40", x.sqrtTwoDouble],
] as const) serviceCases.push(
  { name: `${prefix}_negative_zero`, selector, input: x.negativeZero, output: x.negativeZero, fpsr: "0c000000" },
  { name: `${prefix}_negative_invalid`, selector, input: x.negativeOne, output: x.canonicalPositiveNan, fpsr: "01000080" },
  { name: `${prefix}_infinity`, selector, input: x.positiveInfinity, output: x.positiveInfinity, fpsr: "02000000" },
  { name: `${prefix}_quiet_nan`, selector, input: x.quietNan, output: x.canonicalPositiveNan, fpsr: "01000000" },
  { name: `${prefix}_signalling_nan`, selector, input: x.signallingNan, output: x.canonicalPositiveNan, fpsr: "01000080" },
  { name: `${prefix}_maximum_overflow`, selector, input: x.maximumExtended, output: x.positiveInfinity, fpsr: "02000048" },
  { name: `${prefix}_minimum_underflow`, selector, input: x.minimumNormalExtended, output: x.positiveZero, fpsr: "04000028" },
  { name: `${prefix}_opposite_precision_override`, selector, input: x.singleHalfSquare, output: prefix === "fssqrt" ? x.positiveOne : x.sqrtSingleHalfExtended, fpcr: oppositePrecision, fpsr: prefix === "fssqrt" ? "00000008" : "00000000" },
  { name: `${prefix}_accrued_preserve`, selector, input: x.positiveTwo, output: sqrtTwo, replayFpsr: "0455ff00", fpsr: "00550008" },
);

const strictCases = [
  { name: "fsqrt_fp7_self_strict", selector: "1f84" },
  { name: "fssqrt_fp7_self_strict", selector: "1fc1" },
  { name: "fdsqrt_fp7_self_strict", selector: "1fc5" },
] as const;

function memoryBytes(address: number, bytes: string): string {
  return bytes.split(/\s+/).map((byte, index) => `${(address + index).toString(16)} ${byte}`).join(" ");
}
function writePrefs(path: string, disk: string) {
  writeFileSync(path, [
    `rom ${rom}`, `disk ${disk}`, "ramsize 8388608", "modelid 14", "cpu 4",
    "fpu true", "jit true", "jitfpu true", "jitcachesize 8192",
    "screen win/640/480", "nosound true", "nocdrom true", "nogui true", "ignoresegv true", "",
  ].join("\n"));
}

const diskDir = mkdtempSync(join(tmpdir(), "fpp-sqrt-fallback-disk-"));
const clone = spawnSync("bash", ["-c", [
  "set -euo pipefail", "source \"$1\"", "cow_clone \"$2\" \"$3/disk.img\" fpp-sqrt-fallback",
].join("\n"), "bash", cowLib, diskSource, diskDir], { encoding: "utf8" });
if (clone.status !== 0) {
  console.error(clone.stderr || "FPP_SQRT_FALLBACK_FAIL unable to create isolated disk clone");
  process.exit(1);
}
const disk = clone.stdout.trim().split("\n").at(-1)!;
const selectedService = process.env.CASE ? serviceCases.filter((item) => item.name === process.env.CASE) : serviceCases;
const selectedStrict = process.env.CASE ? strictCases.filter((item) => item.name === process.env.CASE) : strictCases;
if (selectedService.length + selectedStrict.length === 0) throw new Error(`unknown CASE=${process.env.CASE}`);
let servicePass = 0, strictPass = 0, fail = 0;
try {
  for (const item of selectedService) {
    const td = mkdtempSync(join(tmpdir(), "fpp-sqrt-service-"));
    try {
      const pref = join(td, "prefs"); writePrefs(pref, disk);
      const load = item.fp7 ? "F239 4B80" : "F239 4880";
      const store = item.fp7 ? "F210 6B80" : "F210 6800";
      const guard = `9ffe a5 9fff 5a ${memoryBytes(0xa000, x.positiveZero)} a00c 3c a00d c3`;
      const run = spawnSync("timeout", ["-k", "5s", "30s", bin, "--config", pref], { encoding: "utf8", timeout: 35_000, env: {
        ...process.env, SDL_VIDEODRIVER: "x11", DISPLAY: display, HOME: td,
        B2_TEST_HEX: `${load} 0000 9000 F200 ${item.selector} ${store} 2C7C A6F8 0000`, B2_TEST_INIT: zeroInit,
        B2_TEST_MEMORY_BYTES: `${memoryBytes(0x9000, item.input)} ${guard}`, B2_TEST_MEMDUMP: "0x9ffe:16", B2_TEST_DUMP: "1", B2_TEST_DUMP_FP: "1",
        B2_JIT_FORCE_TRANSLATE: "1", B2_TEST_TWO_PASS: "1", B2_TEST_SECOND_PC: "0x1000", B2_TEST_REPLAY_COUNT: "2", B2_TEST_FORCE_L2_RAM: "1",
        B2_TEST_REPLAY_FPCR: item.fpcr ?? "0", B2_TEST_REPLAY_FPSR: item.replayFpsr ?? "0",
      }});
      const output = `${run.stdout ?? ""}${run.stderr ?? ""}`, dump = output.match(/^REGDUMP:.*$/m)?.[0];
      const mem = output.match(/^MEMDUMP [^:]+:(.*)$/m)?.[1].trim().toLowerCase();
      const expected = `a5 5a ${item.output} 3c c3`;
      const a0 = dump?.match(/ A0=([0-9a-f]+)/i)?.[1].toLowerCase();
      const fpsr = dump?.match(/ FPSR=([0-9a-f]+)/i)?.[1].toLowerCase();
      const sr = dump?.match(/ SR=([0-9a-f]+)/i)?.[1].toLowerCase();
      const fallbackCount = (output.match(/JIT_FALLBACK/g) ?? []).length;
      const serviced = fallbackCount === 3 && !output.includes("Caught SIGSEGV");
      if (run.status === 0 && mem === expected && a0 === "0000a000" && fpsr === item.fpsr && sr === "271f" && serviced) servicePass++;
      else {
        fail++;
        console.error(`FPP_SQRT_FALLBACK_FAIL case=${item.name} phase=service rc=${run.status} mem=${mem} want_mem=${expected} a0=${a0} fpsr=${fpsr} want_fpsr=${item.fpsr} sr=${sr} fallbacks=${fallbackCount}`);
      }
    } finally { rmSync(td, { recursive: true, force: true }); }
  }
  for (const item of selectedStrict) {
    const td = mkdtempSync(join(tmpdir(), "fpp-sqrt-strict-"));
    try {
      const pref = join(td, "prefs"); writePrefs(pref, disk);
      const run = spawnSync("timeout", ["-k", "5s", "30s", bin, "--config", pref], { encoding: "utf8", timeout: 35_000, env: {
        ...process.env, SDL_VIDEODRIVER: "x11", DISPLAY: display, HOME: td,
        B2_TEST_HEX: `F23C 4780 4000 0000 F200 ${item.selector} 2C7C A6F7 0000`, B2_TEST_INIT: zeroInit, B2_TEST_DUMP: "1", B2_TEST_DUMP_FP: "1",
        B2_JIT_FORCE_TRANSLATE: "1", B2_TEST_TWO_PASS: "1", B2_TEST_SECOND_PC: "0x1008", B2_TEST_REPLAY_COUNT: "2", B2_TEST_FORCE_L2_RAM: "1", B2_JIT_STRICT_FULL: "1",
      }});
      const output = `${run.stdout ?? ""}${run.stderr ?? ""}`;
      const rejected = output.includes("strict full-JIT: opcode fallback pc=00001008 op=f200");
      const noNative = !output.includes("NATEXEC pc=00001008") && !output.includes("JIT_STRICT_SUMMARY ");
      const noSegv = !output.includes("Caught SIGSEGV");
      if (run.status !== 0 && rejected && noNative && noSegv) strictPass++;
      else {
        fail++;
        console.error(`FPP_SQRT_FALLBACK_FAIL case=${item.name} phase=strict rc=${run.status} rejected=${rejected ? 1 : 0} no_native=${noNative ? 1 : 0} no_segv=${noSegv ? 1 : 0}`);
      }
    } finally { rmSync(td, { recursive: true, force: true }); }
  }
} finally {
  spawnSync("bash", ["-c", "source \"$1\"; cow_release \"$2\"", "bash", cowLib, disk]);
  rmSync(diskDir, { recursive: true, force: true });
}
console.log(`FPP_SQRT_FALLBACK_MATRIX service_pass=${servicePass} strict_pass=${strictPass} fail=${fail} total=${servicePass + strictPass + fail}`);
const expectedService = process.env.CASE ? selectedService.length : 54;
const expectedStrict = process.env.CASE ? selectedStrict.length : 3;
process.exit(fail === 0 && servicePass === expectedService && strictPass === expectedStrict ? 0 : 1);
