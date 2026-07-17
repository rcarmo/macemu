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

const positiveHalfSingle = "3f ff 00 00 80 00 00 80 00 00 00 00";
const negativeHalfSingle = "bf ff 00 00 80 00 00 80 00 00 00 00";
const positiveHalfDouble = "3f ff 00 00 80 00 00 00 00 00 04 00";
const negativeHalfDouble = "bf ff 00 00 80 00 00 00 00 00 04 00";
const positiveOne = "3f ff 00 00 80 00 00 00 00 00 00 00";
const negativeOne = "bf ff 00 00 80 00 00 00 00 00 00 00";
const positiveSingleNext = "3f ff 00 00 80 00 01 00 00 00 00 00";
const negativeSingleNext = "bf ff 00 00 80 00 01 00 00 00 00 00";
const positiveDoubleNext = "3f ff 00 00 80 00 00 00 00 00 08 00";
const negativeDoubleNext = "bf ff 00 00 80 00 00 00 00 00 08 00";

type ServiceCase = {
  name: string;
  selector: "0418" | "041a" | "0458" | "045a" | "045c" | "045e" | "1f9a" | "1fd8";
  input: string;
  output: string;
  fpsr: string;
  fpcr?: string;
  replayFpsr?: string;
  fp7?: boolean;
};

const serviceCases: ServiceCase[] = [
  { name: "fabs_wide_negative", selector: "0418", input: negativeHalfDouble, output: positiveHalfDouble, fpsr: "00000000" },
  { name: "fneg_wide_positive", selector: "041a", input: positiveHalfDouble, output: negativeHalfDouble, fpsr: "08000000" },
  { name: "fneg_negative_zero", selector: "041a", input: "80 00 00 00 00 00 00 00 00 00 00 00", output: "00 00 00 00 00 00 00 00 00 00 00 00", fpsr: "04000000" },
  { name: "fabs_negative_infinity", selector: "0418", input: "ff ff 00 00 00 00 00 00 00 00 00 00", output: "7f ff 00 00 00 00 00 00 00 00 00 00", fpsr: "02000000" },
  { name: "fneg_positive_qnan", selector: "041a", input: "7f ff 00 00 c0 00 12 34 56 78 9a bc", output: "ff ff 00 00 c0 00 12 34 56 78 9a bc", fpsr: "09000000" },
  { name: "fabs_negative_qnan", selector: "0418", input: "ff ff 00 00 c0 00 12 34 56 78 9a bc", output: "7f ff 00 00 c0 00 12 34 56 78 9a bc", fpsr: "01000000" },
];
for (const [fpcr, suffix] of [["40", "nearest"], ["50", "zero"], ["60", "minus"], ["70", "plus"]] as const)
  serviceCases.push({ name: `fabs_single_${suffix}`, selector: "0418", input: negativeHalfSingle, output: positiveOne, fpcr, fpsr: "00000008" });
for (const [fpcr, suffix] of [["80", "nearest"], ["90", "zero"], ["a0", "minus"], ["b0", "plus"]] as const)
  serviceCases.push({ name: `fneg_double_${suffix}`, selector: "041a", input: positiveHalfDouble, output: negativeOne, fpcr, fpsr: "08000008" });
for (const [fpcr, suffix, output] of [
  ["0", "nearest", positiveOne], ["10", "zero", positiveOne],
  ["20", "minus", positiveOne], ["30", "plus", positiveSingleNext],
] as const) serviceCases.push({ name: `fsabs_${suffix}`, selector: "0458", input: negativeHalfSingle, output, fpcr, fpsr: "00000008" });
for (const [fpcr, suffix, output] of [
  ["0", "nearest", negativeOne], ["10", "zero", negativeOne],
  ["20", "minus", negativeSingleNext], ["30", "plus", negativeOne],
] as const) serviceCases.push({ name: `fsneg_${suffix}`, selector: "045a", input: positiveHalfSingle, output, fpcr, fpsr: "08000008" });
serviceCases.push(
  { name: "fdabs_negative_half_nearest", selector: "045c", input: negativeHalfDouble, output: positiveOne, fpsr: "00000008" },
  { name: "fdabs_negative_half_plus", selector: "045c", input: negativeHalfDouble, output: positiveDoubleNext, fpcr: "30", fpsr: "00000008" },
  { name: "fdneg_positive_half_nearest", selector: "045e", input: positiveHalfDouble, output: negativeOne, fpsr: "08000008" },
  { name: "fdneg_positive_half_minus", selector: "045e", input: positiveHalfDouble, output: negativeDoubleNext, fpcr: "20", fpsr: "08000008" },
  { name: "fsabs_maximum_extended_overflow", selector: "0458", input: "ff fe 00 00 ff ff ff ff ff ff ff ff", output: "7f ff 00 00 00 00 00 00 00 00 00 00", fpsr: "02000048" },
  { name: "fdneg_maximum_extended_overflow", selector: "045e", input: "7f fe 00 00 ff ff ff ff ff ff ff ff", output: "ff ff 00 00 00 00 00 00 00 00 00 00", fpsr: "0a000048" },
  { name: "fneg_fp7_self_wide_max_fields", selector: "1f9a", input: positiveHalfDouble, output: negativeHalfDouble, fpsr: "08000000", fp7: true },
  { name: "fsabs_fp7_self_max_fields", selector: "1fd8", input: negativeHalfSingle, output: positiveOne, fpsr: "00000008", fp7: true },
  { name: "fneg_accrued_preserve", selector: "041a", input: positiveHalfDouble, output: negativeHalfDouble, fpsr: "08550008", replayFpsr: "0c55ff08" },
);

const strictCases = [
  { name: "fabs_fp7_self_strict", selector: "1f98" },
  { name: "fneg_fp7_self_strict", selector: "1f9a" },
  { name: "fsabs_fp7_self_strict", selector: "1fd8" },
  { name: "fsneg_fp7_self_strict", selector: "1fda" },
  { name: "fdabs_fp7_self_strict", selector: "1fdc" },
  { name: "fdneg_fp7_self_strict", selector: "1fde" },
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

const diskDir = mkdtempSync(join(tmpdir(), "fpp-sign-fallback-disk-"));
const clone = spawnSync("bash", ["-c", ["set -euo pipefail", "source \"$1\"", "cow_clone \"$2\" \"$3/disk.img\" fpp-sign-fallback"].join("\n"), "bash", cowLib, diskSource, diskDir], { encoding: "utf8" });
if (clone.status !== 0) { console.error(clone.stderr || "FPP_SIGN_FALLBACK_FAIL unable to create isolated disk clone"); process.exit(1); }
const disk = clone.stdout.trim().split("\n").at(-1)!;
const selectedService = process.env.CASE ? serviceCases.filter((item) => item.name === process.env.CASE) : serviceCases;
const selectedStrict = process.env.CASE ? strictCases.filter((item) => item.name === process.env.CASE) : strictCases;
if (selectedService.length + selectedStrict.length === 0) throw new Error(`unknown CASE=${process.env.CASE}`);
let servicePass = 0, strictPass = 0, fail = 0;
try {
  for (const item of selectedService) {
    const td = mkdtempSync(join(tmpdir(), "fpp-sign-service-"));
    try {
      const pref = join(td, "prefs"); writePrefs(pref, disk);
      const load = item.fp7 ? "F239 4B80" : "F239 4880";
      const store = item.fp7 ? "F210 6B80" : "F210 6800";
      const guard = `9ffe a5 9fff 5a ${memoryBytes(0xa000, "00 00 00 00 00 00 00 00 00 00 00 00")} a00c 3c a00d c3`;
      const run = spawnSync("timeout", ["-k", "5s", "30s", bin, "--config", pref], { encoding: "utf8", timeout: 35_000, env: {
        ...process.env, SDL_VIDEODRIVER: "x11", DISPLAY: display, HOME: td,
        B2_TEST_HEX: `${load} 0000 9000 F200 ${item.selector} ${store} 2C7C A6FA 0000`, B2_TEST_INIT: zeroInit,
        B2_TEST_MEMORY_BYTES: `${memoryBytes(0x9000, item.input)} ${guard}`, B2_TEST_MEMDUMP: "0x9ffe:16", B2_TEST_DUMP: "1", B2_TEST_DUMP_FP: "1",
        B2_JIT_FORCE_TRANSLATE: "1", B2_TEST_TWO_PASS: "1", B2_TEST_SECOND_PC: "0x1000", B2_TEST_REPLAY_COUNT: "2", B2_TEST_FORCE_L2_RAM: "1",
        B2_TEST_REPLAY_FPCR: item.fpcr ?? "0", B2_TEST_REPLAY_FPSR: item.replayFpsr ?? "0",
      }});
      const output = `${run.stdout ?? ""}${run.stderr ?? ""}`, dump = output.match(/^REGDUMP:.*$/m)?.[0];
      const mem = output.match(/^MEMDUMP [^:]+:(.*)$/m)?.[1].trim().toLowerCase();
      const expected = `a5 5a ${item.output} 3c c3`, a0 = dump?.match(/ A0=([0-9a-f]+)/i)?.[1].toLowerCase();
      const fpsr = dump?.match(/ FPSR=([0-9a-f]+)/i)?.[1].toLowerCase(), sr = dump?.match(/ SR=([0-9a-f]+)/i)?.[1].toLowerCase();
      const fallbackCount = (output.match(/JIT_FALLBACK/g) ?? []).length;
      const serviced = fallbackCount === 3 && !output.includes("Caught SIGSEGV");
      if (run.status === 0 && mem === expected && a0 === "0000a000" && fpsr === item.fpsr && sr === "271f" && serviced) servicePass++;
      else { fail++; console.error(`FPP_SIGN_FALLBACK_FAIL case=${item.name} phase=service rc=${run.status} mem=${mem} want_mem=${expected} a0=${a0} fpsr=${fpsr} want_fpsr=${item.fpsr} sr=${sr} fallbacks=${fallbackCount}`); }
    } finally { rmSync(td, { recursive: true, force: true }); }
  }
  for (const item of selectedStrict) {
    const td = mkdtempSync(join(tmpdir(), "fpp-sign-strict-"));
    try {
      const pref = join(td, "prefs"); writePrefs(pref, disk);
      const run = spawnSync("timeout", ["-k", "5s", "30s", bin, "--config", pref], { encoding: "utf8", timeout: 35_000, env: {
        ...process.env, SDL_VIDEODRIVER: "x11", DISPLAY: display, HOME: td,
        B2_TEST_HEX: `F23C 4780 3F80 0000 F200 ${item.selector} 2C7C A6F9 0000`, B2_TEST_INIT: zeroInit, B2_TEST_DUMP: "1", B2_TEST_DUMP_FP: "1",
        B2_JIT_FORCE_TRANSLATE: "1", B2_TEST_TWO_PASS: "1", B2_TEST_SECOND_PC: "0x1008", B2_TEST_REPLAY_COUNT: "2", B2_TEST_FORCE_L2_RAM: "1", B2_JIT_STRICT_FULL: "1",
      }});
      const output = `${run.stdout ?? ""}${run.stderr ?? ""}`;
      const rejected = output.includes("strict full-JIT: opcode fallback pc=00001008 op=f200");
      const noNative = !output.includes("NATEXEC pc=00001008") && !output.includes("JIT_STRICT_SUMMARY ");
      const noSegv = !output.includes("Caught SIGSEGV");
      if (run.status !== 0 && rejected && noNative && noSegv) strictPass++;
      else { fail++; console.error(`FPP_SIGN_FALLBACK_FAIL case=${item.name} phase=strict rc=${run.status} rejected=${rejected ? 1 : 0} no_native=${noNative ? 1 : 0} no_segv=${noSegv ? 1 : 0}`); }
    } finally { rmSync(td, { recursive: true, force: true }); }
  }
} finally {
  spawnSync("bash", ["-c", "source \"$1\"; cow_release \"$2\"", "bash", cowLib, disk]);
  rmSync(diskDir, { recursive: true, force: true });
}
console.log(`FPP_SIGN_FALLBACK_MATRIX service_pass=${servicePass} strict_pass=${strictPass} fail=${fail} total=${servicePass + strictPass + fail}`);
const expectedService = process.env.CASE ? selectedService.length : 31, expectedStrict = process.env.CASE ? selectedStrict.length : 6;
process.exit(fail === 0 && servicePass === expectedService && strictPass === expectedStrict ? 0 : 1);
