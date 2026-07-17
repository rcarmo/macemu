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
  negativeTwo: "c0 00 00 00 80 00 00 00 00 00 00 00",
  positiveThree: "40 00 00 00 c0 00 00 00 00 00 00 00",
  negativeThree: "c0 00 00 00 c0 00 00 00 00 00 00 00",
  positiveOneHalf: "3f ff 00 00 c0 00 00 00 00 00 00 00",
  negativeOneHalf: "bf ff 00 00 c0 00 00 00 00 00 00 00",
  positiveTwoHalf: "40 00 00 00 a0 00 00 00 00 00 00 00",
  negativeTwoHalf: "c0 00 00 00 a0 00 00 00 00 00 00 00",
  halfPlusExtendedUlp: "3f fe 00 00 80 00 00 00 00 00 00 01",
  belowPositiveOne: "3f fe 00 00 ff ff ff ff ff ff ff ff",
  onePlusExtendedUlp: "3f ff 00 00 80 00 00 00 00 00 00 01",
  hugeIntegralLowBit: "40 3e 00 00 80 00 00 00 00 00 00 01",
  hugeIntegralSingleRounded: "40 3e 00 00 80 00 00 00 00 00 00 00",
  positiveInfinity: "7f ff 00 00 00 00 00 00 00 00 00 00",
  negativeInfinity: "ff ff 00 00 00 00 00 00 00 00 00 00",
  quietNan: "7f ff 00 00 c0 00 12 34 56 78 9a bc",
  signallingNan: "7f ff 00 00 80 00 12 34 56 78 9a bc",
} as const;

type ServiceCase = {
  name: string;
  selector: "01" | "03";
  input: string;
  output: string;
  fpsr: string;
  fpcr?: string;
  replayFpsr?: string;
  registerAlias?: boolean;
};
const serviceCases: ServiceCase[] = [];
const roundingCases = [
  ["positive_one_half", x.positiveOneHalf, [x.positiveTwo, x.positiveOne, x.positiveOne, x.positiveTwo], false],
  ["negative_one_half", x.negativeOneHalf, [x.negativeTwo, x.negativeOne, x.negativeTwo, x.negativeOne], true],
  ["positive_two_half", x.positiveTwoHalf, [x.positiveTwo, x.positiveTwo, x.positiveTwo, x.positiveThree], false],
  ["negative_two_half", x.negativeTwoHalf, [x.negativeTwo, x.negativeTwo, x.negativeThree, x.negativeTwo], true],
] as const;
const modes = [["0", "nearest"], ["10", "zero"], ["20", "minus"], ["30", "plus"]] as const;
for (let mode = 0; mode < modes.length; mode++) {
  const [fpcr, suffix] = modes[mode];
  for (const [name, input, outputs, negative] of roundingCases) serviceCases.push({
    name: `fint_${name}_${suffix}`, selector: "01", input, output: outputs[mode], fpcr,
    fpsr: negative ? "08000008" : "00000008",
  });
  for (const [name, input, outputs, negative] of roundingCases) serviceCases.push({
    name: `fintrz_${name}_${suffix}`, selector: "03", input,
    output: name.includes("one_half") ? (negative ? x.negativeOne : x.positiveOne) : (negative ? x.negativeTwo : x.positiveTwo),
    fpcr, fpsr: negative ? "08000008" : "00000008",
  });
}
serviceCases.push(
  { name: "fint_positive_zero", selector: "01", input: x.positiveZero, output: x.positiveZero, fpsr: "04000000" },
  { name: "fint_negative_zero", selector: "01", input: x.negativeZero, output: x.negativeZero, fpsr: "0c000000" },
  { name: "fintrz_positive_zero", selector: "03", input: x.positiveZero, output: x.positiveZero, fpsr: "04000000" },
  { name: "fintrz_negative_zero", selector: "03", input: x.negativeZero, output: x.negativeZero, fpsr: "0c000000" },
  { name: "fint_positive_infinity", selector: "01", input: x.positiveInfinity, output: x.positiveInfinity, fpsr: "02000000" },
  { name: "fint_negative_infinity", selector: "01", input: x.negativeInfinity, output: x.negativeInfinity, fpsr: "0a000000" },
  { name: "fintrz_positive_infinity", selector: "03", input: x.positiveInfinity, output: x.positiveInfinity, fpsr: "02000000" },
  { name: "fintrz_negative_infinity", selector: "03", input: x.negativeInfinity, output: x.negativeInfinity, fpsr: "0a000000" },
  { name: "fint_quiet_nan_payload", selector: "01", input: x.quietNan, output: x.quietNan, fpsr: "01000000" },
  { name: "fint_signalling_nan_quiet", selector: "01", input: x.signallingNan, output: x.quietNan, fpsr: "01000080" },
  { name: "fintrz_quiet_nan_payload", selector: "03", input: x.quietNan, output: x.quietNan, fpsr: "01000000" },
  { name: "fintrz_signalling_nan_quiet", selector: "03", input: x.signallingNan, output: x.quietNan, fpsr: "01000080" },
  { name: "fint_one_plus_extended_ulp", selector: "01", input: x.onePlusExtendedUlp, output: x.positiveOne, fpsr: "00000008" },
  { name: "fint_half_plus_ulp_fpcr_single", selector: "01", input: x.halfPlusExtendedUlp, output: x.positiveOne, fpcr: "40", fpsr: "00000008" },
  { name: "fint_half_plus_ulp_fpcr_double", selector: "01", input: x.halfPlusExtendedUlp, output: x.positiveOne, fpcr: "80", fpsr: "00000008" },
  { name: "fintrz_below_one_fpcr_single_plus", selector: "03", input: x.belowPositiveOne, output: x.positiveZero, fpcr: "70", fpsr: "04000008" },
  { name: "fintrz_below_one_fpcr_double_plus", selector: "03", input: x.belowPositiveOne, output: x.positiveZero, fpcr: "b0", fpsr: "04000008" },
  { name: "fint_huge_integral_fpcr_single_rounds", selector: "01", input: x.hugeIntegralLowBit, output: x.hugeIntegralSingleRounded, fpcr: "40", fpsr: "00000008" },
  { name: "fintrz_huge_integral_fpcr_single_rounds", selector: "03", input: x.hugeIntegralLowBit, output: x.hugeIntegralSingleRounded, fpcr: "40", fpsr: "00000008" },
  { name: "fint_fp7_self_alias", selector: "01", input: x.positiveTwoHalf, output: x.positiveTwo, fpsr: "00000008", registerAlias: true },
  { name: "fintrz_fp7_self_alias", selector: "03", input: x.negativeTwoHalf, output: x.negativeTwo, fpsr: "08000008", registerAlias: true },
  { name: "fint_accrued_preserve", selector: "01", input: x.positiveOneHalf, output: x.positiveTwo, replayFpsr: "0455ff00", fpsr: "00550008" },
  { name: "fintrz_accrued_preserve", selector: "03", input: x.negativeOneHalf, output: x.negativeOne, replayFpsr: "0455ff00", fpsr: "08550008" },
);
const strictCases = [
  { name: "fint_fp7_strict", extra: "4b81" },
  { name: "fintrz_fp7_strict", extra: "4b83" },
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

const diskDir = mkdtempSync(join(tmpdir(), "fpp-integral-rounding-disk-"));
const clone = spawnSync("bash", ["-c", [
  "set -euo pipefail", "source \"$1\"", "cow_clone \"$2\" \"$3/disk.img\" fpp-integral-rounding",
].join("\n"), "bash", cowLib, diskSource, diskDir], { encoding: "utf8" });
if (clone.status !== 0) {
  console.error(clone.stderr || "FPP_INTEGRAL_ROUNDING_FAIL unable to create isolated disk clone");
  rmSync(diskDir, { recursive: true, force: true });
  process.exit(1);
}
const disk = clone.stdout.trim().split("\n").at(-1)!;
const selectedService = process.env.CASE ? serviceCases.filter((item) => item.name === process.env.CASE) : serviceCases;
const selectedStrict = process.env.CASE ? strictCases.filter((item) => item.name === process.env.CASE) : strictCases;
let servicePass = 0, strictPass = 0, fail = 0;
try {
  if (selectedService.length + selectedStrict.length === 0) throw new Error(`unknown CASE=${process.env.CASE}`);
  for (const item of selectedService) {
    const td = mkdtempSync(join(tmpdir(), "fpp-integral-rounding-service-"));
    try {
      const pref = join(td, "prefs"); writePrefs(pref, disk);
      const directExtra = (0x4b80 | Number.parseInt(item.selector, 16)).toString(16).padStart(4, "0");
      const registerExtra = (0x1f80 | Number.parseInt(item.selector, 16)).toString(16).padStart(4, "0");
      const stream = item.registerAlias
        ? `F239 4B80 0000 9000 F200 ${registerExtra} F210 6B80 2C7C A6F5 0000`
        : `F239 ${directExtra} 0000 9000 F210 6B80 2C7C A6F5 0000`;
      const guard = `9ffe a5 9fff 5a ${memoryBytes(0xa000, x.positiveZero)} a00c 3c a00d c3`;
      const run = spawnSync("timeout", ["-k", "5s", "30s", bin, "--config", pref], { encoding: "utf8", timeout: 35_000, env: {
        ...process.env, SDL_VIDEODRIVER: "x11", DISPLAY: display, HOME: td,
        B2_TEST_HEX: stream, B2_TEST_INIT: zeroInit,
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
      const serviced = fallbackCount === (item.registerAlias ? 3 : 2) && !output.includes("Caught SIGSEGV");
      if (run.status === 0 && mem === expected && a0 === "0000a000" && fpsr === item.fpsr && sr === "271f" && serviced) servicePass++;
      else {
        fail++;
        console.error(`FPP_INTEGRAL_ROUNDING_FAIL case=${item.name} phase=service rc=${run.status} mem=${mem} want_mem=${expected} a0=${a0} fpsr=${fpsr} want_fpsr=${item.fpsr} sr=${sr} fallbacks=${fallbackCount}`);
      }
    } finally { rmSync(td, { recursive: true, force: true }); }
  }
  for (const item of selectedStrict) {
    const td = mkdtempSync(join(tmpdir(), "fpp-integral-rounding-strict-"));
    try {
      const pref = join(td, "prefs"); writePrefs(pref, disk);
      const run = spawnSync("timeout", ["-k", "5s", "30s", bin, "--config", pref], { encoding: "utf8", timeout: 35_000, env: {
        ...process.env, SDL_VIDEODRIVER: "x11", DISPLAY: display, HOME: td,
        B2_TEST_HEX: `F239 ${item.extra} 0000 9000 2C7C A6F4 0000`, B2_TEST_INIT: zeroInit,
        B2_TEST_MEMORY_BYTES: memoryBytes(0x9000, x.positiveOneHalf), B2_TEST_DUMP: "1", B2_TEST_DUMP_FP: "1",
        B2_JIT_FORCE_TRANSLATE: "1", B2_TEST_TWO_PASS: "1", B2_TEST_SECOND_PC: "0x1000", B2_TEST_REPLAY_COUNT: "2", B2_TEST_FORCE_L2_RAM: "1", B2_JIT_STRICT_FULL: "1",
      }});
      const output = `${run.stdout ?? ""}${run.stderr ?? ""}`;
      const rejected = output.includes("strict full-JIT: opcode fallback pc=00001000 op=f239");
      const noNative = !output.includes("NATEXEC pc=00001000") && !output.includes("JIT_STRICT_SUMMARY ");
      const noSegv = !output.includes("Caught SIGSEGV");
      if (run.status !== 0 && rejected && noNative && noSegv) strictPass++;
      else {
        fail++;
        console.error(`FPP_INTEGRAL_ROUNDING_FAIL case=${item.name} phase=strict rc=${run.status} rejected=${rejected ? 1 : 0} no_native=${noNative ? 1 : 0} no_segv=${noSegv ? 1 : 0}`);
      }
    } finally { rmSync(td, { recursive: true, force: true }); }
  }
} finally {
  spawnSync("bash", ["-c", "source \"$1\"; cow_release \"$2\"", "bash", cowLib, disk]);
  rmSync(diskDir, { recursive: true, force: true });
}
console.log(`FPP_INTEGRAL_ROUNDING_MATRIX service_pass=${servicePass} strict_pass=${strictPass} fail=${fail} total=${servicePass + strictPass + fail}`);
const expectedService = process.env.CASE ? selectedService.length : 55;
const expectedStrict = process.env.CASE ? selectedStrict.length : 2;
process.exit(fail === 0 && servicePass === expectedService && strictPass === expectedStrict ? 0 : 1);
