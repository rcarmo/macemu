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
  positiveOneHalf: "3f ff 00 00 c0 00 00 00 00 00 00 00",
  negativeOneHalf: "bf ff 00 00 c0 00 00 00 00 00 00 00",
  positiveThree: "40 00 00 00 c0 00 00 00 00 00 00 00",
  negativeThree: "c0 00 00 00 c0 00 00 00 00 00 00 00",
  positiveSevenEighths: "40 01 00 00 e0 00 00 00 00 00 00 00",
  negativeSevenEighths: "c0 01 00 00 e0 00 00 00 00 00 00 00",
  exponentOne: "3f ff 00 00 80 00 00 00 00 00 00 00",
  exponentMinusOne: "bf ff 00 00 80 00 00 00 00 00 00 00",
  exponentTwo: "40 00 00 00 80 00 00 00 00 00 00 00",
  exponentMinusTwo: "c0 00 00 00 80 00 00 00 00 00 00 00",
  exponent62: "40 04 00 00 f8 00 00 00 00 00 00 00",
  exponentMinus63: "c0 04 00 00 fc 00 00 00 00 00 00 00",
  exponentMinus16382: "c0 0c 00 00 ff f8 00 00 00 00 00 00",
  exponent16383: "40 0c 00 00 ff fc 00 00 00 00 00 00",
  exponentMinus16445: "c0 0d 00 00 80 7a 00 00 00 00 00 00",
  onePlusExtendedUlp: "3f ff 00 00 80 00 00 00 00 00 00 01",
  minimumNormal: "00 01 00 00 80 00 00 00 00 00 00 00",
  maximumFinite: "7f fe 00 00 ff ff ff ff ff ff ff ff",
  minimumSubnormal: "00 00 00 00 00 00 00 00 00 00 00 01",
  positiveInfinity: "7f ff 00 00 00 00 00 00 00 00 00 00",
  negativeInfinity: "ff ff 00 00 00 00 00 00 00 00 00 00",
  canonicalPositiveNan: "7f ff 00 00 ff ff ff ff ff ff ff ff",
  canonicalNegativeNan: "ff ff 00 00 ff ff ff ff ff ff ff ff",
  quietNan: "7f ff 00 00 c0 00 12 34 56 78 9a bc",
  negativeQuietNan: "ff ff 00 00 c0 00 12 34 56 78 9a bc",
  signallingNan: "7f ff 00 00 80 00 12 34 56 78 9a bc",
  quietedNan: "7f ff 00 00 c0 00 12 34 56 78 9a bc",
} as const;

type ServiceCase = {
  name: string;
  selector: "1e" | "1f";
  input: string;
  output: string;
  fpsr: string;
  operationFpsr?: string;
  fpcr?: string;
  replayFpsr?: string;
  registerAlias?: boolean;
  negateSuccessor?: boolean;
};

const serviceCases: ServiceCase[] = [
  { name: "fgetexp_positive_zero", selector: "1e", input: x.positiveZero, output: x.positiveZero, fpsr: "04000000" },
  { name: "fgetexp_negative_zero", selector: "1e", input: x.negativeZero, output: x.negativeZero, fpsr: "0c000000" },
  { name: "fgetexp_positive_one", selector: "1e", input: x.positiveOne, output: x.positiveZero, fpsr: "04000000" },
  { name: "fgetexp_negative_three", selector: "1e", input: x.negativeThree, output: x.positiveOne, fpsr: "00000000" },
  { name: "fgetexp_positive_seven", selector: "1e", input: x.positiveSevenEighths, output: x.exponentTwo, fpsr: "00000000" },
  { name: "fgetexp_negative_half", selector: "1e", input: x.negativeOneHalf, output: x.positiveZero, fpsr: "04000000" },
  { name: "fgetexp_minimum_normal", selector: "1e", input: x.minimumNormal, output: x.exponentMinus16382, fpsr: "08000000" },
  { name: "fgetexp_maximum_finite", selector: "1e", input: x.maximumFinite, output: x.exponent16383, fpsr: "00000000" },
  { name: "fgetexp_minimum_subnormal", selector: "1e", input: x.minimumSubnormal, output: x.exponentMinus16445, fpsr: "08000000" },
  { name: "fgetexp_positive_infinity_operr", selector: "1e", input: x.positiveInfinity, output: x.canonicalPositiveNan, fpsr: "01000080", operationFpsr: "01002080" },
  { name: "fgetexp_negative_infinity_operr", selector: "1e", input: x.negativeInfinity, output: x.canonicalNegativeNan, fpsr: "09000080", operationFpsr: "09002080" },
  { name: "fgetexp_negative_infinity_fneg_metadata", selector: "1e", input: x.negativeInfinity, output: x.canonicalPositiveNan, fpsr: "01000080", operationFpsr: "09002080", negateSuccessor: true },
  { name: "fgetexp_quiet_nan_payload", selector: "1e", input: x.quietNan, output: x.quietNan, fpsr: "01000000" },
  { name: "fgetexp_negative_quiet_nan_payload", selector: "1e", input: x.negativeQuietNan, output: x.negativeQuietNan, fpsr: "09000000" },
  { name: "fgetexp_signalling_nan_quiet", selector: "1e", input: x.signallingNan, output: x.quietedNan, fpsr: "01000080", operationFpsr: "01004080" },
  { name: "fgetexp_fp7_self_alias", selector: "1e", input: x.maximumFinite, output: x.exponent16383, fpsr: "00000000", registerAlias: true },
  { name: "fgetexp_fpcr_single_plus_independent", selector: "1e", input: x.minimumSubnormal, output: x.exponentMinus16445, fpcr: "70", fpsr: "08000000" },
  { name: "fgetexp_fpcr_double_minus_independent", selector: "1e", input: x.maximumFinite, output: x.exponent16383, fpcr: "a0", fpsr: "00000000" },
  { name: "fgetexp_accrued_preserve", selector: "1e", input: x.positiveThree, output: x.positiveOne, replayFpsr: "0455ff00", fpsr: "00550000" },

  { name: "fgetman_positive_zero", selector: "1f", input: x.positiveZero, output: x.positiveZero, fpsr: "04000000" },
  { name: "fgetman_negative_zero", selector: "1f", input: x.negativeZero, output: x.negativeZero, fpsr: "0c000000" },
  { name: "fgetman_positive_three", selector: "1f", input: x.positiveThree, output: x.positiveOneHalf, fpsr: "00000000" },
  { name: "fgetman_negative_three", selector: "1f", input: x.negativeThree, output: x.negativeOneHalf, fpsr: "08000000" },
  { name: "fgetman_positive_seven", selector: "1f", input: x.positiveSevenEighths, output: "3f ff 00 00 e0 00 00 00 00 00 00 00", fpsr: "00000000" },
  { name: "fgetman_negative_seven", selector: "1f", input: x.negativeSevenEighths, output: "bf ff 00 00 e0 00 00 00 00 00 00 00", fpsr: "08000000" },
  { name: "fgetman_minimum_normal", selector: "1f", input: x.minimumNormal, output: x.positiveOne, fpsr: "00000000" },
  { name: "fgetman_maximum_finite", selector: "1f", input: x.maximumFinite, output: "3f ff 00 00 ff ff ff ff ff ff ff ff", fpsr: "00000000" },
  { name: "fgetman_minimum_subnormal", selector: "1f", input: x.minimumSubnormal, output: x.positiveOne, fpsr: "00000000" },
  { name: "fgetman_positive_infinity_operr", selector: "1f", input: x.positiveInfinity, output: x.canonicalPositiveNan, fpsr: "01000080", operationFpsr: "01002080" },
  { name: "fgetman_negative_infinity_operr", selector: "1f", input: x.negativeInfinity, output: x.canonicalNegativeNan, fpsr: "09000080", operationFpsr: "09002080" },
  { name: "fgetman_negative_infinity_fneg_metadata", selector: "1f", input: x.negativeInfinity, output: x.canonicalPositiveNan, fpsr: "01000080", operationFpsr: "09002080", negateSuccessor: true },
  { name: "fgetman_quiet_nan_payload", selector: "1f", input: x.quietNan, output: x.quietNan, fpsr: "01000000" },
  { name: "fgetman_negative_quiet_nan_payload", selector: "1f", input: x.negativeQuietNan, output: x.negativeQuietNan, fpsr: "09000000" },
  { name: "fgetman_signalling_nan_quiet", selector: "1f", input: x.signallingNan, output: x.quietedNan, fpsr: "01000080", operationFpsr: "01004080" },
  { name: "fgetman_fp7_self_alias", selector: "1f", input: x.negativeThree, output: x.negativeOneHalf, fpsr: "08000000", registerAlias: true },
  { name: "fgetman_fpcr_single_rounds", selector: "1f", input: x.onePlusExtendedUlp, output: x.positiveOne, fpcr: "40", fpsr: "00000008", operationFpsr: "00000208" },
  { name: "fgetman_fpcr_double_rounds", selector: "1f", input: x.onePlusExtendedUlp, output: x.positiveOne, fpcr: "80", fpsr: "00000008", operationFpsr: "00000208" },
  { name: "fgetman_accrued_preserve", selector: "1f", input: x.negativeThree, output: x.negativeOneHalf, replayFpsr: "0455ff00", fpsr: "08550000" },
];

const strictCases = [
  { name: "fgetexp_fp7_strict", extra: "4b9e" },
  { name: "fgetman_fp7_strict", extra: "4b9f" },
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

const diskDir = mkdtempSync(join(tmpdir(), "fpp-decomposition-disk-"));
const clone = spawnSync("bash", ["-c", [
  "set -euo pipefail", "source \"$1\"", "cow_clone \"$2\" \"$3/disk.img\" fpp-decomposition",
].join("\n"), "bash", cowLib, diskSource, diskDir], { encoding: "utf8" });
if (clone.status !== 0) {
  console.error(clone.stderr || "FPP_DECOMPOSITION_FAIL unable to create isolated disk clone");
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
    const td = mkdtempSync(join(tmpdir(), "fpp-decomposition-service-"));
    try {
      const pref = join(td, "prefs"); writePrefs(pref, disk);
      const directExtra = (0x4b80 | Number.parseInt(item.selector, 16)).toString(16).padStart(4, "0");
      const registerExtra = (0x1f80 | Number.parseInt(item.selector, 16)).toString(16).padStart(4, "0");
      const successor = item.negateSuccessor ? " F200 1F9A" : "";
      const stream = item.registerAlias
        ? `F239 4B80 0000 9000 F200 ${registerExtra} F200 A800${successor} F210 6B80 2C7C A6F3 0000`
        : `F239 ${directExtra} 0000 9000 F200 A800${successor} F210 6B80 2C7C A6F3 0000`;
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
      const d0 = dump?.match(/ D0=([0-9a-f]+)/i)?.[1].toLowerCase();
      const a0 = dump?.match(/ A0=([0-9a-f]+)/i)?.[1].toLowerCase();
      const fpsr = dump?.match(/ FPSR=([0-9a-f]+)/i)?.[1].toLowerCase();
      const sr = dump?.match(/ SR=([0-9a-f]+)/i)?.[1].toLowerCase();
      const fallbackCount = (output.match(/JIT_FALLBACK/g) ?? []).length;
      const serviced = fallbackCount === (item.registerAlias ? 4 : 3) + (item.negateSuccessor ? 1 : 0) && !output.includes("Caught SIGSEGV");
      const operationFpsr = item.operationFpsr ?? item.fpsr;
      if (run.status === 0 && mem === expected && d0 === operationFpsr && a0 === "0000a000" && fpsr === item.fpsr && sr === "271f" && serviced) servicePass++;
      else {
        fail++;
        console.error(`FPP_DECOMPOSITION_FAIL case=${item.name} phase=service rc=${run.status} mem=${mem} want_mem=${expected} d0=${d0} want_d0=${operationFpsr} a0=${a0} fpsr=${fpsr} want_fpsr=${item.fpsr} sr=${sr} fallbacks=${fallbackCount}`);
      }
    } finally { rmSync(td, { recursive: true, force: true }); }
  }
  for (const item of selectedStrict) {
    const td = mkdtempSync(join(tmpdir(), "fpp-decomposition-strict-"));
    try {
      const pref = join(td, "prefs"); writePrefs(pref, disk);
      const run = spawnSync("timeout", ["-k", "5s", "30s", bin, "--config", pref], { encoding: "utf8", timeout: 35_000, env: {
        ...process.env, SDL_VIDEODRIVER: "x11", DISPLAY: display, HOME: td,
        B2_TEST_HEX: `F239 ${item.extra} 0000 9000 2C7C A6F2 0000`, B2_TEST_INIT: zeroInit,
        B2_TEST_MEMORY_BYTES: memoryBytes(0x9000, x.positiveThree), B2_TEST_DUMP: "1", B2_TEST_DUMP_FP: "1",
        B2_JIT_FORCE_TRANSLATE: "1", B2_TEST_TWO_PASS: "1", B2_TEST_SECOND_PC: "0x1000", B2_TEST_REPLAY_COUNT: "2", B2_TEST_FORCE_L2_RAM: "1", B2_JIT_STRICT_FULL: "1",
      }});
      const output = `${run.stdout ?? ""}${run.stderr ?? ""}`;
      const rejected = output.includes("strict full-JIT: opcode fallback pc=00001000 op=f239");
      const noNative = !output.includes("NATEXEC pc=00001000") && !output.includes("JIT_STRICT_SUMMARY ");
      const noSegv = !output.includes("Caught SIGSEGV");
      if (run.status !== 0 && rejected && noNative && noSegv) strictPass++;
      else {
        fail++;
        console.error(`FPP_DECOMPOSITION_FAIL case=${item.name} phase=strict rc=${run.status} rejected=${rejected ? 1 : 0} no_native=${noNative ? 1 : 0} no_segv=${noSegv ? 1 : 0}`);
      }
    } finally { rmSync(td, { recursive: true, force: true }); }
  }
} finally {
  spawnSync("bash", ["-c", "source \"$1\"; cow_release \"$2\"", "bash", cowLib, disk]);
  rmSync(diskDir, { recursive: true, force: true });
}
console.log(`FPP_DECOMPOSITION_MATRIX service_pass=${servicePass} strict_pass=${strictPass} fail=${fail} total=${servicePass + strictPass + fail}`);
const expectedService = process.env.CASE ? selectedService.length : 38;
const expectedStrict = process.env.CASE ? selectedStrict.length : 2;
process.exit(fail === 0 && servicePass === expectedService && strictPass === expectedStrict ? 0 : 1);
