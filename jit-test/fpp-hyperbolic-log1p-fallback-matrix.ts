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
  negativeTwo: "c0 00 00 00 80 00 00 00 00 00 00 00",
  positiveInfinity: "7f ff 00 00 00 00 00 00 00 00 00 00",
  negativeInfinity: "ff ff 00 00 00 00 00 00 00 00 00 00",
  canonicalPositiveNan: "7f ff 00 00 ff ff ff ff ff ff ff ff",
  quietNan: "7f ff 00 00 c0 00 12 34 56 78 9a bc",
  negativeQuietNan: "ff ff 00 00 c0 00 12 34 56 78 9a bc",
  signallingNan: "7f ff 00 00 80 00 12 34 56 78 9a bc",
  quietedNan: "7f ff 00 00 c0 00 12 34 56 78 9a bc",
  minimumSubnormal: "00 00 00 00 00 00 00 00 00 00 00 01",
} as const;

type Selector = "02" | "06" | "08" | "09";
type ServiceCase = {
  name: string;
  selector: Selector;
  input: string;
  output: string;
  fpsr: string;
  operationFpsr?: string;
  fpcr?: string;
  replayFpsr?: string;
  registerAlias?: boolean;
};
const serviceCases: ServiceCase[] = [];
const rounding = [
  {
    name: "fsinh", selector: "02" as const,
    input: "40 03 00 00 88 e9 7b dd af 7e f7 3f",
    outputs: ["40 16 00 00 ce 8a c0 00 00 00 00 00", "40 16 00 00 ce 8a bf 00 00 00 00 00", "40 16 00 00 ce 8a bf 00 00 00 00 00", "40 16 00 00 ce 8a c0 00 00 00 00 00"],
  },
  {
    name: "flognp1", selector: "06" as const,
    input: "3f fb 00 00 e8 71 dc a4 e3 a1 c9 7a",
    outputs: ["3f fb 00 00 dc 2c 85 00 00 00 00 00", "3f fb 00 00 dc 2c 85 00 00 00 00 00", "3f fb 00 00 dc 2c 85 00 00 00 00 00", "3f fb 00 00 dc 2c 86 00 00 00 00 00"],
  },
  {
    name: "fetoxm1", selector: "08" as const,
    input: "40 01 00 00 bf b8 85 05 a2 a3 10 b6",
    outputs: ["40 07 00 00 c7 76 44 00 00 00 00 00", "40 07 00 00 c7 76 43 00 00 00 00 00", "40 07 00 00 c7 76 43 00 00 00 00 00", "40 07 00 00 c7 76 44 00 00 00 00 00"],
  },
  {
    name: "ftanh", selector: "09" as const,
    input: "3f fe 00 00 cb a8 d2 8c 33 e5 ad 93",
    outputs: ["3f fe 00 00 a9 5a 99 00 00 00 00 00", "3f fe 00 00 a9 5a 99 00 00 00 00 00", "3f fe 00 00 a9 5a 99 00 00 00 00 00", "3f fe 00 00 a9 5a 9a 00 00 00 00 00"],
  },
];
for (const item of rounding) {
  for (const [index, [fpcr, suffix]] of [["40", "nearest"], ["50", "zero"], ["60", "minus"], ["70", "plus"]].entries()) {
    serviceCases.push({
      name: `${item.name}_extended_source_single_${suffix}`, selector: item.selector,
      input: item.input, output: item.outputs[index], fpcr,
      fpsr: "00000008", operationFpsr: "00000208",
    });
  }
}
for (const item of [
  { name: "fsinh", selector: "02" as const, input: "40 00 00 00 da 26 cb 13 34 14 75 b5", output: "40 02 00 00 f1 85 d7 60 a2 94 38 00" },
  { name: "flognp1", selector: "06" as const, input: "40 01 00 00 9d b6 c0 e1 23 21 53 b8", output: "3f ff 00 00 e3 cf de 55 3b 23 a8 00" },
  { name: "fetoxm1", selector: "08" as const, input: "3f ff 00 00 a2 90 47 d7 1a 13 fb 8c", output: "40 00 00 00 a3 e6 a5 c3 4c ae c0 00" },
  { name: "ftanh", selector: "09" as const, input: "3f fb 00 00 e6 07 cf 58 1e 23 c4 1d", output: "3f fb 00 00 e5 11 6a 9d c0 cf d8 00" },
]) serviceCases.push({
  name: `${item.name}_extended_source_double_nearest`, selector: item.selector,
  input: item.input, output: item.output, fpcr: "80",
  fpsr: "00000008", operationFpsr: "00000208",
});
for (const [name, selector] of [["fsinh", "02"], ["flognp1", "06"], ["fetoxm1", "08"], ["ftanh", "09"]] as const) {
  serviceCases.push(
    { name: `${name}_positive_zero`, selector, input: x.positiveZero, output: x.positiveZero, fpsr: "04000000" },
    { name: `${name}_negative_zero`, selector, input: x.negativeZero, output: x.negativeZero, fpsr: "0c000000" },
  );
}
serviceCases.push(
  { name: "fsinh_positive_infinity", selector: "02", input: x.positiveInfinity, output: x.positiveInfinity, fpsr: "02000000" },
  { name: "fsinh_negative_infinity", selector: "02", input: x.negativeInfinity, output: x.negativeInfinity, fpsr: "0a000000" },
  { name: "flognp1_positive_infinity", selector: "06", input: x.positiveInfinity, output: x.positiveInfinity, fpsr: "02000000" },
  { name: "flognp1_negative_one_dz", selector: "06", input: x.negativeOne, output: x.negativeInfinity, fpsr: "0a000010", operationFpsr: "0a000410" },
  { name: "flognp1_less_than_negative_one_operr", selector: "06", input: x.negativeTwo, output: x.canonicalPositiveNan, fpsr: "01000080", operationFpsr: "01002080" },
  { name: "fetoxm1_positive_infinity", selector: "08", input: x.positiveInfinity, output: x.positiveInfinity, fpsr: "02000000" },
  { name: "fetoxm1_negative_infinity", selector: "08", input: x.negativeInfinity, output: x.negativeOne, fpsr: "08000000" },
  { name: "ftanh_positive_infinity", selector: "09", input: x.positiveInfinity, output: x.positiveOne, fpsr: "00000000" },
  { name: "ftanh_negative_infinity", selector: "09", input: x.negativeInfinity, output: x.negativeOne, fpsr: "08000000" },
  { name: "fsinh_negative_qnan_payload", selector: "02", input: x.negativeQuietNan, output: x.negativeQuietNan, fpsr: "09000000" },
  { name: "flognp1_signalling_nan_quiet", selector: "06", input: x.signallingNan, output: x.quietedNan, fpsr: "01000080", operationFpsr: "01004080" },
  { name: "fetoxm1_quiet_nan_payload", selector: "08", input: x.quietNan, output: x.quietNan, fpsr: "01000000" },
  { name: "ftanh_signalling_nan_quiet", selector: "09", input: x.signallingNan, output: x.quietedNan, fpsr: "01000080", operationFpsr: "01004080" },
  { name: "fsinh_extended_min_single_underflow", selector: "02", input: x.minimumSubnormal, output: x.positiveZero, fpcr: "40", fpsr: "04000028", operationFpsr: "04000a28" },
  { name: "flognp1_extended_min_single_underflow", selector: "06", input: x.minimumSubnormal, output: x.positiveZero, fpcr: "40", fpsr: "04000028", operationFpsr: "04000a28" },
  { name: "fetoxm1_extended_min_single_underflow", selector: "08", input: x.minimumSubnormal, output: x.positiveZero, fpcr: "40", fpsr: "04000028", operationFpsr: "04000a28" },
  { name: "ftanh_extended_min_single_underflow", selector: "09", input: x.minimumSubnormal, output: x.positiveZero, fpcr: "40", fpsr: "04000028", operationFpsr: "04000a28" },
  { name: "fsinh_fp7_self_alias", selector: "02", input: x.positiveZero, output: x.positiveZero, fpsr: "04000000", registerAlias: true },
  { name: "ftanh_fp7_self_alias", selector: "09", input: x.negativeZero, output: x.negativeZero, fpsr: "0c000000", registerAlias: true },
  { name: "fetoxm1_accrued_preserve", selector: "08", input: x.positiveZero, output: x.positiveZero, replayFpsr: "0455ff00", fpsr: "04550000" },
);
const strictCases = [
  { name: "fsinh_fp7_strict", extra: "4b82" },
  { name: "flognp1_fp7_strict", extra: "4b86" },
  { name: "fetoxm1_fp7_strict", extra: "4b88" },
  { name: "ftanh_fp7_strict", extra: "4b89" },
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

const diskDir = mkdtempSync(join(tmpdir(), "fpp-hyperbolic-log1p-disk-"));
const clone = spawnSync("bash", ["-c", [
  "set -euo pipefail", "source \"$1\"", "cow_clone \"$2\" \"$3/disk.img\" fpp-hyperbolic-log1p",
].join("\n"), "bash", cowLib, diskSource, diskDir], { encoding: "utf8" });
if (clone.status !== 0) {
  console.error(clone.stderr || "FPP_HYPERBOLIC_LOG1P_FAIL unable to create isolated disk clone");
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
    const td = mkdtempSync(join(tmpdir(), "fpp-hyperbolic-log1p-service-"));
    try {
      const pref = join(td, "prefs"); writePrefs(pref, disk);
      const directExtra = (0x4b80 | Number.parseInt(item.selector, 16)).toString(16).padStart(4, "0");
      const registerExtra = (0x1f80 | Number.parseInt(item.selector, 16)).toString(16).padStart(4, "0");
      const stream = item.registerAlias
        ? `F239 4B80 0000 9000 F200 ${registerExtra} F200 A800 F210 6B80 2C7C A6F1 0000`
        : `F239 ${directExtra} 0000 9000 F200 A800 F210 6B80 2C7C A6F1 0000`;
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
      const serviced = fallbackCount === (item.registerAlias ? 4 : 3) && !output.includes("Caught SIGSEGV");
      const operationFpsr = item.operationFpsr ?? item.fpsr;
      if (run.status === 0 && mem === expected && d0 === operationFpsr && a0 === "0000a000" && fpsr === item.fpsr && sr === "271f" && serviced) servicePass++;
      else {
        fail++;
        console.error(`FPP_HYPERBOLIC_LOG1P_FAIL case=${item.name} phase=service rc=${run.status} mem=${mem} want_mem=${expected} d0=${d0} want_d0=${operationFpsr} a0=${a0} fpsr=${fpsr} want_fpsr=${item.fpsr} sr=${sr} fallbacks=${fallbackCount}`);
      }
    } finally { rmSync(td, { recursive: true, force: true }); }
  }
  for (const item of selectedStrict) {
    const td = mkdtempSync(join(tmpdir(), "fpp-hyperbolic-log1p-strict-"));
    try {
      const pref = join(td, "prefs"); writePrefs(pref, disk);
      const run = spawnSync("timeout", ["-k", "5s", "30s", bin, "--config", pref], { encoding: "utf8", timeout: 35_000, env: {
        ...process.env, SDL_VIDEODRIVER: "x11", DISPLAY: display, HOME: td,
        B2_TEST_HEX: `F239 ${item.extra} 0000 9000 2C7C A6F0 0000`, B2_TEST_INIT: zeroInit,
        B2_TEST_MEMORY_BYTES: memoryBytes(0x9000, x.positiveOne), B2_TEST_DUMP: "1", B2_TEST_DUMP_FP: "1",
        B2_JIT_FORCE_TRANSLATE: "1", B2_TEST_TWO_PASS: "1", B2_TEST_SECOND_PC: "0x1000", B2_TEST_REPLAY_COUNT: "2", B2_TEST_FORCE_L2_RAM: "1", B2_JIT_STRICT_FULL: "1",
      }});
      const output = `${run.stdout ?? ""}${run.stderr ?? ""}`;
      const rejected = output.includes("strict full-JIT: opcode fallback pc=00001000 op=f239");
      const noNative = !output.includes("NATEXEC pc=00001000") && !output.includes("JIT_STRICT_SUMMARY ");
      const noSegv = !output.includes("Caught SIGSEGV");
      if (run.status !== 0 && rejected && noNative && noSegv) strictPass++;
      else {
        fail++;
        console.error(`FPP_HYPERBOLIC_LOG1P_FAIL case=${item.name} phase=strict rc=${run.status} rejected=${rejected ? 1 : 0} no_native=${noNative ? 1 : 0} no_segv=${noSegv ? 1 : 0}`);
      }
    } finally { rmSync(td, { recursive: true, force: true }); }
  }
} finally {
  spawnSync("bash", ["-c", "source \"$1\"; cow_release \"$2\"", "bash", cowLib, disk]);
  rmSync(diskDir, { recursive: true, force: true });
}
console.log(`FPP_HYPERBOLIC_LOG1P_MATRIX service_pass=${servicePass} strict_pass=${strictPass} fail=${fail} total=${servicePass + strictPass + fail}`);
const expectedService = process.env.CASE ? selectedService.length : 48;
const expectedStrict = process.env.CASE ? selectedStrict.length : 4;
process.exit(fail === 0 && servicePass === expectedService && strictPass === expectedStrict ? 0 : 1);
