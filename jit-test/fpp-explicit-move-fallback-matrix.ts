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

const fsPositiveHalf = "3f ff 00 00 80 00 00 80 00 00 00 00"; // 1 + 2^-24
const fsNegativeHalf = "bf ff 00 00 80 00 00 80 00 00 00 00"; // -1 - 2^-24
const fdPositiveHalf = "3f ff 00 00 80 00 00 00 00 00 04 00"; // 1 + 2^-53
const positiveOne = "3f ff 00 00 80 00 00 00 00 00 00 00";
const positiveSingleNext = "3f ff 00 00 80 00 01 00 00 00 00 00";
const negativeOne = "bf ff 00 00 80 00 00 00 00 00 00 00";
const negativeSingleNext = "bf ff 00 00 80 00 01 00 00 00 00 00";
const positiveDoubleNext = "3f ff 00 00 80 00 00 00 00 00 08 00";

type ServiceCase = { name: string; op: "0440" | "0444"; input: string; output: string; fpcr: string; fpsr: string };
const serviceCases: ServiceCase[] = [
  { name: "fsmove_positive_half_nearest", op: "0440", input: fsPositiveHalf, output: positiveOne, fpcr: "0", fpsr: "00000008" },
  { name: "fsmove_positive_half_zero", op: "0440", input: fsPositiveHalf, output: positiveOne, fpcr: "10", fpsr: "00000008" },
  { name: "fsmove_positive_half_minus", op: "0440", input: fsPositiveHalf, output: positiveOne, fpcr: "20", fpsr: "00000008" },
  { name: "fsmove_positive_half_plus", op: "0440", input: fsPositiveHalf, output: positiveSingleNext, fpcr: "30", fpsr: "00000008" },
  { name: "fsmove_negative_half_nearest", op: "0440", input: fsNegativeHalf, output: negativeOne, fpcr: "0", fpsr: "08000008" },
  { name: "fsmove_negative_half_zero", op: "0440", input: fsNegativeHalf, output: negativeOne, fpcr: "10", fpsr: "08000008" },
  { name: "fsmove_negative_half_minus", op: "0440", input: fsNegativeHalf, output: negativeSingleNext, fpcr: "20", fpsr: "08000008" },
  { name: "fsmove_negative_half_plus", op: "0440", input: fsNegativeHalf, output: negativeOne, fpcr: "30", fpsr: "08000008" },
  { name: "fdmove_positive_half_nearest", op: "0444", input: fdPositiveHalf, output: positiveOne, fpcr: "0", fpsr: "00000008" },
  { name: "fdmove_positive_half_plus", op: "0444", input: fdPositiveHalf, output: positiveDoubleNext, fpcr: "30", fpsr: "00000008" },
  { name: "fdmove_maximum_extended_overflow", op: "0444", input: "7f fe 00 00 ff ff ff ff ff ff ff ff", output: "7f ff 00 00 00 00 00 00 00 00 00 00", fpcr: "0", fpsr: "02000048" },
  { name: "fsmove_positive_infinity_exact", op: "0440", input: "7f ff 00 00 00 00 00 00 00 00 00 00", output: "7f ff 00 00 00 00 00 00 00 00 00 00", fpcr: "0", fpsr: "02000000" },
  { name: "fdmove_negative_zero_exact", op: "0444", input: "80 00 00 00 00 00 00 00 00 00 00 00", output: "80 00 00 00 00 00 00 00 00 00 00 00", fpcr: "0", fpsr: "0c000000" },
];
const strictCases = [
  { name: "fsmove_fp7_self_alias_max_fields", setup: "F23C 4780 3F80 0000", op: "F200 1FC0", anchor: 0x1008 },
  { name: "fdmove_fp7_self_alias_max_fields", setup: "F23C 4780 3F80 0000", op: "F200 1FC4", anchor: 0x1008 },
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

const diskDir = mkdtempSync(join(tmpdir(), "fpp-explicit-move-fallback-disk-"));
const clone = spawnSync("bash", ["-c", ["set -euo pipefail", "source \"$1\"", "cow_clone \"$2\" \"$3/disk.img\" fpp-explicit-move-fallback"].join("\n"), "bash", cowLib, diskSource, diskDir], { encoding: "utf8" });
if (clone.status !== 0) { console.error(clone.stderr || "FPP_EXPLICIT_MOVE_FALLBACK_FAIL unable to create isolated disk clone"); process.exit(1); }
const disk = clone.stdout.trim().split("\n").at(-1)!;
const selectedService = process.env.CASE ? serviceCases.filter((item) => item.name === process.env.CASE) : serviceCases;
const selectedStrict = process.env.CASE ? strictCases.filter((item) => item.name === process.env.CASE) : strictCases;
if (selectedService.length + selectedStrict.length === 0) throw new Error(`unknown CASE=${process.env.CASE}`);
let servicePass = 0, strictPass = 0, fail = 0;
try {
  for (const item of selectedService) {
    const td = mkdtempSync(join(tmpdir(), "fpp-explicit-move-service-"));
    try {
      const pref = join(td, "prefs"); writePrefs(pref, disk);
      const guard = "9ffe a5 9fff 5a a000 00 a001 00 a002 00 a003 00 a004 00 a005 00 a006 00 a007 00 a008 00 a009 00 a00a 00 a00b 00 a00c 3c a00d c3";
      // FMOVE.X ($9000).L,FP1; FSMOVE/FDMOVE FP1,FP0; FMOVE.X FP0,(A0)
      const run = spawnSync("timeout", ["-k", "5s", "30s", bin, "--config", pref], { encoding: "utf8", timeout: 35_000, env: {
        ...process.env, SDL_VIDEODRIVER: "x11", DISPLAY: display, HOME: td,
        B2_TEST_HEX: `F239 4880 0000 9000 F200 ${item.op} F210 6800 2C7C A6FB 0000`, B2_TEST_INIT: zeroInit,
        B2_TEST_MEMORY_BYTES: `${memoryBytes(0x9000, item.input)} ${guard}`, B2_TEST_MEMDUMP: "0x9ffe:16", B2_TEST_DUMP: "1", B2_TEST_DUMP_FP: "1",
        B2_JIT_FORCE_TRANSLATE: "1", B2_TEST_TWO_PASS: "1", B2_TEST_SECOND_PC: "0x1000", B2_TEST_REPLAY_COUNT: "2", B2_TEST_FORCE_L2_RAM: "1", B2_TEST_REPLAY_FPCR: item.fpcr,
      }});
      const output = `${run.stdout ?? ""}${run.stderr ?? ""}`, dump = output.match(/^REGDUMP:.*$/m)?.[0];
      const mem = output.match(/^MEMDUMP [^:]+:(.*)$/m)?.[1].trim().toLowerCase();
      const expected = `a5 5a ${item.output} 3c c3`, a0 = dump?.match(/ A0=([0-9a-f]+)/i)?.[1].toLowerCase();
      const fpsr = dump?.match(/ FPSR=([0-9a-f]+)/i)?.[1].toLowerCase(), sr = dump?.match(/ SR=([0-9a-f]+)/i)?.[1].toLowerCase();
      const serviced = (output.match(/JIT_FALLBACK/g) ?? []).length >= 3 && !output.includes("Caught SIGSEGV");
      if (run.status === 0 && mem === expected && a0 === "0000a000" && fpsr === item.fpsr && sr === "271f" && serviced) servicePass++;
      else { fail++; console.error(`FPP_EXPLICIT_MOVE_FALLBACK_FAIL case=${item.name} phase=service rc=${run.status} mem=${mem} want_mem=${expected} a0=${a0} fpsr=${fpsr} want_fpsr=${item.fpsr} sr=${sr} serviced=${serviced ? 1 : 0}`); }
    } finally { rmSync(td, { recursive: true, force: true }); }
  }
  for (const item of selectedStrict) {
    const td = mkdtempSync(join(tmpdir(), "fpp-explicit-move-strict-"));
    try {
      const pref = join(td, "prefs"); writePrefs(pref, disk);
      const run = spawnSync("timeout", ["-k", "5s", "30s", bin, "--config", pref], { encoding: "utf8", timeout: 35_000, env: {
        ...process.env, SDL_VIDEODRIVER: "x11", DISPLAY: display, HOME: td,
        B2_TEST_HEX: `${item.setup} ${item.op} 2C7C A6FC 0000`, B2_TEST_INIT: zeroInit, B2_TEST_DUMP: "1", B2_TEST_DUMP_FP: "1",
        B2_JIT_FORCE_TRANSLATE: "1", B2_TEST_TWO_PASS: "1", B2_TEST_SECOND_PC: `0x${item.anchor.toString(16)}`, B2_TEST_REPLAY_COUNT: "2", B2_TEST_FORCE_L2_RAM: "1", B2_JIT_STRICT_FULL: "1",
      }});
      const output = `${run.stdout ?? ""}${run.stderr ?? ""}`;
      const rejected = output.includes("strict full-JIT: opcode fallback");
      const noNative = !output.includes(`NATEXEC pc=${item.anchor.toString(16).padStart(8, "0")}`) && !output.includes("JIT_STRICT_SUMMARY ");
      const noSegv = !output.includes("Caught SIGSEGV");
      if (run.status !== 0 && rejected && noNative && noSegv) strictPass++;
      else { fail++; console.error(`FPP_EXPLICIT_MOVE_FALLBACK_FAIL case=${item.name} phase=strict rc=${run.status} rejected=${rejected ? 1 : 0} no_native=${noNative ? 1 : 0} no_segv=${noSegv ? 1 : 0}`); }
    } finally { rmSync(td, { recursive: true, force: true }); }
  }
} finally {
  spawnSync("bash", ["-c", "source \"$1\"; cow_release \"$2\"", "bash", cowLib, disk]); rmSync(diskDir, { recursive: true, force: true });
}
console.log(`FPP_EXPLICIT_MOVE_FALLBACK_MATRIX service_pass=${servicePass} strict_pass=${strictPass} fail=${fail} total=${servicePass + strictPass + fail}`);
const expectedService = process.env.CASE ? selectedService.length : 13, expectedStrict = process.env.CASE ? selectedStrict.length : 2;
process.exit(fail === 0 && servicePass === expectedService && strictPass === expectedStrict ? 0 : 1);
