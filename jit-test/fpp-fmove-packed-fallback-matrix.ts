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

type ServiceCase = { name: string; input: string; output: string; extra: string; fpsr: string; d1?: number };
const serviceCases: ServiceCase[] = [
  { name: "static_17_positive", input: "00 00 00 01 23 45 67 89 01 23 45 67", output: "00 00 00 01 23 45 67 89 01 23 45 67", extra: "6C11", fpsr: "00000208" },
  { name: "dynamic_17_positive", input: "00 00 00 01 23 45 67 89 01 23 45 67", output: "00 00 00 01 23 45 67 89 01 23 45 67", extra: "7C10", fpsr: "00000208", d1: 17 },
  { name: "static_5_rounding", input: "00 00 00 01 23 45 67 89 01 23 45 67", output: "00 00 00 01 23 46 00 00 00 00 00 00", extra: "6C05", fpsr: "00000208" },
  { name: "dynamic_5_rounding", input: "00 00 00 01 23 45 67 89 01 23 45 67", output: "00 00 00 01 23 46 00 00 00 00 00 00", extra: "7C10", fpsr: "00000208", d1: 5 },
  { name: "negative_mantissa_negative_exponent", input: "c0 02 00 09 87 65 43 21 09 87 65 43", output: "c0 02 00 09 87 65 43 21 09 87 65 43", extra: "6C11", fpsr: "08000208" },
  { name: "positive_zero", input: "00 00 00 00 00 00 00 00 00 00 00 00", output: "00 00 00 00 00 00 00 00 00 00 00 00", extra: "6C11", fpsr: "04000000" },
  { name: "negative_zero", input: "80 00 00 00 00 00 00 00 00 00 00 00", output: "80 00 00 00 00 00 00 00 00 00 00 00", extra: "6C11", fpsr: "0c000000" },
  { name: "positive_infinity", input: "7f ff 00 00 00 00 00 00 00 00 00 00", output: "7f ff 00 00 00 00 00 00 00 00 00 00", extra: "6C11", fpsr: "02000000" },
  { name: "negative_infinity", input: "ff ff 00 00 00 00 00 00 00 00 00 00", output: "ff ff 00 00 00 00 00 00 00 00 00 00", extra: "6C11", fpsr: "0a000000" },
];
const strictCases = [
  { name: "immediate_source", stream: "F23C 4C00 0000 0001 2345 6789 0123 4567", anchor: 0x1000 },
  { name: "postinc_source", stream: "F218 4C00", anchor: 0x1000, memory: serviceCases[0].input },
  { name: "postinc_static_destination", stream: "F23C 4400 3F80 0000 F218 6C11", anchor: 0x1008 },
  { name: "predec_dynamic_destination", stream: "F23C 4400 3F80 0000 F220 7C10", anchor: 0x1008, init: "0 00000011 0 0 0 0 0 0 0000a00c 0 0 0 0 0 0 007fe000 271f" },
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

const diskDir = mkdtempSync(join(tmpdir(), "fpp-fmove-packed-fallback-disk-"));
const clone = spawnSync("bash", ["-c", ["set -euo pipefail", "source \"$1\"", "cow_clone \"$2\" \"$3/disk.img\" fpp-fmove-packed-fallback"].join("\n"), "bash", cowLib, diskSource, diskDir], { encoding: "utf8" });
if (clone.status !== 0) { console.error(clone.stderr || "FPP_FMOVE_PACKED_FALLBACK_FAIL unable to create isolated disk clone"); process.exit(1); }
const disk = clone.stdout.trim().split("\n").at(-1)!;
const selectedService = process.env.CASE ? serviceCases.filter((item) => item.name === process.env.CASE) : serviceCases;
const selectedStrict = process.env.CASE ? strictCases.filter((item) => item.name === process.env.CASE) : strictCases;
if (selectedService.length + selectedStrict.length === 0) throw new Error(`unknown CASE=${process.env.CASE}`);
let servicePass = 0, strictPass = 0, fail = 0;
try {
  for (const item of selectedService) {
    const td = mkdtempSync(join(tmpdir(), "fpp-fmove-packed-service-"));
    try {
      const pref = join(td, "prefs"); writePrefs(pref, disk);
      const init = zeroInit.split(" "); if (item.d1 !== undefined) init[1] = item.d1.toString(16).padStart(8, "0");
      const input = memoryBytes(0x9000, item.input);
      const guard = "9ffe a5 9fff 5a a000 00 a001 00 a002 00 a003 00 a004 00 a005 00 a006 00 a007 00 a008 00 a009 00 a00a 00 a00b 00 a00c 3c a00d c3";
      const run = spawnSync("timeout", ["-k", "5s", "30s", bin, "--config", pref], { encoding: "utf8", timeout: 35_000, env: {
        ...process.env, SDL_VIDEODRIVER: "x11", DISPLAY: display, HOME: td,
        B2_TEST_HEX: `F239 4C00 0000 9000 F210 ${item.extra} 2C7C A6F9 0000`, B2_TEST_INIT: init.join(" "),
        B2_TEST_MEMORY_BYTES: `${input} ${guard}`, B2_TEST_MEMDUMP: "0x9ffe:16", B2_TEST_DUMP: "1", B2_TEST_DUMP_FP: "1",
        B2_JIT_FORCE_TRANSLATE: "1", B2_TEST_TWO_PASS: "1", B2_TEST_SECOND_PC: "0x1000", B2_TEST_REPLAY_COUNT: "2", B2_TEST_FORCE_L2_RAM: "1",
      }});
      const output = `${run.stdout ?? ""}${run.stderr ?? ""}`, dump = output.match(/^REGDUMP:.*$/m)?.[0];
      const mem = output.match(/^MEMDUMP [^:]+:(.*)$/m)?.[1].trim().toLowerCase();
      const expected = `a5 5a ${item.output.toLowerCase()} 3c c3`, a0 = dump?.match(/ A0=([0-9a-f]+)/i)?.[1].toLowerCase();
      const d1 = dump?.match(/ D1=([0-9a-f]+)/i)?.[1].toLowerCase(), sr = dump?.match(/ SR=([0-9a-f]+)/i)?.[1].toLowerCase();
      const fpsr = dump?.match(/ FPSR=([0-9a-f]+)/i)?.[1].toLowerCase();
      const d1ok = item.d1 === undefined || d1 === item.d1.toString(16).padStart(8, "0");
      const serviced = (output.match(/JIT_FALLBACK/g) ?? []).length >= 2 && !output.includes("Caught SIGSEGV");
      if (run.status === 0 && mem === expected && a0 === "0000a000" && d1ok && sr === "271f" && fpsr === item.fpsr && serviced) servicePass++;
      else { fail++; console.error(`FPP_FMOVE_PACKED_FALLBACK_FAIL case=${item.name} phase=service rc=${run.status} mem=${mem} want_mem=${expected} a0=${a0} d1=${d1} d1ok=${d1ok ? 1 : 0} sr=${sr} fpsr=${fpsr} want_fpsr=${item.fpsr} serviced=${serviced ? 1 : 0}`); }
    } finally { rmSync(td, { recursive: true, force: true }); }
  }
  for (const item of selectedStrict) {
    const td = mkdtempSync(join(tmpdir(), "fpp-fmove-packed-strict-"));
    try {
      const pref = join(td, "prefs"); writePrefs(pref, disk);
      const run = spawnSync("timeout", ["-k", "5s", "30s", bin, "--config", pref], { encoding: "utf8", timeout: 35_000, env: {
        ...process.env, SDL_VIDEODRIVER: "x11", DISPLAY: display, HOME: td,
        B2_TEST_HEX: `${item.stream} 2C7C A6FA 0000`, B2_TEST_INIT: item.init ?? zeroInit,
        B2_TEST_MEMORY_BYTES: item.memory ? memoryBytes(0xa000, item.memory) : "a000 a5 a001 5a", B2_TEST_DUMP: "1", B2_TEST_DUMP_FP: "1",
        B2_JIT_FORCE_TRANSLATE: "1", B2_TEST_TWO_PASS: "1", B2_TEST_SECOND_PC: `0x${item.anchor.toString(16)}`, B2_TEST_REPLAY_COUNT: "2", B2_TEST_FORCE_L2_RAM: "1", B2_JIT_STRICT_FULL: "1",
      }});
      const output = `${run.stdout ?? ""}${run.stderr ?? ""}`;
      const rejected = output.includes("strict full-JIT: opcode fallback");
      const noNative = !output.includes(`NATEXEC pc=${item.anchor.toString(16).padStart(8, "0")}`) && !output.includes("JIT_STRICT_SUMMARY ");
      const noSegv = !output.includes("Caught SIGSEGV");
      if (run.status !== 0 && rejected && noNative && noSegv) strictPass++;
      else { fail++; console.error(`FPP_FMOVE_PACKED_FALLBACK_FAIL case=${item.name} phase=strict rc=${run.status} rejected=${rejected ? 1 : 0} no_native=${noNative ? 1 : 0} no_segv=${noSegv ? 1 : 0}`); }
    } finally { rmSync(td, { recursive: true, force: true }); }
  }
} finally {
  spawnSync("bash", ["-c", "source \"$1\"; cow_release \"$2\"", "bash", cowLib, disk]); rmSync(diskDir, { recursive: true, force: true });
}
console.log(`FPP_FMOVE_PACKED_FALLBACK_MATRIX service_pass=${servicePass} strict_pass=${strictPass} fail=${fail} total=${servicePass + strictPass + fail}`);
const expectedService = process.env.CASE ? selectedService.length : 9, expectedStrict = process.env.CASE ? selectedStrict.length : 4;
process.exit(fail === 0 && servicePass === expectedService && strictPass === expectedStrict ? 0 : 1);
