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
  p2: "40 00 00 00 80 00 00 00 00 00 00 00", pinf: "7f ff 00 00 00 00 00 00 00 00 00 00",
  ninf: "ff ff 00 00 00 00 00 00 00 00 00 00", pio2: "3f ff 00 00 c9 0f da a2 21 68 c2 35",
  npio2: "bf ff 00 00 c9 0f da a2 21 68 c2 35", pnan: "7f ff 00 00 ff ff ff ff ff ff ff ff",
  qnan: "7f ff 00 00 c0 00 12 34 56 78 9a bc", nqnan: "ff ff 00 00 c0 00 12 34 56 78 9a bc",
  snan: "7f ff 00 00 80 00 12 34 56 78 9a bc", quieted: "7f ff 00 00 c0 00 12 34 56 78 9a bc",
  minsub: "00 00 00 00 00 00 00 00 00 00 00 01",
} as const;
type Selector = "0a" | "0c" | "0d";
type Case = { name: string; selector: Selector; input: string; output: string; fpsr: string; operationFpsr?: string; fpcr?: string; replayFpsr?: string; alias?: boolean };
const cases: Case[] = [];
const rounds = [
  { name: "fatan", selector: "0a" as const, input: "3f fd 00 00 e3 20 53 62 e1 78 2e b8", outputs: ["3f fd 00 00 d5 c5 b4 00 00 00 00 00", "3f fd 00 00 d5 c5 b3 00 00 00 00 00", "3f fd 00 00 d5 c5 b3 00 00 00 00 00", "3f fd 00 00 d5 c5 b4 00 00 00 00 00"] },
  { name: "fasin", selector: "0c" as const, input: "bf fe 00 00 97 41 7f 79 c6 5f 5f c3", outputs: ["bf fe 00 00 a1 d1 8a 00 00 00 00 00", "bf fe 00 00 a1 d1 89 00 00 00 00 00", "bf fe 00 00 a1 d1 8a 00 00 00 00 00", "bf fe 00 00 a1 d1 89 00 00 00 00 00"] },
  { name: "fatanh", selector: "0d" as const, input: "3f fe 00 00 f8 7a 25 d6 99 0b 44 b1", outputs: ["40 00 00 00 86 94 14 00 00 00 00 00", "40 00 00 00 86 94 14 00 00 00 00 00", "40 00 00 00 86 94 14 00 00 00 00 00", "40 00 00 00 86 94 15 00 00 00 00 00"] },
];
for (const item of rounds) for (const [i, [fpcr, suffix]] of [["40", "nearest"], ["50", "zero"], ["60", "minus"], ["70", "plus"]].entries()) cases.push({ name: `${item.name}_extended_source_single_${suffix}`, selector: item.selector, input: item.input, output: item.outputs[i], fpcr, fpsr: item.name === "fasin" ? "08000008" : "00000008", operationFpsr: item.name === "fasin" ? "08000208" : "00000208" });
for (const item of [
  { name: "fatan", selector: "0a" as const, input: "3f fe 00 00 f6 33 4c 9f 1c 60 bb 7e", output: "3f fe 00 00 c4 11 30 7b 9f 48 a0 00", fpsr: "00000008", operationFpsr: "00000208" },
  { name: "fasin", selector: "0c" as const, input: "3f fe 00 00 8d 32 e0 a4 35 7c f4 77", output: "3f fe 00 00 95 90 1f 50 86 4f 60 00", fpsr: "00000008", operationFpsr: "00000208" },
  { name: "fatanh", selector: "0d" as const, input: "bf fe 00 00 ad b6 c7 89 fa d5 8c 58", output: "bf fe 00 00 d3 92 d6 71 18 ce 70 00", fpsr: "08000008", operationFpsr: "08000208" },
]) cases.push({ ...item, name: `${item.name}_extended_source_double_nearest`, fpcr: "80" });
for (const [name, selector] of [["fatan", "0a"], ["fasin", "0c"], ["fatanh", "0d"]] as const) cases.push(
  { name: `${name}_positive_zero`, selector, input: x.pz, output: x.pz, fpsr: "04000000" },
  { name: `${name}_negative_zero`, selector, input: x.nz, output: x.nz, fpsr: "0c000000" },
);
cases.push(
  { name: "fatan_positive_infinity", selector: "0a", input: x.pinf, output: x.pio2, fpsr: "00000008", operationFpsr: "00000208" },
  { name: "fatan_negative_infinity", selector: "0a", input: x.ninf, output: x.npio2, fpsr: "08000008", operationFpsr: "08000208" },
  { name: "fasin_positive_one", selector: "0c", input: x.p1, output: x.pio2, fpsr: "00000008", operationFpsr: "00000208" },
  { name: "fasin_negative_one", selector: "0c", input: x.n1, output: x.npio2, fpsr: "08000008", operationFpsr: "08000208" },
  { name: "fasin_outside_domain_operr", selector: "0c", input: x.p2, output: x.pnan, fpsr: "01000080", operationFpsr: "01002080" },
  { name: "fatanh_positive_one_dz", selector: "0d", input: x.p1, output: x.pinf, fpsr: "02000010", operationFpsr: "02000410" },
  { name: "fatanh_negative_one_dz", selector: "0d", input: x.n1, output: x.ninf, fpsr: "0a000010", operationFpsr: "0a000410" },
  { name: "fatanh_outside_domain_operr", selector: "0d", input: x.p2, output: x.pnan, fpsr: "01000080", operationFpsr: "01002080" },
  { name: "fatan_negative_qnan_payload", selector: "0a", input: x.nqnan, output: x.nqnan, fpsr: "09000000" },
  { name: "fasin_signalling_nan_quiet", selector: "0c", input: x.snan, output: x.quieted, fpsr: "01000080", operationFpsr: "01004080" },
  { name: "fatanh_quiet_nan_payload", selector: "0d", input: x.qnan, output: x.qnan, fpsr: "01000000" },
  { name: "fatan_extended_min_single_underflow", selector: "0a", input: x.minsub, output: x.pz, fpcr: "40", fpsr: "04000028", operationFpsr: "04000a28" },
  { name: "fasin_extended_min_single_underflow", selector: "0c", input: x.minsub, output: x.pz, fpcr: "40", fpsr: "04000028", operationFpsr: "04000a28" },
  { name: "fatanh_extended_min_single_underflow", selector: "0d", input: x.minsub, output: x.pz, fpcr: "40", fpsr: "04000028", operationFpsr: "04000a28" },
  { name: "fatan_fp7_self_alias", selector: "0a", input: x.pz, output: x.pz, fpsr: "04000000", alias: true },
  { name: "fatanh_fp7_self_alias", selector: "0d", input: x.nz, output: x.nz, fpsr: "0c000000", alias: true },
  { name: "fasin_accrued_preserve", selector: "0c", input: x.pz, output: x.pz, replayFpsr: "0455ff00", fpsr: "04550000" },
);
const strict = [{ name: "fatan_fp7_strict", extra: "4b8a" }, { name: "fasin_fp7_strict", extra: "4b8c" }, { name: "fatanh_fp7_strict", extra: "4b8d" }] as const;
function bytes(addr: number, value: string) { return value.split(/\s+/).map((b, i) => `${(addr + i).toString(16)} ${b}`).join(" "); }
function prefs(path: string, disk: string) { writeFileSync(path, [`rom ${rom}`, `disk ${disk}`, "ramsize 8388608", "modelid 14", "cpu 4", "fpu true", "jit true", "jitfpu true", "jitcachesize 8192", "screen win/640/480", "nosound true", "nocdrom true", "nogui true", "ignoresegv true", ""].join("\n")); }
const diskDir = mkdtempSync(join(tmpdir(), "fpp-inverse-disk-"));
const clone = spawnSync("bash", ["-c", "set -euo pipefail\nsource \"$1\"\ncow_clone \"$2\" \"$3/disk.img\" fpp-inverse", "bash", cowLib, diskSource, diskDir], { encoding: "utf8" });
if (clone.status !== 0) { console.error(clone.stderr || "FPP_INVERSE_FAIL clone"); rmSync(diskDir, { recursive: true, force: true }); process.exit(1); }
const disk = clone.stdout.trim().split("\n").at(-1)!;
const selectedCases = process.env.CASE ? cases.filter((x) => x.name === process.env.CASE) : cases;
const selectedStrict = process.env.CASE ? strict.filter((x) => x.name === process.env.CASE) : strict;
let servicePass = 0, strictPass = 0, fail = 0;
try {
  if (!selectedCases.length && !selectedStrict.length) throw new Error(`unknown CASE=${process.env.CASE}`);
  for (const item of selectedCases) {
    const td = mkdtempSync(join(tmpdir(), "fpp-inverse-service-"));
    try {
      const pref = join(td, "prefs"); prefs(pref, disk);
      const de = (0x4b80 | parseInt(item.selector, 16)).toString(16), re = (0x1f80 | parseInt(item.selector, 16)).toString(16);
      const stream = item.alias ? `F239 4B80 0000 9000 F200 ${re} F200 A800 F210 6B80 2C7C A6EF 0000` : `F239 ${de} 0000 9000 F200 A800 F210 6B80 2C7C A6EF 0000`;
      const guard = `9ffe a5 9fff 5a ${bytes(0xa000, x.pz)} a00c 3c a00d c3`;
      const run = spawnSync("timeout", ["-k", "5s", "30s", bin, "--config", pref], { encoding: "utf8", timeout: 35000, env: { ...process.env, SDL_VIDEODRIVER: "x11", DISPLAY: display, HOME: td, B2_TEST_HEX: stream, B2_TEST_INIT: zeroInit, B2_TEST_MEMORY_BYTES: `${bytes(0x9000, item.input)} ${guard}`, B2_TEST_MEMDUMP: "0x9ffe:16", B2_TEST_DUMP: "1", B2_TEST_DUMP_FP: "1", B2_JIT_FORCE_TRANSLATE: "1", B2_TEST_TWO_PASS: "1", B2_TEST_SECOND_PC: "0x1000", B2_TEST_REPLAY_COUNT: "2", B2_TEST_FORCE_L2_RAM: "1", B2_TEST_REPLAY_FPCR: item.fpcr ?? "0", B2_TEST_REPLAY_FPSR: item.replayFpsr ?? "0" } });
      const output = `${run.stdout ?? ""}${run.stderr ?? ""}`, dump = output.match(/^REGDUMP:.*$/m)?.[0], mem = output.match(/^MEMDUMP [^:]+:(.*)$/m)?.[1].trim().toLowerCase();
      const expected = `a5 5a ${item.output} 3c c3`, d0 = dump?.match(/ D0=([0-9a-f]+)/i)?.[1].toLowerCase(), a0 = dump?.match(/ A0=([0-9a-f]+)/i)?.[1].toLowerCase(), fpsr = dump?.match(/ FPSR=([0-9a-f]+)/i)?.[1].toLowerCase(), sr = dump?.match(/ SR=([0-9a-f]+)/i)?.[1].toLowerCase(), fallbackCount = (output.match(/JIT_FALLBACK/g) ?? []).length;
      if (run.status === 0 && mem === expected && d0 === (item.operationFpsr ?? item.fpsr) && a0 === "0000a000" && fpsr === item.fpsr && sr === "271f" && fallbackCount === (item.alias ? 4 : 3) && !output.includes("Caught SIGSEGV")) servicePass++; else { fail++; console.error(`FPP_INVERSE_FAIL case=${item.name} rc=${run.status} mem=${mem} want=${expected} d0=${d0} want_d0=${item.operationFpsr ?? item.fpsr} fpsr=${fpsr} want_fpsr=${item.fpsr} fallbacks=${fallbackCount}`); }
    } finally { rmSync(td, { recursive: true, force: true }); }
  }
  for (const item of selectedStrict) {
    const td = mkdtempSync(join(tmpdir(), "fpp-inverse-strict-"));
    try { const pref = join(td, "prefs"); prefs(pref, disk); const run = spawnSync("timeout", ["-k", "5s", "30s", bin, "--config", pref], { encoding: "utf8", timeout: 35000, env: { ...process.env, SDL_VIDEODRIVER: "x11", DISPLAY: display, HOME: td, B2_TEST_HEX: `F239 ${item.extra} 0000 9000 2C7C A6EE 0000`, B2_TEST_INIT: zeroInit, B2_TEST_MEMORY_BYTES: bytes(0x9000, x.p1), B2_TEST_DUMP: "1", B2_JIT_FORCE_TRANSLATE: "1", B2_TEST_TWO_PASS: "1", B2_TEST_SECOND_PC: "0x1000", B2_TEST_REPLAY_COUNT: "2", B2_TEST_FORCE_L2_RAM: "1", B2_JIT_STRICT_FULL: "1" } }); const output = `${run.stdout ?? ""}${run.stderr ?? ""}`; if (run.status !== 0 && output.includes("strict full-JIT: opcode fallback pc=00001000 op=f239") && !output.includes("NATEXEC pc=00001000") && !output.includes("JIT_STRICT_SUMMARY ") && !output.includes("Caught SIGSEGV")) strictPass++; else { fail++; console.error(`FPP_INVERSE_FAIL strict=${item.name} rc=${run.status}`); } } finally { rmSync(td, { recursive: true, force: true }); }
  }
} finally { spawnSync("bash", ["-c", "source \"$1\"; cow_release \"$2\"", "bash", cowLib, disk]); rmSync(diskDir, { recursive: true, force: true }); }
console.log(`FPP_INVERSE_MATRIX service_pass=${servicePass} strict_pass=${strictPass} fail=${fail} total=${servicePass + strictPass + fail}`);
const expectedService = process.env.CASE ? selectedCases.length : 38, expectedStrict = process.env.CASE ? selectedStrict.length : 3;
process.exit(fail === 0 && servicePass === expectedService && strictPass === expectedStrict ? 0 : 1);
