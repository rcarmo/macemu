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
const baseRegs = [
  "11111111", "22222222", "33333333", "44444444", "55555555", "66666666", "77777777", "88888888",
  "00009000", "99999999", "aaaaaaaa", "bbbbbbbb", "cccccccc", "dddddddd", "eeeeeeee", "00009000",
];
const fpcr = "deadffb0", fpsr = "abcdefab", fpiar = "cafebabe";
const representedFpcr = "0000ffb0", representedFpsr = "0bcdefa8";
const all = "00 00 ff b0 0b cd ef a8 ca fe ba be";
const sparse = "00 00 ff b0 ca fe ba be";
const inputAll = "12 34 ff b0 8b cd ef ab ca fe ba be";
const inputSparse = "12 34 ff b0 fe dc ba 98";

type Case = {
  name: string;
  stream: string;
  opcode: string;
  address: number;
  before: string;
  after: string;
  a0?: string;
  a7?: string;
  expected?: Record<string, string>;
};
const seed = "F23C 8400 CAFE BABE";
const nops = "4E71 4E71 4E71 4E71";
const readback = "F201 B000 F202 A800 F203 A400";
const cases: Case[] = [
  { name: "to_aind_all_order", stream: `${seed} F210 BC00`, opcode: "f210", address: 0x9000, before: "11 22 33 44 55 66 77 88 99 aa bb cc", after: all },
  { name: "to_aind_sparse_order", stream: `${seed} F210 B400`, opcode: "f210", address: 0x9000, before: "11 22 33 44 55 66 77 88", after: sparse },
  { name: "to_postinc_a7_all", stream: `${seed} F21F BC00`, opcode: "f21f", address: 0x9000, before: "11 22 33 44 55 66 77 88 99 aa bb cc", after: all, a7: "0000900c" },
  { name: "to_predec_a7_all", stream: `${seed} F227 BC00`, opcode: "f227", address: 0x9000, before: "11 22 33 44 55 66 77 88 99 aa bb cc", after: all, a7: "00009000" },
  { name: "to_d16_a0_all", stream: `${seed} F228 BC00 0010`, opcode: "f228", address: 0x9010, before: "11 22 33 44 55 66 77 88 99 aa bb cc", after: all },
  { name: "to_absw_all", stream: `${seed} F238 BC00 7000`, opcode: "f238", address: 0x7000, before: "11 22 33 44 55 66 77 88 99 aa bb cc", after: all },
  { name: "to_absl_all", stream: `${seed} F239 BC00 0000 9020`, opcode: "f239", address: 0x9020, before: "11 22 33 44 55 66 77 88 99 aa bb cc", after: all },
  { name: "from_aind_all_order", stream: `${nops} F210 9C00 ${readback}`, opcode: "f210", address: 0x9000, before: inputAll, after: inputAll, expected: { D1: representedFpcr, D2: representedFpsr, D3: fpiar } },
  { name: "from_aind_sparse_order", stream: `${nops} F210 9400 F201 B000 F203 A400`, opcode: "f210", address: 0x9000, before: inputSparse, after: inputSparse, expected: { D1: representedFpcr, D3: "fedcba98" } },
  { name: "from_postinc_a7_all", stream: `${nops} F21F 9C00 ${readback}`, opcode: "f21f", address: 0x9000, before: inputAll, after: inputAll, a7: "0000900c", expected: { D1: representedFpcr, D2: representedFpsr, D3: fpiar } },
  { name: "from_predec_a7_all", stream: `${nops} F227 9C00 ${readback}`, opcode: "f227", address: 0x9000, before: inputAll, after: inputAll, a7: "00009000", expected: { D1: representedFpcr, D2: representedFpsr, D3: fpiar } },
  { name: "from_d16_a0_all", stream: `${nops} F228 9C00 0010 ${readback}`, opcode: "f228", address: 0x9010, before: inputAll, after: inputAll, expected: { D1: representedFpcr, D2: representedFpsr, D3: fpiar } },
  { name: "from_absw_all", stream: `${nops} F238 9C00 7000 ${readback}`, opcode: "f238", address: 0x7000, before: inputAll, after: inputAll, expected: { D1: representedFpcr, D2: representedFpsr, D3: fpiar } },
  { name: "from_absl_all", stream: `${nops} F239 9C00 0000 9020 ${readback}`, opcode: "f239", address: 0x9020, before: inputAll, after: inputAll, expected: { D1: representedFpcr, D2: representedFpsr, D3: fpiar } },
  { name: "from_pc_d16_all", stream: `${nops} F23A 9C00 7FF4 ${readback}`, opcode: "f23a", address: 0x9000, before: inputAll, after: inputAll, expected: { D1: representedFpcr, D2: representedFpsr, D3: fpiar } },
];
const strict = [
  { name: "to_aind_all_strict", stream: "F210 BC00 2C7C A6C1 0001", opcode: "f210" },
  { name: "from_predec_all_strict", stream: "F220 9C00 2C7C A6C1 0002", opcode: "f220" },
  { name: "from_pc_d16_strict", stream: "F23A 9C00 0004 2C7C A6C1 0003", opcode: "f23a" },
] as const;
function bytes(address: number, value: string) { return value.split(/\s+/).map((byte, i) => `${(address + i).toString(16)} ${byte}`).join(" "); }
function prefs(path: string, disk: string) { writeFileSync(path, [`rom ${rom}`, `disk ${disk}`, "ramsize 8388608", "modelid 14", "cpu 4", "fpu true", "jit true", "jitfpu true", "jitcachesize 8192", "screen win/640/480", "nosound true", "nocdrom true", "nogui true", "ignoresegv true", ""].join("\n")); }
function initFor(item: Case) { const regs = [...baseRegs]; if (item.name.includes("predec")) regs[15] = "0000900c"; return `${regs.join(" ")} 271f`; }
function field(dump: string | undefined, name: string) { return dump?.match(new RegExp(` ${name}=([0-9a-f]+)`, "i"))?.[1].toLowerCase(); }
const diskDir = mkdtempSync(join(tmpdir(), "fpp-control-memory-basic-disk-"));
const clone = spawnSync("bash", ["-c", "set -euo pipefail\nsource \"$1\"\ncow_clone \"$2\" \"$3/disk.img\" fpp-control-memory-basic", "bash", cowLib, diskSource, diskDir], { encoding: "utf8" });
if (clone.status !== 0) { console.error(clone.stderr || "FPP_CONTROL_MEMORY_BASIC_FAIL clone"); rmSync(diskDir, { recursive: true, force: true }); process.exit(1); }
const disk = clone.stdout.trim().split("\n").at(-1)!;
const selected = process.env.CASE ? cases.filter((item) => item.name === process.env.CASE) : cases;
const selectedStrict = process.env.CASE ? strict.filter((item) => item.name === process.env.CASE) : strict;
let servicePass = 0, strictPass = 0, fail = 0;
try {
  if (!selected.length && !selectedStrict.length) throw new Error(`unknown CASE=${process.env.CASE}`);
  for (const item of selected) {
    const td = mkdtempSync(join(tmpdir(), "fpp-control-memory-basic-service-"));
    try {
      prefs(join(td, "prefs"), disk);
      const guardAddress = item.address - 2, dumpLength = item.before.split(/\s+/).length + 4;
      const run = spawnSync("timeout", ["-k", "5s", "30s", bin, "--config", join(td, "prefs")], { encoding: "utf8", timeout: 35000, env: {
        ...process.env, SDL_VIDEODRIVER: "x11", DISPLAY: display, HOME: td,
        B2_TEST_HEX: `${item.stream} 2C7C A6C1 1000`, B2_TEST_INIT: initFor(item),
        B2_TEST_MEMORY_BYTES: `${bytes(guardAddress, "a5 5a")} ${bytes(item.address, item.before)} ${bytes(item.address + item.before.split(/\s+/).length, "3c c3")}`,
        B2_TEST_MEMDUMP: `0x${guardAddress.toString(16)}:${dumpLength}`, B2_TEST_DUMP: "1",
        B2_JIT_FORCE_TRANSLATE: "1", B2_TEST_TWO_PASS: "1", B2_TEST_SECOND_PC: "0x1008", B2_TEST_REPLAY_COUNT: "2", B2_TEST_FORCE_L2_RAM: "1",
        B2_TEST_REPLAY_FPCR: fpcr, B2_TEST_REPLAY_FPSR: fpsr, B2_NATIVE_ASSERT_PC: "0x1008",
      }});
      const output = `${run.stdout ?? ""}${run.stderr ?? ""}`, dump = output.match(/^REGDUMP:.*$/m)?.[0];
      const memory = output.match(/^MEMDUMP [^:]+:(.*)$/m)?.[1].trim().toLowerCase();
      const wantMemory = `a5 5a ${item.after} 3c c3`;
      const regsMatch = Object.entries(item.expected ?? {}).every(([name, value]) => field(dump, name) === value);
      const a0 = field(dump, "A0"), a7 = field(dump, "A7"), sr = field(dump, "SR");
      const native = output.includes("NATEXEC pc=00001008"), fallback = output.includes(`JIT_FALLBACK op=${item.opcode} pc=00001008`);
      if (run.status === 0 && memory === wantMemory && regsMatch && a0 === (item.a0 ?? "00009000") && a7 === (item.a7 ?? "00009000") && sr === "271f" && native && fallback && !output.includes("Caught SIGSEGV")) servicePass++;
      else { fail++; console.error(`FPP_CONTROL_MEMORY_BASIC_FAIL case=${item.name} rc=${run.status} mem=${memory} want=${wantMemory} regs=${regsMatch ? 1 : 0} a0=${a0} a7=${a7} sr=${sr} native=${native ? 1 : 0} fallback=${fallback ? 1 : 0}`); if (dump) console.error(dump); if (process.env.VERBOSE) console.error(output); }
    } finally { rmSync(td, { recursive: true, force: true }); }
  }
  for (const item of selectedStrict) {
    const td = mkdtempSync(join(tmpdir(), "fpp-control-memory-basic-strict-"));
    try {
      prefs(join(td, "prefs"), disk);
      const run = spawnSync("timeout", ["-k", "5s", "30s", bin, "--config", join(td, "prefs")], { encoding: "utf8", timeout: 35000, env: { ...process.env, SDL_VIDEODRIVER: "x11", DISPLAY: display, HOME: td, B2_TEST_HEX: item.stream, B2_TEST_INIT: `${baseRegs.join(" ")} 271f`, B2_TEST_DUMP: "1", B2_JIT_FORCE_TRANSLATE: "1", B2_TEST_FORCE_L2_RAM: "1", B2_JIT_STRICT_FULL: "1" }});
      const output = `${run.stdout ?? ""}${run.stderr ?? ""}`;
      if (run.status !== 0 && output.includes(`strict full-JIT: opcode fallback pc=00001000 op=${item.opcode}`) && !output.includes("NATEXEC pc=00001000")) strictPass++;
      else { fail++; console.error(`FPP_CONTROL_MEMORY_BASIC_FAIL strict=${item.name} rc=${run.status}`); if (process.env.VERBOSE) console.error(output); }
    } finally { rmSync(td, { recursive: true, force: true }); }
  }
} finally {
  spawnSync("bash", ["-c", "source \"$1\"; cow_release \"$2\"", "bash", cowLib, disk]);
  rmSync(diskDir, { recursive: true, force: true });
}
const expectedService = process.env.CASE ? selected.length : 15, expectedStrict = process.env.CASE ? selectedStrict.length : 3;
console.log(`FPP_CONTROL_MEMORY_BASIC_MATRIX service_pass=${servicePass} strict_pass=${strictPass} fail=${fail} total=${servicePass + strictPass + fail}`);
process.exit(fail === 0 && servicePass === expectedService && strictPass === expectedStrict ? 0 : 1);
