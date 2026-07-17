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
const zeroInit = "0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 007fe000 271F";

type Case = {
  name: string;
  opcode: string;
  extra: string;
  bytes: string;
  base: number;
  addressReg?: number;
  fpReg?: number;
  wantAddress: number;
  fp: string;
  fpsr: string;
};

const formats = [
  { name: "byte", extra: "5800", bytes: "80", size: 1, fp: "c060000000000000", fpsr: "08000000" },
  { name: "word", extra: "5000", bytes: "80 00", size: 2, fp: "c0e0000000000000", fpsr: "08000000" },
  { name: "long", extra: "4000", bytes: "80 00 00 00", size: 4, fp: "c1e0000000000000", fpsr: "08000000" },
  { name: "single", extra: "4400", bytes: "bf c0 00 00", size: 4, fp: "bff8000000000000", fpsr: "08000000" },
  { name: "double", extra: "5400", bytes: "3f f8 00 00 00 00 00 00", size: 8, fp: "3ff8000000000000", fpsr: "00000000" },
] as const;

const cases: Case[] = [];
for (const mode of [
  { name: "aind", opcode: "F210", base: 0xa000, delta: (_size: number) => 0 },
  { name: "postinc", opcode: "F218", base: 0xa000, delta: (size: number) => size },
  { name: "predec", opcode: "F220", base: 0xa010, delta: (size: number) => -size },
]) {
  for (const format of formats) {
    const effective = mode.base + mode.delta(format.size);
    cases.push({
      name: `${format.name}_${mode.name}_a0`, opcode: mode.opcode, extra: format.extra,
      bytes: format.bytes, base: mode.base, wantAddress: effective,
      fp: format.fp, fpsr: format.fpsr,
    });
  }
}
// A7 byte geometry is two bytes even though the operand itself is one byte.
for (const mode of [
  { name: "postinc", opcode: "F21F", base: 0xa000, effective: 0xa000, want: 0xa002 },
  { name: "predec", opcode: "F227", base: 0xa010, effective: 0xa00e, want: 0xa00e },
]) cases.push({
  name: `byte_${mode.name}_a7_geometry`, opcode: mode.opcode, extra: "5800",
  bytes: "80", base: mode.base, addressReg: 7, wantAddress: mode.want,
  fp: "c060000000000000", fpsr: "08000000",
});
cases.push({
  name: "long_aind_a7_to_fp7_max_fields", opcode: "F217", extra: "4380",
  bytes: "80 00 00 00", base: 0xa000, addressReg: 7, fpReg: 7,
  wantAddress: 0xa000, fp: "c1e0000000000000", fpsr: "08000000",
});

function memoryBytes(address: number, bytes: string): string {
  return bytes.split(/\s+/).map((byte, index) =>
    `${(address + index).toString(16)} ${byte}`,
  ).join(" ");
}

const diskDir = mkdtempSync(join(tmpdir(), "fpp-fmove-memory-disk-"));
const clone = spawnSync("bash", ["-c", [
  "set -euo pipefail", "source \"$1\"",
  "cow_clone \"$2\" \"$3/disk.img\" fpp-fmove-memory-basic",
].join("\n"), "bash", cowLib, diskSource, diskDir], { encoding: "utf8" });
if (clone.status !== 0) {
  console.error(clone.stderr || "FPP_FMOVE_MEMORY_BASIC_FAIL unable to create isolated disk clone");
  process.exit(1);
}
const disk = clone.stdout.trim().split("\n").at(-1)!;
const selected = process.env.CASE ? cases.filter((item) => item.name === process.env.CASE) : cases;
if (selected.length === 0) throw new Error(`unknown CASE=${process.env.CASE}`);
let pass = 0;
let fail = 0;
try {
  for (const item of selected) {
    const td = mkdtempSync(join(tmpdir(), "fpp-fmove-memory-"));
    try {
      const prefs = join(td, "prefs");
      writeFileSync(prefs, [
        `rom ${rom}`, `disk ${disk}`, "ramsize 8388608", "modelid 14", "cpu 4",
        "fpu true", "jit true", "jitfpu true", "jitcachesize 8192",
        "screen win/640/480", "nosound true", "nocdrom true", "nogui true",
        "ignoresegv true", "",
      ].join("\n"));
      const init = zeroInit.split(" ");
      const addressReg = item.addressReg ?? 0;
      init[8 + addressReg] = item.base.toString(16).padStart(8, "0");
      const operandSize = item.bytes.split(/\s+/).length;
      const effective = item.name.includes("predec")
        ? item.base - (addressReg === 7 && operandSize === 1 ? 2 : operandSize)
        : item.base;
      const run = spawnSync("timeout", ["-k", "5s", "30s", bin, "--config", prefs], {
        encoding: "utf8", timeout: 35_000,
        env: {
          ...process.env, SDL_VIDEODRIVER: "x11", DISPLAY: display, HOME: td,
          B2_TEST_HEX: `${item.opcode} ${item.extra} 2C7C A6F1 ${pass.toString(16).padStart(4, "0")}`,
          B2_TEST_INIT: init.join(" "), B2_TEST_MEMORY_BYTES: memoryBytes(effective, item.bytes),
          B2_TEST_DUMP: "1", B2_TEST_DUMP_FP: "1", B2_JIT_FORCE_TRANSLATE: "1",
          B2_TEST_TWO_PASS: "1", B2_TEST_SECOND_PC: "0x1000", B2_TEST_REPLAY_COUNT: "2",
          B2_TEST_FORCE_L2_RAM: "1", B2_JIT_STRICT_FULL: "1", B2_NATIVE_ASSERT_PC: "0x1000",
        },
      });
      const output = `${run.stdout ?? ""}${run.stderr ?? ""}`;
      const dump = output.match(/^REGDUMP:.*$/m)?.[0];
      const fpReg = item.fpReg ?? 0;
      const fp = dump?.match(new RegExp(` FP${fpReg}=([0-9a-f]+)`, "i"))?.[1].toLowerCase();
      const fpsr = dump?.match(/ FPSR=([0-9a-f]+)/i)?.[1].toLowerCase();
      const sr = dump?.match(/ SR=([0-9a-f]+)/i)?.[1].toLowerCase();
      const address = dump?.match(new RegExp(` A${addressReg}=([0-9a-f]+)`, "i"))?.[1].toLowerCase();
      const wantAddress = item.wantAddress.toString(16).padStart(8, "0");
      const native = output.includes("NATEXEC pc=00001000");
      const strict = output.includes("JIT_STRICT_SUMMARY ") &&
        !output.includes("strict full-JIT:") && !output.includes("JIT_FALLBACK");
      if (run.status === 0 && fp === item.fp && fpsr === item.fpsr && sr === "271f" &&
          address === wantAddress && native && strict) {
        pass++;
      } else {
        fail++;
        console.error(`FPP_FMOVE_MEMORY_BASIC_FAIL case=${item.name} rc=${run.status} ` +
          `fp=${fp} want_fp=${item.fp} fpsr=${fpsr} want_fpsr=${item.fpsr} sr=${sr} ` +
          `a${addressReg}=${address} want_a=${wantAddress} native=${native ? 1 : 0} strict=${strict ? 1 : 0}`);
        for (const line of output.split("\n").filter((text) =>
          /REGDUMP|Caught|strict full-JIT|unsupported|NATEXEC|JIT_STRICT/.test(text)).slice(-12)) console.error(line);
      }
    } finally {
      rmSync(td, { recursive: true, force: true });
    }
  }
} finally {
  spawnSync("bash", ["-c", "source \"$1\"; cow_release \"$2\"", "bash", cowLib, disk]);
  rmSync(diskDir, { recursive: true, force: true });
}
console.log(`FPP_FMOVE_MEMORY_BASIC_MATRIX pass=${pass} fail=${fail} total=${pass + fail}`);
const expected = process.env.CASE ? 1 : 18;
process.exit(fail === 0 && pass === expected && selected.length === expected ? 0 : 1);
