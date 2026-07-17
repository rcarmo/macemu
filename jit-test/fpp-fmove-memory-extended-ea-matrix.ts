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
  stream: string;
  effective: number;
  bytes: string;
  fp: string;
  fpsr: string;
  fpReg?: number;
  regs?: Record<number, number>;
  addressRegs?: Record<number, number>;
  extraMemory?: string;
};

const formats = [
  { name: "byte", extra: 0x5800, bytes: "80", fp: "c060000000000000", fpsr: "08000000" },
  { name: "word", extra: 0x5000, bytes: "80 00", fp: "c0e0000000000000", fpsr: "08000000" },
  { name: "long", extra: 0x4000, bytes: "80 00 00 00", fp: "c1e0000000000000", fpsr: "08000000" },
  { name: "single", extra: 0x4400, bytes: "bf c0 00 00", fp: "bff8000000000000", fpsr: "08000000" },
  { name: "double", extra: 0x5400, bytes: "3f f8 00 00 00 00 00 00", fp: "3ff8000000000000", fpsr: "00000000" },
] as const;
const word = (value: number) => (value & 0xffff).toString(16).padStart(4, "0");
const longWords = (value: number) => `${word(value >>> 16)} ${word(value)}`;
const cases: Case[] = [];

for (const format of formats) {
  cases.push({
    name: `${format.name}_d16_a0_positive`,
    stream: `F228 ${word(format.extra)} 0010`, effective: 0xa010,
    bytes: format.bytes, fp: format.fp, fpsr: format.fpsr,
    addressRegs: { 0: 0xa000 },
  });
  cases.push({
    name: `${format.name}_indexed_a0_d1_long_scale2_negative_disp`,
    // Brief extension: D1.L*2 plus signed 8-bit displacement -4.
    stream: `F230 ${word(format.extra)} 1AFC`, effective: 0xa00c,
    bytes: format.bytes, fp: format.fp, fpsr: format.fpsr,
    regs: { 1: 8 }, addressRegs: { 0: 0xa000 },
  });
  cases.push({
    name: `${format.name}_absolute_short`,
    stream: `F238 ${word(format.extra)} 6000`, effective: 0x6000,
    bytes: format.bytes, fp: format.fp, fpsr: format.fpsr,
  });
  cases.push({
    name: `${format.name}_absolute_long`,
    stream: `F239 ${word(format.extra)} ${longWords(0xa000)}`, effective: 0xa000,
    bytes: format.bytes, fp: format.fp, fpsr: format.fpsr,
  });
  cases.push({
    name: `${format.name}_pc_d16_forward`,
    // The 68040 PC-relative base is the EA extension-word address, 0x1004.
    stream: `F23A ${word(format.extra)} 0FFC`, effective: 0x2000,
    bytes: format.bytes, fp: format.fp, fpsr: format.fpsr,
  });
}

cases.push({
  name: "long_d16_a7_negative_to_fp7_max_fields",
  stream: "F22F 4380 FFF0", effective: 0x9ff0, bytes: "80 00 00 00",
  fp: "c1e0000000000000", fpsr: "08000000", fpReg: 7,
  addressRegs: { 7: 0xa000 },
});
cases.push({
  name: "word_indexed_a0_d7_word_scale8_max_index_field",
  // D7.W*8 plus +4; low word FFFE sign-extends to -2.
  stream: "F230 5000 7604", effective: 0x9ff4, bytes: "80 00",
  fp: "c0e0000000000000", fpsr: "08000000",
  regs: { 7: 0x0000fffe }, addressRegs: { 0: 0xa000 },
});
cases.push({
  name: "single_pc_d16_backward",
  stream: "F23A 4400 F7FC", effective: 0x0800, bytes: "3f c0 00 00",
  fp: "3ff8000000000000", fpsr: "00000000",
});
cases.push({
  name: "double_absolute_long_to_fp7_max_field",
  stream: "F239 5780 0000 A000", effective: 0xa000,
  bytes: "bf f8 00 00 00 00 00 00", fp: "bff8000000000000",
  fpsr: "08000000", fpReg: 7,
});
cases.push({
  name: "long_indexed_full_direct_word_bd",
  // Full format: A0 + D1.L + signed word base displacement -16.
  stream: "F230 4000 1920 FFF0", effective: 0xa000,
  bytes: "80 00 00 00", fp: "c1e0000000000000", fpsr: "08000000",
  regs: { 1: 0 }, addressRegs: { 0: 0xa010 },
});
cases.push({
  name: "long_indexed_full_preindexed_word_outer",
  // Full preindexed indirect: ([A0 + D1.L - 4], +16).
  stream: "F230 4000 1922 FFFC 0010", effective: 0xa000,
  bytes: "80 00 00 00", fp: "c1e0000000000000", fpsr: "08000000",
  regs: { 1: 4 }, addressRegs: { 0: 0xa100 },
  extraMemory: "a100 00 a101 00 a102 9f a103 f0",
});
cases.push({
  name: "long_indexed_full_postindexed_word_outer",
  // Full postindexed indirect: ([A0 - 4], D1.L, +0).
  stream: "F230 4000 1926 FFFC 0000", effective: 0xa000,
  bytes: "80 00 00 00", fp: "c1e0000000000000", fpsr: "08000000",
  regs: { 1: 4 }, addressRegs: { 0: 0xa104 },
  extraMemory: "a100 00 a101 00 a102 9f a103 fc",
});
for (const format of formats) cases.push({
  name: `${format.name}_pc_indexed_brief_d1_long`,
  // Brief PC-relative index: extension-word PC 0x1004 + D1.L + signed -4.
  stream: `F23B ${word(format.extra)} 18FC`, effective: 0x2000,
  bytes: format.bytes, fp: format.fp, fpsr: format.fpsr,
  regs: { 1: 0x1000 },
});
cases.push({
  name: "long_pc_indexed_full_direct_word_bd",
  // Full PC-relative format: extension-word PC 0x1004 + D1.L + word bd -8.
  stream: "F23B 4000 1920 FFF8", effective: 0x2000,
  bytes: "80 00 00 00", fp: "c1e0000000000000", fpsr: "08000000",
  regs: { 1: 0x1004 },
});
cases.push({
  name: "long_pc_indexed_full_preindexed_indirect",
  // Full PC preindexed indirect: ([PC + D1.L - 4], +16).
  stream: "F23B 4000 1922 FFFC 0010", effective: 0x3000,
  bytes: "80 00 00 00", fp: "c1e0000000000000", fpsr: "08000000",
  regs: { 1: 0x1000 }, extraMemory: "2000 00 2001 00 2002 2f 2003 f0",
});

function memoryBytes(address: number, bytes: string): string {
  return bytes.split(/\s+/).map((byte, index) =>
    `${(address + index).toString(16)} ${byte}`,
  ).join(" ");
}

const diskDir = mkdtempSync(join(tmpdir(), "fpp-fmove-extended-ea-disk-"));
const clone = spawnSync("bash", ["-c", [
  "set -euo pipefail", "source \"$1\"",
  "cow_clone \"$2\" \"$3/disk.img\" fpp-fmove-extended-ea",
].join("\n"), "bash", cowLib, diskSource, diskDir], { encoding: "utf8" });
if (clone.status !== 0) {
  console.error(clone.stderr || "FPP_FMOVE_EXTENDED_EA_FAIL unable to create isolated disk clone");
  process.exit(1);
}
const disk = clone.stdout.trim().split("\n").at(-1)!;
const selected = process.env.CASE ? cases.filter((item) => item.name === process.env.CASE) : cases;
if (selected.length === 0) throw new Error(`unknown CASE=${process.env.CASE}`);
let pass = 0;
let fail = 0;
try {
  for (const item of selected) {
    const td = mkdtempSync(join(tmpdir(), "fpp-fmove-extended-ea-"));
    try {
      const prefs = join(td, "prefs");
      writeFileSync(prefs, [
        `rom ${rom}`, `disk ${disk}`, "ramsize 8388608", "modelid 14", "cpu 4",
        "fpu true", "jit true", "jitfpu true", "jitcachesize 8192",
        "screen win/640/480", "nosound true", "nocdrom true", "nogui true",
        "ignoresegv true", "",
      ].join("\n"));
      const init = zeroInit.split(" ");
      for (const [reg, value] of Object.entries(item.regs ?? {})) init[Number(reg)] = word(value >>> 16) + word(value);
      for (const [reg, value] of Object.entries(item.addressRegs ?? {})) init[8 + Number(reg)] = word(value >>> 16) + word(value);
      const run = spawnSync("timeout", ["-k", "5s", "30s", bin, "--config", prefs], {
        encoding: "utf8", timeout: 35_000,
        env: {
          ...process.env, SDL_VIDEODRIVER: "x11", DISPLAY: display, HOME: td,
          B2_TEST_HEX: `${item.stream} 2C7C A6F2 ${pass.toString(16).padStart(4, "0")}`,
          B2_TEST_INIT: init.join(" "),
          B2_TEST_MEMORY_BYTES: `${memoryBytes(item.effective, item.bytes)} ${item.extraMemory ?? ""}`.trim(),
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
      const regsPreserved = Object.entries(item.regs ?? {}).every(([reg, value]) =>
        dump?.match(new RegExp(` D${reg}=([0-9a-f]+)`, "i"))?.[1].toLowerCase() === (value >>> 0).toString(16).padStart(8, "0"));
      const addressRegsPreserved = Object.entries(item.addressRegs ?? {}).every(([reg, value]) =>
        dump?.match(new RegExp(` A${reg}=([0-9a-f]+)`, "i"))?.[1].toLowerCase() === (value >>> 0).toString(16).padStart(8, "0"));
      const native = output.includes("NATEXEC pc=00001000");
      const strict = output.includes("JIT_STRICT_SUMMARY ") &&
        !output.includes("strict full-JIT:") && !output.includes("JIT_FALLBACK");
      if (run.status === 0 && fp === item.fp && fpsr === item.fpsr && sr === "271f" &&
          regsPreserved && addressRegsPreserved && native && strict) {
        pass++;
      } else {
        fail++;
        console.error(`FPP_FMOVE_EXTENDED_EA_FAIL case=${item.name} rc=${run.status} ` +
          `fp=${fp} want_fp=${item.fp} fpsr=${fpsr} want_fpsr=${item.fpsr} sr=${sr} ` +
          `dregs=${regsPreserved ? 1 : 0} aregs=${addressRegsPreserved ? 1 : 0} ` +
          `native=${native ? 1 : 0} strict=${strict ? 1 : 0}`);
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
console.log(`FPP_FMOVE_EXTENDED_EA_MATRIX pass=${pass} fail=${fail} total=${pass + fail}`);
const expected = process.env.CASE ? 1 : 39;
process.exit(fail === 0 && pass === expected && selected.length === expected ? 0 : 1);
