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
const defaultSource = "F23C 4400 C0A0 0000"; // FMOVE.S #-5.0,FP0

type Case = {
  name: string;
  stream: string;
  effective: number;
  bytes: string;
  source?: string;
  regs?: Record<number, number>;
  addressRegs?: Record<number, number>;
  extraMemory?: string;
};

const formats = [
  { name: "byte", extra: 0x7800, bytes: "fb" },
  { name: "word", extra: 0x7000, bytes: "ff fb" },
  { name: "long", extra: 0x6000, bytes: "ff ff ff fb" },
  { name: "single", extra: 0x6400, bytes: "c0 a0 00 00" },
  { name: "double", extra: 0x7400, bytes: "c0 14 00 00 00 00 00 00" },
] as const;
const word = (value: number) => (value & 0xffff).toString(16).padStart(4, "0");
const longWords = (value: number) => `${word(value >>> 16)} ${word(value)}`;
const cases: Case[] = [];

for (const format of formats) {
  cases.push({
    name: `${format.name}_d16_a0_positive`,
    stream: `F228 ${word(format.extra)} 0010`, effective: 0xa010,
    bytes: format.bytes, addressRegs: { 0: 0xa000 },
  });
  cases.push({
    name: `${format.name}_indexed_a0_d1_long_scale2_negative_disp`,
    // Brief extension: D1.L*2 plus signed 8-bit displacement -4.
    stream: `F230 ${word(format.extra)} 1AFC`, effective: 0xa00c,
    bytes: format.bytes, regs: { 1: 8 }, addressRegs: { 0: 0xa000 },
  });
  cases.push({
    name: `${format.name}_absolute_short`,
    stream: `F238 ${word(format.extra)} 6000`, effective: 0x6000,
    bytes: format.bytes,
  });
  cases.push({
    name: `${format.name}_absolute_long`,
    stream: `F239 ${word(format.extra)} ${longWords(0xa000)}`, effective: 0xa000,
    bytes: format.bytes,
  });
}

cases.push({
  name: "long_d16_a7_negative_from_fp7_max_fields",
  stream: "F22F 6380 FFF0", effective: 0x9ff0, bytes: "ff ff ff fb",
  source: "F23C 4780 C0A0 0000", addressRegs: { 7: 0xa000 },
});
cases.push({
  name: "word_indexed_a0_d7_word_scale8_max_index_field",
  // D7.W*8 plus +4; low word FFFE sign-extends to -2.
  stream: "F230 7000 7604", effective: 0x9ff4, bytes: "ff fb",
  regs: { 7: 0x0000fffe }, addressRegs: { 0: 0xa000 },
});
cases.push({
  name: "long_indexed_full_direct_word_bd",
  // Full format: A0 + D1.L + signed word base displacement -16.
  stream: "F230 6000 1920 FFF0", effective: 0xa000, bytes: "ff ff ff fb",
  regs: { 1: 0 }, addressRegs: { 0: 0xa010 },
});
cases.push({
  name: "long_indexed_full_preindexed_word_outer",
  // Full preindexed indirect: ([A0 + D1.L - 4], +16).
  stream: "F230 6000 1922 FFFC 0010", effective: 0xa000, bytes: "ff ff ff fb",
  regs: { 1: 4 }, addressRegs: { 0: 0xa100 },
  extraMemory: "a100 00 a101 00 a102 9f a103 f0",
});
cases.push({
  name: "long_indexed_full_postindexed_word_outer",
  // Full postindexed indirect: ([A0 - 4], D1.L, +0).
  stream: "F230 6000 1926 FFFC 0000", effective: 0xa000, bytes: "ff ff ff fb",
  regs: { 1: 4 }, addressRegs: { 0: 0xa104 },
  extraMemory: "a100 00 a101 00 a102 9f a103 fc",
});
cases.push({
  name: "long_indexed_brief_all_integer_registers_live",
  // D7.L*2 plus -4 while every Dn and non-sentinel/non-SP An is live.
  stream: "F230 6000 7AFC", effective: 0xa00c, bytes: "ff ff ff fb",
  regs: {
    0: 0x11110000, 1: 0x22220001, 2: 0x33330002, 3: 0x44440003,
    4: 0x55550004, 5: 0x66660005, 6: 0x77770006, 7: 8,
  },
  addressRegs: {
    0: 0xa000, 1: 0x2100, 2: 0x2200, 3: 0x2300,
    4: 0x2400, 5: 0x2500,
  },
});

function guardedMemory(address: number, bytes: string): { init: string; expected: string; start: number; length: number } {
  const result = bytes.split(/\s+/);
  const start = address - 2;
  const expected = ["a5", "5a", ...result, "3c", "c3"];
  return {
    start,
    length: expected.length,
    expected: expected.join(" "),
    init: expected.map((_byte, index) => `${(start + index).toString(16)} ${index < 2 ? ["a5", "5a"][index] : index >= result.length + 2 ? ["3c", "c3"][index - result.length - 2] : "00"}`).join(" "),
  };
}

const diskDir = mkdtempSync(join(tmpdir(), "fpp-fmove-dest-extended-ea-disk-"));
const clone = spawnSync("bash", ["-c", [
  "set -euo pipefail", "source \"$1\"",
  "cow_clone \"$2\" \"$3/disk.img\" fpp-fmove-dest-extended-ea",
].join("\n"), "bash", cowLib, diskSource, diskDir], { encoding: "utf8" });
if (clone.status !== 0) {
  console.error(clone.stderr || "FPP_FMOVE_DEST_EXTENDED_EA_FAIL unable to create isolated disk clone");
  process.exit(1);
}
const disk = clone.stdout.trim().split("\n").at(-1)!;
const groupPattern = new Map([
  ["integer", /^(?:byte|word|long)_/],
  ["single", /^single_/],
]);
if (process.env.GROUP && !groupPattern.has(process.env.GROUP))
  throw new Error(`unknown GROUP=${process.env.GROUP}`);
const selected = cases.filter((item) =>
  (!process.env.CASE || item.name === process.env.CASE) &&
  (!process.env.GROUP || groupPattern.get(process.env.GROUP)!.test(item.name))
);
if (selected.length === 0)
  throw new Error(`unknown CASE=${process.env.CASE} GROUP=${process.env.GROUP}`);
let pass = 0;
let fail = 0;
try {
  for (const item of selected) {
    const td = mkdtempSync(join(tmpdir(), "fpp-fmove-dest-extended-ea-"));
    try {
      const prefs = join(td, "prefs");
      writeFileSync(prefs, [
        `rom ${rom}`, `disk ${disk}`, "ramsize 8388608", "modelid 14", "cpu 4",
        "fpu true", "jit true", "jitfpu true", "jitcachesize 8192",
        "screen win/640/480", "nosound true", "nocdrom true", "nogui true",
        "ignoresegv true", "",
      ].join("\n"));
      const init = zeroInit.split(" ");
      for (const [reg, value] of Object.entries(item.regs ?? {})) init[Number(reg)] = (value >>> 0).toString(16).padStart(8, "0");
      for (const [reg, value] of Object.entries(item.addressRegs ?? {})) init[8 + Number(reg)] = (value >>> 0).toString(16).padStart(8, "0");
      const source = item.source ?? defaultSource;
      const anchor = 0x1000 + source.trim().split(/\s+/).length * 2;
      const guarded = guardedMemory(item.effective, item.bytes);
      const run = spawnSync("timeout", ["-k", "5s", "30s", bin, "--config", prefs], {
        encoding: "utf8", timeout: 35_000,
        env: {
          ...process.env, SDL_VIDEODRIVER: "x11", DISPLAY: display, HOME: td,
          B2_TEST_HEX: `${source} ${item.stream} 2C7C A6F4 ${pass.toString(16).padStart(4, "0")}`,
          B2_TEST_INIT: init.join(" "),
          B2_TEST_MEMORY_BYTES: `${guarded.init} ${item.extraMemory ?? ""}`.trim(),
          B2_TEST_MEMDUMP: `0x${guarded.start.toString(16)}:${guarded.length}`,
          B2_TEST_DUMP: "1", B2_TEST_DUMP_FP: "1", B2_JIT_FORCE_TRANSLATE: "1",
          B2_TEST_TWO_PASS: "1", B2_TEST_REPLAY_FPSR: "0c55ff08", B2_TEST_REPLAY_FPCR: "0",
          B2_TEST_SECOND_PC: `0x${anchor.toString(16)}`, B2_TEST_REPLAY_COUNT: "2",
          B2_TEST_FORCE_L2_RAM: "1", B2_JIT_STRICT_FULL: "1",
          B2_NATIVE_ASSERT_PC: `0x${anchor.toString(16)}`,
        },
      });
      const output = `${run.stdout ?? ""}${run.stderr ?? ""}`;
      const dump = output.match(/^REGDUMP:.*$/m)?.[0];
      const mem = output.match(/^MEMDUMP [^:]+:(.*)$/m)?.[1].trim().toLowerCase();
      const fpsr = dump?.match(/ FPSR=([0-9a-f]+)/i)?.[1].toLowerCase();
      const sr = dump?.match(/ SR=([0-9a-f]+)/i)?.[1].toLowerCase();
      const regsPreserved = Object.entries(item.regs ?? {}).every(([reg, value]) =>
        dump?.match(new RegExp(` D${reg}=([0-9a-f]+)`, "i"))?.[1].toLowerCase() === (value >>> 0).toString(16).padStart(8, "0"));
      const addressRegsPreserved = Object.entries(item.addressRegs ?? {}).every(([reg, value]) =>
        dump?.match(new RegExp(` A${reg}=([0-9a-f]+)`, "i"))?.[1].toLowerCase() === (value >>> 0).toString(16).padStart(8, "0"));
      const nativePc = anchor.toString(16).padStart(8, "0");
      const native = output.includes(`NATEXEC pc=${nativePc}`);
      const strict = output.includes("JIT_STRICT_SUMMARY ") &&
        !output.includes("strict full-JIT:") && !output.includes("JIT_FALLBACK");
      if (run.status === 0 && mem === guarded.expected && fpsr === "0c550008" && sr === "271f" &&
          regsPreserved && addressRegsPreserved && native && strict) pass++;
      else {
        fail++;
        console.error(`FPP_FMOVE_DEST_EXTENDED_EA_FAIL case=${item.name} rc=${run.status} ` +
          `mem=${mem} want_mem=${guarded.expected} fpsr=${fpsr} want_fpsr=0c550008 sr=${sr} ` +
          `dregs=${regsPreserved ? 1 : 0} aregs=${addressRegsPreserved ? 1 : 0} ` +
          `native=${native ? 1 : 0} strict=${strict ? 1 : 0}`);
        for (const line of output.split("\n").filter((text) =>
          /REGDUMP|MEMDUMP|Caught|strict full-JIT|unsupported|NATEXEC|JIT_STRICT/.test(text)).slice(-15)) console.error(line);
      }
    } finally { rmSync(td, { recursive: true, force: true }); }
  }
} finally {
  spawnSync("bash", ["-c", "source \"$1\"; cow_release \"$2\"", "bash", cowLib, disk]);
  rmSync(diskDir, { recursive: true, force: true });
}
console.log(`FPP_FMOVE_DEST_EXTENDED_EA_MATRIX pass=${pass} fail=${fail} total=${pass + fail}`);
const expected = process.env.CASE ? 1 : process.env.GROUP === "integer" ? 18 : process.env.GROUP === "single" ? 4 : 26;
process.exit(fail === 0 && pass === expected && selected.length === expected ? 0 : 1);
