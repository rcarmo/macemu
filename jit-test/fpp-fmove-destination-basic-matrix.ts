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
const zeroInit = "a5a50000 0 0 0 0 0 0 0 0 0 0 0 0 0 0 007fe000 271F";
const defaultSource = "F23C 4400 C0A0 0000"; // FMOVE.S #-5.0,FP0

type Case = {
  name: string;
  opcode: string;
  extra: string;
  anchor?: number;
  addressReg?: number;
  base?: number;
  wantAddress?: number;
  wantD0?: string;
  dataReg?: number;
  memoryAddress?: number;
  wantBytes?: string;
  source?: string;
  wantFpsr?: string;
  replayFpcr?: string;
};

const formats = [
  { name: "byte", extra: "7800", bytes: "fb", size: 1 },
  { name: "word", extra: "7000", bytes: "ff fb", size: 2 },
  { name: "long", extra: "6000", bytes: "ff ff ff fb", size: 4 },
  { name: "single", extra: "6400", bytes: "c0 a0 00 00", size: 4 },
  { name: "double", extra: "7400", bytes: "c0 14 00 00 00 00 00 00", size: 8 },
] as const;
const cases: Case[] = [
  { name: "byte_fp0_to_d0", opcode: "F200", extra: "7800", wantD0: "a5a500fb" },
  { name: "word_fp0_to_d0", opcode: "F200", extra: "7000", wantD0: "a5a5fffb" },
  { name: "long_fp0_to_d0", opcode: "F200", extra: "6000", wantD0: "fffffffb" },
  { name: "single_fp0_to_d0", opcode: "F200", extra: "6400", wantD0: "c0a00000" },
  { name: "single_exact_clears_prior_status", opcode: "F200", extra: "6400", wantD0: "c0a00000" },
  { name: "byte_fraction_round_nearest_even", opcode: "F200", extra: "7800", source: "F23C 4400 4060 0000", wantD0: "a5a50004", wantFpsr: "0c550208" },
  { name: "byte_fraction_round_zero", opcode: "F200", extra: "7800", source: "F23C 4400 4060 0000", replayFpcr: "10", wantD0: "a5a50003", wantFpsr: "0c550208" },
  { name: "byte_fraction_round_minus_inf", opcode: "F200", extra: "7800", source: "F23C 4400 c060 0000", replayFpcr: "20", wantD0: "a5a500fc", wantFpsr: "0c550208" },
  { name: "byte_fraction_round_plus_inf", opcode: "F200", extra: "7800", source: "F23C 4400 4060 0000", replayFpcr: "30", wantD0: "a5a50004", wantFpsr: "0c550208" },
  { name: "byte_exact_min_no_operr", opcode: "F200", extra: "7800", source: "F23C 4400 c300 0000", wantD0: "a5a50080" },
  { name: "byte_exact_max_no_operr", opcode: "F200", extra: "7800", source: "F23C 4400 42fe 0000", wantD0: "a5a5007f" },
  { name: "byte_one_below_saturates", opcode: "F200", extra: "7800", source: "F23C 4400 c301 0000", wantD0: "a5a50080", wantFpsr: "0c552088" },
  { name: "byte_one_above_saturates", opcode: "F200", extra: "7800", source: "F23C 4400 4300 0000", wantD0: "a5a5007f", wantFpsr: "0c552088" },
  { name: "byte_fractional_overflow_operr_inex", opcode: "F200", extra: "7800", source: "F23C 4400 4300 8000", wantD0: "a5a5007f", wantFpsr: "0c552288" },
  { name: "word_exact_min_no_operr", opcode: "F200", extra: "7000", source: "F23C 4400 c700 0000", wantD0: "a5a58000" },
  { name: "word_exact_max_no_operr", opcode: "F200", extra: "7000", source: "F23C 4400 46ff fe00", wantD0: "a5a57fff" },
  { name: "word_one_above_saturates", opcode: "F200", extra: "7000", source: "F23C 4400 4700 0000", wantD0: "a5a57fff", wantFpsr: "0c552088" },
  { name: "word_positive_overflow_saturates", opcode: "F200", extra: "7000", source: "F23C 4400 4700 0000", wantD0: "a5a57fff", wantFpsr: "0c552088" },
  { name: "word_negative_overflow_saturates", opcode: "F200", extra: "7000", source: "F23C 4400 c701 0000", wantD0: "a5a58000", wantFpsr: "0c552088" },
  { name: "long_positive_overflow_saturates", opcode: "F200", extra: "6000", source: "F23C 5400 41e0 0000 0000 0000", wantD0: "7fffffff", wantFpsr: "0c552088" },
  { name: "long_negative_overflow_saturates", opcode: "F200", extra: "6000", source: "F23C 5400 c1e0 0000 0020 0000", wantD0: "80000000", wantFpsr: "0c552088" },
  { name: "long_positive_infinity_saturates", opcode: "F200", extra: "6000", source: "F23C 4400 7f80 0000", wantD0: "7fffffff", wantFpsr: "0c552088" },
  { name: "long_negative_infinity_saturates", opcode: "F200", extra: "6000", source: "F23C 4400 ff80 0000", wantD0: "80000000", wantFpsr: "0c552088" },
  { name: "long_positive_nan_saturates", opcode: "F200", extra: "6000", source: "F23C 4400 7fc0 0001", wantD0: "7fffffff", wantFpsr: "0c552088" },
  { name: "long_negative_nan_saturates", opcode: "F200", extra: "6000", source: "F23C 4400 ffc0 0001", wantD0: "80000000", wantFpsr: "0c552088" },
  { name: "long_exact_min_no_operr", opcode: "F200", extra: "6000", source: "F23C 5400 c1e0 0000 0000 0000", wantD0: "80000000" },
  { name: "fp7_to_d7_max_fields", opcode: "F207", extra: "6380", source: "F23C 4780 c0a0 0000", dataReg: 7, wantD0: "fffffffb" },
  { name: "double_aind_exact_clears_prior_status", opcode: "F210", extra: "7400",
    base: 0xa000, wantAddress: 0xa000, memoryAddress: 0xa000,
    wantBytes: "c0 14 00 00 00 00 00 00" },
];
for (const mode of [
  { name: "aind", opcode: "F210", base: 0xa000, effective: (_size: number) => 0xa000, final: (_size: number) => 0xa000 },
  { name: "postinc", opcode: "F218", base: 0xa000, effective: (_size: number) => 0xa000, final: (size: number) => 0xa000 + size },
  { name: "predec", opcode: "F220", base: 0xa010, effective: (size: number) => 0xa010 - size, final: (size: number) => 0xa010 - size },
]) for (const format of formats) cases.push({
  name: `${format.name}_${mode.name}_a0`, opcode: mode.opcode, extra: format.extra,
  base: mode.base, wantAddress: mode.final(format.size),
  memoryAddress: mode.effective(format.size), wantBytes: format.bytes,
});
for (const mode of [
  { name: "postinc", opcode: "F21F", base: 0xa000, effective: 0xa000, final: 0xa002 },
  { name: "predec", opcode: "F227", base: 0xa010, effective: 0xa00e, final: 0xa00e },
]) cases.push({
  name: `byte_${mode.name}_a7_geometry`, opcode: mode.opcode, extra: "7800",
  addressReg: 7, base: mode.base, wantAddress: mode.final,
  memoryAddress: mode.effective, wantBytes: "fb",
});

const diskDir = mkdtempSync(join(tmpdir(), "fpp-fmove-dest-basic-disk-"));
const clone = spawnSync("bash", ["-c", [
  "set -euo pipefail", "source \"$1\"",
  "cow_clone \"$2\" \"$3/disk.img\" fpp-fmove-dest-basic",
].join("\n"), "bash", cowLib, diskSource, diskDir], { encoding: "utf8" });
if (clone.status !== 0) {
  console.error(clone.stderr || "FPP_FMOVE_DEST_BASIC_FAIL unable to create isolated disk clone");
  process.exit(1);
}
const disk = clone.stdout.trim().split("\n").at(-1)!;
const integerFormats = new Set([0, 4, 6]); // long, word, byte format field
const selected = process.env.CASE ? cases.filter((item) => item.name === process.env.CASE)
  : process.env.GROUP === "integer" ? cases.filter((item) =>
      integerFormats.has((Number.parseInt(item.extra, 16) >> 10) & 7))
  : cases;
if (selected.length === 0) throw new Error(`unknown CASE=${process.env.CASE} GROUP=${process.env.GROUP}`);
let pass = 0;
let fail = 0;
try {
  for (const item of selected) {
    const td = mkdtempSync(join(tmpdir(), "fpp-fmove-dest-basic-"));
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
      if (item.base !== undefined) init[8 + addressReg] = item.base.toString(16).padStart(8, "0");
      const sourceWords = (item.source ?? defaultSource).trim().split(/\s+/).length;
      const anchor = item.anchor ?? (0x1000 + sourceWords * 2);
      const run = spawnSync("timeout", ["-k", "5s", "30s", bin, "--config", prefs], {
        encoding: "utf8", timeout: 35_000,
        env: {
          ...process.env, SDL_VIDEODRIVER: "x11", DISPLAY: display, HOME: td,
          B2_TEST_HEX: `${item.source ?? defaultSource} ${item.opcode} ${item.extra} 2C7C A6F3 ${pass.toString(16).padStart(4, "0")}`,
          B2_TEST_INIT: init.join(" "), B2_TEST_DUMP: "1", B2_TEST_DUMP_FP: "1",
          B2_TEST_MEMORY_BYTES: item.memoryAddress === undefined ? "" : `${item.memoryAddress.toString(16)} 00`,
          B2_TEST_MEMDUMP: item.memoryAddress === undefined ? "" : `0x${item.memoryAddress.toString(16)}:${item.wantBytes!.split(/\s+/).length}`,
          /* The replay begins at FMOVE destination.  Seed non-zero CCB,
             quotient, and accrued INEX to prove the store preserves all three
             while replacing only exception status and accruing new bits. */
          B2_JIT_FORCE_TRANSLATE: "1", B2_TEST_TWO_PASS: "1", B2_TEST_REPLAY_FPSR: "0c55ff08",
          B2_TEST_REPLAY_FPCR: item.replayFpcr ?? "0",
          B2_TEST_SECOND_PC: `0x${anchor.toString(16)}`, B2_TEST_REPLAY_COUNT: "2",
          B2_TEST_FORCE_L2_RAM: "1", B2_JIT_STRICT_FULL: "1",
          B2_NATIVE_ASSERT_PC: `0x${anchor.toString(16)}`,
        },
      });
      const output = `${run.stdout ?? ""}${run.stderr ?? ""}`;
      const dump = output.match(/^REGDUMP:.*$/m)?.[0];
      const dataReg = item.dataReg ?? 0;
      const d0 = dump?.match(new RegExp(` D${dataReg}=([0-9a-f]+)`, "i"))?.[1].toLowerCase();
      const fpsr = dump?.match(/ FPSR=([0-9a-f]+)/i)?.[1].toLowerCase();
      const sr = dump?.match(/ SR=([0-9a-f]+)/i)?.[1].toLowerCase();
      const address = dump?.match(new RegExp(` A${addressReg}=([0-9a-f]+)`, "i"))?.[1].toLowerCase();
      const mem = output.match(/^MEMDUMP [^:]+:(.*)$/m)?.[1].trim().toLowerCase();
      const nativePc = anchor.toString(16).padStart(8, "0");
      const native = output.includes(`NATEXEC pc=${nativePc}`);
      const strict = output.includes("JIT_STRICT_SUMMARY ") &&
        !output.includes("strict full-JIT:") && !output.includes("JIT_FALLBACK");
      const dataOk = item.wantD0 ? d0 === item.wantD0 : mem === item.wantBytes;
      const addressOk = item.wantAddress === undefined || address === item.wantAddress.toString(16).padStart(8, "0");
      if (run.status === 0 && dataOk && addressOk && fpsr === (item.wantFpsr ?? "0c550008") && sr === "271f" && native && strict) pass++;
      else {
        fail++;
        console.error(`FPP_FMOVE_DEST_BASIC_FAIL case=${item.name} rc=${run.status} d${dataReg}=${d0} want_d=${item.wantD0} ` +
          `mem=${mem} want_mem=${item.wantBytes} a${addressReg}=${address} want_a=${item.wantAddress?.toString(16)} ` +
          `fpsr=${fpsr} want_fpsr=${item.wantFpsr ?? "0c550008"} sr=${sr} native=${native ? 1 : 0} strict=${strict ? 1 : 0}`);
        for (const line of output.split("\n").filter((text) =>
          /REGDUMP|MEMDUMP|Caught|strict full-JIT|unsupported|NATEXEC|JIT_STRICT/.test(text)).slice(-15)) console.error(line);
      }
    } finally { rmSync(td, { recursive: true, force: true }); }
  }
} finally {
  spawnSync("bash", ["-c", "source \"$1\"; cow_release \"$2\"", "bash", cowLib, disk]);
  rmSync(diskDir, { recursive: true, force: true });
}
console.log(`FPP_FMOVE_DEST_BASIC_MATRIX pass=${pass} fail=${fail} total=${pass + fail}`);
const expected = process.env.CASE ? 1 : process.env.GROUP === "integer" ? 36 : 45;
process.exit(fail === 0 && pass === expected && selected.length === expected ? 0 : 1);
