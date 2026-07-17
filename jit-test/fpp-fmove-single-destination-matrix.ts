#!/usr/bin/env bun

import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { spawnSync } from "node:child_process";

const root = new URL("..", import.meta.url).pathname;
const bin = `${root}/BasiliskII/src/Unix/BasiliskII`;
const rom = process.env.ROM ?? "/workspace/projects/rpi-basilisk2-sdl2-nox/Quadra800.ROM";
const diskSource = process.env.DISK ?? "/workspace/fixtures/basilisk/images/HD200MB";
const cowLib = process.env.COW_LIB ?? "/workspace/scripts/lib/cow-disk.sh";
const display = process.env.DISPLAY ?? ":99";
const init = "a5a50000 0 0 0 0 0 0 0 0 0 0 0 0 0 0 007fe000 271F";

type Case = {
  name: string;
  source: string;
  want: string;
  fpsr: string;
  fpcr?: string;
  opcode?: string;
  extra?: string;
  memoryAddress?: number;
};

const cases: Case[] = [
  { name: "positive_zero", source: "F23C 5400 0000 0000 0000 0000", want: "00000000", fpsr: "0c550008" },
  { name: "negative_zero", source: "F23C 5400 8000 0000 0000 0000", want: "80000000", fpsr: "0c550008" },
  { name: "positive_infinity", source: "F23C 5400 7ff0 0000 0000 0000", want: "7f800000", fpsr: "0c550008" },
  { name: "negative_infinity", source: "F23C 5400 fff0 0000 0000 0000", want: "ff800000", fpsr: "0c550008" },
  { name: "max_finite_exact", source: "F23C 5400 47ef ffff e000 0000", want: "7f7fffff", fpsr: "0c550008" },
  { name: "min_normal_exact", source: "F23C 5400 3810 0000 0000 0000", want: "00800000", fpsr: "0c550008" },
  { name: "min_subnormal_exact", source: "F23C 5400 36a0 0000 0000 0000", want: "00000001", fpsr: "0c550008" },
  { name: "normal_inexact_nearest", source: "F23C 5400 3ff0 0000 1000 0000", want: "3f800000", fpsr: "0c550208" },
  { name: "normal_inexact_plus_inf", source: "F23C 5400 3ff0 0000 1000 0000", want: "3f800001", fpsr: "0c550208", fpcr: "30" },
  { name: "positive_overflow_nearest", source: "F23C 5400 47f0 0000 0000 0000", want: "7f800000", fpsr: "0c551248" },
  { name: "positive_overflow_zero", source: "F23C 5400 47f0 0000 0000 0000", want: "7f7fffff", fpsr: "0c551248", fpcr: "10" },
  { name: "positive_overflow_minus_inf", source: "F23C 5400 47f0 0000 0000 0000", want: "7f7fffff", fpsr: "0c551248", fpcr: "20" },
  { name: "positive_overflow_plus_inf", source: "F23C 5400 47f0 0000 0000 0000", want: "7f800000", fpsr: "0c551248", fpcr: "30" },
  { name: "negative_overflow_zero", source: "F23C 5400 c7f0 0000 0000 0000", want: "ff7fffff", fpsr: "0c551248", fpcr: "10" },
  { name: "negative_overflow_minus_inf", source: "F23C 5400 c7f0 0000 0000 0000", want: "ff800000", fpsr: "0c551248", fpcr: "20" },
  { name: "half_min_subnormal_nearest", source: "F23C 5400 3690 0000 0000 0000", want: "00000000", fpsr: "0c550a28" },
  { name: "half_min_subnormal_plus_inf", source: "F23C 5400 3690 0000 0000 0000", want: "00000001", fpsr: "0c550a28", fpcr: "30" },
  { name: "negative_half_min_subnormal_minus_inf", source: "F23C 5400 b690 0000 0000 0000", want: "80000001", fpsr: "0c550a28", fpcr: "20" },
  { name: "quiet_nan_payload_positive", source: "F23C 4400 7fc1 2345", want: "7fc12345", fpsr: "0c550008" },
  { name: "quiet_nan_payload_negative", source: "F23C 4400 ffc1 2345", want: "ffc12345", fpsr: "0c550008" },
  { name: "memory_aind_overflow", source: "F23C 5400 47f0 0000 0000 0000", want: "7f800000", fpsr: "0c551248", opcode: "F210", extra: "6400", memoryAddress: 0xa000 },
];

const diskDir = mkdtempSync(join(tmpdir(), "fpp-single-dest-disk-"));
const clone = spawnSync("bash", ["-c", [
  "set -euo pipefail", "source \"$1\"", "cow_clone \"$2\" \"$3/disk.img\" fpp-single-dest",
].join("\n"), "bash", cowLib, diskSource, diskDir], { encoding: "utf8" });
if (clone.status !== 0) throw new Error(clone.stderr || "CoW clone failed");
const disk = clone.stdout.trim().split("\n").at(-1)!;
const selected = process.env.CASE ? cases.filter((item) => item.name === process.env.CASE) : cases;
if (selected.length === 0) throw new Error(`unknown CASE=${process.env.CASE}`);
let pass = 0, fail = 0;
try {
  for (const item of selected) {
    const td = mkdtempSync(join(tmpdir(), "fpp-single-dest-"));
    try {
      const prefs = join(td, "prefs");
      writeFileSync(prefs, [
        `rom ${rom}`, `disk ${disk}`, "ramsize 8388608", "modelid 14", "cpu 4",
        "fpu true", "jit true", "jitfpu true", "jitcachesize 8192",
        "screen win/640/480", "nosound true", "nocdrom true", "nogui true", "ignoresegv true", "",
      ].join("\n"));
      const sourceWords = item.source.trim().split(/\s+/).length;
      const anchor = 0x1000 + sourceWords * 2;
      const opcode = item.opcode ?? "F200";
      const extra = item.extra ?? "6400";
      const regs = init.split(" ");
      if (item.memoryAddress !== undefined) regs[8] = item.memoryAddress.toString(16).padStart(8, "0");
      const run = spawnSync("timeout", ["-k", "5s", "30s", bin, "--config", prefs], {
        encoding: "utf8", timeout: 35_000,
        env: {
          ...process.env, SDL_VIDEODRIVER: "x11", DISPLAY: display, HOME: td,
          B2_TEST_HEX: `${item.source} ${opcode} ${extra} 2C7C A6F4 ${pass.toString(16).padStart(4, "0")}`,
          B2_TEST_INIT: regs.join(" "), B2_TEST_DUMP: "1", B2_TEST_DUMP_FP: "1",
          B2_TEST_MEMORY_BYTES: item.memoryAddress === undefined ? "" : `${item.memoryAddress.toString(16)} 00`,
          B2_TEST_MEMDUMP: item.memoryAddress === undefined ? "" : `0x${item.memoryAddress.toString(16)}:4`,
          B2_JIT_FORCE_TRANSLATE: "1", B2_TEST_TWO_PASS: "1",
          B2_TEST_REPLAY_FPSR: "0c55ff08", B2_TEST_REPLAY_FPCR: item.fpcr ?? "0",
          B2_TEST_SECOND_PC: `0x${anchor.toString(16)}`, B2_TEST_REPLAY_COUNT: "2",
          B2_TEST_FORCE_L2_RAM: "1", B2_JIT_STRICT_FULL: "1", B2_NATIVE_ASSERT_PC: `0x${anchor.toString(16)}`,
        },
      });
      const output = `${run.stdout ?? ""}${run.stderr ?? ""}`;
      const dump = output.match(/^REGDUMP:.*$/m)?.[0];
      const value = item.memoryAddress === undefined
        ? dump?.match(/ D0=([0-9a-f]+)/i)?.[1].toLowerCase()
        : output.match(/^MEMDUMP [^:]+:(.*)$/m)?.[1].trim().replaceAll(" ", "").toLowerCase();
      const fpsr = dump?.match(/ FPSR=([0-9a-f]+)/i)?.[1].toLowerCase();
      const sr = dump?.match(/ SR=([0-9a-f]+)/i)?.[1].toLowerCase();
      const native = output.includes(`NATEXEC pc=${anchor.toString(16).padStart(8, "0")}`);
      const strict = output.includes("JIT_STRICT_SUMMARY ") && !output.includes("strict full-JIT:") && !output.includes("JIT_FALLBACK");
      if (run.status === 0 && value === item.want && fpsr === item.fpsr && sr === "271f" && native && strict) pass++;
      else {
        fail++;
        console.error(`FPP_SINGLE_DEST_FAIL case=${item.name} rc=${run.status} value=${value} want=${item.want} fpsr=${fpsr} want_fpsr=${item.fpsr} sr=${sr} native=${native ? 1 : 0} strict=${strict ? 1 : 0}`);
        for (const line of output.split("\n").filter((text) => /REGDUMP|MEMDUMP|NATEXEC|JIT_STRICT|fallback|Caught/.test(text)).slice(-15)) console.error(line);
      }
    } finally { rmSync(td, { recursive: true, force: true }); }
  }
} finally {
  spawnSync("bash", ["-c", "source \"$1\"; cow_release \"$2\"", "bash", cowLib, disk]);
  rmSync(diskDir, { recursive: true, force: true });
}
console.log(`FPP_SINGLE_DEST_MATRIX pass=${pass} fail=${fail} total=${pass + fail}`);
const expected = process.env.CASE ? 1 : 21;
process.exit(fail === 0 && pass === expected && selected.length === expected ? 0 : 1);
