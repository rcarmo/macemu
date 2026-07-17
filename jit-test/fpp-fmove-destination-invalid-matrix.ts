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
const source = "F23C 4400 C0A0 0000"; // FMOVE.S #-5.0,FP0
const cases = [
  { name: "d16_pc_is_not_writable", stream: "F23A 6000 0FF2" },
  { name: "indexed_pc_is_not_writable", stream: "F23B 6000 1800" },
  { name: "immediate_is_not_writable", stream: "F23C 6000 DEAD BEEF" },
] as const;

const diskDir = mkdtempSync(join(tmpdir(), "fpp-fmove-dest-invalid-disk-"));
const clone = spawnSync("bash", ["-c", [
  "set -euo pipefail", "source \"$1\"",
  "cow_clone \"$2\" \"$3/disk.img\" fpp-fmove-dest-invalid",
].join("\n"), "bash", cowLib, diskSource, diskDir], { encoding: "utf8" });
if (clone.status !== 0) {
  console.error(clone.stderr || "FPP_FMOVE_DEST_INVALID_FAIL unable to create isolated disk clone");
  process.exit(1);
}
const disk = clone.stdout.trim().split("\n").at(-1)!;
const selected = process.env.CASE ? cases.filter((item) => item.name === process.env.CASE) : cases;
if (selected.length === 0) throw new Error(`unknown CASE=${process.env.CASE}`);
let pass = 0;
let fail = 0;
try {
  for (const item of selected) {
    const td = mkdtempSync(join(tmpdir(), "fpp-fmove-dest-invalid-"));
    try {
      const prefs = join(td, "prefs");
      writeFileSync(prefs, [
        `rom ${rom}`, `disk ${disk}`, "ramsize 8388608", "modelid 14", "cpu 4",
        "fpu true", "jit true", "jitfpu true", "jitcachesize 8192",
        "screen win/640/480", "nosound true", "nocdrom true", "nogui true",
        "ignoresegv true", "",
      ].join("\n"));
      const run = spawnSync("timeout", ["-k", "5s", "30s", bin, "--config", prefs], {
        encoding: "utf8", timeout: 35_000,
        env: {
          ...process.env, SDL_VIDEODRIVER: "x11", DISPLAY: display, HOME: td,
          B2_TEST_HEX: `${source} ${item.stream} 2C7C A6F5 0000`,
          B2_TEST_INIT: "0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 007fe000 271F",
          B2_TEST_MEMORY_BYTES: "2000 a5 2001 5a 2002 3c 2003 c3",
          B2_TEST_DUMP: "1", B2_TEST_DUMP_FP: "1", B2_JIT_FORCE_TRANSLATE: "1",
          B2_TEST_TWO_PASS: "1", B2_TEST_SECOND_PC: "0x1008", B2_TEST_REPLAY_COUNT: "2",
          B2_TEST_FORCE_L2_RAM: "1", B2_JIT_STRICT_FULL: "1",
        },
      });
      const output = `${run.stdout ?? ""}${run.stderr ?? ""}`;
      const rejected = output.includes("strict full-JIT: opcode fallback");
      const noSuccess = !output.includes("NATEXEC pc=00001008") && !output.includes("JIT_STRICT_SUMMARY ");
      if (run.status !== 0 && rejected && noSuccess) pass++;
      else {
        fail++;
        console.error(`FPP_FMOVE_DEST_INVALID_FAIL case=${item.name} rc=${run.status} rejected=${rejected ? 1 : 0} no_success=${noSuccess ? 1 : 0}`);
        for (const line of output.split("\n").filter((text) =>
          /REGDUMP|Caught|strict full-JIT|unsupported|NATEXEC|JIT_STRICT|JIT_FALLBACK/.test(text)).slice(-15)) console.error(line);
      }
    } finally { rmSync(td, { recursive: true, force: true }); }
  }
} finally {
  spawnSync("bash", ["-c", "source \"$1\"; cow_release \"$2\"", "bash", cowLib, disk]);
  rmSync(diskDir, { recursive: true, force: true });
}
console.log(`FPP_FMOVE_DEST_INVALID_MATRIX pass=${pass} fail=${fail} total=${pass + fail}`);
const expected = process.env.CASE ? 1 : 3;
process.exit(fail === 0 && pass === expected && selected.length === expected ? 0 : 1);
