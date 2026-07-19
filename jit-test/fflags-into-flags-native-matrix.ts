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

const cases = [
  { name: "fscc_positive_ogt_d0", kind: "fscc", stream: "f240 0002 2c7c a6c8 0001", anchor: 0x1000, fpsr: "00000000", reg: 0, value: "123456ff" },
  { name: "fscc_zero_eq_d7", kind: "fscc", stream: "f247 0001 2c7c a6c8 0002", anchor: 0x1000, fpsr: "04000000", reg: 7, value: "89abcdff" },
  { name: "fscc_negative_olt_d0", kind: "fscc", stream: "f240 0004 2c7c a6c8 0003", anchor: 0x1000, fpsr: "08000000", reg: 0, value: "123456ff" },
  { name: "fscc_nan_ordered_d7_false", kind: "fscc", stream: "f247 0007 2c7c a6c8 0004", anchor: 0x1000, fpsr: "01000000", reg: 7, value: "89abcd00" },
  { name: "fbcc_ftst_positive_ogt_word", kind: "fbcc", stream: "f23c 4400 3f80 0000 f200 003a f282 000a 207c 1111 1111 6006 207c 2222 2222 2c7c a6c8 0011", anchor: 0x100c, fpsr: "00000000", a0: "22222222" },
  { name: "fbcc_ftst_nan_un_long", kind: "fbcc", stream: "f23c 4400 7fff ffff f200 003a f2c8 0000 000c 207c 1111 1111 6006 207c 2222 2222 2c7c a6c8 0012", anchor: 0x100c, fpsr: "01000000", a0: "22222222" },
  { name: "fbcc_fcmp_less_olt_word", kind: "fbcc", stream: "f23c 4400 bf80 0000 f23c 4438 3f80 0000 f284 000a 207c 1111 1111 6006 207c 2222 2222 2c7c a6c8 0013", anchor: 0x1010, fpsr: "08000000", a0: "22222222" },
  { name: "fbcc_fcmp_equal_eq_long", kind: "fbcc", stream: "f23c 4400 3f80 0000 f23c 4438 3f80 0000 f2c1 0000 000c 207c 1111 1111 6006 207c 2222 2222 2c7c a6c8 0014", anchor: 0x1010, fpsr: "04000000", a0: "22222222" },
] as const;

const diskDir = mkdtempSync(join(tmpdir(), "fflags-into-flags-disk-"));
const clone = spawnSync("bash", ["-c", 'set -euo pipefail\nsource "$1"\ncow_clone "$2" "$3/disk.img" fflags-into-flags', "bash", cowLib, diskSource, diskDir], { encoding: "utf8" });
if (clone.status !== 0) {
  console.error(clone.stderr || "FFLAGS_INTO_FLAGS_FAIL unable to create isolated disk clone");
  process.exit(1);
}
const disk = clone.stdout.trim().split("\n").at(-1)!;

let pass = 0;
let fail = 0;
try {
  for (const item of cases) {
    const td = mkdtempSync(join(tmpdir(), "fflags-into-flags-"));
    try {
      const prefs = join(td, "prefs");
      writeFileSync(prefs, [
        `rom ${rom}`, `disk ${disk}`, "ramsize 8388608", "modelid 14", "cpu 4",
        "fpu true", "jit true", "jitfpu true", "jitcachesize 8192",
        "screen win/640/480", "nosound true", "nocdrom true", "nogui true", "ignoresegv true", "",
      ].join("\n"));
      const initial = Array(16).fill("00000000");
      initial[0] = "123456aa";
      initial[7] = "89abcdaa";
      initial[15] = "007fe000";
      const anchor = `0x${item.anchor.toString(16)}`;
      const env: Record<string, string> = {
        ...process.env as Record<string, string>, SDL_VIDEODRIVER: "x11", DISPLAY: display, HOME: td,
        B2_TEST_HEX: item.stream, B2_TEST_INIT: `${initial.join(" ")} 271F`,
        B2_TEST_DUMP: "1", B2_TEST_DUMP_FP: "1", B2_JIT_FORCE_TRANSLATE: "1",
        B2_TEST_TWO_PASS: "1", B2_TEST_SECOND_PC: anchor, B2_TEST_REPLAY_COUNT: "2",
        B2_TEST_FORCE_L2_RAM: "1", B2_JIT_STRICT_FULL: "1", B2_NATIVE_ASSERT_PC: anchor,
      };
      if (item.kind === "fscc") env.B2_TEST_REPLAY_FPSR = item.fpsr;
      const run = spawnSync("timeout", ["-k", "5s", "30s", bin, "--config", prefs], {
        env, encoding: "utf8", timeout: 35_000,
      });
      const output = `${run.stdout ?? ""}${run.stderr ?? ""}`;
      const dump = output.match(/^REGDUMP:.*$/m)?.[0];
      const sr = dump?.match(/ SR=([0-9a-f]+)/i)?.[1].toLowerCase();
      const fpsr = dump?.match(/ FPSR=([0-9a-f]+)/i)?.[1].toLowerCase();
      const native = output.includes(`NATEXEC pc=${item.anchor.toString(16).padStart(8, "0")}`);
      const strict = output.includes("JIT_STRICT_SUMMARY ") && !output.includes("strict full-JIT:") && !output.includes("JIT_FALLBACK");
      let semantic = false;
      if (item.kind === "fscc") {
        const value = dump?.match(new RegExp(` D${item.reg}=([0-9a-f]+)`, "i"))?.[1].toLowerCase();
        const otherReg = item.reg === 0 ? 7 : 0;
        const other = dump?.match(new RegExp(` D${otherReg}=([0-9a-f]+)`, "i"))?.[1].toLowerCase();
        semantic = value === item.value && other === (item.reg === 0 ? "89abcdaa" : "123456aa");
      } else {
        semantic = dump?.match(/ A0=([0-9a-f]+)/i)?.[1].toLowerCase() === item.a0;
      }
      if (run.status === 0 && semantic && sr === "271f" && fpsr === item.fpsr && native && strict) {
        pass++;
      } else {
        fail++;
        console.error(`FFLAGS_INTO_FLAGS_FAIL case=${item.name} rc=${run.status} semantic=${semantic ? 1 : 0} sr=${sr} fpsr=${fpsr} want_fpsr=${item.fpsr} native=${native ? 1 : 0} strict=${strict ? 1 : 0}`);
        for (const line of output.split("\n").filter((text) => /REGDUMP|Caught|strict full-JIT|JIT_FALLBACK|NATEXEC|JIT_STRICT/.test(text)).slice(-10)) console.error(line);
      }
    } finally {
      rmSync(td, { recursive: true, force: true });
    }
  }
} finally {
  spawnSync("bash", ["-c", 'source "$1"; cow_release "$2"', "bash", cowLib, disk]);
  rmSync(diskDir, { recursive: true, force: true });
}

console.log(`FFLAGS_INTO_FLAGS_NATIVE_MATRIX pass=${pass} fail=${fail} total=${pass + fail}`);
process.exit(fail === 0 && pass === 8 ? 0 : 1);
