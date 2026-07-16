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

const diskDir = mkdtempSync(join(tmpdir(), "fpp-compare-disk-"));
const clone = spawnSync("bash", ["-c", [
  "set -euo pipefail",
  "source \"$1\"",
  "cow_clone \"$2\" \"$3/disk.img\" fpp-compare",
].join("\n"), "bash", cowLib, diskSource, diskDir], { encoding: "utf8" });
if (clone.status !== 0) {
  console.error(clone.stderr || "FPP_COMPARE_FAIL unable to create isolated disk clone");
  process.exit(1);
}
const disk = clone.stdout.trim().split("\n").at(-1)!;

/* FMOVE.S #dest,FP0; FCMP.S #source,FP0.  These values distinguish the
   arithmetic-subtraction failure modes from architectural comparison. */
const cases = [
  { name: "finite_less", dest: "bf800000", source: "3f800000", relation: "less" },
  { name: "finite_equal", dest: "3f800000", source: "3f800000", relation: "equal" },
  { name: "negative_finite_equal", dest: "bf800000", source: "bf800000", relation: "equal" },
  { name: "finite_greater", dest: "3f800000", source: "bf800000", relation: "greater" },
  { name: "signed_zero_equal", dest: "80000000", source: "00000000", relation: "negative_equal" },
  { name: "positive_inf_equal", dest: "7f800000", source: "7f800000", relation: "equal" },
  { name: "negative_inf_equal", dest: "ff800000", source: "ff800000", relation: "negative_equal" },
  { name: "positive_inf_greater", dest: "7f800000", source: "3f800000", relation: "greater" },
  { name: "negative_inf_less", dest: "ff800000", source: "bf800000", relation: "less" },
  { name: "dest_nan", dest: "7fc00001", source: "3f800000", relation: "unordered" },
  { name: "source_nan", dest: "3f800000", source: "ffc00001", relation: "unordered" },
] as const;

type Relation = (typeof cases)[number]["relation"];
function expected(cc: number, relation: Relation): boolean {
  const negative = relation === "less" || relation === "negative_equal";
  const zero = relation === "equal" || relation === "negative_equal";
  const nan = relation === "unordered";
  return [
    false,
    zero,
    !nan && !zero && !negative,
    zero || (!nan && !negative),
    negative && !nan && !zero,
    zero || (negative && !nan),
    !nan && !zero,
    !nan,
    nan,
    nan || zero,
    nan || (!negative && !zero),
    nan || zero || !negative,
    nan || (negative && !zero),
    nan || zero || negative,
    !zero,
    true,
  ][cc];
}

let pass = 0;
let fail = 0;
try {
  for (const item of cases) {
    if (process.env.FPP_COMPARE_CASE && item.name !== process.env.FPP_COMPARE_CASE) continue;
    for (let cc = 0; cc < 16; cc++) {
      if (process.env.FPP_COMPARE_CC && cc !== Number(process.env.FPP_COMPARE_CC)) continue;
      const td = mkdtempSync(join(tmpdir(), "fpp-compare-"));
      try {
        const prefs = join(td, "prefs");
        writeFileSync(prefs, [
          `rom ${rom}`,
          `disk ${disk}`,
          "ramsize 8388608",
          "modelid 14",
          "cpu 4",
          "fpu true",
          "jit true",
          "jitfpu true",
          "jitcachesize 8192",
          "screen win/640/480",
          "nosound true",
          "nocdrom true",
          "nogui true",
          "ignoresegv true",
          "",
        ].join("\n"));

        const opcode = 0xf280 + cc; // FBcc.W
        const words = (hex: string) => `${hex.slice(0, 4)} ${hex.slice(4)}`;
        const stream = [
          "F23C 4400", words(item.dest),
          "F23C 4438", words(item.source),
          opcode.toString(16), "000A",
          "207C 1111 1111 6006 207C 2222 2222",
          "2C7C A6FC", cc.toString(16).padStart(4, "0"),
        ].join(" ");
        const anchor = 0x1008;
        const env = {
          ...process.env,
          SDL_VIDEODRIVER: "x11",
          DISPLAY: display,
          HOME: td,
          B2_TEST_HEX: stream,
          B2_TEST_INIT: "0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 007fe000 271F",
          B2_TEST_DUMP: "1",
          B2_JIT_FORCE_TRANSLATE: "1",
          B2_TEST_TWO_PASS: "1",
          B2_TEST_SECOND_PC: `0x${anchor.toString(16)}`,
          B2_TEST_REPLAY_COUNT: "2",
          B2_TEST_FORCE_L2_RAM: "1",
          B2_JIT_STRICT_FULL: "1",
          B2_NATIVE_ASSERT_PC: `0x${anchor.toString(16)}`,
        };
        const run = spawnSync("timeout", ["-k", "5s", "30s", bin, "--config", prefs], {
          env,
          encoding: "utf8",
          timeout: 35_000,
        });
        const output = `${run.stdout ?? ""}${run.stderr ?? ""}`;
        const dump = output.match(/^REGDUMP:.*$/m)?.[0];
        const a0 = dump?.match(/ A0=([0-9a-f]+)/i)?.[1].toLowerCase();
        const sr = dump?.match(/ SR=([0-9a-f]+)/i)?.[1].toLowerCase();
        const fpsr = dump?.match(/ FPSR=([0-9a-f]+)/i)?.[1].toLowerCase();
        const native = output.includes("NATEXEC pc=00001008");
        const strict = output.includes("JIT_STRICT_SUMMARY ") &&
          !output.includes("strict full-JIT:") && !output.includes("JIT_FALLBACK");
        const wantA0 = expected(cc, item.relation) ? "22222222" : "11111111";
        const wantFpsr = item.relation === "less" ? "08000000" :
          item.relation === "negative_equal" ? "0c000000" :
          item.relation === "equal" ? "04000000" :
          item.relation === "unordered" ? "01000000" : "00000000";
        if (run.status === 0 && a0 === wantA0 && sr === "271f" && fpsr === wantFpsr && native && strict) {
          pass++;
        } else {
          fail++;
          console.error(
            `FPP_COMPARE_FAIL case=${item.name} cc=${cc} rc=${run.status} ` +
            `a0=${a0} want_a0=${wantA0} sr=${sr} fpsr=${fpsr} want_fpsr=${wantFpsr} ` +
            `native=${native ? 1 : 0} strict=${strict ? 1 : 0}`,
          );
          for (const line of output.split("\n").filter((text) =>
            /REGDUMP|Caught|strict full-JIT|unsupported|NATEXEC|JIT_STRICT/.test(text)).slice(-12)) {
            console.error(line);
          }
          if (!dump) console.error(output.split("\n").slice(-20).join("\n"));
        }
      } finally {
        rmSync(td, { recursive: true, force: true });
      }
    }
  }
} finally {
  spawnSync("bash", ["-c", "source \"$1\"; cow_release \"$2\"", "bash", cowLib, disk]);
  rmSync(diskDir, { recursive: true, force: true });
}

console.log(`FPP_COMPARE_NATIVE_MATRIX pass=${pass} fail=${fail} total=${pass + fail}`);
process.exit(fail === 0 && pass === 176 ? 0 : 1);
