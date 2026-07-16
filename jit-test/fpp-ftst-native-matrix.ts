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

const diskDir = mkdtempSync(join(tmpdir(), "fpp-ftst-disk-"));
const clone = spawnSync("bash", ["-c", [
  "set -euo pipefail",
  "source \"$1\"",
  "cow_clone \"$2\" \"$3/disk.img\" fpp-ftst",
].join("\n"), "bash", cowLib, diskSource, diskDir], { encoding: "utf8" });
if (clone.status !== 0) {
  console.error(clone.stderr || "FPP_FTST_FAIL unable to create isolated disk clone");
  process.exit(1);
}
const disk = clone.stdout.trim().split("\n").at(-1)!;

const states = [
  { name: "positive", bits: "3f800000", relation: "greater", fpsr: "00000000" },
  { name: "negative", bits: "bf800000", relation: "less", fpsr: "08000000" },
  { name: "positive_zero", bits: "00000000", relation: "equal", fpsr: "04000000" },
  { name: "negative_zero", bits: "80000000", relation: "negative_equal", fpsr: "0c000000" },
  { name: "positive_infinity", bits: "7f800000", relation: "greater", fpsr: "02000000" },
  { name: "negative_infinity", bits: "ff800000", relation: "less", fpsr: "0a000000" },
  { name: "positive_nan", bits: "7fc00001", relation: "unordered", fpsr: "01000000" },
  { name: "negative_nan", bits: "ffc00001", relation: "unordered_negative", fpsr: "09000000" },
] as const;

type Relation = (typeof states)[number]["relation"];
function expected(cc: number, relation: Relation): boolean {
  const negative = relation === "less" || relation === "negative_equal" || relation === "unordered_negative";
  const zero = relation === "equal" || relation === "negative_equal";
  const nan = relation === "unordered" || relation === "unordered_negative";
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
  for (const state of states) {
    for (let cc = 0; cc < 16; cc++) {
      const td = mkdtempSync(join(tmpdir(), "fpp-ftst-"));
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

        const words = `${state.bits.slice(0, 4)} ${state.bits.slice(4)}`;
        const opcode = (0xf280 + cc).toString(16);
        const stream = [
          "F23C 443A", words,
          opcode, "000A",
          "207C 1111 1111 6006 207C 2222 2222",
          "2C7C A6FD", cc.toString(16).padStart(4, "0"),
        ].join(" ");
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
          B2_TEST_SECOND_PC: "0x1000",
          B2_TEST_REPLAY_COUNT: "2",
          B2_TEST_FORCE_L2_RAM: "1",
          B2_JIT_STRICT_FULL: "1",
          B2_NATIVE_ASSERT_PC: "0x1000",
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
        const native = output.includes("NATEXEC pc=00001000");
        const strict = output.includes("JIT_STRICT_SUMMARY ") &&
          !output.includes("strict full-JIT:") && !output.includes("JIT_FALLBACK");
        const wantA0 = expected(cc, state.relation) ? "22222222" : "11111111";
        if (run.status === 0 && a0 === wantA0 && sr === "271f" && fpsr === state.fpsr && native && strict) {
          pass++;
        } else {
          fail++;
          console.error(
            `FPP_FTST_FAIL state=${state.name} cc=${cc} rc=${run.status} ` +
            `a0=${a0} want_a0=${wantA0} sr=${sr} fpsr=${fpsr} want_fpsr=${state.fpsr} ` +
            `native=${native ? 1 : 0} strict=${strict ? 1 : 0}`,
          );
          for (const line of output.split("\n").filter((text) =>
            /REGDUMP|Caught|strict full-JIT|unsupported|NATEXEC|JIT_STRICT/.test(text)).slice(-12)) {
            console.error(line);
          }
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

console.log(`FPP_FTST_NATIVE_MATRIX pass=${pass} fail=${fail} total=${pass + fail}`);
process.exit(fail === 0 && pass === 128 ? 0 : 1);
