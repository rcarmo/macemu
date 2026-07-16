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

const diskDir = mkdtempSync(join(tmpdir(), "fbcc-native-disk-"));
const clone = spawnSync("bash", ["-c", [
  "set -euo pipefail",
  "source \"$1\"",
  "cow_clone \"$2\" \"$3/disk.img\" fbcc-native",
].join("\n"), "bash", cowLib, diskSource, diskDir], { encoding: "utf8" });
if (clone.status !== 0) {
  console.error(clone.stderr || "FBCC_FAIL unable to create isolated disk clone");
  process.exit(1);
}
const disk = clone.stdout.trim().split("\n").at(-1)!;

const states = [
  { name: "positive", prefix: "F200 5C32 F200 003A" },
  { name: "zero", prefix: "F200 5C0F F200 003A" },
  { name: "negative", prefix: "F23C 4400 BF80 0000 F200 003A" },
  { name: "nan", prefix: "F23C 4400 7FFF FFFF F200 003A" },
  { name: "negative_nan", prefix: "F23C 4400 FFFF FFFF F200 003A" },
] as const;

function expected(cc: number, state: (typeof states)[number]["name"]): boolean {
  const negative = state === "negative";
  const zero = state === "zero";
  const nan = state === "nan" || state === "negative_nan";
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
    for (const width of ["word", "long"] as const) {
      const td = mkdtempSync(join(tmpdir(), "fbcc-native-"));
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

        const opcode = (width === "word" ? 0xf280 : 0xf2c0) + cc;
        const prefixBytes = state.prefix.split(/\s+/).length * 2;
        const anchor = 0x1000 + prefixBytes;
        const branch = width === "word"
          ? `${opcode.toString(16)} 000A`
          : `${opcode.toString(16)} 0000 000C`;
        const tag = ((cc << 4) + (width === "word" ? 1 : 2)).toString(16).padStart(4, "0");
        const stream = `${state.prefix} ${branch} 207C 1111 1111 6006 207C 2222 2222 2C7C A6FB ${tag}`;
        const anchorHex = `0x${anchor.toString(16)}`;
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
          B2_TEST_SECOND_PC: anchorHex,
          B2_TEST_REPLAY_COUNT: "2",
          B2_TEST_FORCE_L2_RAM: "1",
          B2_JIT_STRICT_FULL: "1",
          B2_NATIVE_ASSERT_PC: anchorHex,
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
        const native = output.includes(`NATEXEC pc=${anchor.toString(16).padStart(8, "0")}`);
        const strict = output.includes("JIT_STRICT_SUMMARY ") &&
          !output.includes("strict full-JIT:") && !output.includes("JIT_FALLBACK");
        const wantA0 = expected(cc, state.name) ? "22222222" : "11111111";
        if (run.status === 0 && a0 === wantA0 && sr === "271f" && native && strict) {
          pass++;
        } else {
          fail++;
          console.error(
            `FBCC_FAIL state=${state.name} cc=${cc} width=${width} rc=${run.status} ` +
            `a0=${a0} want_a0=${wantA0} sr=${sr} native=${native ? 1 : 0} strict=${strict ? 1 : 0}`,
          );
          for (const line of output.split("\n").filter((item) =>
            /REGDUMP|Caught|strict full-JIT|unsupported|NATEXEC/.test(item)).slice(-8)) {
            console.error(line);
          }
        }
      } finally {
        rmSync(td, { recursive: true, force: true });
      }
    }
  }
}
} finally {
  spawnSync("bash", ["-c", "source \"$1\"; cow_release \"$2\"", "bash", cowLib, disk]);
  rmSync(diskDir, { recursive: true, force: true });
}

console.log(`FBCC_NATIVE_MATRIX pass=${pass} fail=${fail} total=${pass + fail}`);
process.exit(fail === 0 && pass === 160 ? 0 : 1);
