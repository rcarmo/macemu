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
  {
    name: "single_fp0_then_fp1",
    stream: "F23C 4400 3F80 0000 F23C 4480 C000 0000",
    fpsr: "08000000", fp: [[0, "3ff0000000000000"], [1, "c000000000000000"]],
  },
  {
    name: "byte_fp0_then_fp7",
    stream: "F23C 5800 0080 F23C 5B80 007F",
    fpsr: "00000000", fp: [[0, "c060000000000000"], [7, "405fc00000000000"]],
  },
  {
    name: "long_fp0_then_fp3",
    stream: "F23C 4000 8000 0000 F23C 4180 0000 0001",
    fpsr: "00000000", fp: [[0, "c1e0000000000000"], [3, "3ff0000000000000"]],
  },
  {
    name: "double_fp0_then_negative_zero_fp6",
    stream: "F23C 5400 3FF0 0000 0000 0000 F23C 5700 8000 0000 0000 0000",
    fpsr: "0c000000", fp: [[0, "3ff0000000000000"], [6, "8000000000000000"]],
  },
  {
    name: "ftst_then_word_fp2",
    stream: "F23C 4400 BF80 0000 F200 003A F23C 5100 7FFF",
    fpsr: "00000000", fp: [[0, "bff0000000000000"], [2, "40dfffc000000000"]],
  },
  {
    name: "double_fp7_then_byte_fp0",
    stream: "F23C 5780 4004 0000 0000 0000 F23C 5800 00FF",
    fpsr: "08000000", fp: [[7, "4004000000000000"], [0, "bff0000000000000"]],
  },
] as const;

const diskDir = mkdtempSync(join(tmpdir(), "f-scratch-lifecycle-disk-"));
const clone = spawnSync("bash", ["-c", [
  "set -euo pipefail",
  "source \"$1\"",
  "cow_clone \"$2\" \"$3/disk.img\" f-scratch-lifecycle",
].join("\n"), "bash", cowLib, diskSource, diskDir], { encoding: "utf8" });
if (clone.status !== 0) {
  console.error(clone.stderr || "F_SCRATCH_LIFECYCLE_FAIL unable to create isolated disk clone");
  process.exit(1);
}
const disk = clone.stdout.trim().split("\n").at(-1)!;

function run(stream: string, jit: boolean, ordinal: number) {
  const td = mkdtempSync(join(tmpdir(), `f-scratch-lifecycle-${jit ? "jit" : "int"}-`));
  try {
    const prefs = join(td, "prefs");
    writeFileSync(prefs, [
      `rom ${rom}`, `disk ${disk}`, "ramsize 8388608", "modelid 14", "cpu 4",
      "fpu true", `jit ${jit}`, `jitfpu ${jit}`, "jitcachesize 8192",
      "screen win/640/480", "nosound true", "nocdrom true", "nogui true",
      "ignoresegv true", "",
    ].join("\n"));
    const env: NodeJS.ProcessEnv = {
      ...process.env,
      SDL_VIDEODRIVER: "x11", DISPLAY: display, HOME: td,
      B2_TEST_HEX: `${stream} 2C7C A6F5 ${ordinal.toString(16).padStart(4, "0")}`,
      B2_TEST_INIT: "0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 007fe000 271f",
      B2_TEST_DUMP: "1", B2_TEST_DUMP_FP: "1",
    };
    if (jit) Object.assign(env, {
      B2_JIT_FORCE_TRANSLATE: "1", B2_TEST_TWO_PASS: "1",
      B2_TEST_SECOND_PC: "0x1000", B2_TEST_REPLAY_COUNT: "2",
      B2_TEST_FORCE_L2_RAM: "1", B2_JIT_STRICT_FULL: "1",
      B2_NATIVE_ASSERT_PC: "0x1000",
    });
    const result = spawnSync("timeout", ["-k", "5s", "40s", bin, "--config", prefs], {
      encoding: "utf8", timeout: 45_000, env,
    });
    const output = `${result.stdout ?? ""}${result.stderr ?? ""}`;
    const dumps = [...output.matchAll(/^REGDUMP:.*$/gm)].map((match) => match[0]);
    return {
      status: result.status,
      output,
      dump: dumps.at(-1),
      native: output.includes("NATEXEC pc=00001000"),
      strict: output.includes("JIT_STRICT_SUMMARY ") &&
        !output.includes("strict full-JIT:") && !output.includes("JIT_FALLBACK"),
    };
  } finally {
    rmSync(td, { recursive: true, force: true });
  }
}

let pass = 0;
let fail = 0;
try {
  const selected = process.env.CASE ? cases.filter((item) => item.name === process.env.CASE) : cases;
  if (selected.length === 0) throw new Error(`unknown CASE=${process.env.CASE}`);
  for (const [ordinal, item] of selected.entries()) {
    const interp = run(item.stream, false, ordinal);
    const jit = run(item.stream, true, ordinal);
    const fpsr = jit.dump?.match(/\bFPSR=([0-9a-f]+)/i)?.[1].toLowerCase();
    const sr = jit.dump?.match(/\bSR=([0-9a-f]+)/i)?.[1].toLowerCase();
    const architectural = (dump: string | undefined) => dump?.replace(/ FP[0-7]=[0-9a-f]+/gi, "");
    const equivalent = architectural(interp.dump) !== undefined &&
      architectural(interp.dump) === architectural(jit.dump);
    const fpExact = item.fp.every(([reg, expected]) =>
      jit.dump?.match(new RegExp(`\\bFP${reg}=([0-9a-f]+)`, "i"))?.[1].toLowerCase() === expected);
    if (interp.status === 0 && jit.status === 0 && equivalent && fpExact && fpsr === item.fpsr &&
        sr === "271f" && jit.native && jit.strict) {
      pass++;
    } else {
      fail++;
      console.error(
        `F_SCRATCH_LIFECYCLE_FAIL case=${item.name} int=${interp.status} jit=${jit.status} ` +
        `equiv=${Number(equivalent)} fp_exact=${Number(fpExact)} fpsr=${fpsr} want_fpsr=${item.fpsr} sr=${sr} ` +
        `native=${Number(jit.native)} strict=${Number(jit.strict)}`,
      );
      console.error(`interp=${interp.dump ?? "missing"}`);
      console.error(`jit=${jit.dump ?? "missing"}`);
      for (const line of jit.output.split("\n").filter((text) =>
        /Caught|strict full-JIT|JIT_FALLBACK|NATEXEC/.test(text)).slice(-14)) console.error(line);
    }
  }
} finally {
  spawnSync("bash", ["-c", "source \"$1\"; cow_release \"$2\"", "bash", cowLib, disk]);
  rmSync(diskDir, { recursive: true, force: true });
}

console.log(`F_SCRATCH_LIFECYCLE_NATIVE_MATRIX pass=${pass} fail=${fail} total=${pass + fail}`);
process.exit(fail === 0 && pass === (process.env.CASE ? 1 : cases.length) ? 0 : 1);
