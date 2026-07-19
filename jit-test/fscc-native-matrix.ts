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
const diskDir = mkdtempSync(join(tmpdir(), "fscc-native-disk-"));
const clone = spawnSync("bash", ["-c", 'set -euo pipefail\nsource "$1"\ncow_clone "$2" "$3/disk.img" fscc-native', "bash", cowLib, diskSource, diskDir], { encoding: "utf8" });
if (clone.status !== 0) {
  console.error(clone.stderr || "FSCC_FAIL unable to create isolated disk clone");
  process.exit(1);
}
const disk = clone.stdout.trim().split("\n").at(-1)!;

const states = [
  { name: "positive", fpsr: "00000000" },
  { name: "zero", fpsr: "04000000" },
  { name: "negative", fpsr: "08000000" },
  { name: "nan", fpsr: "01000000" },
  { name: "negative_nan", fpsr: "09000000" },
] as const;
const memoryService = [
  { name: "memory_aind_false", stream: "f250 0000 2c7c a6c7 0030", fpsr: "00000000", a0: "00009000", address: 0x9000, byte: "00", finalA0: "00009000" },
  { name: "memory_postinc_true_alias", stream: "f258 001f 2c7c a6c7 0031", fpsr: "00000000", a0: "00009000", address: 0x9000, byte: "ff", finalA0: "00009001" },
  { name: "memory_predec_unordered", stream: "f260 0008 2c7c a6c7 0032", fpsr: "01000000", a0: "00009001", address: 0x9000, byte: "ff", finalA0: "00009000" },
  { name: "memory_d16_equal", stream: "f268 0001 0004 2c7c a6c7 0033", fpsr: "04000000", a0: "00009000", address: 0x9004, byte: "ff", finalA0: "00009000" },
] as const;
const rejected = [
  { name: "invalid_cc_20", stream: "f240 0020 2c7c a6c7 0020" },
  { name: "memory_aind_strict", stream: "f250 0001 2c7c a6c7 0021" },
] as const;

function expected(cc: number, state: (typeof states)[number]["name"]): boolean {
  const condition = cc & 0x0f;
  const negative = state === "negative";
  const zero = state === "zero";
  const nan = state === "nan" || state === "negative_nan";
  return [
    false, zero, !nan && !zero && !negative, zero || (!nan && !negative),
    negative && !nan && !zero, zero || (negative && !nan), !nan && !zero, !nan,
    nan, nan || zero, nan || (!negative && !zero), nan || zero || !negative,
    nan || (negative && !zero), nan || zero || negative, !zero, true,
  ][condition];
}

function prefs(path: string) {
  writeFileSync(path, [
    `rom ${rom}`, `disk ${disk}`, "ramsize 8388608", "modelid 14", "cpu 4",
    "fpu true", "jit true", "jitfpu true", "jitcachesize 8192",
    "screen win/640/480", "nosound true", "nocdrom true", "nogui true", "ignoresegv true", "",
  ].join("\n"));
}

let pass = 0;
let fail = 0;
try {
  for (const state of states) {
    for (let cc = 0; cc < 32; cc++) {
      for (const reg of [0, 7]) {
        const caseName = `${state.name}_cc${cc.toString(16).padStart(2, "0")}_d${reg}`;
        if (process.env.CASE && process.env.CASE !== caseName) continue;
        const td = mkdtempSync(join(tmpdir(), "fscc-native-"));
        try {
          const pref = join(td, "prefs");
          prefs(pref);
          const anchor = 0x1000;
          const opcode = 0xf240 + reg;
          const stream = `${opcode.toString(16)} ${cc.toString(16).padStart(4, "0")} 2C7C A6C7 ${cc.toString(16).padStart(4, "0")}`;
          const initial = Array(16).fill("00000000");
          initial[0] = "123456aa";
          initial[7] = "89abcdaa";
          initial[15] = "007fe000";
          const run = spawnSync("timeout", ["-k", "5s", "30s", bin, "--config", pref], {
            encoding: "utf8", timeout: 35_000,
            env: {
              ...process.env, SDL_VIDEODRIVER: "x11", DISPLAY: display, HOME: td,
              B2_TEST_HEX: stream, B2_TEST_INIT: `${initial.join(" ")} 271F`,
              B2_TEST_DUMP: "1", B2_TEST_DUMP_FP: "1", B2_JIT_FORCE_TRANSLATE: "1",
              B2_TEST_TWO_PASS: "1", B2_TEST_SECOND_PC: `0x${anchor.toString(16)}`,
              B2_TEST_REPLAY_COUNT: "2", B2_TEST_REPLAY_FPSR: state.fpsr,
              B2_TEST_FORCE_L2_RAM: "1", B2_JIT_STRICT_FULL: "1",
              B2_NATIVE_ASSERT_PC: `0x${anchor.toString(16)}`,
            },
          });
          const output = `${run.stdout ?? ""}${run.stderr ?? ""}`;
          const dump = output.match(/^REGDUMP:.*$/m)?.[0];
          const value = dump?.match(new RegExp(` D${reg}=([0-9a-f]+)`, "i"))?.[1].toLowerCase();
          const otherReg = reg === 0 ? 7 : 0;
          const other = dump?.match(new RegExp(` D${otherReg}=([0-9a-f]+)`, "i"))?.[1].toLowerCase();
          const want = `${reg === 0 ? "123456" : "89abcd"}${expected(cc, state.name) ? "ff" : "00"}`;
          const wantOther = reg === 0 ? "89abcdaa" : "123456aa";
          const sr = dump?.match(/ SR=([0-9a-f]+)/i)?.[1].toLowerCase();
          const fpsr = dump?.match(/ FPSR=([0-9a-f]+)/i)?.[1].toLowerCase();
          const native = output.includes(`NATEXEC pc=${anchor.toString(16).padStart(8, "0")}`);
          const strict = output.includes("JIT_STRICT_SUMMARY ") && !output.includes("strict full-JIT:") && !output.includes("JIT_FALLBACK");
          if (run.status === 0 && value === want && other === wantOther && sr === "271f" && fpsr === state.fpsr && native && strict) {
            pass++;
          } else {
            fail++;
            console.error(`FSCC_FAIL case=${caseName} rc=${run.status} value=${value} want=${want} other=${other} want_other=${wantOther} sr=${sr} fpsr=${fpsr} want_fpsr=${state.fpsr} native=${native ? 1 : 0} strict=${strict ? 1 : 0}`);
            for (const line of output.split("\n").filter((item) => /REGDUMP|Caught|strict full-JIT|JIT_FALLBACK|NATEXEC/.test(item)).slice(-8)) console.error(line);
          }
        } finally {
          rmSync(td, { recursive: true, force: true });
        }
      }
    }
  }
  for (const item of memoryService) {
    if (process.env.CASE && process.env.CASE !== item.name) continue;
    const td = mkdtempSync(join(tmpdir(), "fscc-memory-service-"));
    try {
      const pref = join(td, "prefs");
      prefs(pref);
      const initial = Array(16).fill("00000000");
      initial[0] = "123456aa";
      initial[8] = item.a0;
      initial[15] = "007fe000";
      const guardStart = item.address - 1;
      const run = spawnSync("timeout", ["-k", "5s", "30s", bin, "--config", pref], {
        encoding: "utf8", timeout: 35_000,
        env: {
          ...process.env, SDL_VIDEODRIVER: "x11", DISPLAY: display, HOME: td,
          B2_TEST_HEX: item.stream, B2_TEST_INIT: `${initial.join(" ")} 271F`,
          B2_TEST_MEMORY_BYTES: `${guardStart.toString(16)} a5 ${item.address.toString(16)} aa ${(item.address + 1).toString(16)} 5a`,
          B2_TEST_MEMDUMP: `0x${guardStart.toString(16)}:3`, B2_TEST_DUMP: "1", B2_TEST_DUMP_FP: "1",
          B2_JIT_FORCE_TRANSLATE: "1", B2_TEST_TWO_PASS: "1", B2_TEST_SECOND_PC: "0x1000",
          B2_TEST_REPLAY_COUNT: "2", B2_TEST_REPLAY_FPSR: item.fpsr, B2_TEST_FORCE_L2_RAM: "1",
          B2_NATIVE_ASSERT_PC: "0x1000",
        },
      });
      const output = `${run.stdout ?? ""}${run.stderr ?? ""}`;
      const dump = output.match(/^REGDUMP:.*$/m)?.[0];
      const memory = output.match(/^MEMDUMP [^:]+:(.*)$/m)?.[1].trim().toLowerCase();
      const a0 = dump?.match(/ A0=([0-9a-f]+)/i)?.[1].toLowerCase();
      const sr = dump?.match(/ SR=([0-9a-f]+)/i)?.[1].toLowerCase();
      const fpsr = dump?.match(/ FPSR=([0-9a-f]+)/i)?.[1].toLowerCase();
      const native = output.includes("NATEXEC pc=00001000");
      const opcode = item.stream.split(/\s+/)[0].toLowerCase();
      const fallback = output.includes(`JIT_FALLBACK op=${opcode} pc=00001000`) && !output.includes("Caught SIGSEGV");
      if (run.status === 0 && memory === `a5 ${item.byte} 5a` && a0 === item.finalA0 && sr === "271f" && fpsr === item.fpsr && native && fallback) {
        pass++;
      } else {
        fail++;
        console.error(`FSCC_FAIL case=${item.name} phase=memory_service rc=${run.status} memory=${memory} want_memory=a5 ${item.byte} 5a a0=${a0} want_a0=${item.finalA0} sr=${sr} fpsr=${fpsr} want_fpsr=${item.fpsr} native=${native ? 1 : 0} fallback=${fallback ? 1 : 0}`);
        for (const line of output.split("\n").filter((text) => /REGDUMP|MEMDUMP|Caught|JIT_FALLBACK|NATEXEC/.test(text)).slice(-12)) console.error(line);
      }
    } finally {
      rmSync(td, { recursive: true, force: true });
    }
  }
  for (const item of rejected) {
    if (process.env.CASE && process.env.CASE !== item.name) continue;
    const td = mkdtempSync(join(tmpdir(), "fscc-native-reject-"));
    try {
      const pref = join(td, "prefs");
      prefs(pref);
      const initial = Array(16).fill("00000000");
      initial[0] = "123456aa";
      initial[8] = "00009000";
      initial[15] = "007fe000";
      const run = spawnSync("timeout", ["-k", "5s", "30s", bin, "--config", pref], {
        encoding: "utf8", timeout: 35_000,
        env: {
          ...process.env, SDL_VIDEODRIVER: "x11", DISPLAY: display, HOME: td,
          B2_TEST_HEX: item.stream, B2_TEST_INIT: `${initial.join(" ")} 271F`,
          B2_TEST_MEMORY_BYTES: "9000 5a", B2_TEST_DUMP: "1", B2_JIT_FORCE_TRANSLATE: "1",
          B2_TEST_FORCE_L2_RAM: "1", B2_JIT_STRICT_FULL: "1", B2_NATIVE_ASSERT_PC: "0x1000",
        },
      });
      const output = `${run.stdout ?? ""}${run.stderr ?? ""}`;
      const strictReject = output.includes("strict full-JIT: opcode fallback");
      const noNativeMutation = !output.includes("NATEXEC pc=00001000") && !output.includes("JIT_STRICT_SUMMARY ");
      const noSegv = !output.includes("Caught SIGSEGV");
      if (run.status !== 0 && strictReject && noNativeMutation && noSegv) {
        pass++;
      } else {
        fail++;
        console.error(`FSCC_FAIL case=${item.name} phase=reject rc=${run.status} strict_reject=${strictReject ? 1 : 0} no_native_mutation=${noNativeMutation ? 1 : 0} no_segv=${noSegv ? 1 : 0}`);
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
const expectedTotal = process.env.CASE ? 1 : 326;
console.log(`FSCC_NATIVE_MATRIX pass=${pass} fail=${fail} total=${pass + fail}`);
process.exit(fail === 0 && pass === expectedTotal ? 0 : 1);
