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
const base = ["11111111", "22222222", "33333333", "44444444", "55555555", "66666666", "77777777", "88888888", "0000a000", "99999999", "0000a100", "bbbbbbbb", "cccccccc", "dddddddd", "eeeeeeee", "00009000"];
const nops = "4E71 4E71 4E71 4E71";

type Value = { name: string; ext: string; copied: string; fpsr: string; finalFpsr: string };
const values: Value[] = [
  { name: "low_significand", ext: "3f ff 00 00 80 00 00 00 00 00 00 01", copied: "3f ff 00 00 80 00 00 00 00 00 00 01", fpsr: "00550008", finalFpsr: "00550008" },
  { name: "maximum_finite", ext: "7f fe 00 00 ff ff ff ff ff ff ff ff", copied: "7f fe 00 00 ff ff ff ff ff ff ff ff", fpsr: "00550008", finalFpsr: "00550008" },
  { name: "below_binary64_range", ext: "3b cb 00 00 80 00 00 00 00 00 00 01", copied: "3b cb 00 00 80 00 00 00 00 00 00 01", fpsr: "00550008", finalFpsr: "00550008" },
  { name: "negative_zero", ext: "80 00 00 00 00 00 00 00 00 00 00 00", copied: "80 00 00 00 00 00 00 00 00 00 00 00", fpsr: "0c550008", finalFpsr: "0c550008" },
  { name: "positive_infinity", ext: "7f ff 00 00 00 00 00 00 00 00 00 00", copied: "7f ff 00 00 00 00 00 00 00 00 00 00", fpsr: "02550008", finalFpsr: "02550008" },
  { name: "quiet_nan_payload", ext: "7f ff 00 00 c0 00 12 34 56 78 9a bc", copied: "7f ff 00 00 c0 00 12 34 56 78 9a bc", fpsr: "01550008", finalFpsr: "01550008" },
  { name: "signalling_nan_payload", ext: "7f ff 00 00 80 00 12 34 56 78 9a bc", copied: "7f ff 00 00 c0 00 12 34 56 78 9a bc", fpsr: "01554088", finalFpsr: "01550088" },
  { name: "negative_extended", ext: "c0 00 00 00 a0 00 00 00 00 00 00 01", copied: "c0 00 00 00 a0 00 00 00 00 00 00 01", fpsr: "08550008", finalFpsr: "08550008" },
];
type Case = { name: string; source: number; destination: number; value: Value; fpcr?: string };
const cases: Case[] = [];
for (let source = 0; source < 8; source++) for (let destination = 0; destination < 8; destination++) {
  cases.push({ name: `fp${source}_to_fp${destination}_${values[source].name}`, source, destination, value: values[source] });
}
cases.push(
  { name: "fp0_to_fp7_low_significand_fpcr_single", source: 0, destination: 7, value: values[0], fpcr: "40" },
  { name: "fp0_to_fp7_low_significand_fpcr_double", source: 0, destination: 7, value: values[0], fpcr: "80" },
);
const strict = [
  { name: "fp0_to_fp1_strict", extra: "0080" },
  { name: "fp7_to_fp0_strict", extra: "1c00" },
  { name: "fp7_self_alias_strict", extra: "1f80" },
] as const;
function prefs(path: string, disk: string) { writeFileSync(path, [`rom ${rom}`, `disk ${disk}`, "ramsize 8388608", "modelid 14", "cpu 4", "fpu true", "jit true", "jitfpu true", "jitcachesize 8192", "screen win/640/480", "nosound true", "nocdrom true", "nogui true", "ignoresegv true", ""].join("\n")); }
function words(value: string) { return value.replaceAll(" ", "").match(/.{8}/g)!.join(" "); }
function field(dump: string | undefined, name: string) { return dump?.match(new RegExp(` ${name}=([0-9a-f]+)`, "i"))?.[1].toLowerCase(); }
function expectedSource(item: Case) { return item.source === item.destination ? item.value.copied : item.value.ext; }

const diskDir = mkdtempSync(join(tmpdir(), "fpp-register-move-disk-"));
const clone = spawnSync("bash", ["-c", "set -euo pipefail\nsource \"$1\"\ncow_clone \"$2\" \"$3/disk.img\" fpp-register-move", "bash", cowLib, diskSource, diskDir], { encoding: "utf8" });
if (clone.status !== 0) throw new Error(clone.stderr || "CoW clone failed");
const disk = clone.stdout.trim().split("\n").at(-1)!;
const selectedCases = process.env.CASE ? cases.filter((item) => item.name === process.env.CASE) : cases;
const selectedStrict = process.env.CASE ? strict.filter((item) => item.name === process.env.CASE) : strict;
let servicePass = 0, strictPass = 0, fail = 0;
try {
  if (!selectedCases.length && !selectedStrict.length) throw new Error(`unknown CASE=${process.env.CASE}`);
  for (const item of selectedCases) {
    const td = mkdtempSync(join(tmpdir(), "fpp-register-move-service-"));
    try {
      prefs(join(td, "prefs"), disk);
      const extra = ((item.source << 10) | (item.destination << 7)).toString(16).padStart(4, "0");
      const sourceStore = (0x6800 | (item.source << 7)).toString(16).padStart(4, "0");
      const destinationStore = (0x6800 | (item.destination << 7)).toString(16).padStart(4, "0");
      const env: Record<string, string> = {
        ...process.env as Record<string, string>, SDL_VIDEODRIVER: "x11", DISPLAY: display, HOME: td,
        B2_TEST_HEX: `${nops} F200 ${extra} F206 A800 F239 ${sourceStore} 0000 A020 F239 ${destinationStore} 0000 A030 2C7C A6C6 1000`,
        B2_TEST_INIT: `${base.join(" ")} 271f`, B2_TEST_MEMORY_BYTES: "a020 00 a030 00",
        B2_TEST_MEMDUMP: "0xa020:12 0xa030:12", B2_TEST_DUMP: "1", B2_TEST_DUMP_FP: "1",
        B2_JIT_FORCE_TRANSLATE: "1", B2_TEST_TWO_PASS: "1", B2_TEST_SECOND_PC: "0x1008", B2_TEST_REPLAY_COUNT: "2", B2_TEST_FORCE_L2_RAM: "1",
        B2_TEST_REPLAY_FPCR: item.fpcr ?? "0", B2_TEST_REPLAY_FPSR: "0c55ff08", B2_NATIVE_ASSERT_PC: "0x1008",
      };
      for (let reg = 0; reg < 8; reg++) env[`B2_TEST_REPLAY_FP${reg}_EXT`] = words(values[reg].ext);
      const run = spawnSync("timeout", ["-k", "5s", "30s", bin, "--config", join(td, "prefs")], { encoding: "utf8", timeout: 35_000, env });
      const output = `${run.stdout ?? ""}${run.stderr ?? ""}`;
      const dump = output.match(/^REGDUMP:.*$/m)?.[0];
      const mem = [...output.matchAll(/^MEMDUMP [^:]+:(.*)$/gm)].map((match) => match[1].trim().toLowerCase());
      const integerPreserved = [0,1,2,3,4,5,7].every((reg) => field(dump, `D${reg}`) === base[reg]) &&
        [0,1,2,3,4,5,7].every((reg) => field(dump, `A${reg}`) === base[8 + reg]);
      const native = output.includes("NATEXEC pc=00001008");
      const fallback = output.includes("JIT_FALLBACK op=f200 pc=00001008");
      const ok = run.status === 0 && mem[0] === expectedSource(item) && mem[1] === item.value.copied &&
        field(dump, "D6") === item.value.fpsr && field(dump, "FPSR") === item.value.finalFpsr && field(dump, "SR") === "271f" &&
        integerPreserved && native && fallback && !output.includes("Caught SIGSEGV");
      if (ok) servicePass++;
      else {
        fail++;
        console.error(`FPP_REGISTER_MOVE_FAIL case=${item.name} rc=${run.status} source=${mem[0]} want_source=${expectedSource(item)} destination=${mem[1]} want_destination=${item.value.copied} snap=${field(dump,"D6")} want_snap=${item.value.fpsr} fpsr=${field(dump,"FPSR")} want_fpsr=${item.value.finalFpsr} int=${integerPreserved?1:0} native=${native?1:0} fallback=${fallback?1:0}`);
        for (const line of output.split("\n").filter((text) => /REGDUMP|MEMDUMP|NATEXEC|fallback|Caught/.test(text)).slice(-20)) console.error(line);
      }
    } finally { rmSync(td, { recursive: true, force: true }); }
  }
  for (const item of selectedStrict) {
    const td = mkdtempSync(join(tmpdir(), "fpp-register-move-strict-"));
    try {
      prefs(join(td, "prefs"), disk);
      const run = spawnSync("timeout", ["-k", "5s", "30s", bin, "--config", join(td, "prefs")], { encoding: "utf8", timeout: 35_000, env: { ...process.env, SDL_VIDEODRIVER: "x11", DISPLAY: display, HOME: td, B2_TEST_HEX: `F200 ${item.extra} 2C7C A6C6 0001`, B2_TEST_INIT: `${base.join(" ")} 271f`, B2_TEST_DUMP: "1", B2_JIT_FORCE_TRANSLATE: "1", B2_TEST_FORCE_L2_RAM: "1", B2_JIT_STRICT_FULL: "1" } });
      const output = `${run.stdout ?? ""}${run.stderr ?? ""}`;
      if (run.status !== 0 && output.includes("strict full-JIT: opcode fallback pc=00001000 op=f200") && !output.includes("NATEXEC pc=00001000")) strictPass++;
      else { fail++; console.error(`FPP_REGISTER_MOVE_FAIL strict=${item.name}`); }
    } finally { rmSync(td, { recursive: true, force: true }); }
  }
} finally {
  spawnSync("bash", ["-c", "source \"$1\"; cow_release \"$2\"", "bash", cowLib, disk]);
  rmSync(diskDir, { recursive: true, force: true });
}
const expectedService = process.env.CASE ? selectedCases.length : 66;
const expectedStrict = process.env.CASE ? selectedStrict.length : 3;
console.log(`FPP_REGISTER_MOVE_MATRIX service_pass=${servicePass} strict_pass=${strictPass} fail=${fail} total=${servicePass + strictPass + fail}`);
process.exit(fail === 0 && servicePass === expectedService && strictPass === expectedStrict ? 0 : 1);
