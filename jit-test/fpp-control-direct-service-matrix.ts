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
const initial = [
  "11111111", "22222222", "33333333", "44444444",
  "55555555", "13579bdf", "abcdefab", "deadbeef",
  "0000a000", "99999999", "aaaaaaaa", "bbbbbbbb",
  "cccccccc", "2468ace0", "dddddddd", "007fe000",
];
const init = `${initial.join(" ")} 271f`;

type Case = {
  name: string;
  stream: string;
  auditedOpcode: string;
  expected: Record<string, string>;
  replayFpcr?: string;
  replayFpsr?: string;
};

/* Every audited instruction starts at 0x1008.  FPIAR reads use the trace pass
 * to seed state with the immediately preceding legal transfer, because FPIAR
 * deliberately has no test-only replay hook. */
const nops = "4E71 4E71 4E71 4E71";
const cases: Case[] = [
  { name: "fpcr_to_d7_masks_68040", stream: `${nops} F207 B000 2C7C A6C0 0001`, auditedOpcode: "f207", replayFpcr: "deadbeef", expected: { D7: "0000beef" } },
  { name: "d7_to_fpcr_then_d1", stream: `${nops} F207 9000 F201 B000 2C7C A6C0 0002`, auditedOpcode: "f207", expected: { D1: "0000beef", D7: "deadbeef" } },
  { name: "immediate_to_fpcr_then_d2", stream: `${nops} F23C 9000 1234 FFB0 F202 B000 2C7C A6C0 0003`, auditedOpcode: "f23c", expected: { D2: "0000ffb0" } },
  { name: "fpsr_to_d6_masks_reserved_bits", stream: `${nops} F206 A800 2C7C A6C0 0004`, auditedOpcode: "f206", replayFpsr: "abcdefab", expected: { D6: "0bcdefa8" }, },
  { name: "d6_to_fpsr_then_d0", stream: `${nops} F206 8800 F200 A800 2C7C A6C0 0005`, auditedOpcode: "f206", expected: { D0: "0bcdefa8", D6: "abcdefab" } },
  { name: "immediate_to_fpsr_then_d3", stream: `${nops} F23C 8800 89AB CDEF F203 A800 2C7C A6C0 0006`, auditedOpcode: "f23c", expected: { D3: "09abcde8" } },
  { name: "fpiar_to_d5_full_width", stream: `F23C 8400 CAFE BABE F205 A400 2C7C A6C0 0007`, auditedOpcode: "f205", expected: { D5: "cafebabe" } },
  { name: "fpiar_to_a7_full_width", stream: `F23C 8400 1020 3040 F20F A400 2C7C A6C0 0008`, auditedOpcode: "f20f", expected: { A7: "10203040" } },
  { name: "d5_to_fpiar_then_d4", stream: `${nops} F205 8400 F204 A400 2C7C A6C0 0009`, auditedOpcode: "f205", expected: { D4: "13579bdf", D5: "13579bdf" } },
  { name: "a5_to_fpiar_then_d4", stream: `${nops} F20D 8400 F204 A400 2C7C A6C0 000A`, auditedOpcode: "f20d", expected: { D4: "2468ace0", A5: "2468ace0" } },
  { name: "immediate_to_fpiar_then_d4", stream: `${nops} F23C 8400 FEDC BA98 F204 A400 2C7C A6C0 000B`, auditedOpcode: "f23c", expected: { D4: "fedcba98" } },
];

const strict = [
  { name: "fpcr_to_d7_strict", stream: "F207 B000 2C7C A6C0 0101", opcode: "f207" },
  { name: "d7_to_fpsr_strict", stream: "F207 8800 2C7C A6C0 0102", opcode: "f207" },
  { name: "a7_to_fpiar_strict", stream: "F20F 8400 2C7C A6C0 0103", opcode: "f20f" },
  { name: "immediate_to_fpiar_strict", stream: "F23C 8400 1234 5678 2C7C A6C0 0104", opcode: "f23c" },
] as const;

function prefs(path: string, disk: string) {
  writeFileSync(path, [
    `rom ${rom}`, `disk ${disk}`, "ramsize 8388608", "modelid 14", "cpu 4",
    "fpu true", "jit true", "jitfpu true", "jitcachesize 8192",
    "screen win/640/480", "nosound true", "nocdrom true", "nogui true", "ignoresegv true", "",
  ].join("\n"));
}
function field(dump: string | undefined, name: string) {
  return dump?.match(new RegExp(` ${name}=([0-9a-f]+)`, "i"))?.[1].toLowerCase();
}

const diskDir = mkdtempSync(join(tmpdir(), "fpp-control-direct-disk-"));
const clone = spawnSync("bash", ["-c", "set -euo pipefail\nsource \"$1\"\ncow_clone \"$2\" \"$3/disk.img\" fpp-control-direct", "bash", cowLib, diskSource, diskDir], { encoding: "utf8" });
if (clone.status !== 0) {
  console.error(clone.stderr || "FPP_CONTROL_DIRECT_FAIL clone");
  rmSync(diskDir, { recursive: true, force: true });
  process.exit(1);
}
const disk = clone.stdout.trim().split("\n").at(-1)!;
const selectedCases = process.env.CASE ? cases.filter((item) => item.name === process.env.CASE) : cases;
const selectedStrict = process.env.CASE ? strict.filter((item) => item.name === process.env.CASE) : strict;
let servicePass = 0, strictPass = 0, fail = 0;
try {
  if (!selectedCases.length && !selectedStrict.length) throw new Error(`unknown CASE=${process.env.CASE}`);
  for (const item of selectedCases) {
    const td = mkdtempSync(join(tmpdir(), "fpp-control-direct-service-"));
    try {
      prefs(join(td, "prefs"), disk);
      const run = spawnSync("timeout", ["-k", "5s", "30s", bin, "--config", join(td, "prefs")], {
        encoding: "utf8", timeout: 35000,
        env: {
          ...process.env, SDL_VIDEODRIVER: "x11", DISPLAY: display, HOME: td,
          B2_TEST_HEX: item.stream, B2_TEST_INIT: init, B2_TEST_DUMP: "1",
          B2_JIT_FORCE_TRANSLATE: "1", B2_TEST_TWO_PASS: "1", B2_TEST_SECOND_PC: "0x1008",
          B2_TEST_REPLAY_COUNT: "2", B2_TEST_FORCE_L2_RAM: "1",
          B2_TEST_REPLAY_FPCR: item.replayFpcr ?? "0", B2_TEST_REPLAY_FPSR: item.replayFpsr ?? "0",
          B2_NATIVE_ASSERT_PC: "0x1008",
        },
      });
      const output = `${run.stdout ?? ""}${run.stderr ?? ""}`;
      const dump = output.match(/^REGDUMP:.*$/m)?.[0];
      const registersMatch = Object.entries(item.expected).every(([reg, value]) => field(dump, reg) === value);
      const sr = field(dump, "SR");
      const native = output.includes("NATEXEC pc=00001008");
      const fallback = output.includes(`JIT_FALLBACK op=${item.auditedOpcode} pc=00001008`);
      if (run.status === 0 && registersMatch && sr === "271f" && native && fallback && !output.includes("Caught SIGSEGV")) {
        servicePass++;
      } else {
        fail++;
        console.error(`FPP_CONTROL_DIRECT_FAIL case=${item.name} rc=${run.status} regs=${registersMatch ? 1 : 0} sr=${sr} native=${native ? 1 : 0} fallback=${fallback ? 1 : 0}`);
        if (dump) console.error(dump);
        if (process.env.VERBOSE) console.error(output);
      }
    } finally {
      rmSync(td, { recursive: true, force: true });
    }
  }
  for (const item of selectedStrict) {
    const td = mkdtempSync(join(tmpdir(), "fpp-control-direct-strict-"));
    try {
      prefs(join(td, "prefs"), disk);
      const run = spawnSync("timeout", ["-k", "5s", "30s", bin, "--config", join(td, "prefs")], {
        encoding: "utf8", timeout: 35000,
        env: {
          ...process.env, SDL_VIDEODRIVER: "x11", DISPLAY: display, HOME: td,
          B2_TEST_HEX: item.stream, B2_TEST_INIT: init, B2_TEST_DUMP: "1",
          B2_JIT_FORCE_TRANSLATE: "1", B2_TEST_FORCE_L2_RAM: "1", B2_JIT_STRICT_FULL: "1",
        },
      });
      const output = `${run.stdout ?? ""}${run.stderr ?? ""}`;
      if (run.status !== 0 && output.includes(`strict full-JIT: opcode fallback pc=00001000 op=${item.opcode}`) && !output.includes("NATEXEC pc=00001000")) {
        strictPass++;
      } else {
        fail++;
        console.error(`FPP_CONTROL_DIRECT_FAIL strict=${item.name} rc=${run.status}`);
        if (process.env.VERBOSE) console.error(output);
      }
    } finally {
      rmSync(td, { recursive: true, force: true });
    }
  }
} finally {
  spawnSync("bash", ["-c", "source \"$1\"; cow_release \"$2\"", "bash", cowLib, disk]);
  rmSync(diskDir, { recursive: true, force: true });
}
const expectedService = process.env.CASE ? selectedCases.length : 11;
const expectedStrict = process.env.CASE ? selectedStrict.length : 4;
console.log(`FPP_CONTROL_DIRECT_MATRIX service_pass=${servicePass} strict_pass=${strictPass} fail=${fail} total=${servicePass + strictPass + fail}`);
process.exit(fail === 0 && servicePass === expectedService && strictPass === expectedStrict ? 0 : 1);
