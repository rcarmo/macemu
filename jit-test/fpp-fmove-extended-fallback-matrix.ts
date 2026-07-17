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
const zeroInit = "0 0 0 0 0 0 0 0 0000a000 0 0 0 0 0 0 007fe000 271f";

type ServiceCase = { name: string; words: string };
const serviceCases: ServiceCase[] = [
  { name: "positive_one", words: "3f ff 00 00 80 00 00 00 00 00 00 00" },
  { name: "negative_one", words: "bf ff 00 00 80 00 00 00 00 00 00 00" },
  { name: "fraction_low_bit_beyond_binary64", words: "3f ff 00 00 80 00 00 00 00 00 00 01" },
  { name: "fraction_all_64_bits", words: "40 00 00 00 ff ff ff ff ff ff ff ff" },
  { name: "maximum_finite", words: "7f fe 00 00 ff ff ff ff ff ff ff ff" },
  { name: "minimum_normal", words: "00 01 00 00 80 00 00 00 00 00 00 00" },
  { name: "positive_zero", words: "00 00 00 00 00 00 00 00 00 00 00 00" },
  { name: "negative_zero", words: "80 00 00 00 00 00 00 00 00 00 00 00" },
];
const strictCases = [
  { name: "immediate_source", stream: "F23C 4800 3FFF 0000 8000 0000 0000 0001", anchor: 0x1000 },
  { name: "postinc_source", stream: "F218 4800", anchor: 0x1000, memory: serviceCases[2].words },
  { name: "postinc_destination", stream: "F23C 4400 3F80 0000 F218 6800", anchor: 0x1008 },
  { name: "predec_destination", stream: "F23C 4400 3F80 0000 F220 6800", anchor: 0x1008, init: zeroInit.replace("0000a000", "0000a00c") },
] as const;

function memoryBytes(address: number, bytes: string): string {
  return bytes.split(/\s+/).map((byte, index) => `${(address + index).toString(16)} ${byte}`).join(" ");
}
function prefs(path: string, disk: string) {
  writeFileSync(path, [
    `rom ${rom}`, `disk ${disk}`, "ramsize 8388608", "modelid 14", "cpu 4",
    "fpu true", "jit true", "jitfpu true", "jitcachesize 8192",
    "screen win/640/480", "nosound true", "nocdrom true", "nogui true",
    "ignoresegv true", "",
  ].join("\n"));
}

const diskDir = mkdtempSync(join(tmpdir(), "fpp-fmove-extended-fallback-disk-"));
const clone = spawnSync("bash", ["-c", [
  "set -euo pipefail", "source \"$1\"",
  "cow_clone \"$2\" \"$3/disk.img\" fpp-fmove-extended-fallback",
].join("\n"), "bash", cowLib, diskSource, diskDir], { encoding: "utf8" });
if (clone.status !== 0) {
  console.error(clone.stderr || "FPP_FMOVE_EXTENDED_FALLBACK_FAIL unable to create isolated disk clone");
  process.exit(1);
}
const disk = clone.stdout.trim().split("\n").at(-1)!;
const selectedService = process.env.CASE ? serviceCases.filter((item) => item.name === process.env.CASE) : serviceCases;
const selectedStrict = process.env.CASE ? strictCases.filter((item) => item.name === process.env.CASE) : strictCases;
if (selectedService.length + selectedStrict.length === 0) throw new Error(`unknown CASE=${process.env.CASE}`);
let servicePass = 0;
let strictPass = 0;
let fail = 0;
try {
  for (const item of selectedService) {
    const td = mkdtempSync(join(tmpdir(), "fpp-fmove-extended-service-"));
    try {
      const pref = join(td, "prefs"); prefs(pref, disk);
      const input = item.words.split(/\s+/).map((byte, index) => `${(0x9000 + index).toString(16)} ${byte}`).join(" ");
      const guard = "9ffe a5 9fff 5a a000 00 a001 00 a002 00 a003 00 a004 00 a005 00 a006 00 a007 00 a008 00 a009 00 a00a 00 a00b 00 a00c 3c a00d c3";
      // FMOVE.X ($9000).L,FP0; FMOVE.X FP0,(A0)
      const run = spawnSync("timeout", ["-k", "5s", "30s", bin, "--config", pref], {
        encoding: "utf8", timeout: 35_000,
        env: {
          ...process.env, SDL_VIDEODRIVER: "x11", DISPLAY: display, HOME: td,
          B2_TEST_HEX: "F239 4800 0000 9000 F210 6800 2C7C A6F7 0000",
          B2_TEST_INIT: zeroInit, B2_TEST_MEMORY_BYTES: `${input} ${guard}`,
          B2_TEST_MEMDUMP: "0x9ffe:16", B2_TEST_DUMP: "1", B2_TEST_DUMP_FP: "1",
          B2_JIT_FORCE_TRANSLATE: "1", B2_TEST_TWO_PASS: "1",
          B2_TEST_SECOND_PC: "0x1000", B2_TEST_REPLAY_COUNT: "2", B2_TEST_FORCE_L2_RAM: "1",
        },
      });
      const output = `${run.stdout ?? ""}${run.stderr ?? ""}`;
      const mem = output.match(/^MEMDUMP [^:]+:(.*)$/m)?.[1].trim().toLowerCase();
      const expected = `a5 5a ${item.words.toLowerCase()} 3c c3`;
      const dump = output.match(/^REGDUMP:.*$/m)?.[0];
      const a0 = dump?.match(/ A0=([0-9a-f]+)/i)?.[1].toLowerCase();
      const sr = dump?.match(/ SR=([0-9a-f]+)/i)?.[1].toLowerCase();
      const serviced = output.includes("JIT_FALLBACK") && !output.includes("Caught SIGSEGV");
      if (run.status === 0 && mem === expected && a0 === "0000a000" && sr === "271f" && serviced) servicePass++;
      else {
        fail++;
        console.error(`FPP_FMOVE_EXTENDED_FALLBACK_FAIL case=${item.name} phase=service rc=${run.status} mem=${mem} want_mem=${expected} a0=${a0} sr=${sr} serviced=${serviced ? 1 : 0}`);
        for (const line of output.split("\n").filter((text) => /REGDUMP|MEMDUMP|Caught|JIT_FALLBACK|unsupported/.test(text)).slice(-15)) console.error(line);
      }
    } finally { rmSync(td, { recursive: true, force: true }); }
  }

  for (const item of selectedStrict) {
    const td = mkdtempSync(join(tmpdir(), "fpp-fmove-extended-strict-"));
    try {
      const pref = join(td, "prefs"); prefs(pref, disk);
      const run = spawnSync("timeout", ["-k", "5s", "30s", bin, "--config", pref], {
        encoding: "utf8", timeout: 35_000,
        env: {
          ...process.env, SDL_VIDEODRIVER: "x11", DISPLAY: display, HOME: td,
          B2_TEST_HEX: `${item.stream} 2C7C A6F8 0000`, B2_TEST_INIT: item.init ?? zeroInit,
          B2_TEST_MEMORY_BYTES: item.memory ? memoryBytes(0xa000, item.memory) : "a000 a5 a001 5a",
          B2_TEST_DUMP: "1", B2_TEST_DUMP_FP: "1", B2_JIT_FORCE_TRANSLATE: "1",
          B2_TEST_TWO_PASS: "1", B2_TEST_SECOND_PC: `0x${item.anchor.toString(16)}`,
          B2_TEST_REPLAY_COUNT: "2", B2_TEST_FORCE_L2_RAM: "1", B2_JIT_STRICT_FULL: "1",
        },
      });
      const output = `${run.stdout ?? ""}${run.stderr ?? ""}`;
      const rejected = output.includes("strict full-JIT: opcode fallback");
      const noNative = !output.includes(`NATEXEC pc=${item.anchor.toString(16).padStart(8, "0")}`) && !output.includes("JIT_STRICT_SUMMARY ");
      const noSegv = !output.includes("Caught SIGSEGV");
      if (run.status !== 0 && rejected && noNative && noSegv) strictPass++;
      else {
        fail++;
        console.error(`FPP_FMOVE_EXTENDED_FALLBACK_FAIL case=${item.name} phase=strict rc=${run.status} rejected=${rejected ? 1 : 0} no_native=${noNative ? 1 : 0} no_segv=${noSegv ? 1 : 0}`);
        for (const line of output.split("\n").filter((text) => /REGDUMP|Caught|strict full-JIT|NATEXEC|JIT_STRICT|JIT_FALLBACK/.test(text)).slice(-15)) console.error(line);
      }
    } finally { rmSync(td, { recursive: true, force: true }); }
  }
} finally {
  spawnSync("bash", ["-c", "source \"$1\"; cow_release \"$2\"", "bash", cowLib, disk]);
  rmSync(diskDir, { recursive: true, force: true });
}
console.log(`FPP_FMOVE_EXTENDED_FALLBACK_MATRIX service_pass=${servicePass} strict_pass=${strictPass} fail=${fail} total=${servicePass + strictPass + fail}`);
const expectedService = process.env.CASE ? selectedService.length : 8;
const expectedStrict = process.env.CASE ? selectedStrict.length : 4;
process.exit(fail === 0 && servicePass === expectedService && strictPass === expectedStrict ? 0 : 1);
