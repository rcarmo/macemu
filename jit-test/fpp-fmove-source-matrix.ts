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
const zeroInit = "0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 007fe000 271F";

type FmoveCase = {
  name: string;
  stream: string;
  anchor: number;
  fp: string;
  fpsr: string;
  fpReg?: number;
  initD0?: string;
  initD7?: string;
  fpExpected?: Record<number, string>;
};

const cases: FmoveCase[] = [
  { name: "dn_byte_negative", stream: "F200 5800", initD0: "00000080", anchor: 0x1000, fp: "c060000000000000", fpsr: "08000000" },
  { name: "dn_byte_positive", stream: "F200 5800", initD0: "0000007f", anchor: 0x1000, fp: "405fc00000000000", fpsr: "00000000" },
  { name: "dn_word_negative", stream: "F200 5000", initD0: "00008000", anchor: 0x1000, fp: "c0e0000000000000", fpsr: "08000000" },
  { name: "dn_word_positive", stream: "F200 5000", initD0: "00007fff", anchor: 0x1000, fp: "40dfffc000000000", fpsr: "00000000" },
  { name: "dn_long_negative", stream: "F200 4000", initD0: "80000000", anchor: 0x1000, fp: "c1e0000000000000", fpsr: "08000000" },
  { name: "dn_long_positive", stream: "F200 4000", initD0: "7fffffff", anchor: 0x1000, fp: "41dfffffffc00000", fpsr: "00000000" },
  { name: "dn_single_negative_zero", stream: "F200 4400", initD0: "80000000", anchor: 0x1000, fp: "8000000000000000", fpsr: "0c000000" },
  { name: "dn_single_positive_inf", stream: "F200 4400", initD0: "7f800000", anchor: 0x1000, fp: "7ff0000000000000", fpsr: "02000000" },
  { name: "imm_byte_negative", stream: "F23C 5800 0080", anchor: 0x1000, fp: "c060000000000000", fpsr: "08000000" },
  { name: "imm_word_negative", stream: "F23C 5000 8000", anchor: 0x1000, fp: "c0e0000000000000", fpsr: "08000000" },
  { name: "imm_long_negative", stream: "F23C 4000 8000 0000", anchor: 0x1000, fp: "c1e0000000000000", fpsr: "08000000" },
  { name: "imm_single_fraction", stream: "F23C 4400 3FC0 0000", anchor: 0x1000, fp: "3ff8000000000000", fpsr: "00000000" },
  { name: "imm_double_fraction", stream: "F23C 5400 BFF8 0000 0000 0000", anchor: 0x1000, fp: "bff8000000000000", fpsr: "08000000" },
  { name: "fp1_to_fp0", stream: "F23C 4480 3FC0 0000 F200 0400", anchor: 0x1008, fp: "3ff8000000000000", fpsr: "00000000" },
  { name: "fp0_self_alias", stream: "F23C 4400 BFC0 0000 F200 0000", anchor: 0x1008, fp: "bff8000000000000", fpsr: "08000000" },
  { name: "fp7_self_alias_max", stream: "F23C 4780 3FC0 0000 F200 1F80", anchor: 0x1008, fp: "3ff8000000000000", fpsr: "00000000", fpReg: 7 },
  { name: "dn_byte_min", stream: "F200 5800", initD0: "ffffff80", anchor: 0x1000, fp: "c060000000000000", fpsr: "08000000" },
  { name: "dn_word_min", stream: "F200 5000", initD0: "ffff8000", anchor: 0x1000, fp: "c0e0000000000000", fpsr: "08000000" },
  { name: "dn_long_minus_one", stream: "F200 4000", initD0: "ffffffff", anchor: 0x1000, fp: "bff0000000000000", fpsr: "08000000" },
  { name: "dn_single_negative_inf", stream: "F200 4400", initD0: "ff800000", anchor: 0x1000, fp: "fff0000000000000", fpsr: "0a000000" },
  { name: "dn_single_positive_nan", stream: "F200 4400", initD0: "7fc00001", anchor: 0x1000, fp: "7ff8000020000000", fpsr: "01000000" },
  { name: "imm_byte_positive", stream: "F23C 5800 007F", anchor: 0x1000, fp: "405fc00000000000", fpsr: "00000000" },
  { name: "imm_word_positive", stream: "F23C 5000 7FFF", anchor: 0x1000, fp: "40dfffc000000000", fpsr: "00000000" },
  { name: "imm_long_positive", stream: "F23C 4000 7FFF FFFF", anchor: 0x1000, fp: "41dfffffffc00000", fpsr: "00000000" },
  { name: "imm_single_negative_zero", stream: "F23C 4400 8000 0000", anchor: 0x1000, fp: "8000000000000000", fpsr: "0c000000" },
  { name: "imm_single_negative_nan", stream: "F23C 4400 FFC0 0001", anchor: 0x1000, fp: "fff8000020000000", fpsr: "09000000" },
  { name: "imm_double_negative_inf", stream: "F23C 5400 FFF0 0000 0000 0000", anchor: 0x1000, fp: "fff0000000000000", fpsr: "0a000000" },
  { name: "fp0_to_fp7_max", stream: "F23C 4400 4020 0000 F200 0380", anchor: 0x1008, fp: "4004000000000000", fpsr: "00000000", fpReg: 7 },
  { name: "fp7_to_fp0_max", stream: "F23C 4780 C020 0000 F200 1C00", anchor: 0x1008, fp: "c004000000000000", fpsr: "08000000" },
  { name: "dn_byte_d7_max_field", stream: "F207 5B80", initD7: "00000080", anchor: 0x1000, fp: "c060000000000000", fpsr: "08000000", fpReg: 7 },
  { name: "dn_word_d7_max_field", stream: "F207 5380", initD7: "00008000", anchor: 0x1000, fp: "c0e0000000000000", fpsr: "08000000", fpReg: 7 },
  { name: "dn_long_d7_max_field", stream: "F207 4380", initD7: "80000000", anchor: 0x1000, fp: "c1e0000000000000", fpsr: "08000000", fpReg: 7 },
  { name: "dn_single_d7_max_field", stream: "F207 4780", initD7: "7F800000", anchor: 0x1000, fp: "7ff0000000000000", fpsr: "02000000", fpReg: 7 },
  { name: "imm_double_fp7_max_field", stream: "F23C 5780 4004 0000 0000 0000", anchor: 0x1000, fp: "4004000000000000", fpsr: "00000000", fpReg: 7 },
];

const fpRouteValues = [
  { words: "3F80 0000", bits: "3ff0000000000000", fpsr: "00000000" },
  { words: "3FC0 0000", bits: "3ff8000000000000", fpsr: "00000000" },
  { words: "4000 0000", bits: "4000000000000000", fpsr: "00000000" },
  { words: "4020 0000", bits: "4004000000000000", fpsr: "00000000" },
  { words: "BF80 0000", bits: "bff0000000000000", fpsr: "08000000" },
  { words: "BFC0 0000", bits: "bff8000000000000", fpsr: "08000000" },
  { words: "7F80 0000", bits: "7ff0000000000000", fpsr: "02000000" },
  { words: "8000 0000", bits: "8000000000000000", fpsr: "0c000000" },
];
for (let source = 0; source < 8; source++) {
  const destination = (source + 3) & 7;
  const initExtra = (0x4400 | (source << 7)).toString(16).padStart(4, "0");
  const moveExtra = ((source << 10) | (destination << 7)).toString(16).padStart(4, "0");
  const value = fpRouteValues[source];
  cases.push({
    name: `fp${source}_to_fp${destination}_field_route`,
    stream: `F23C ${initExtra} ${value.words} F200 ${moveExtra}`,
    anchor: 0x1008,
    fp: value.bits,
    fpsr: value.fpsr,
    fpReg: destination,
    fpExpected: { [source]: value.bits, [destination]: value.bits },
  });
}

const allLiveInitializers = fpRouteValues.map((value, reg) =>
  `F23C ${(0x4400 | (reg << 7)).toString(16).padStart(4, "0")} ${value.words}`,
).join(" ");
cases.push({
  name: "fp_all_live_fp0_to_fp7",
  stream: `${allLiveInitializers} F200 0380`,
  anchor: 0x1040,
  fp: fpRouteValues[0].bits,
  fpsr: fpRouteValues[0].fpsr,
  fpReg: 7,
  fpExpected: Object.fromEntries(fpRouteValues.map((value, reg) =>
    [reg, reg === 7 ? fpRouteValues[0].bits : value.bits],
  )),
});

const diskDir = mkdtempSync(join(tmpdir(), "fpp-fmove-source-disk-"));
const clone = spawnSync("bash", ["-c", [
  "set -euo pipefail",
  "source \"$1\"",
  "cow_clone \"$2\" \"$3/disk.img\" fpp-fmove-source",
].join("\n"), "bash", cowLib, diskSource, diskDir], { encoding: "utf8" });
if (clone.status !== 0) {
  console.error(clone.stderr || "FPP_FMOVE_SOURCE_FAIL unable to create isolated disk clone");
  process.exit(1);
}
const disk = clone.stdout.trim().split("\n").at(-1)!;

let pass = 0;
let fail = 0;
const selectedCases = process.env.CASE
  ? cases.filter((item) => item.name === process.env.CASE)
  : cases;
if (selectedCases.length === 0) throw new Error(`unknown CASE=${process.env.CASE}`);
try {
  for (const item of selectedCases) {
    const td = mkdtempSync(join(tmpdir(), "fpp-fmove-source-"));
    try {
      const prefs = join(td, "prefs");
      writeFileSync(prefs, [
        `rom ${rom}`, `disk ${disk}`, "ramsize 8388608", "modelid 14", "cpu 4",
        "fpu true", "jit true", "jitfpu true", "jitcachesize 8192",
        "screen win/640/480", "nosound true", "nocdrom true", "nogui true",
        "ignoresegv true", "",
      ].join("\n"));
      const initWords = zeroInit.split(" ");
      if (item.initD0) initWords[0] = item.initD0;
      if (item.initD7) initWords[7] = item.initD7;
      const init = initWords.join(" ");
      const anchorHex = `0x${item.anchor.toString(16)}`;
      const run = spawnSync("timeout", ["-k", "5s", "30s", bin, "--config", prefs], {
        encoding: "utf8",
        timeout: 35_000,
        env: {
          ...process.env,
          SDL_VIDEODRIVER: "x11", DISPLAY: display, HOME: td,
          B2_TEST_HEX: `${item.stream} 2C7C A6FE ${pass.toString(16).padStart(4, "0")}`,
          B2_TEST_INIT: init, B2_TEST_DUMP: "1", B2_TEST_DUMP_FP: "1",
          B2_JIT_FORCE_TRANSLATE: "1",
          B2_TEST_TWO_PASS: "1", B2_TEST_SECOND_PC: anchorHex,
          B2_TEST_REPLAY_COUNT: "2", B2_TEST_FORCE_L2_RAM: "1",
          B2_JIT_STRICT_FULL: "1", B2_NATIVE_ASSERT_PC: anchorHex,
        },
      });
      const output = `${run.stdout ?? ""}${run.stderr ?? ""}`;
      const dump = output.match(/^REGDUMP:.*$/m)?.[0];
      const fpReg = item.fpReg ?? 0;
      const fp = dump?.match(new RegExp(` FP${fpReg}=([0-9a-f]+)`, "i"))?.[1].toLowerCase();
      const fpExpected = item.fpExpected ?? { [fpReg]: item.fp };
      const fpRegistersMatch = Object.entries(fpExpected).every(([reg, expected]) =>
        dump?.match(new RegExp(` FP${reg}=([0-9a-f]+)`, "i"))?.[1].toLowerCase() === expected,
      );
      const fpsr = dump?.match(/ FPSR=([0-9a-f]+)/i)?.[1].toLowerCase();
      const sr = dump?.match(/ SR=([0-9a-f]+)/i)?.[1].toLowerCase();
      const nativePc = item.anchor.toString(16).padStart(8, "0");
      const native = output.includes(`NATEXEC pc=${nativePc}`);
      const strict = output.includes("JIT_STRICT_SUMMARY ") &&
        !output.includes("strict full-JIT:") && !output.includes("JIT_FALLBACK");
      if (run.status === 0 && fp === item.fp && fpRegistersMatch && fpsr === item.fpsr && sr === "271f" && native && strict) {
        pass++;
      } else {
        fail++;
        console.error(
          `FPP_FMOVE_SOURCE_FAIL case=${item.name} rc=${run.status} fp=${fp} want_fp=${item.fp} ` +
          `fp_regs=${fpRegistersMatch ? 1 : 0} fpsr=${fpsr} want_fpsr=${item.fpsr} ` +
          `sr=${sr} native=${native ? 1 : 0} strict=${strict ? 1 : 0}`,
        );
        const diagnosticLines = process.env.VERBOSE
          ? output.split("\n")
          : output.split("\n").filter((text) =>
              /REGDUMP|Caught|strict full-JIT|unsupported|NATEXEC|JIT_STRICT/.test(text)).slice(-12);
        for (const line of diagnosticLines) console.error(line);
      }
    } finally {
      rmSync(td, { recursive: true, force: true });
    }
  }
} finally {
  spawnSync("bash", ["-c", "source \"$1\"; cow_release \"$2\"", "bash", cowLib, disk]);
  rmSync(diskDir, { recursive: true, force: true });
}

console.log(`FPP_FMOVE_SOURCE_MATRIX pass=${pass} fail=${fail} total=${pass + fail}`);
const expectedTotal = process.env.CASE ? 1 : 43;
process.exit(fail === 0 && pass === expectedTotal && selectedCases.length === expectedTotal ? 0 : 1);
