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

const x = {
  pz: "00 00 00 00 00 00 00 00 00 00 00 00",
  nz: "80 00 00 00 00 00 00 00 00 00 00 00",
  p1: "3f ff 00 00 80 00 00 00 00 00 00 00",
  n1: "bf ff 00 00 80 00 00 00 00 00 00 00",
  p2: "40 00 00 00 80 00 00 00 00 00 00 00",
  n2: "c0 00 00 00 80 00 00 00 00 00 00 00",
  p3: "40 00 00 00 c0 00 00 00 00 00 00 00",
  p6: "40 01 00 00 c0 00 00 00 00 00 00 00",
  pinf: "7f ff 00 00 00 00 00 00 00 00 00 00",
  ninf: "ff ff 00 00 00 00 00 00 00 00 00 00",
  qnanA: "7f ff 00 00 c0 00 12 34 56 78 9a bc",
  nqnanB: "ff ff 00 00 c0 00 de ad be ef 12 34",
  snanA: "7f ff 00 00 80 00 12 34 56 78 9a bc",
  nsnanB: "ff ff 00 00 80 00 de ad be ef 12 34",
  quietA: "7f ff 00 00 c0 00 12 34 56 78 9a bc",
  nquietB: "ff ff 00 00 c0 00 de ad be ef 12 34",
  oneThirdExtended: "3f fd 00 00 aa aa aa aa aa aa aa ab",
  oneThirdSingle: "3f fd 00 00 aa aa ab 00 00 00 00 00",
  oneThirdSingleDown: "3f fd 00 00 aa aa aa 00 00 00 00 00",
  oneThirdDouble: "3f fd 00 00 aa aa aa aa aa aa a8 00",
  oneThirdDoubleUp: "3f fd 00 00 aa aa aa aa aa aa b0 00",
  onePlusExtendedUlp: "3f ff 00 00 80 00 00 00 00 00 00 01",
  reciprocalWide: "3f fe 00 00 ff ff ff ff ff ff ff fe",
  maxExtended: "7f fe 00 00 ff ff ff ff ff ff ff ff",
  minNormalExtended: "00 01 00 00 80 00 00 00 00 00 00 00",
} as const;

type Selector = "27";
type ServiceCase = {
  name: string;
  selector: Selector;
  destination: string;
  source: string;
  output: string;
  fpsr: string;
  operationFpsr?: string;
  fpcr?: string;
  replayFpsr?: string;
  destinationSnan?: boolean;
  aliasFp7?: boolean;
  destinationFp7?: boolean;
  ea?: "absolute" | "postinc" | "predec";
  expectedA0?: string;
};

const serviceCases: ServiceCase[] = [
  { name: "fsglmul_exact", selector: "27", destination: x.p2, source: x.p3, output: x.p6, fpsr: "00000000" },
  { name: "fsglmul_extended_destination_one_sided", selector: "27", destination: "3f ff 00 00 c2 1e f2 ae 03 ca e1 4a", source: "3f ff 00 00 87 16 46 0a 3d 4c 66 08", output: "3f ff 00 00 cc de 6b 00 00 00 00 00", fpsr: "00000008" },
  { name: "fsglmul_extended_source_one_sided", selector: "27", destination: "3f ff 00 00 95 fe 6e 0d 7c a7 46 74", source: "3f ff 00 00 bc ba f0 98 8c b1 15 f8", output: "3f ff 00 00 dd 28 c1 00 00 00 00 00", fpsr: "00000008" },
  { name: "fsglmul_double_round_midpoint", selector: "27", destination: "3f ff 00 00 80 00 00 80 80 00 00 81", source: "3f fe 00 00 ff ff ff ff 00 00 00 00", output: "3f ff 00 00 80 00 01 00 00 00 00 00", fpsr: "00000008" },
  { name: "fsglmul_single_nearest_independent_fpcr", selector: "27", destination: x.p1, source: x.onePlusExtendedUlp, output: x.p1, fpcr: "80", fpsr: "00000008" },
  { name: "fsglmul_single_plus", selector: "27", destination: x.p1, source: x.onePlusExtendedUlp, output: "3f ff 00 00 80 00 01 00 00 00 00 00", fpcr: "30", fpsr: "00000008" },
  { name: "fsglmul_negative_minus", selector: "27", destination: x.n1, source: x.onePlusExtendedUlp, output: "bf ff 00 00 80 00 01 00 00 00 00 00", fpcr: "20", fpsr: "08000008" },
  { name: "fsglmul_signed_zero", selector: "27", destination: x.nz, source: x.n2, output: x.pz, fpsr: "04000000" },
  { name: "fsglmul_signed_infinity", selector: "27", destination: x.ninf, source: x.p2, output: x.ninf, fpsr: "0a000000" },
  { name: "fsglmul_zero_infinity_invalid", selector: "27", destination: x.pz, source: x.pinf, output: "7f ff 00 00 ff ff ff ff ff ff ff ff", fpsr: "01000080", operationFpsr: "01002080" },
  { name: "fsglmul_infinity_zero_invalid", selector: "27", destination: x.ninf, source: x.pz, output: "7f ff 00 00 ff ff ff ff ff ff ff ff", fpsr: "01000080", operationFpsr: "01002080" },
  { name: "fsglmul_extended_exponent_no_single_overflow", selector: "27", destination: "7f fe 00 00 80 00 00 00 00 00 00 00", source: x.p1, output: "7f fe 00 00 80 00 00 00 00 00 00 00", fpsr: "00000000" },
  { name: "fsglmul_extended_exponent_no_single_underflow", selector: "27", destination: x.minNormalExtended, source: x.p1, output: x.minNormalExtended, fpsr: "00000000" },
  { name: "fsglmul_destination_qnan", selector: "27", destination: x.qnanA, source: x.pz, output: x.qnanA, fpsr: "01000000" },
  { name: "fsglmul_source_qnan", selector: "27", destination: x.pinf, source: x.nqnanB, output: x.nqnanB, fpsr: "09000000" },
  { name: "fsglmul_source_snan_destination_precedence", selector: "27", destination: x.qnanA, source: x.nsnanB, output: x.qnanA, fpsr: "01000080", operationFpsr: "01004080" },
  { name: "fsglmul_destination_snan_quiet", selector: "27", destination: x.snanA, source: x.p1, output: x.quietA, fpsr: "01000080", operationFpsr: "01004080", destinationSnan: true },
  { name: "fsglmul_fp7_self_alias", selector: "27", destination: x.p2, source: x.p2, output: "40 01 00 00 80 00 00 00 00 00 00 00", fpsr: "00000000", aliasFp7: true },
  { name: "fsglmul_fp7_destination_reseed", selector: "27", destination: x.p2, source: x.p3, output: x.p6, fpsr: "00000000", destinationFp7: true },
  { name: "fsglmul_postincrement_source", selector: "27", destination: x.p2, source: x.p3, output: x.p6, fpsr: "00000000", ea: "postinc", expectedA0: "0000a00c" },
  { name: "fsglmul_predecrement_source", selector: "27", destination: x.p2, source: x.p3, output: x.p6, fpsr: "00000000", ea: "predec", expectedA0: "0000a000" },
  { name: "fsglmul_accrued_preserve", selector: "27", destination: x.p2, source: x.p2, output: "40 01 00 00 80 00 00 00 00 00 00 00", replayFpsr: "0455ff00", fpsr: "00550000" },
];

const strictCases = [
  { name: "fsglmul_strict", extra: "1fa7" },
] as const;

function memoryBytes(address: number, bytes: string): string {
  return bytes.split(/\s+/).map((byte, index) => `${(address + index).toString(16)} ${byte}`).join(" ");
}
function writePrefs(path: string, disk: string) {
  writeFileSync(path, [
    `rom ${rom}`, `disk ${disk}`, "ramsize 8388608", "modelid 14", "cpu 4",
    "fpu true", "jit true", "jitfpu true", "jitcachesize 8192",
    "screen win/640/480", "nosound true", "nocdrom true", "nogui true", "ignoresegv true", "",
  ].join("\n"));
}

const diskDir = mkdtempSync(join(tmpdir(), "fpp-sglmul-disk-"));
const clone = spawnSync("bash", ["-c", "set -euo pipefail\nsource \"$1\"\ncow_clone \"$2\" \"$3/disk.img\" fpp-sglmul", "bash", cowLib, diskSource, diskDir], { encoding: "utf8" });
if (clone.status !== 0) { console.error(clone.stderr || "FPP_SGLMUL_FAIL clone"); rmSync(diskDir, { recursive: true, force: true }); process.exit(1); }
const disk = clone.stdout.trim().split("\n").at(-1)!;
const selectedService = process.env.CASE ? serviceCases.filter((item) => item.name === process.env.CASE) : serviceCases;
const selectedStrict = process.env.CASE ? strictCases.filter((item) => item.name === process.env.CASE) : strictCases;
let servicePass = 0, strictPass = 0, fail = 0;
try {
  if (selectedService.length + selectedStrict.length === 0) throw new Error(`unknown CASE=${process.env.CASE}`);
  for (const item of selectedService) {
    const td = mkdtempSync(join(tmpdir(), "fpp-sglmul-service-"));
    try {
      const pref = join(td, "prefs"); writePrefs(pref, disk);
      const fp7Destination = item.aliasFp7 || item.destinationFp7;
      const load = item.destinationSnan ? "F239 D080" : fp7Destination ? "F239 4B80" : "F239 4800";
      const operationExtra = (0x4800 + (fp7Destination ? 0x380 : 0) + parseInt(item.selector, 16)).toString(16);
      const operation = item.aliasFp7 ? `F200 ${"1FA7"}`
        : `${item.ea === "postinc" ? "F218" : item.ea === "predec" ? "F220" : "F239"} ${operationExtra}${item.ea ? "" : " 0000 9010"}`;
      const store = fp7Destination ? "F239 6B80 0000 A000" : "F239 6800 0000 A000";
      const stream = `${load} 0000 9000 ${operation} F200 A800 ${store} 2C7C A6D4 0000`;
      const guard = `${memoryBytes(0x9ffe, "a5 5a")} ${memoryBytes(0xa000, "00 00 00 00 00 00 00 00 00 00 00 00")} ${memoryBytes(0xa00c, "3c c3")}`;
      const sourceAddress = item.ea ? 0x9020 : 0x9010;
      const init = item.ea === "postinc" ? zeroInit.replace("0000a000", "00009020") : item.ea === "predec" ? zeroInit.replace("0000a000", "0000902c") : zeroInit;
      const run = spawnSync("timeout", ["-k", "5s", "30s", bin, "--config", pref], { encoding: "utf8", timeout: 35_000, env: {
        ...process.env, SDL_VIDEODRIVER: "x11", DISPLAY: display, HOME: td,
        B2_TEST_HEX: stream, B2_TEST_INIT: init,
        B2_TEST_MEMORY_BYTES: `${memoryBytes(0x9000, item.destination)} ${memoryBytes(sourceAddress, item.source)} ${guard}`,
        B2_TEST_MEMDUMP: "0x9ffe:16", B2_TEST_DUMP: "1", B2_TEST_DUMP_FP: "1",
        B2_JIT_FORCE_TRANSLATE: "1", B2_TEST_TWO_PASS: "1", B2_TEST_SECOND_PC: "0x1008", B2_TEST_REPLAY_COUNT: "2", B2_TEST_FORCE_L2_RAM: "1",
        B2_TEST_REPLAY_FPCR: item.fpcr ?? "0", B2_TEST_REPLAY_FPSR: item.replayFpsr ?? "0",
        [fp7Destination ? "B2_TEST_REPLAY_FP7_EXT" : "B2_TEST_REPLAY_FP0_EXT"]: item.destination.replaceAll(" ", "").match(/.{8}/g)!.join(" "), B2_NATIVE_ASSERT_PC: "0x1008",
      }});
      const output = `${run.stdout ?? ""}${run.stderr ?? ""}`;
      const dump = output.match(/^REGDUMP:.*$/m)?.[0];
      const mem = output.match(/^MEMDUMP [^:]+:(.*)$/m)?.[1].trim().toLowerCase();
      const expected = `a5 5a ${item.output} 3c c3`, fpsr = dump?.match(/ FPSR=([0-9a-f]+)/i)?.[1].toLowerCase();
      const d0 = dump?.match(/ D0=([0-9a-f]+)/i)?.[1].toLowerCase(), a0 = dump?.match(/ A0=([0-9a-f]+)/i)?.[1].toLowerCase(), sr = dump?.match(/ SR=([0-9a-f]+)/i)?.[1].toLowerCase();
      const fallbackCount = (output.match(/JIT_FALLBACK/g) ?? []).length;
      const auditedOpcode = item.aliasFp7 ? "f200" : item.ea === "postinc" ? "f218" : item.ea === "predec" ? "f220" : "f239";
      const expectedFallbacks = item.destinationSnan ? 6 : 7;
      const expectedD0 = item.operationFpsr ?? (parseInt(item.fpsr, 16) & 8 ? (parseInt(item.fpsr, 16) | 0x200).toString(16).padStart(8, "0") : item.fpsr);
      const expectedA0 = item.expectedA0 ? (parseInt(item.expectedA0, 16) - 0xa000 + 0x9020).toString(16).padStart(8, "0") : "0000a000";
      if (run.status === 0 && mem === expected && fpsr === item.fpsr && d0 === expectedD0 && a0 === expectedA0 && sr === "271f" && fallbackCount === expectedFallbacks && output.includes("NATEXEC pc=00001008") && output.includes(`JIT_FALLBACK op=${auditedOpcode} pc=00001008`) && !output.includes("Caught SIGSEGV")) servicePass++;
      else { fail++; console.error(`FPP_SGLMUL_FAIL case=${item.name} rc=${run.status} mem=${mem} want=${expected} d0=${d0} want_d0=${expectedD0} fpsr=${fpsr} want_fpsr=${item.fpsr} a0=${a0} want_a0=${expectedA0} sr=${sr} fallbacks=${fallbackCount} want_fallbacks=${expectedFallbacks}`); }
    } finally { rmSync(td, { recursive: true, force: true }); }
  }
  for (const item of selectedStrict) {
    const td = mkdtempSync(join(tmpdir(), "fpp-sglmul-strict-"));
    try {
      const pref = join(td, "prefs"); writePrefs(pref, disk);
      const run = spawnSync("timeout", ["-k", "5s", "30s", bin, "--config", pref], { encoding: "utf8", timeout: 35_000, env: {
        ...process.env, SDL_VIDEODRIVER: "x11", DISPLAY: display, HOME: td,
        B2_TEST_HEX: `F200 ${item.extra} 2C7C A6D5 0000`, B2_TEST_INIT: zeroInit, B2_TEST_DUMP: "1",
        B2_JIT_FORCE_TRANSLATE: "1", B2_TEST_FORCE_L2_RAM: "1", B2_JIT_STRICT_FULL: "1",
      }});
      const output = `${run.stdout ?? ""}${run.stderr ?? ""}`;
      if (run.status !== 0 && output.includes("strict full-JIT: opcode fallback pc=00001000 op=f200") && !output.includes("NATEXEC pc=00001000") && !output.includes("JIT_STRICT_SUMMARY ") && !output.includes("Caught SIGSEGV")) strictPass++;
      else { fail++; console.error(`FPP_SGLMUL_FAIL strict=${item.name} rc=${run.status}`); }
    } finally { rmSync(td, { recursive: true, force: true }); }
  }
} finally {
  spawnSync("bash", ["-c", "source \"$1\"; cow_release \"$2\"", "bash", cowLib, disk]);
  rmSync(diskDir, { recursive: true, force: true });
}
console.log(`FPP_SGLMUL_MATRIX service_pass=${servicePass} strict_pass=${strictPass} fail=${fail} total=${servicePass + strictPass + fail}`);
const expectedService = process.env.CASE ? selectedService.length : serviceCases.length;
const expectedStrict = process.env.CASE ? selectedStrict.length : strictCases.length;
process.exit(fail === 0 && servicePass === expectedService && strictPass === expectedStrict ? 0 : 1);
