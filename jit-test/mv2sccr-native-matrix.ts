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
const diskDir = mkdtempSync(join(tmpdir(), "mv2sccr-native-disk-"));
const clone = spawnSync("bash", ["-c", 'set -euo pipefail\nsource "$1"\ncow_clone "$2" "$3/disk.img" mv2sccr-native', "bash", cowLib, diskSource, diskDir], { encoding: "utf8" });
if (clone.status !== 0) {
  console.error(clone.stderr || "MV2SCCR_FAIL unable to create isolated disk clone");
  process.exit(1);
}
const disk = clone.stdout.trim().split("\n").at(-1)!;

type TestCase = {
  name: string;
  stream: string;
  regs?: Partial<Record<`D${number}` | `A${number}`, string>>;
  sr?: string;
  memory?: string;
  special?: boolean;
  expected: Partial<Record<`D${number}` | `A${number}` | "SR", string>>;
};

const cases: TestCase[] = [];
for (let ccr = 0; ccr < 32; ccr++) {
  const source = ((0xa5a50000 | ccr) >>> 0).toString(16).padStart(8, "0");
  cases.push({
    name: `reg_${ccr.toString(16).padStart(2, "0")}`,
    stream: "44c0 2c7c a6cc 0001",
    regs: { D0: source },
    sr: "2700",
    expected: { D0: source, SR: `27${ccr.toString(16).padStart(2, "0")}` },
  });
}
const eaCases: TestCase[] = [
  { name: "aind", stream: "44d0 2c7c a6cc 0010", regs: { A0: "00009000" }, memory: "9000 a5 9001 1f", expected: { A0: "00009000", SR: "271f" } },
  { name: "aind_special", stream: "44d0 2c7c a6cc 001b", regs: { A0: "00009000" }, memory: "9000 5a 9001 0d", special: true, expected: { A0: "00009000", SR: "270d" } },
  { name: "postinc", stream: "44d8 2c7c a6cc 0011", regs: { A0: "00009000" }, memory: "9000 00 9001 0a", expected: { A0: "00009002", SR: "270a" } },
  { name: "predec", stream: "44e0 2c7c a6cc 0012", regs: { A0: "00009002" }, memory: "9000 00 9001 15", expected: { A0: "00009000", SR: "2715" } },
  { name: "d16", stream: "44e8 0010 2c7c a6cc 0013", regs: { A0: "00009000" }, memory: "9010 00 9011 06", expected: { A0: "00009000", SR: "2706" } },
  { name: "index", stream: "44f0 1000 2c7c a6cc 0014", regs: { D1: "00000002", A0: "00009000" }, memory: "9002 00 9003 19", expected: { D1: "00000002", A0: "00009000", SR: "2719" } },
  { name: "absw", stream: "44f8 6000 2c7c a6cc 0015", memory: "6000 00 6001 03", expected: { SR: "2703" } },
  { name: "absl", stream: "44f9 0000 9000 2c7c a6cc 0016", memory: "9000 00 9001 1c", expected: { SR: "271c" } },
  { name: "pc16", stream: "44fa 1ffe 2c7c a6cc 0017", memory: "3000 00 3001 11", expected: { SR: "2711" } },
  { name: "pcindex", stream: "44fb 18fe 2c7c a6cc 0018", regs: { D1: "00002000" }, memory: "3000 00 3001 12", expected: { D1: "00002000", SR: "2712" } },
  { name: "immediate", stream: "44fc a51b 2c7c a6cc 0019", expected: { SR: "271b" } },
];
cases.push(...eaCases,
  { name: "rtr_ccr_pc", stream: "4e77 4e71 4e71 4e71 2c7c a6cc 001a", regs: { A7: "00009000" }, sr: "270a", memory: "9000 00 9001 15 9002 00 9003 00 9004 10 9005 08", expected: { A7: "00009006", SR: "2715" } },
);

function prefs(path: string, jit: boolean) {
  writeFileSync(path, [
    `rom ${rom}`, `disk ${disk}`, "ramsize 8388608", "modelid 14", "cpu 4",
    "fpu false", `jit ${jit ? "true" : "false"}`, "jitfpu false", "jitcachesize 8192",
    "screen win/640/480", "nosound true", "nocdrom true", "nogui true", "ignoresegv true", "",
  ].join("\n"));
}

function initial(item: TestCase): string {
  const values = Array(16).fill("00000000");
  values[15] = "007fe000";
  for (const [name, value] of Object.entries(item.regs ?? {})) {
    const index = Number(name.slice(1)) + (name.startsWith("A") ? 8 : 0);
    values[index] = value;
  }
  return `${values.join(" ")} ${item.sr ?? "271f"}`;
}

function dumpFields(dump: string | undefined): Record<string, string> {
  const result: Record<string, string> = {};
  for (const match of dump?.matchAll(/\b(D[0-7]|A[0-7]|SR)=([0-9a-f]+)/gi) ?? []) result[match[1].toUpperCase()] = match[2].toLowerCase();
  return result;
}

function run(item: TestCase, jit: boolean) {
  const td = mkdtempSync(join(tmpdir(), `mv2sccr-${jit ? "jit" : "interp"}-`));
  try {
    const pref = join(td, "prefs"); prefs(pref, jit);
    const env: NodeJS.ProcessEnv = { ...process.env, SDL_VIDEODRIVER: "x11", DISPLAY: display, HOME: td,
      B2_TEST_HEX: item.stream, B2_TEST_INIT: initial(item), B2_TEST_DUMP: "1" };
    if (item.memory) env.B2_TEST_MEMORY_BYTES = item.memory;
    if (jit) {
      Object.assign(env, { B2_JIT_FORCE_TRANSLATE: "1", B2_TEST_TWO_PASS: "1", B2_TEST_SECOND_PC: "0x1000",
        B2_TEST_REPLAY_COUNT: "2", B2_TEST_FORCE_L2_RAM: "1", B2_JIT_STRICT_FULL: "1", B2_NATIVE_ASSERT_PC: "0x1000" });
      if (item.special) env.B2_JIT_ALL_SPECIAL_MEM = "1";
    }
    const child = spawnSync("timeout", ["-k", "5s", "30s", bin, "--config", pref], { encoding: "utf8", timeout: 35_000, env });
    const output = `${child.stdout ?? ""}${child.stderr ?? ""}`;
    const dumps = [...output.matchAll(/^REGDUMP:.*$/gm)].map((match) => match[0]);
    return { status: child.status, output, dump: dumps.at(-1), fields: dumpFields(dumps.at(-1)) };
  } finally { rmSync(td, { recursive: true, force: true }); }
}

let pass = 0, fail = 0;
try {
  for (const item of cases) {
    if (process.env.CASE && process.env.CASE !== item.name) continue;
    const interp = run(item, false), jit = run(item, true);
    const exact = Object.entries(item.expected).every(([name, value]) => interp.fields[name] === value.toLowerCase() && jit.fields[name] === value.toLowerCase());
    const equivalent = interp.dump !== undefined && interp.dump === jit.dump;
    const native = jit.output.includes("NATEXEC pc=00001000");
    const strict = jit.output.includes("JIT_STRICT_SUMMARY ") && !jit.output.includes("strict full-JIT:") && !jit.output.includes("JIT_FALLBACK");
    if (interp.status === 0 && jit.status === 0 && exact && equivalent && native && strict) pass++;
    else {
      fail++;
      console.error(`MV2SCCR_FAIL case=${item.name} interp_rc=${interp.status} jit_rc=${jit.status} exact=${exact ? 1 : 0} equivalent=${equivalent ? 1 : 0} native=${native ? 1 : 0} strict=${strict ? 1 : 0}`);
      console.error(`interp=${interp.dump ?? "missing"}`); console.error(`jit=${jit.dump ?? "missing"}`);
      for (const line of jit.output.split("\n").filter((text) => /Caught|strict full-JIT|JIT_FALLBACK|NATEXEC|JIT_STRICT/.test(text)).slice(-12)) console.error(line);
    }
  }
} finally {
  spawnSync("bash", ["-c", 'source "$1"; cow_release "$2"', "bash", cowLib, disk]);
  rmSync(diskDir, { recursive: true, force: true });
}
const expectedTotal = process.env.CASE ? 1 : cases.length;
console.log(`MV2SCCR_NATIVE_MATRIX pass=${pass} fail=${fail} total=${pass + fail}`);
process.exit(fail === 0 && pass === expectedTotal ? 0 : 1);
