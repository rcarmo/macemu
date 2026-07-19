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
const diskDir = mkdtempSync(join(tmpdir(), "control-address-native-disk-"));
const clone = spawnSync("bash", ["-c", 'set -euo pipefail\nsource "$1"\ncow_clone "$2" "$3/disk.img" control-address-native', "bash", cowLib, diskSource, diskDir], { encoding: "utf8" });
if (clone.status !== 0) {
  console.error(clone.stderr || "CONTROL_ADDRESS_FAIL unable to create isolated disk clone");
  process.exit(1);
}
const disk = clone.stdout.trim().split("\n").at(-1)!;

type TestCase = {
  name: string;
  stream: string;
  regs?: Partial<Record<`D${number}` | `A${number}`, string>>;
  sr?: string;
  memory?: string;
  expected: Partial<Record<`D${number}` | `A${number}` | "SR", string>>;
};

const cases: TestCase[] = [
  { name: "nop_preserve", stream: "4e71 2c7c a6c7 2001", expected: { SR: "271f" } },
  { name: "lea_aind_a5", stream: "4bd0 2c7c a6c7 2002", regs: { A0: "00009000" }, expected: { A5: "00009000", SR: "271f" } },
  { name: "lea_pc_index_a5", stream: "4bfb 7804 4e71 4e71 2c7c a6c7 2003", regs: { D7: "00000000" }, expected: { A5: "00001006", SR: "271f" } },
  { name: "pea_a7_snapshot", stream: "4857 205f 2c7c a6c7 2004", regs: { A7: "00009000" }, expected: { A0: "00009000", A7: "00009000", SR: "271f" } },
  { name: "link_w_a7_snapshot", stream: "4e57 fff8 206f 0008 2c7c a6c7 2005", regs: { A7: "00009000" }, expected: { A0: "00008ffc", A7: "00008ff4", SR: "271f" } },
  { name: "link_l_a7_snapshot", stream: "480f ffff fff0 206f 0010 2c7c a6c7 2006", regs: { A7: "00009000" }, expected: { A0: "00008ffc", A7: "00008fec", SR: "271f" } },
  { name: "unlk_a7_alias", stream: "4e5f 2c7c a6c7 2007", regs: { A7: "00009000" }, memory: "9000 00 9001 00 9002 a0 9003 00", expected: { A7: "0000a000", SR: "271f" } },
  { name: "unlk_a5", stream: "4e5d 2c7c a6c7 2008", regs: { A5: "00009000", A7: "007fe000" }, memory: "9000 12 9001 34 9002 56 9003 78", expected: { A5: "12345678", A7: "00009004", SR: "271f" } },
  { name: "rtd_positive", stream: "4e74 0004 4e71 4e71 2c7c a6c7 2009", regs: { A7: "00009000" }, memory: "9000 00 9001 00 9002 10 9003 08", expected: { A7: "00009008", SR: "271f" } },
  { name: "rtd_negative", stream: "4e74 fffc 4e71 4e71 2c7c a6c7 200a", regs: { A7: "00009000" }, memory: "9000 00 9001 00 9002 10 9003 08", expected: { A7: "00009000", SR: "271f" } },
  { name: "rtr_ccr_pc", stream: "4e77 4e71 4e71 4e71 2c7c a6c7 200b", regs: { A7: "00009000" }, sr: "270a", memory: "9000 00 9001 15 9002 00 9003 00 9004 10 9005 08", expected: { A7: "00009006", SR: "2715" } },
  { name: "jsr_a7_target_snapshot", stream: "4e97 2c7c a6c7 200c", regs: { A7: "00002000" }, memory: "2000 20 2001 7c 2002 de 2003 ad 2004 be 2005 ef 2006 4e 2007 75", expected: { A0: "deadbeef", A7: "00002000", SR: "271f" } },
  { name: "jsr_d16_a7", stream: "4eaf f008 2c7c a6c7 200d", regs: { A7: "00003000" }, memory: "2008 20 2009 7c 200a ca 200b fe 200c ba 200d be 200e 4e 200f 75", expected: { A0: "cafebabe", A7: "00003000", SR: "271f" } },
  { name: "jmp_a7", stream: "4ed7 2c7c a6c7 200e", regs: { A7: "00001002" }, expected: { A7: "00001002", SR: "271f" } },
  { name: "jmp_pc_index", stream: "4efb 0002 4e71 4e71 2c7c a6c7 200f", regs: { D0: "00000004" }, expected: { SR: "271f" } },
];

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
  const td = mkdtempSync(join(tmpdir(), `control-address-${jit ? "jit" : "interp"}-`));
  try {
    const pref = join(td, "prefs");
    prefs(pref, jit);
    const env: NodeJS.ProcessEnv = {
      ...process.env, SDL_VIDEODRIVER: "x11", DISPLAY: display, HOME: td,
      B2_TEST_HEX: item.stream, B2_TEST_INIT: initial(item), B2_TEST_DUMP: "1",
    };
    if (item.memory) env.B2_TEST_MEMORY_BYTES = item.memory;
    if (jit) Object.assign(env, {
      B2_JIT_FORCE_TRANSLATE: "1", B2_TEST_TWO_PASS: "1", B2_TEST_SECOND_PC: "0x1000",
      B2_TEST_REPLAY_COUNT: "2", B2_TEST_FORCE_L2_RAM: "1", B2_JIT_STRICT_FULL: "1",
      B2_NATIVE_ASSERT_PC: "0x1000",
    });
    const child = spawnSync("timeout", ["-k", "5s", "30s", bin, "--config", pref], { encoding: "utf8", timeout: 35_000, env });
    const output = `${child.stdout ?? ""}${child.stderr ?? ""}`;
    const dumps = [...output.matchAll(/^REGDUMP:.*$/gm)].map((match) => match[0]);
    return { status: child.status, output, dump: dumps.at(-1), fields: dumpFields(dumps.at(-1)) };
  } finally {
    rmSync(td, { recursive: true, force: true });
  }
}

let pass = 0;
let fail = 0;
try {
  for (const item of cases) {
    if (process.env.CASE && process.env.CASE !== item.name) continue;
    const interp = run(item, false);
    const jit = run(item, true);
    const exact = Object.entries(item.expected).every(([name, value]) => interp.fields[name] === value.toLowerCase() && jit.fields[name] === value.toLowerCase());
    const equivalent = interp.dump !== undefined && interp.dump === jit.dump;
    const native = jit.output.includes("NATEXEC pc=00001000");
    const strict = jit.output.includes("JIT_STRICT_SUMMARY ") && !jit.output.includes("strict full-JIT:") && !jit.output.includes("JIT_FALLBACK");
    if (interp.status === 0 && jit.status === 0 && exact && equivalent && native && strict) {
      pass++;
    } else {
      fail++;
      console.error(`CONTROL_ADDRESS_FAIL case=${item.name} interp_rc=${interp.status} jit_rc=${jit.status} exact=${exact ? 1 : 0} equivalent=${equivalent ? 1 : 0} native=${native ? 1 : 0} strict=${strict ? 1 : 0}`);
      console.error(`interp=${interp.dump ?? "missing"}`);
      console.error(`jit=${jit.dump ?? "missing"}`);
      for (const line of jit.output.split("\n").filter((text) => /Caught|strict full-JIT|JIT_FALLBACK|NATEXEC|JIT_STRICT/.test(text)).slice(-12)) console.error(line);
    }
  }
} finally {
  spawnSync("bash", ["-c", 'source "$1"; cow_release "$2"', "bash", cowLib, disk]);
  rmSync(diskDir, { recursive: true, force: true });
}
const expectedTotal = process.env.CASE ? 1 : cases.length;
console.log(`CONTROL_ADDRESS_NATIVE_MATRIX pass=${pass} fail=${fail} total=${pass + fail}`);
process.exit(fail === 0 && pass === expectedTotal ? 0 : 1);
