#!/usr/bin/env bun
import { readFileSync, writeFileSync } from "node:fs";

interface Row {
  opcode: number;
  mapped: number;
  canonical: number;
  mnemonic: string;
  size: number;
  smode: number;
  dmode: number;
  clev: number;
  cflow: number;
  flagdead: number;
  flaglive: number;
  legal: boolean;
  normal: boolean;
  noflags: boolean;
  kind: string;
  implementation: string;
}

const input = process.argv[2];
const output = process.argv[3];
if (!input || !output) {
  console.error(`usage: bun ${process.argv[1]} COVERAGE.csv REPORT.md`);
  process.exit(2);
}

const lines = readFileSync(input, "utf8").trimEnd().split("\n");
const header = lines.shift()?.split(",") ?? [];
const expected = ["opcode", "mapped", "canonical", "mnemonic", "size", "smode", "dmode", "clev", "cflow", "flagdead", "flaglive", "legal", "normal", "noflags", "kind", "implementation"];
if (header.join(",") !== expected.join(",")) throw new Error(`unexpected coverage header: ${header.join(",")}`);
const rows: Row[] = lines.map((line) => {
  const c = line.split(",");
  return {
    opcode: Number.parseInt(c[0], 16), mapped: Number.parseInt(c[1], 16), canonical: Number(c[2]),
    mnemonic: c[3], size: Number(c[4]), smode: Number(c[5]), dmode: Number(c[6]),
    clev: Number(c[7]), cflow: Number(c[8]), flagdead: Number(c[9]), flaglive: Number(c[10]),
    legal: c[11] === "1", normal: c[12] === "1", noflags: c[13] === "1",
    kind: c[14], implementation: c[15],
  };
});
if (rows.length !== 65536) throw new Error(`expected 65536 rows, got ${rows.length}`);

const hex = (value: number) => value.toString(16).padStart(4, "0");
const compactRanges = (values: number[]) => {
  const sorted = [...new Set(values)].sort((a, b) => a - b);
  const ranges: string[] = [];
  for (let i = 0; i < sorted.length;) {
    let j = i;
    while (j + 1 < sorted.length && sorted[j + 1] === sorted[j] + 1) j++;
    ranges.push(i === j ? `\`${hex(sorted[i])}\`` : `\`${hex(sorted[i])}–${hex(sorted[j])}\``);
    i = j + 1;
  }
  return ranges.join(", ");
};
const groupBy = <T>(items: T[], key: (item: T) => string) => {
  const map = new Map<string, T[]>();
  for (const item of items) {
    const k = key(item);
    const group = map.get(k) ?? [];
    group.push(item);
    map.set(k, group);
  }
  return map;
};

const legal = rows.filter((row) => row.legal);
const generated = legal.filter((row) => row.kind === "native_generated");
const helpers = legal.filter((row) => row.kind === "semantic_helper");
const fallback = legal.filter((row) => row.kind === "fallback_null");
const legalTraps = legal.filter((row) => row.kind === "architectural_trap");
const allTrapSlots = rows.filter((row) => row.kind === "architectural_trap");
const normalOnly = legal.filter((row) => row.normal && !row.noflags);
const fallbackGroups = [...groupBy(fallback, (row) => row.mnemonic)].map(([mnemonic, group]) => ({ mnemonic, group }));
const riskRank: Record<string, number> = {
  TRAP: 0, TRAPcc: 0, FTRAPcc: 0, FDBcc: 0,
  MOVES: 1, MVPRM: 1, MVPMR: 1, CHK2: 1, CINVL: 1, CINVP: 1, CINVA: 1,
  BKPT: 2, PACK: 2, UNPK: 2,
  CALLM: 3, RTM: 3,
};
const riskLabel = ["P0 control-flow/trap", "P1 state/memory", "P2 specialised", "P3 obsolete/low-likelihood"];
fallbackGroups.sort((a, b) => (riskRank[a.mnemonic] ?? 9) - (riskRank[b.mnemonic] ?? 9) || b.group.length - a.group.length || a.mnemonic.localeCompare(b.mnemonic));
const helperGroups = [...groupBy(helpers, (row) => row.implementation)]
  .map(([implementation, group]) => ({ implementation, group }))
  .sort((a, b) => b.group.length - a.group.length || a.implementation.localeCompare(b.implementation));

const pct = (n: number, d: number) => `${(100 * n / d).toFixed(2)}%`;
const report: string[] = [];
report.push("# BasiliskII AArch64 JIT opcode coverage map", "");
report.push(`Generated from post-registration runtime tables: \`${input}\`.`);
report.push("This includes canonical handler propagation, explicit AArch64 table overrides, and generated handlers that emit whole-instruction runtime semantic services. A non-null generated entry is therefore not automatically counted as native.", "");
report.push("## Summary", "");
report.push("| Class | Opcodes | Share of legal |", "|---|---:|---:|", `| Native generated | ${generated.length} | ${pct(generated.length, legal.length)} |`, `| Semantic helper | ${helpers.length} | ${pct(helpers.length, legal.length)} |`, `| Architectural trap (legal encodings) | ${legalTraps.length} | ${pct(legalTraps.length, legal.length)} |`, `| Null / interpreter fallback | ${fallback.length} | ${pct(fallback.length, legal.length)} |`, `| **Legal total** | **${legal.length}** | **100%** |`, `| Architectural trap slots (all 65,536 entries) | ${allTrapSlots.length} | — |`, `| Normal-only (missing no-flags handler) | ${normalOnly.length} | ${pct(normalOnly.length, legal.length)} |`, "");
report.push("## Remaining null/fallback families", "");
report.push("Strict full-JIT must fail closed if any repeated/native execution reaches these encodings. Priority reflects architectural blast radius, not observed workload frequency.", "");
report.push("| Priority | Mnemonic | Count | Sizes | Source modes | Destination modes | Opcodes |", "|---|---|---:|---|---|---|---|");
for (const { mnemonic, group } of fallbackGroups) {
  const rank = riskRank[mnemonic] ?? 9;
  const sizes = [...new Set(group.map((r) => r.size))].sort().join(",");
  const smodes = [...new Set(group.map((r) => r.smode))].sort((a, b) => a - b).join(",");
  const dmodes = [...new Set(group.map((r) => r.dmode))].sort((a, b) => a - b).join(",");
  report.push(`| ${riskLabel[rank] ?? "Unranked"} | ${mnemonic} | ${group.length} | ${sizes} | ${smodes} | ${dmodes} | ${compactRanges(group.map((r) => r.opcode))} |`);
}
report.push("", "## Semantic-helper coverage", "", "| Implementation | Opcodes | Mnemonics | Opcode ranges |", "|---|---:|---|---|");
for (const { implementation, group } of helperGroups) {
  const mnemonics = [...new Set(group.map((r) => r.mnemonic))].sort().join(", ");
  report.push(`| \`${implementation}\` | ${group.length} | ${mnemonics} | ${compactRanges(group.map((r) => r.opcode))} |`);
}
report.push("", "## Interpretation", "", "- Availability is not semantic correctness. The MOVEM `(An)` writeback defect was in a non-null generated family and therefore required path/state equivalence, not a null-handler scan.", `- The map removes encounter-order blind spots: all ${legal.length} legal encodings now have an explicit native-generator, semantic-helper, or architectural-trap classification; ${fallback.length} remain null strict-mode blockers.`, "- Generated and helper families still require focused dynamic instruction/path coverage plus ordinary/strict architectural-state comparison.", "- Memory/state helpers require successful and failing equivalence vectors, including aliasing, partial-register, fault-PC and write-order cases.", "");
report.push("## Machine-readable invariants", "", `- Rows: ${rows.length}`, `- Legal opcodes: ${legal.length}`, `- Classified legal opcodes: ${generated.length + helpers.length + legalTraps.length}`, `- Legal architectural traps: ${legalTraps.length}`, `- Normal/no-flags parity gaps: ${normalOnly.length}`, `- Remaining legal null handlers: ${fallback.length}`, "");
writeFileSync(output, report.join("\n"));
console.log(`wrote ${output}: legal=${legal.length} generated=${generated.length} helper=${helpers.length} fallback=${fallback.length}`);
