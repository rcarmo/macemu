#!/usr/bin/env bun
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, relative, resolve } from "node:path";

/**
 * Source-derived AArch64 JIT closure inventory.
 *
 * This is deliberately conservative: an entry is "audited" only when an
 * accepted family/contract report names its semantic class. Merely being
 * registered, built, or exercised by Finder does not make it audited.
 */

type Status = "audited" | "serviced" | "unreachable" | "unreviewed";
type Layer = "generator" | "midfunc" | "emitter_api" | "raw_boundary" | "runtime_boundary";
interface Row {
  layer: Layer;
  name: string;
  status: Status;
  evidence: string;
  file: string;
  line: number;
  references: number;
  risk: number;
  family: string;
}

const root = resolve(import.meta.dir, "..");
const rel = (path: string) => relative(root, path);
const load = (path: string) => readFileSync(resolve(root, path), "utf8");
const lineAt = (text: string, index: number) => text.slice(0, index).split("\n").length;
const esc = (value: string) => value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
const countToken = (text: string, name: string) =>
  [...text.matchAll(new RegExp(`\\b${esc(name)}\\b`, "g"))].length;
const csv = (value: string | number) => {
  const text = String(value);
  return /[",\n]/.test(text) ? `"${text.replaceAll('"', '""')}"` : text;
};

const paths = {
  generated: "BasiliskII/src/Unix/compemu.cpp",
  gencomp: "BasiliskII/src/uae_cpu_2026/compiler/gencomp.c",
  mid1: "BasiliskII/src/uae_cpu_2026/compiler/compemu_midfunc_arm64.cpp",
  mid2: "BasiliskII/src/uae_cpu_2026/compiler/compemu_midfunc_arm64_2.cpp",
  support: "BasiliskII/src/uae_cpu_2026/compiler/compemu_support_arm.cpp",
  compat: "BasiliskII/src/uae_cpu_2026/compiler/compemu_legacy_arm64_compat.cpp",
  fpp: "BasiliskII/src/uae_cpu_2026/compiler/compemu_fpp.cpp",
  fppCompat: "BasiliskII/src/uae_cpu_2026/compiler/compemu_fpp_arm64_compat.h",
  codegen: "BasiliskII/src/uae_cpu_2026/compiler/codegen_arm64.cpp",
  codegenHeader: "BasiliskII/src/uae_cpu_2026/compiler/codegen_arm64.h",
  helperHeader: "BasiliskII/src/uae_cpu_2026/compiler/jit_native_helpers.h",
  makefile: "BasiliskII/src/Unix/Makefile",
};
const source = Object.fromEntries(Object.entries(paths).map(([key, path]) => [key, load(path)])) as Record<keyof typeof paths, string>;
if (!source.makefile.includes("-DUSE_JIT_FPU"))
  throw new Error("current build no longer enables USE_JIT_FPU; recompute conditional FPU reachability");

/* Follow the configured translation unit rather than reading both sides of
   compemu_fpp.cpp's preprocessor branches. Full preprocessing is intentional:
   the ARM64 compatibility header maps legacy FPU names through macros, and the
   expanded call sites are stronger reachability evidence than unused macro
   definitions. Keep only lines attributed to the requested source file so
   declarations and unrelated inline bodies from included headers do not become
   roots merely because the preprocessor saw them. */
const configuredDefines = [...source.makefile.matchAll(/-D([A-Za-z_][A-Za-z0-9_]*)/g)]
  .map((match) => `-D${match[1]}`);
const unixDir = resolve(root, "BasiliskII/src/Unix");
const configuredIncludes = [
  "BasiliskII/src/include",
  "BasiliskII/src/Unix",
  "BasiliskII/src/CrossPlatform",
  "BasiliskII/src/uae_cpu_2026",
  "BasiliskII/src/slirp",
].map((path) => `-I${resolve(root, path)}`);
const configuredExpandedSource = (path: string, directivesOnly = false): string => {
  const target = resolve(root, path);
  const result = Bun.spawnSync([
    "g++", "-E", ...(directivesOnly ? ["-fdirectives-only"] : []), "-x", "c++",
    ...configuredIncludes,
    ...configuredDefines,
    target,
  ], { cwd: unixDir, stdout: "pipe", stderr: "pipe" });
  if (result.exitCode !== 0)
    throw new Error(`configured preprocessing failed for ${path}: ${result.stderr.toString().trim()}`);

  const active: string[] = [];
  let inTarget = false;
  for (const line of result.stdout.toString().split("\n")) {
    const marker = line.match(/^#\s+\d+\s+"([^"]+)"/);
    if (marker) {
      const markerPath = marker[1];
      inTarget = !markerPath.startsWith("<") && resolve(unixDir, markerPath) === target;
    } else if (inTarget) {
      active.push(line);
    }
  }
  return active.join("\n");
};
const configuredGenerated = configuredExpandedSource(paths.generated);
const configuredGencomp = configuredExpandedSource(paths.gencomp);
const configuredMid1 = configuredExpandedSource(paths.mid1);
const configuredMid2 = configuredExpandedSource(paths.mid2);
const configuredSupport = configuredExpandedSource(paths.support);
const configuredCompat = configuredExpandedSource(paths.compat);
const configuredFpp = configuredExpandedSource(paths.fpp);
const configuredFppCompat = configuredExpandedSource(paths.fppCompat);

/* Directive-only preprocessing retains API spellings while still removing
   comments and inactive #if branches. Use it where macro expansion would hide
   the emitter/raw boundary that the inventory is meant to classify. */
const activeGenerated = configuredExpandedSource(paths.generated, true);
const activeGencomp = configuredExpandedSource(paths.gencomp, true);
const activeMid1 = configuredExpandedSource(paths.mid1, true);
const activeMid2 = configuredExpandedSource(paths.mid2, true);
const activeSupport = configuredExpandedSource(paths.support, true);
const activeCompat = configuredExpandedSource(paths.compat, true);
const activeFpp = configuredExpandedSource(paths.fpp, true);
const activeFppCompat = configuredExpandedSource(paths.fppCompat, true);
const activeCodegen = configuredExpandedSource(paths.codegen, true);

const auditFamilyRules: Array<[RegExp, string]> = [
  [/^(?:i_|jff_|jnf_)?ADD(?:_|$)/, "AARCH64_JIT_AUDIT_ADD_LIFECYCLE.md"],
  [/^(?:i_(?:CMP|CMPM|CMPA)|jff_CMP_[bwl](?:_imm)?)$/, "AARCH64_JIT_AUDIT_COMPARE_LIFECYCLE.md"],
  [/^(?:i_|jff_|jnf_)?(?:BTST|BCHG|BCLR|BSET)(?:_|$)/, "AARCH64_JIT_AUDIT_CLASSIC_BITOPS.md"],
  [/^(?:(?:i_|jff_|jnf_)?(?:DBCC|DBcc|SCC|Scc)(?:_|$)|dbcc_cond_move_ne_w$|dbf_dec_test_ne_w$)/, "AARCH64_JIT_AUDIT_DBCC_SCC_LIFECYCLE.md"],
  [/^(?:i_|jff_|jnf_)?MOVE16$/, "AARCH64_JIT_AUDIT_MOVE_LIFECYCLE.md"],
  [/^(?:i_|jff_|jnf_)?MOVEA(?:_[wl](?:_imm)?|$)/, "AARCH64_JIT_AUDIT_MOVE_LIFECYCLE.md"],
  [/^(?:i_|jff_|jnf_)?MOVE(?:_[bwl](?:_imm)?|$)/, "AARCH64_JIT_AUDIT_MOVE_LIFECYCLE.md"],
  [/^(?:i_|jff_|jnf_)?TAS(?:_|$)/, "AARCH64_JIT_AUDIT_TAS_LIFECYCLE.md"],
  [/^(?:i_|jff_|jnf_)?NEG(?:_|$)/, "AARCH64_JIT_AUDIT_NEG_LIFECYCLE.md"],
  [/^(?:i_|jff_|jnf_)?NEGX(?:_|$)/, "AARCH64_JIT_AUDIT_NEGX_LIFECYCLE.md"],
  [/^(?:i_|jff_|jnf_)?(?:ADDX|SUBX|ANDSR|EORSR|ORSR)(?:_|$)/, "AARCH64_JIT_AUDIT_ADDX_SUBX_CCR.md"],
  [/^(?:i_|jff_|jnf_)?(?:ABCD|SBCD|NBCD)(?:_|$)/, "AARCH64_JIT_AUDIT_BCD.md"],
  [/^(?:i_|jff_|jnf_)?CHK(?:_|$)/, "AARCH64_JIT_AUDIT_CHK_EXCEPTIONS.md"],
  [/^(?:i_|jff_|jnf_)?(?:DIVU|DIVS|DIVL|DIVLU32|DIVLS32|DIVLU64|DIVLS64|TRAPV)(?:_|$)/, "AARCH64_JIT_AUDIT_DIVISION_LIFECYCLE.md"],
  [/^(?:i_|jff_|jnf_)?(?:ASL|ASR|LSL|LSR)(?:W|_|$)/, "AARCH64_JIT_AUDIT_REGISTER_SHIFTS.md; AARCH64_JIT_AUDIT_MEMORY_SHIFTS_ROX.md"],
  [/^(?:i_|jff_|jnf_)?(?:ROL|ROR)(?:W|_|$)/, "AARCH64_JIT_AUDIT_ROTATES.md"],
  [/^(?:i_|jff_|jnf_)?(?:ROXL|ROXR)(?:W|_|$)/, "AARCH64_JIT_AUDIT_ROTATES.md; AARCH64_JIT_AUDIT_MEMORY_SHIFTS_ROX.md"],
  [/^(?:i_|jff_|jnf_)?(?:MULL|MULS32|MULS64|MULU32|MULU64)(?:_|$)/, "AARCH64_JIT_AUDIT_MULL_LIFECYCLE.md"],
  [/^(?:i_|jff_|jnf_)?(?:MVMEL|MVMLE|MOVEM)(?:_|$)/, "AARCH64_JIT_AUDIT_MOVEM_LIFECYCLE.md"],
  [/^(?:arm_ADD_l_ri|arm_ADD_l_ri_hostptr|arm_ADD_ptr_ri|disp_ea20_target_|lea_l_|sign_extend_16_rr)/, "AARCH64_JIT_AUDIT_AREA5_VALUE_AND_POINTER_CONTRACTS.md"],
  [/^(?:jnf_)?MEM_(?:GETADR|READ|WRITE)/, "AARCH64_JIT_AUDIT_AREA6_MEMORY_ACCESS_CONTRACTS.md"],
  [/^(?:live_flags|dont_care_flags|preserve_flags_before_nzcv_clobber|discard_flags_in_nzcv|save_and_discard_flags_in_nzcv|make_flags_live)$/, "AARCH64_JIT_AUDIT_AREA3_FLAGS_LIVENESS.md"],
  [/^(?:call_helper|mov_l_mi|mov_l_mr|mov_l_rm)$/, "AARCH64_JIT_AUDIT_AREA4_CALLS_AND_ALLOCATOR.md"],
];

const serviceGenerator = new Set([
  "i_MVPRM", "i_MVPMR", "i_CHK2", "i_PACK", "i_UNPK",
  "i_BFTST", "i_BFEXTU", "i_BFCHG", "i_BFEXTS", "i_BFCLR", "i_BFFFO", "i_BFSET", "i_BFINS",
  "i_MVSR2", "i_MV2SR", "i_MVR2USP", "i_MVUSP2R", "i_RESET", "i_STOP", "i_RTE", "i_MOVEC2", "i_MOVE2C",
  "i_CINVA", "i_CINVL", "i_CINVP", "i_CPUSHA", "i_CPUSHL", "i_CPUSHP",
  "i_BKPT", "i_CALLM", "i_RTM", "i_TRAP", "i_TRAPcc", "i_EMULOP", "i_EMULOP_RETURN", "i_RTS", "i_BSR",
  /* These four are always replaced by explicit runtime boundaries. FPP, FScc,
     and FBcc are replaced only when compfpu is disabled; their native compiler
     path remains reachable in this USE_JIT_FPU build and must stay unreviewed. */
  "i_FDBcc", "i_FTRAPcc", "i_FSAVE", "i_FRESTORE",
  "i_CAS", "i_CAS2", "i_MOVES",
]);
const conditionalFpuServiceGenerator = new Set(["i_FPP", "i_FScc", "i_FBcc"]);

const riskOf = (name: string, layer: Layer): number => {
  const op = name.replace(/^i_/, "").replace(/^j(?:ff|nf)_/, "");
  const is = (...families: string[]) => families.some((family) => op === family || op.startsWith(`${family}_`));
  if (is("MVMEL", "MVMLE", "MOVEM")) return 100;
  if (is("NEGX", "TAS")) return 97;
  if (is("MOVE16", "MOVEA", "MOVE")) return 94;
  if (is("DBCC", "DBcc", "SCC", "Scc")) return 92;
  if (is("BCHG", "BCLR", "BSET", "BTST")) return 90;
  if (is("CMP", "CMPA", "NEG")) return 88;
  if (layer === "emitter_api" && /^(?:B_|BCC|BCS|BEQ|BNE|CB|TB|JMP|BR)/.test(op)) return 87;
  if (layer === "raw_boundary" && /(?:branch|jmp|set_pc|endblock|call)/.test(op)) return 86;
  if (is("ADD", "SUB", "AND", "EOR", "OR")) return 80;
  return layer === "generator" ? 72 : layer === "midfunc" ? 68 : 60;
};
const emitterAuditRules: Array<[RegExp, string]> = [
  [/^CMP_(?:wi|xi|ww|xx|wwLSLi)$/, "AARCH64_JIT_AUDIT_COMPARE_EMITTERS.md"],
  [/^NEG_ww$/, "AARCH64_JIT_AUDIT_NEG_LIFECYCLE.md"],
  [/^(?:B_i|BR_x|CC_B_i|B(?:CC|CS|EQ|GE|GT|HI|LE|LS|LT|MI|NE|PL|VC|VS)_i|CB(?:NZ|Z)_[wx]i|TBNZ_[wx]ii|TBZ_[wx]ii)$/, "AARCH64_JIT_AUDIT_BRANCH_EMITTERS.md"],
];
const familyOf = (name: string) => name
  .replace(/^i_/, "")
  .replace(/^j(?:ff|nf)_/, "")
  .replace(/_(?:b|w|l|q)$/, "")
  .replace(/(?:32|64)$/, "");

for (const [, reports] of [...auditFamilyRules, ...emitterAuditRules]) {
  for (const report of reports.split(";").map((item) => item.trim())) {
    if (!existsSync(resolve(root, "BasiliskII/docs", report)))
      throw new Error(`accepted audit report is missing: ${report}`);
  }
}
const acceptedAudit = (name: string): string | undefined =>
  auditFamilyRules.find(([pattern]) => pattern.test(name))?.[1];
const acceptedEmitterAudit = (name: string): string | undefined =>
  emitterAuditRules.find(([pattern]) => pattern.test(name))?.[1];

interface MidDef { name: string; file: string; line: number; body: string; }
const midDefs: MidDef[] = [];
for (const key of ["mid1", "mid2"] as const) {
  const text = source[key];
  const pattern = /^MIDFUNC\(\s*\d+\s*,\s*([A-Za-z0-9_]+)\s*,/gm;
  for (const match of text.matchAll(pattern)) {
    const name = match[1];
    const start = match.index!;
    const endPattern = new RegExp(`^MENDFUNC\\(\\s*\\d+\\s*,\\s*${esc(name)}\\s*,`, "gm");
    endPattern.lastIndex = start;
    const endMatch = endPattern.exec(text);
    if (!endMatch) throw new Error(`missing MENDFUNC for ${name}`);
    midDefs.push({ name, file: paths[key], line: lineAt(text, start), body: text.slice(start, endMatch.index) });
  }
}
const midNames = new Set(midDefs.map((entry) => entry.name));
if (midDefs.length !== 422 || midNames.size !== 422)
  throw new Error(`MIDFUNC census changed: definitions=${midDefs.length} unique=${midNames.size}, expected 422`);

/* Reparse configured MIDFUNC bodies for graph edges. The raw definitions keep
   authoritative file/line metadata, while preprocessing removes comments and
   inactive branches that must not manufacture callees. */
const parseConfiguredMidBodies = (texts: string[], label: string) => {
  const bodies = new Map<string, string>();
  for (const text of texts) {
    const pattern = /^MIDFUNC\(\s*\d+\s*,\s*([A-Za-z0-9_]+)\s*,/gm;
    for (const match of text.matchAll(pattern)) {
      const name = match[1];
      const endPattern = new RegExp(`^MENDFUNC\\(\\s*\\d+\\s*,\\s*${esc(name)}\\s*,`, "gm");
      endPattern.lastIndex = match.index!;
      const endMatch = endPattern.exec(text);
      if (!endMatch) throw new Error(`missing ${label} MENDFUNC for ${name}`);
      if (bodies.has(name)) throw new Error(`duplicate ${label} MIDFUNC for ${name}`);
      bodies.set(name, text.slice(match.index!, endMatch.index));
    }
  }
  if (bodies.size !== midDefs.length)
    throw new Error(`${label} MIDFUNC census changed: ${bodies.size}, expected ${midDefs.length}`);
  return bodies;
};
const configuredMidBodies = parseConfiguredMidBodies([configuredMid1, configuredMid2], "configured");
const activeMidBodies = parseConfiguredMidBodies([activeMid1, activeMid2], "directive-only");
for (const def of midDefs) {
  const configuredBody = configuredMidBodies.get(def.name);
  if (!configuredBody) throw new Error(`configured MIDFUNC disappeared: ${def.name}`);
  def.body = configuredBody;
}

/* MV2SR.W is present in generated output but every legal slot is replaced
   unconditionally after registration. Other unused MIDFUNCs are classified by
   the actual root/call graph; do not guess from naming conventions. In
   particular, USE_JIT_FPU makes f* MIDFUNCs reachable when compfpu is enabled. */
const overriddenMidfunc = (name: string) => name === "jnf_MV2SR_w";
const rootMidText = `${configuredGenerated}\n${configuredSupport}\n${configuredCompat}\n${configuredFpp}\n${configuredFppCompat}`;
const rootMid = new Set<string>();
for (const name of midNames) {
  if (countToken(rootMidText, name) > 0 && !overriddenMidfunc(name)) rootMid.add(name);
}
const midEdges = new Map<string, Set<string>>();
for (const def of midDefs) {
  const edges = new Set<string>();
  for (const target of midNames) {
    if (target !== def.name && countToken(def.body, target) > 0) edges.add(target);
  }
  midEdges.set(def.name, edges);
}
const reachableMid = new Set(rootMid);
for (let changed = true; changed;) {
  changed = false;
  for (const name of [...reachableMid]) {
    for (const target of midEdges.get(name) ?? []) {
      if (!overriddenMidfunc(target) && !reachableMid.has(target)) {
        reachableMid.add(target); changed = true;
      }
    }
  }
}

/* These formerly ambiguous rows have positive control-path evidence in
   addition to call-graph absence. Keep the proof local and fail closed if a
   future generator or configured root makes any of them reachable. */
const structuralUnreachableMid = new Map<string, string>([
  ["jff_BFINS_dd", "all BFINS slots are post-registration op_bitfield_comp_ff services; the legacy inline BFINS MIDFUNC is not selectable"],
  ["jnf_MVMEL_l", "i_MVMEL selects repaired genmovemel cursor/read primitives; the legacy fixed-offset MIDFUNC is not selected"],
  ["jnf_MOVE16", "i_MOVE16 selects genmov16 and its direct/special-memory primitives; the legacy MOVE16 MIDFUNC is not selected"],
  ["jff_MOVE_l", "i_MOVE routes long flags through genflags and storage through genastore; the legacy MOVE.L MIDFUNC is not selected"],
  ["jnf_TAS", "i_TAS unconditionally selects jff_TAS because TAS defines CCR; no no-flags TAS path is selected"],
  ["jnf_DIVS", "i_DIVS unconditionally selects jff_DIVS for divide exception and overflow flag semantics"],
  ["frndint_rr", "its only source call is inside inactive USE_X86_FPUCW code in the configured AArch64 build"],
  ["sub_w_ri", "raw references were comments; configured DBcc uses dbcc_dec_w -> jnf_SUB_w_imm instead"],
]);
const structuralProofTokens: Array<[string, string, string[]]> = [
  ["jff_BFINS_dd", source.support, ["table68k[opcode].mnemo == i_BFINS", "op_bitfield_comp_ff"]],
  ["jnf_MVMEL_l", source.gencomp, ["case i_MVMEL:", "genmovemel (opcode);"]],
  ["jnf_MOVE16", source.gencomp, ["case i_MOVE16:", "genmov16(opcode,curi);"]],
  ["jff_MOVE_l", source.gencomp, ["case i_MOVE:", "genflags (flag_logical", "genastore (\"src\""]],
  ["jnf_TAS", source.gencomp, ["case i_TAS:", "jff_TAS(src)"]],
  ["jnf_DIVS", source.gencomp, ["case i_DIVS:", "jff_DIVS(dst, src)"]],
  ["sub_w_ri", source.compat, ["void dbcc_dec_w(W2 d) { jnf_SUB_w_imm(d, 1); }"]],
];
for (const [name, text, tokens] of structuralProofTokens) {
  if (tokens.some((token) => !text.includes(token)))
    throw new Error(`structural unreachable proof changed for ${name}`);
}
for (const name of structuralUnreachableMid.keys()) {
  if (!midNames.has(name)) throw new Error(`structural unreachable MIDFUNC disappeared: ${name}`);
  if (reachableMid.has(name)) throw new Error(`structural unreachable MIDFUNC became reachable: ${name}`);
}
if (countToken(configuredFpp, "frndint_rr") !== 0)
  throw new Error("configured AArch64 FPU path now reaches frndint_rr");

const rows: Row[] = [];
for (const def of midDefs) {
  const references = countToken(rootMidText, def.name) + [...midDefs].reduce((sum, item) => item.name === def.name ? sum : sum + countToken(item.body, def.name), 0);
  const audit = acceptedAudit(def.name);
  const status: Status = !reachableMid.has(def.name) ? "unreachable" : audit ? "audited" : "unreviewed";
  const evidence = status === "unreachable"
    ? (structuralUnreachableMid.get(def.name) ?? (overriddenMidfunc(def.name) ? "post-registration AArch64 semantic-service override" : "no path from configured generated/support/FPU compiler roots"))
    : audit ? `BasiliskII/docs/${audit}` : "reachable; no accepted family-level closure report";
  rows.push({ layer: "midfunc", name: def.name, status, evidence, file: def.file, line: def.line, references, risk: riskOf(def.name, "midfunc"), family: familyOf(def.name) });
}

const genCases = [...source.gencomp.matchAll(/^\s*case\s+(i_[A-Za-z0-9_]+)\s*:/gm)];
const uniqueGen = new Map<string, { line: number; index: number }>();
for (const match of genCases) if (!uniqueGen.has(match[1])) uniqueGen.set(match[1], { line: lineAt(source.gencomp, match.index!), index: match.index! });
/* A raw `case i_` grep reports 132 by counting two commented-out NATFEAT
   labels. There are 130 live switch labels; keep the parser anchored to code. */
if (uniqueGen.size !== 130) throw new Error(`gencomp case census changed: ${uniqueGen.size}, expected 130 live cases`);
const serviceEvidenceAliases = new Map([
  ["i_BSR", "op_bsr_comp_ff"],
  ["i_RTS", "op_rts_comp_ff"],
  ["i_EMULOP", "op_emulop_comp_ff"],
  ["i_EMULOP_RETURN", "op_emulop_comp_ff"],
  /* MV2SR is selected by its complete legal opcode range rather than a
     mnemonic comparison; its generated MIDFUNC is deliberately unreachable. */
  ["i_MV2SR", "op_fullsr_mv2sr_w_comp_ff"],
]);
for (const name of serviceGenerator) {
  if (!uniqueGen.has(name)) throw new Error(`semantic-service generator row disappeared: ${name}`);
  const evidenceToken = serviceEvidenceAliases.get(name) ?? name;
  if (countToken(configuredSupport, evidenceToken) === 0)
    throw new Error(`semantic-service row has no configured post-registration/coverage-map evidence: ${name}`);
}
for (const [name, found] of uniqueGen) {
  const audit = acceptedAudit(name);
  const serviced = serviceGenerator.has(name);
  const status: Status = serviced ? "serviced" : audit ? "audited" : "unreviewed";
  const evidence = serviced
    ? "post-registration or generated ordered semantic-service table; AARCH64_JIT_AUDIT_ORDERED_SEMANTIC_SERVICES.md"
    : audit ? `BasiliskII/docs/${audit}`
    : conditionalFpuServiceGenerator.has(name)
      ? "native when compfpu is enabled; semantic service when disabled; native FPU path has no accepted closure report"
      : "native generator case; no accepted family-level closure report";
  rows.push({ layer: "generator", name, status, evidence, file: paths.gencomp, line: found.line, references: genCases.filter((item) => item[1] === name).length, risk: riskOf(name, "generator"), family: familyOf(name) });
}

const runtimeNames = new Set<string>();
for (const text of [source.support, source.compat, source.helperHeader, source.gencomp]) {
  for (const match of text.matchAll(/\b((?:jit_runtime_|jit_op_)[A-Za-z0-9_]+)\b/g)) runtimeNames.add(match[1]);
}
if (runtimeNames.size !== 69)
  throw new Error(`runtime-boundary census changed: ${runtimeNames.size}, expected 69`);
for (const name of [...runtimeNames].sort()) {
  let file = paths.support;
  let text = source.support;
  let index = text.search(new RegExp(`\\b${esc(name)}\\b`));
  if (index < 0) { file = paths.compat; text = source.compat; index = text.search(new RegExp(`\\b${esc(name)}\\b`)); }
  const allText = `${configuredGenerated}\n${configuredGencomp}\n${configuredSupport}\n${configuredCompat}\n${configuredFpp}\n${configuredFppCompat}\n${midDefs.filter((item) => reachableMid.has(item.name)).map((item) => item.body).join("\n")}`;
  const references = countToken(allText, name);
  const declarationAndDefinition = countToken(source.helperHeader, name) + 1;
  const reachable = references > declarationAndDefinition || countToken(configuredGenerated, name) > 0 || countToken(configuredGencomp, name) > 0;
  rows.push({
    layer: "runtime_boundary", name, status: reachable ? "serviced" : "unreachable",
    evidence: reachable ? "explicit flushed/end-block runtime semantic boundary" : "definition/declaration has no generated or registration caller",
    file, line: index >= 0 ? lineAt(text, index) : 0, references,
    risk: riskOf(name, "runtime_boundary"), family: familyOf(name),
  });
}

const rawFiles = [paths.codegen, paths.support, paths.mid1, paths.mid2, paths.compat] as const;
const rawNames = new Set<string>();
for (const path of rawFiles) for (const match of load(path).matchAll(/\b((?:compemu_raw_|raw_)[A-Za-z0-9_]+)\s*\(/g)) rawNames.add(match[1]);
if (rawNames.size !== 82)
  throw new Error(`raw-boundary census changed: ${rawNames.size}, expected 82`);
const auditedRaw = /^(?:compemu_raw_(?:branch|call|call_observer_|cmp_pc|endblock_|jmp|maybe_cachemiss|maybe_recompile|observer_|set_pc_)|raw_(?:flags_to_reg|reg_to_flags|jcc|push_regs_to_preserve|pop_preserved_regs))/;
for (const name of [...rawNames].sort()) {
  let file = rawFiles[0]; let text = load(file); let index = text.search(new RegExp(`\\b${esc(name)}\\b`));
  for (const candidate of rawFiles) {
    const candidateText = load(candidate); const candidateIndex = candidateText.search(new RegExp(`\\b${esc(name)}\\b`));
    if (candidateIndex >= 0) { file = candidate; text = candidateText; index = candidateIndex; break; }
  }
  const activeReachableMid = [...reachableMid].map((mid) => activeMidBodies.get(mid) ?? "").join("\n");
  const configuredRawText = `${activeGenerated}\n${activeGencomp}\n${activeCodegen}\n${activeSupport}\n${activeCompat}\n${activeFpp}\n${activeFppCompat}\n${activeReachableMid}`;
  const references = countToken(configuredRawText, name);
  const status: Status = auditedRaw.test(name) ? "audited" : references <= 1 ? "unreachable" : "unreviewed";
  const evidence = status === "audited"
    ? "AARCH64_JIT_AUDIT_AREA1_BLOCK_LIFECYCLE.md; AREA2_PC_OWNERSHIP.md; AREA3_FLAGS_LIVENESS.md; AREA4_CALLS_AND_ALLOCATOR.md"
    : status === "unreachable" ? "no production caller"
    : /^raw_f/.test(name) && name !== "raw_flags_to_reg"
      ? "reachable when USE_JIT_FPU compfpu is enabled; no exact closure classification"
      : "reachable raw boundary; no exact closure classification";
  rows.push({ layer: "raw_boundary", name, status, evidence, file, line: index >= 0 ? lineAt(text, index) : 0, references, risk: riskOf(name, "raw_boundary"), family: familyOf(name) });
}

const emitterDefinitions = new Map<string, { index: number; line: number; chunk: string }>();
const emitterStart = /^(?:#define\s+|STATIC_INLINE\s+[^\n(]+\s+)([A-Za-z_][A-Za-z0-9_]*)\s*\(/gm;
const starts = [...source.codegenHeader.matchAll(emitterStart)];
for (let i = 0; i < starts.length; i++) {
  const match = starts[i]; const name = match[1];
  if (!emitterDefinitions.has(name)) {
    emitterDefinitions.set(name, { index: match.index!, line: lineAt(source.codegenHeader, match.index!), chunk: source.codegenHeader.slice(match.index!, starts[i + 1]?.index ?? source.codegenHeader.length) });
  }
}
const emitterNames = new Set(emitterDefinitions.keys());
if (emitterDefinitions.size !== 294)
  throw new Error(`emitter API census changed: ${emitterDefinitions.size}, expected 294`);
const activeReachableMid = [...reachableMid].map((mid) => activeMidBodies.get(mid) ?? "").join("\n");
const emitterRootText = `${activeGenerated}\n${activeGencomp}\n${activeCodegen}\n${activeSupport}\n${activeCompat}\n${activeFpp}\n${activeFppCompat}\n${activeReachableMid}`;
const reachableEmitter = new Set<string>();
for (const name of emitterNames) if (countToken(emitterRootText, name) > 0) reachableEmitter.add(name);
for (let changed = true; changed;) {
  changed = false;
  for (const name of [...reachableEmitter]) {
    const chunk = emitterDefinitions.get(name)?.chunk ?? "";
    for (const target of emitterNames) if (!reachableEmitter.has(target) && countToken(chunk, target) > 0) { reachableEmitter.add(target); changed = true; }
  }
}
const structuralUnreachableEmitter = new Map<string, string>([
  ["SUBS_wwish", "only used by unreachable sub_w_ri; configured DBcc uses dbcc_dec_w -> jnf_SUB_w_imm"],
]);
for (const name of structuralUnreachableEmitter.keys()) {
  if (!emitterNames.has(name)) throw new Error(`structural unreachable emitter disappeared: ${name}`);
  if (reachableEmitter.has(name)) throw new Error(`structural unreachable emitter became reachable: ${name}`);
}
for (const [name, def] of emitterDefinitions) {
  const references = countToken(emitterRootText, name) + countToken(source.codegenHeader, name) - 1;
  const report = acceptedEmitterAudit(name);
  const status: Status = reachableEmitter.has(name) ? (report ? "audited" : "unreviewed") : "unreachable";
  rows.push({
    layer: "emitter_api", name, status,
    evidence: status === "audited" ? report!
      : status === "unreachable" ? (structuralUnreachableEmitter.get(name) ?? "no path from reachable AArch64 compiler/emitter roots")
      : "reachable encoder API; requires opcode/width/branch-range contract classification",
    file: paths.codegenHeader, line: def.line, references, risk: riskOf(name, "emitter_api"), family: familyOf(name),
  });
}

rows.sort((a, b) => a.layer.localeCompare(b.layer) || a.name.localeCompare(b.name));
const csvPath = resolve(root, process.argv[2] ?? "BasiliskII/docs/AARCH64_JIT_CLOSURE_INVENTORY.csv");
const mdPath = resolve(root, process.argv[3] ?? "BasiliskII/docs/AARCH64_JIT_CLOSURE_INVENTORY.md");
writeFileSync(csvPath, ["layer,name,status,family,risk,references,file,line,evidence", ...rows.map((row) =>
  [row.layer, row.name, row.status, row.family, row.risk, row.references, row.file, row.line, row.evidence].map(csv).join(",")
)].join("\n") + "\n");

const layers: Layer[] = ["generator", "midfunc", "emitter_api", "raw_boundary", "runtime_boundary"];
const statuses: Status[] = ["audited", "serviced", "unreachable", "unreviewed"];
const summary = layers.map((layer) => {
  const items = rows.filter((row) => row.layer === layer);
  return { layer, total: items.length, counts: Object.fromEntries(statuses.map((status) => [status, items.filter((row) => row.status === status).length])) as Record<Status, number> };
});
const highest = rows.filter((row) => row.status === "unreviewed").sort((a, b) => b.risk - a.risk || a.layer.localeCompare(b.layer) || a.name.localeCompare(b.name));
const highFamilies = new Map<string, Row[]>();
for (const row of highest) {
  const key = row.family;
  if (!highFamilies.has(key)) highFamilies.set(key, []);
  highFamilies.get(key)!.push(row);
}
const selectedFamilies = [...highFamilies.entries()].sort((a, b) => Math.max(...b[1].map((r) => r.risk)) - Math.max(...a[1].map((r) => r.risk)) || a[0].localeCompare(b[0])).slice(0, 20);

const md: string[] = [];
md.push("# AArch64 JIT authoritative closure inventory", "", "Generated by `bun jit-test/closure-inventory.ts` from the merged canonical source tree.", "", "## Classification policy", "", "- **audited**: an accepted contract/family report covers the entry;", "- **serviced**: every reachable configuration routes the generator/runtime entry through an explicit ordered semantic boundary;", "- **unreachable**: no path exists from current generated/support/FPU roots, or an unconditional post-registration service override replaces the implementation;", "- **unreviewed**: reachable source with no accepted exact family/contract classification.", "", "The current Makefile enables `USE_JIT_FPU`. Therefore native `compfpu` paths remain reachable even though disabling `compfpu` installs a semantic service; a conditional service does not classify that native path as serviced or unreachable.", "", "Registration, a green corpus, and Finder boot do not by themselves promote an entry to **audited**.", "", "## Census", "", "| Layer | Total | Audited | Serviced | Unreachable | Unreviewed |", "|---|---:|---:|---:|---:|---:|");
for (const item of summary) md.push(`| ${item.layer} | ${item.total} | ${item.counts.audited} | ${item.counts.serviced} | ${item.counts.unreachable} | ${item.counts.unreviewed} |`);
md.push("", `Detailed rows: \`${rel(csvPath)}\`.`, "", "## Configured-root and registration corrections", "", "Configured, macro-expanded AArch64 roots and final registration state correct classifications that a raw token scan gets wrong:", "", "- `frndint_rr` is unreachable: its only call is under inactive `USE_X86_FPUCW`;", "- `sub_w_ri` is unreachable: its apparent uses were comments, while live DBcc decrement uses `dbcc_dec_w` -> `jnf_SUB_w_imm`;", "- emitter `SUBS_wwish` is consequently unreachable because its sole implementation consumer is `sub_w_ri`;", "- generator `i_MV2SR` is serviced because every legal slot is unconditionally replaced by `op_fullsr_mv2sr_w_comp_ff`, while the superseded `jnf_MV2SR_w` MIDFUNC is unreachable.", "", "The explicit BFINS, MOVEM, MOVE16, MOVE.L, TAS, and DIVS legacy-MIDFUNC rows also require positive generator or post-registration provider evidence; zero textual references alone do not classify them.", "", "## Highest-risk unreviewed families", "", "Risk is a deterministic triage score, not a correctness verdict.", "", "| Risk | Family | Layers / entries |", "|---:|---|---|");
for (const [family, items] of selectedFamilies) md.push(`| ${Math.max(...items.map((row) => row.risk))} | \`${family}\` | ${items.slice(0, 8).map((row) => `${row.layer}:\`${row.name}\``).join(", ")}${items.length > 8 ? `, +${items.length - 8}` : ""} |`);
const nextFamily = selectedFamilies[0];
const nextFamilyText = nextFamily
  ? `\`${nextFamily[0]}\` is the highest-risk family still classified as unreviewed. Its current rows are ${nextFamily[1].map((row) => `${row.layer}:\`${row.name}\``).join(", ")}. Selection is mechanical; shared ownership, flags, fault, and helper-boundary contracts still require source review.`
  : "No unreviewed family remains in the current source-derived inventory.";
md.push("", "## Accepted closure targets", "", "- `MOVEM` (`i_MVMEL` / `i_MVMLE`) is closed by `AARCH64_JIT_AUDIT_MOVEM_LIFECYCLE.md`. Its four legacy `jnf_MVMEL/MVMLE` MIDFUNC definitions remain unreachable; the repaired live contract is emitted directly by `genmovemel()` / `genmovemle()` and generic memory primitives.", "- `NEGX` (`i_NEGX`) is closed by `AARCH64_JIT_AUDIT_NEGX_LIFECYCLE.md`. Its six `jff_/jnf_NEGX_{b,w,l}` namesakes remain unreachable; the live generator uses the shared repaired `flag_subx` -> `sbb_b/w/l` lifecycle.", "- `ADD` (`i_ADD`) is closed by `AARCH64_JIT_AUDIT_ADD_LIFECYCLE.md` through its 12 reachable flag-live/no-flags and immediate MIDFUNC routes. The unused `jnf_ADD_im8` remains unreachable, while generic `ADD_*` encoder APIs remain independently unreviewed.", "", "## Next selected family", "", nextFamilyText, "", "## Mechanical invariants", "", `- unique \`gencomp.c\` mnemonic cases: **${uniqueGen.size}**;`, `- unique AArch64 MIDFUNC definitions: **${midDefs.length}**;`, `- codegen emitter API definitions: **${emitterDefinitions.size}**;`, `- raw boundary functions: **${rawNames.size}**;`, `- runtime helper boundaries: **${runtimeNames.size}**;`, "- FPU roots come from the macro-expanded source selected by the current Makefile defines, not inactive preprocessor branches or unused compatibility macros;", "- the script fails closed if any known layer census or accepted report changes.", "", "## Regeneration", "", "```sh", "bun jit-test/closure-inventory.ts", "git diff --check", "```", "");
writeFileSync(mdPath, md.join("\n"));

console.log(`CLOSURE_INVENTORY rows=${rows.length} generator=${uniqueGen.size} midfunc=${midDefs.length} emitter_api=${emitterDefinitions.size} raw_boundary=${rawNames.size} runtime_boundary=${runtimeNames.size}`);
for (const item of summary) console.log(`CLOSURE_LAYER layer=${item.layer} total=${item.total} audited=${item.counts.audited} serviced=${item.counts.serviced} unreachable=${item.counts.unreachable} unreviewed=${item.counts.unreviewed}`);
console.log(`wrote ${rel(csvPath)} and ${rel(mdPath)}`);
