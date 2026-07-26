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
  [/^i_(?:NOP|RTD|LINK|UNLK|RTR|JSR|JMP|LEA|PEA)$/, "AARCH64_JIT_AUDIT_CONTROL_ADDRESS_LIFECYCLE.md"],
  [/^i_FPP$/, "AARCH64_JIT_AUDIT_FPP_LIFECYCLE.md"],
  [/^(?:i_FScc|fp_fscc_ri)$/, "AARCH64_JIT_AUDIT_FSCC_LIFECYCLE.md"],
  [/^(?:fmov_[bwl]_rr|raw_fmov_[bwl]_rr)$/, "AARCH64_JIT_AUDIT_FPP_FMOVE_INTEGER_SOURCE.md"],
  [/^fmov_to_[bwl]_rr$/, "AARCH64_JIT_AUDIT_FMOV_TO_INTEGER_LIFECYCLE.md"],
  [/^fmov_s_rr$/, "AARCH64_JIT_AUDIT_FMOV_S_RR_LIFECYCLE.md"],
  [/^fmov_to_s_rr$/, "AARCH64_JIT_AUDIT_FMOV_TO_S_RR_LIFECYCLE.md"],
  [/^(?:i_(?:MULS|MULU|NOT|SUBA|SWAP|TST)|jnf_MUL[SU]|jff_TST_[bwl](?:_imm)?)$/, "AARCH64_JIT_AUDIT_INTEGER_TAIL_LIFECYCLES.md"],
  [/^i_FBcc$/, "AARCH64_JIT_AUDIT_FBCC_LIFECYCLE.md"],
  [/^i_EXT$/, "AARCH64_JIT_AUDIT_EXT_LIFECYCLE.md"],
  [/^i_EXG$/, "AARCH64_JIT_AUDIT_EXG_LIFECYCLE.md"],
  [/^i_CLR$/, "AARCH64_JIT_AUDIT_CLR_LIFECYCLE.md"],
  [/^i_Bcc$/, "AARCH64_JIT_AUDIT_BCC_LIFECYCLE.md"],
  [/^(?:i_|jnf_)?ADDA(?:_[wl](?:_imm)?|$)/, "AARCH64_JIT_AUDIT_ADDA_LIFECYCLE.md"],
  [/^(?:i_|jff_|jnf_)?ADD(?:_|$)/, "AARCH64_JIT_AUDIT_ADD_LIFECYCLE.md"],
  [/^(?:i_|jff_|jnf_)?SUB(?:_[bwl](?:_imm)?|$)/, "AARCH64_JIT_AUDIT_SUB_LIFECYCLE.md"],
  [/^(?:i_|jff_|jnf_)?AND(?:_[bwl](?:_imm)?|$)/, "AARCH64_JIT_AUDIT_AND_LIFECYCLE.md"],
  [/^(?:i_|jff_|jnf_)?EOR(?:_[bwl](?:_imm)?|$)/, "AARCH64_JIT_AUDIT_EOR_LIFECYCLE.md"],
  [/^(?:i_|jff_|jnf_)?OR(?:_[bwl](?:_imm)?|$)/, "AARCH64_JIT_AUDIT_OR_LIFECYCLE.md"],
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
  [/^(?:arm_ADD_l(?:_ri(?:_hostptr)?)?|arm_ADD_ptr_ri|disp_ea20_target_.*|lea_l_.*|sign_extend_16_rr)$/, "AARCH64_JIT_AUDIT_AREA5_VALUE_AND_POINTER_CONTRACTS.md"],
  [/^dont_care_fflags$/, "AARCH64_JIT_AUDIT_DONT_CARE_FFLAGS.md"],
  [/^f_forget_about$/, "AARCH64_JIT_AUDIT_F_FORGET_ABOUT.md"],
  [/^forget_about$/, "AARCH64_JIT_AUDIT_FORGET_ABOUT.md"],
  [/^fflags_into_flags$/, "AARCH64_JIT_AUDIT_FFLAGS_INTO_FLAGS.md"],
  [/^fmov_rm$/, "AARCH64_JIT_AUDIT_FMOV_RM_LIFECYCLE.md"],
  [/^(?:jnf_)?MEM_(?:GETADR|READ|WRITE)/, "AARCH64_JIT_AUDIT_AREA6_MEMORY_ACCESS_CONTRACTS.md"],
  [/^(?:live_flags|dont_care_flags|preserve_flags_before_nzcv_clobber|discard_flags_in_nzcv|save_and_discard_flags_in_nzcv|make_flags_live)$/, "AARCH64_JIT_AUDIT_AREA3_FLAGS_LIVENESS.md"],
  [/^(?:call_helper|mov_l_mi|mov_l_mr|mov_l_rm)$/, "AARCH64_JIT_AUDIT_AREA4_CALLS_AND_ALLOCATOR.md"],
];

const configuredUnreachableGenerator = new Map([
  ["i_MMUOP030", "inactive UAE-only generator label; no configured Unix opcode/provider"],
  ["i_PFLUSHN", "inactive UAE-only generator label; no configured Unix opcode/provider"],
  ["i_PFLUSH", "inactive UAE-only generator label; no configured Unix opcode/provider"],
  ["i_PFLUSHAN", "inactive UAE-only generator label; no configured Unix opcode/provider"],
  ["i_PFLUSHA", "inactive UAE-only generator label; no configured Unix opcode/provider"],
  ["i_PLPAR", "inactive UAE-only generator label; no configured Unix opcode/provider"],
  ["i_PLPAW", "inactive UAE-only generator label; no configured Unix opcode/provider"],
  ["i_PTESTR", "inactive UAE-only generator label; no configured Unix opcode/provider"],
  ["i_PTESTW", "inactive UAE-only generator label; no configured Unix opcode/provider"],
  ["i_LPSTOP", "inactive UAE-only generator label; no configured Unix opcode/provider"],
  ["i_MMUOP", "historical ARAnyM generator label; no configured BasiliskII opcode/provider"],
]);
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
  [/^ADD_(?:wwi|xxi|wwwEX|xxwEX|www|xxx|wwwLSLi)$/, "AARCH64_JIT_AUDIT_ADD_EMITTERS.md"],
  [/^(?:SUB_(?:wwi|xxi|www|xxx)|SUBS_(?:wwi|www|wwwLSLi))$/, "AARCH64_JIT_AUDIT_SUB_EMITTERS.md"],
  [/^AND_(?:ww3f|www|xxx)$/, "AARCH64_JIT_AUDIT_AND_EMITTERS.md"],
  [/^(?:EOR_(?:www|wwwLSLi|xxbit|xxCflag)|immOP_EOR)$/, "AARCH64_JIT_AUDIT_EOR_EMITTERS.md"],
  [/^NEG_ww$/, "AARCH64_JIT_AUDIT_NEG_LIFECYCLE.md"],
  [/^FMOV_dd$/, "AARCH64_JIT_AUDIT_FMOV_PRIMITIVES.md"],
  [/^FCMP_(?:dd|d0)$/, "AARCH64_JIT_AUDIT_FCMP_EMITTERS.md"],
  [/^FCVTAS_wd$/, "AARCH64_JIT_AUDIT_FCVTAS_EMITTER.md"],
  [/^FCVT_(?:sd|ds)$/, "AARCH64_JIT_AUDIT_FCVT_EMITTERS.md"],
  [/^FMOV_(?:sw|ws)$/, "AARCH64_JIT_AUDIT_FMOV_SW_WS_EMITTERS.md"],
  [/^FMOV_(?:dx|xd)$/, "AARCH64_JIT_AUDIT_FMOV_DX_XD_EMITTERS.md"],
  [/^SCVTF_dw$/, "AARCH64_JIT_AUDIT_SCVTF_EMITTER.md"],
  [/^(?:CLEAR_LOW8_xx|SET_LOW8_xx)$/, "AARCH64_JIT_AUDIT_FSCC_LIFECYCLE.md"],
  [/^FRINT(?:A|I|Z)_dd$/, "AARCH64_JIT_AUDIT_FRINT_EMITTERS.md"],
  [/^FMOV_di$/, "AARCH64_JIT_AUDIT_FMOV_DI_EMITTER.md"],
  [/^FSQRT_dd$/, "AARCH64_JIT_AUDIT_FSQRT_EMITTER.md"],
  [/^FSUB_ddd$/, "AARCH64_JIT_AUDIT_FSUB_EMITTER.md"],
  [/^FMUL_ddd$/, "AARCH64_JIT_AUDIT_FMUL_D_EMITTER.md"],
  [/^FMUL_sss$/, "AARCH64_JIT_AUDIT_FMUL_S_EMITTER.md"],
  [/^FDIV_(?:ddd|sss)$/, "AARCH64_JIT_AUDIT_FDIV_EMITTERS.md"],
  [/^FMSUB_dddd$/, "AARCH64_JIT_AUDIT_FMSUB_EMITTER.md"],
  [/^(?:B_i|BR_x|CC_B_i|B(?:CC|CS|EQ|GE|GT|HI|LE|LS|LT|MI|NE|PL|VC|VS)_i|CB(?:NZ|Z)_[wx]i|TBNZ_[wx]ii|TBZ_[wx]ii)$/, "AARCH64_JIT_AUDIT_BRANCH_EMITTERS.md"],
];
const primitiveAuditRules: Array<[RegExp, string]> = [
  [/^(?:fmov_[bwl]_rr|raw_fmov_[bwl]_rr)$/, "AARCH64_JIT_AUDIT_FPP_FMOVE_INTEGER_SOURCE.md"],
  [/^raw_fmov_to_[bwl]_rr$/, "AARCH64_JIT_AUDIT_FMOV_TO_INTEGER_LIFECYCLE.md"],
  [/^raw_fmov_s_rr$/, "AARCH64_JIT_AUDIT_FMOV_S_RR_LIFECYCLE.md"],
  [/^raw_fmov_to_s_rr$/, "AARCH64_JIT_AUDIT_FMOV_TO_S_RR_LIFECYCLE.md"],
  [/^raw_fmov_d_rm$/, "AARCH64_JIT_AUDIT_FMOV_RM_LIFECYCLE.md"],
  [/^(?:fmov_rr|raw_fmov_rr)$/, "AARCH64_JIT_AUDIT_FMOV_PRIMITIVES.md"],
  [/^raw_fp_fscc_ri$/, "AARCH64_JIT_AUDIT_FSCC_LIFECYCLE.md"],
];
const familyOf = (name: string) => name
  .replace(/^i_/, "")
  .replace(/^j(?:ff|nf)_/, "")
  .replace(/_(?:b|w|l|q)$/, "")
  .replace(/(?:32|64)$/, "");

for (const [, reports] of [...auditFamilyRules, ...emitterAuditRules, ...primitiveAuditRules]) {
  for (const report of reports.split(";").map((item) => item.trim())) {
    if (!existsSync(resolve(root, "BasiliskII/docs", report)))
      throw new Error(`accepted audit report is missing: ${report}`);
  }
}
const acceptedAudit = (name: string): string | undefined =>
  auditFamilyRules.find(([pattern]) => pattern.test(name))?.[1];
const acceptedEmitterAudit = (name: string): string | undefined =>
  emitterAuditRules.find(([pattern]) => pattern.test(name))?.[1];
const acceptedPrimitiveAudit = (name: string): string | undefined =>
  primitiveAuditRules.find(([pattern]) => pattern.test(name))?.[1];

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
   unconditionally after registration. FABS/FNEG retain dead native source after
   unconditional configured-AArch64 semantic-service exits; do not let those
   post-return tokens become reachability roots. Every override below has a
   positive ordered control-flow proof before graph construction. */
const semanticServiceMid = new Map<string, string>([
  ["fabs_rr", "all configured AArch64 FABS/FSABS/FDABS selectors enter semantic service before operand acquisition or the retained native MIDFUNC call"],
  ["fneg_rr", "all configured AArch64 FNEG/FSNEG/FDNEG selectors enter semantic service before operand acquisition or the retained native MIDFUNC call"],
  ["fadd_rr", "all configured AArch64 FADD/FSADD/FDADD selectors enter semantic service before operand acquisition or the retained native MIDFUNC call"],
  ["fsqrt_rr", "all configured AArch64 FSQRT/FSSQRT/FDSQRT selectors enter semantic service before operand acquisition or the retained native MIDFUNC call"],
  ["fsub_rr", "all configured AArch64 FSUB/FSSUB/FDSUB selectors enter semantic service before operand acquisition or the retained native MIDFUNC call; configured FCMP uses fcompare_result_rr"],
  ["fmul_rr", "both configured AArch64 roots (FMUL/FSMUL/FDMUL and FSGLMUL) enter semantic service before operand acquisition or the retained native MIDFUNC calls"],
  ["fdiv_rr", "both configured AArch64 roots (FDIV/FSDIV/FDDIV and FSGLDIV) enter semantic service before operand acquisition or the retained native MIDFUNC calls"],
  ["ffunc_rr", "all four configured AArch64 host-libm roots (FSIN/FETOX/FLOG2/FCOS) enter MPFR semantic service before operand acquisition or the retained MIDFUNC calls; AARCH64_JIT_AUDIT_FFUNC_RETIREMENT.md"],
  ["fmov_d_ri_0", "the configured AArch64 FMOVECR gate enters exact MPFR service before selector 15 can reach fmov_0/fmov_d_ri_0; the only other parent fmov_l_ri is unreachable; AARCH64_JIT_AUDIT_FMOV_ZERO_ONE_RETIREMENT.md"],
  ["fmov_d_ri_1", "the configured AArch64 FMOVECR gate enters exact MPFR service before selector 50 can reach fmov_1/fmov_d_ri_1; the only other parent fmov_l_ri is unreachable; AARCH64_JIT_AUDIT_FMOV_ZERO_ONE_RETIREMENT.md"],
  ["fmov_s_ri", "all four configured AArch64 binary32 constant roots are retained only below the FMOVECR exact-MPFR service return; raw_fmov_s_rr remains live through fmov_s_rr; AARCH64_JIT_AUDIT_FMOV_S_RI_UNREACHABLE.md"],
  ["fmov_to_d_rrr", "the sole retained put_fp_value(size=5) root is dominated by the configured AArch64 exact-MPFR double-destination service return; AARCH64_JIT_AUDIT_FMOV_TO_D_RRR_UNREACHABLE.md"],
  ["fp_from_exten_mr", "all three configured store compositions are dominated by exact service: ordinary size-2 FMOVE rejects before EA acquisition and both static-FMOVEM loops return before get_fp_ad; AARCH64_JIT_AUDIT_FP_EXTENDED_MEMORY_UNREACHABLE.md"],
  ["fp_to_exten_rm", "all three configured load compositions are dominated by exact service: ordinary size-2 FMOVE rejects before EA acquisition and both static-FMOVEM loops return before get_fp_ad; AARCH64_JIT_AUDIT_FP_EXTENDED_MEMORY_UNREACHABLE.md"],
]);
const configuredUnreachableMid = new Map<string, string>([
  ["fp_from_double_mr", "its sole configured spelling is a legacy extern declaration; the retained fmov_mr call is confined to the inactive non-AArch64 arm below exact double-destination service; AARCH64_JIT_AUDIT_FP_FROM_DOUBLE_MR_UNREACHABLE.md"],
  ["fmov_d_rm", "its sole external spelling is a legacy extern declaration; configured double-memory FMOVE uses fmov_rm -> raw_fmov_d_rm; AARCH64_JIT_AUDIT_FMOV_D_RM_UNREACHABLE.md"],
  ["fmovs_rm", "its sole configured spelling is a legacy extern declaration; both raw source sites select fmov_s_rr in the configured AArch64 arms and retain fmovs_rm only in inactive #else arms; AARCH64_JIT_AUDIT_FMOVS_RM_UNREACHABLE.md"],
]);
const overriddenMidfunc = (name: string) => name === "jnf_MV2SR_w" || semanticServiceMid.has(name) || configuredUnreachableMid.has(name);
const semanticServiceBlocks: Array<[string, string, string]> = [
  ["fabs_rr", "case 0x18:", "case 0x19:"],
  ["fneg_rr", "case 0x1a:", "case 0x1c:"],
  ["fadd_rr", "case 0x22:", "case 0x23:"],
  ["fsqrt_rr", "case 0x04:", "case 0x06:"],
  ["fsub_rr", "case 0x28:", "case 0x30:"],
];
for (const [name, startMarker, endMarker] of semanticServiceBlocks) {
  const start = source.fpp.indexOf(startMarker);
  const end = source.fpp.indexOf(endMarker, start + startMarker.length);
  if (start < 0 || end < 0) throw new Error(`configured semantic-service block disappeared: ${name}`);
  const block = source.fpp.slice(start, end);
  const gate = block.indexOf("#if defined(CPU_aarch64) || defined(CPU_AARCH64)");
  const fail = block.indexOf("FAIL(1);", gate);
  const ret = block.indexOf("return;", fail);
  const operand = block.indexOf("get_fp_value");
  const call = block.indexOf(`${name}(`);
  if (gate < 0 || fail < gate || ret < fail || operand < ret || call < operand)
    throw new Error(`configured AArch64 semantic service no longer precedes ${name}`);
}
const configuredFmoveDestinationStart = source.fpp.indexOf("case 3:\t\t\t\t\t\t\t/* FMOVE Fpn,<ea> */");
const configuredFmoveDestinationEnd = source.fpp.indexOf("case 6:", configuredFmoveDestinationStart);
if (configuredFmoveDestinationStart < 0 || configuredFmoveDestinationEnd < 0)
  throw new Error("configured ordinary FMOVE destination block disappeared");
const configuredFmoveDestination = source.fpp.slice(configuredFmoveDestinationStart, configuredFmoveDestinationEnd);
const configuredDoubleGate = configuredFmoveDestination.indexOf("((extra >> 10) & 7) == 5");
const configuredDoubleFail = configuredFmoveDestination.indexOf("FAIL(1);", configuredDoubleGate);
const configuredDoubleReturn = configuredFmoveDestination.indexOf("return;", configuredDoubleFail);
const configuredPutFpValue = configuredFmoveDestination.indexOf("put_fp_value(", configuredDoubleReturn);
if (configuredDoubleGate < 0 || configuredDoubleFail < configuredDoubleGate ||
    configuredDoubleReturn < configuredDoubleFail || configuredPutFpValue < configuredDoubleReturn)
  throw new Error("configured double-destination service no longer dominates put_fp_value/fmov_to_d_rrr");
if (countToken(source.fpp, "fmov_to_d_rrr") !== 1)
  throw new Error(`fmov_to_d_rrr raw source-call census=${countToken(source.fpp, "fmov_to_d_rrr")}, expected sole retained put_fp_value root`);

for (const [name, blocks] of [
  ["fmul_rr", [["case 0x23:", "case 0x24:"], ["case 0x27:", "case 0x28:"]]],
  ["fdiv_rr", [["case 0x20:", "case 0x21:"], ["case 0x24:", "case 0x25:"]]],
] as const) {
  for (const [startMarker, endMarker] of blocks) {
    const start = source.fpp.indexOf(startMarker);
    const end = source.fpp.indexOf(endMarker, start + startMarker.length);
    if (start < 0 || end < 0) throw new Error(`configured ${name} service block disappeared: ${startMarker}`);
    const block = source.fpp.slice(start, end);
    const gate = block.indexOf("#if defined(CPU_aarch64) || defined(CPU_AARCH64)");
    const fail = block.indexOf("FAIL(1);", gate);
    const ret = block.indexOf("return;", fail);
    const operand = block.indexOf("get_fp_value");
    const call = block.indexOf(`${name}(`);
    if (gate < 0 || fail < gate || ret < fail || operand < ret || call < operand)
      throw new Error(`configured AArch64 semantic service no longer precedes ${name} in ${startMarker}`);
  }
}
const configuredFmovecrStart = source.fpp.indexOf("if ((extra & 0xfc00) == 0x5c00)");
const configuredFmovecrSwitch = source.fpp.indexOf("switch (extra & 0x7f)", configuredFmovecrStart);
if (configuredFmovecrStart < 0 || configuredFmovecrSwitch < 0)
  throw new Error("configured FMOVECR service boundary disappeared");
const configuredFmovecrGate = source.fpp.slice(configuredFmovecrStart, configuredFmovecrSwitch);
const configuredFmovecrFail = configuredFmovecrGate.indexOf("FAIL(1);");
const configuredFmovecrReturn = configuredFmovecrGate.indexOf("return;", configuredFmovecrFail);
if (configuredFmovecrFail < 0 || configuredFmovecrReturn < configuredFmovecrFail)
  throw new Error("configured FMOVECR no longer enters service before selector dispatch");
const configuredFmovRmCalls = [...source.fpp.matchAll(/^\s*fmov_rm\s*\(/gm)].map((match) => match.index!);
if (configuredFmovRmCalls.length !== 5)
  throw new Error(`fmov_rm raw source-call census=${configuredFmovRmCalls.length}, expected one live plus four FMOVECR residue`);
const liveDoubleFmovRm = source.fpp.indexOf("fmov_rm(FS1, (uintptr) (temp_fp));");
if (liveDoubleFmovRm < 0 || liveDoubleFmovRm >= configuredFmovecrStart)
  throw new Error("live fmov_rm double-memory root disappeared or moved behind FMOVECR service");
const fmovRmBeforeService = configuredFmovRmCalls.filter((call) => call < configuredFmovecrStart);
const fmovRmAfterDispatch = configuredFmovRmCalls.filter((call) => call > configuredFmovecrSwitch);
if (fmovRmBeforeService.length !== 1 || fmovRmAfterDispatch.length !== 4)
  throw new Error(`fmov_rm control-flow roots before/after FMOVECR=${fmovRmBeforeService.length}/${fmovRmAfterDispatch.length}, expected 1/4`);
for (const [selector, callName] of [["case 0x0f:", "fmov_0"], ["case 0x32:", "fmov_1"]] as const) {
  const selectorAt = source.fpp.indexOf(selector, configuredFmovecrSwitch);
  const callAt = source.fpp.indexOf(`${callName}(`, selectorAt);
  if (selectorAt < configuredFmovecrSwitch || callAt < selectorAt)
    throw new Error(`retained FMOVECR ${callName} selector disappeared`);
}

for (const [callName, startMarker, endMarker] of [
  ["fsin_rr", "case 0x0e:\t\t\t\t\t\t/* FSIN */", "case 0x0f:\t\t\t\t\t\t/* FTAN */"],
  ["fetox_rr", "case 0x10:\t\t\t\t\t\t/* FETOX */", "case 0x11:\t\t\t\t\t\t/* FTWOTOX */"],
  ["flog2_rr", "case 0x16:\t\t\t\t\t\t/* FLOG2 */", "case 0x18:\t\t\t\t\t\t/* FABS */"],
  ["fcos_rr", "case 0x1d:\t\t\t\t\t\t/* FCOS */", "case 0x1e:\t\t\t\t\t\t/* FGETEXP */"],
] as const) {
  const start = source.fpp.indexOf(startMarker);
  const end = source.fpp.indexOf(endMarker, start + startMarker.length);
  if (start < 0 || end < 0) throw new Error(`configured ffunc_rr service block disappeared: ${startMarker}`);
  const block = source.fpp.slice(start, end);
  const gate = block.indexOf("#if defined(CPU_aarch64) || defined(CPU_AARCH64)");
  const fail = block.indexOf("FAIL(1);", gate);
  const ret = block.indexOf("return;", fail);
  const operand = block.indexOf("get_fp_value");
  const call = block.indexOf(`${callName}(`);
  if (gate < 0 || fail < gate || ret < fail || operand < ret || call < operand)
    throw new Error(`configured AArch64 MPFR service no longer precedes ${callName} in ${startMarker}`);
}
/* `dont_care_fflags` has one configured control-flow-reachable AArch64 root:
   ordinary memory/immediate FMOVE. The other retained call spellings sit after
   unconditional semantic-service returns. Keep that distinction fail closed so
   accepting the invalidation helper cannot silently accept another FP family. */
/* The configured `f_forget_about` root must remain exactly the unconditional
   per-opcode cleanup of FS1. It is not a general floating-register discard. */
const configuredFForgetCalls = [...configuredSupport.matchAll(/\bf_forget_about\s*\(\s*([^)]*)\)/g)]
  .map((match) => match[1].trim());
if (configuredFForgetCalls.length !== 1 || configuredFForgetCalls[0] !== "9")
  throw new Error(`configured f_forget_about roots=${configuredFForgetCalls.join("|")}, expected sole FS1`);
if (countToken(`${configuredGenerated}\n${configuredCompat}\n${configuredFpp}\n${configuredFppCompat}`, "f_forget_about") !== 0)
  throw new Error("f_forget_about gained a configured root outside per-opcode support cleanup");

/* `fflags_into_flags` has exactly two configured compiler roots: FScc and
   FBcc. Its raw compare boundary remains a separate closure row. */
const configuredFflagsIntoFlagsCalls = countToken(configuredFpp, "fflags_into_flags");
if (configuredFflagsIntoFlagsCalls !== 2)
  throw new Error(`configured fflags_into_flags roots=${configuredFflagsIntoFlagsCalls}, expected FScc and FBcc`);
if (countToken(`${configuredGenerated}\n${configuredSupport}\n${configuredCompat}\n${configuredFppCompat}`, "fflags_into_flags") !== 0)
  throw new Error("fflags_into_flags gained a configured root outside the FPU compiler");
for (const [startMarker, endMarker, consumer] of [
  ["void comp_fscc_opp", "void comp_ftrapcc_opp", "fp_fscc_ri"],
  ["void comp_fbcc_opp", "void comp_fsave_opp", "register_branch"],
] as const) {
  const start = configuredFpp.indexOf(startMarker);
  const end = configuredFpp.indexOf(endMarker, start + startMarker.length);
  if (start < 0 || end < 0) throw new Error(`configured fflags_into_flags ${startMarker} boundary disappeared`);
  const body = configuredFpp.slice(start, end);
  const preserve = body.indexOf("preserve_flags_before_nzcv_clobber");
  const materialise = body.indexOf("fflags_into_flags");
  const consume = body.indexOf(consumer, materialise);
  if (countToken(body, "fflags_into_flags") !== 1 || preserve < 0 || materialise <= preserve || consume <= materialise)
    throw new Error(`configured fflags_into_flags ${startMarker} ordering changed`);
}

const configuredDontCareFflagsCalls = countToken(configuredFpp, "dont_care_fflags");
if (configuredDontCareFflagsCalls !== 32)
  throw new Error(`configured dont_care_fflags call census=${configuredDontCareFflagsCalls}, expected 32`);
const configuredFppOperationStart = configuredFpp.search(/void comp_fpp_opp\s*\([^)]*opcode\s*,[^)]*extra\s*\)/);
if (configuredFppOperationStart < 0)
  throw new Error("configured FPP operation compiler boundary disappeared");
const configuredFppOperation = configuredFpp.slice(configuredFppOperationStart);
const configuredOrdinaryMoveStart = configuredFppOperation.indexOf("case 0x00:");
const configuredOrdinaryMoveEnd = configuredFppOperation.indexOf("case 0x01:", configuredOrdinaryMoveStart);
if (configuredOrdinaryMoveStart < 0 || configuredOrdinaryMoveEnd < 0)
  throw new Error("configured ordinary FMOVE selector disappeared");
const configuredOrdinaryMove = configuredFppOperation.slice(configuredOrdinaryMoveStart, configuredOrdinaryMoveEnd);
if (countToken(configuredOrdinaryMove, "dont_care_fflags") !== 1 ||
    configuredOrdinaryMove.indexOf("dont_care_fflags();") > configuredOrdinaryMove.indexOf("get_fp_value(opcode, extra)"))
  throw new Error("configured ordinary FMOVE invalidation ordering changed");
for (const match of configuredFppOperation.matchAll(/\bdont_care_fflags\s*\(\s*\)/g)) {
  if (match.index! >= configuredOrdinaryMoveStart && match.index! < configuredOrdinaryMoveEnd) continue;
  const selectorStart = configuredFppOperation.lastIndexOf("case 0x", match.index!);
  const selectorPrefix = configuredFppOperation.slice(selectorStart, match.index!);
  if (selectorStart < 0 || selectorPrefix.lastIndexOf("return;") < 0)
    throw new Error(`dont_care_fflags gained a configured non-FMOVE root near offset ${match.index}`);
}

const rootMidText = `${configuredGenerated}\n${configuredSupport}\n${configuredCompat}\n${configuredFpp}\n${configuredFppCompat}`;
for (const name of semanticServiceMid.keys()) {
  const rootReferences = countToken(rootMidText, name);
  const midReferences = midDefs.reduce((sum, def) =>
    sum + (def.name === name ? 0 : countToken(def.body, name)), 0);
  const expectedRootReferences = name === "ffunc_rr" || name === "fmov_s_ri" ||
      name === "fp_from_exten_mr" || name === "fp_to_exten_rm" ? 4
    : name === "fmul_rr" || name === "fdiv_rr" ? 2 : 1;
  const expectedMidReferences = name === "fmov_d_ri_0" || name === "fmov_d_ri_1" ? 1 : 0;
  if (rootReferences !== expectedRootReferences)
    throw new Error(`serviced native MIDFUNC ${name} configured-root references=${rootReferences}, expected ${expectedRootReferences} retained selector call(s)`);
  if (midReferences !== expectedMidReferences)
    throw new Error(`serviced native MIDFUNC ${name} MIDFUNC references=${midReferences}, expected ${expectedMidReferences}`);
}
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
  ...configuredUnreachableMid,
  ...semanticServiceMid,
]);
const structuralProofTokens: Array<[string, string, string[]]> = [
  ["jff_BFINS_dd", source.support, ["table68k[opcode].mnemo == i_BFINS", "op_bitfield_comp_ff"]],
  ["jnf_MVMEL_l", source.gencomp, ["case i_MVMEL:", "genmovemel (opcode);"]],
  ["jnf_MOVE16", source.gencomp, ["case i_MOVE16:", "genmov16(opcode,curi);"]],
  ["jff_MOVE_l", source.gencomp, ["case i_MOVE:", "genflags (flag_logical", "genastore (\"src\""]],
  ["jnf_TAS", source.gencomp, ["case i_TAS:", "jff_TAS(src)"]],
  ["jnf_DIVS", source.gencomp, ["case i_DIVS:", "jff_DIVS(dst, src)"]],
  ["sub_w_ri", source.compat, ["void dbcc_dec_w(W2 d) { jnf_SUB_w_imm(d, 1); }"]],
  ["fmov_d_rm", source.fpp, ["extern void fmov_d_rm(unsigned int r, uintptr m);", "fmov_rm(FS1, (uintptr) (temp_fp));"]],
  ["fmovs_rm", source.fpp, ["extern void fmovs_rm(unsigned int r, uintptr m);", "fmov_s_rr(FS1, reg);", "fmov_s_rr(FS1, S2);", "fmovs_rm(FS1, (uintptr) temp_fp);"]],
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
  const audit = acceptedAudit(def.name) ?? acceptedPrimitiveAudit(def.name);
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
const configuredOpcodeSources = [
  load("BasiliskII/src/Unix/cpudefs.cpp"),
  load("BasiliskII/src/Unix/compstbl.cpp"),
  source.generated,
];
const configuredUnreachableUaeOnly = new Set([...configuredUnreachableGenerator.keys()].filter((name) => name !== "i_MMUOP"));
for (const [name] of configuredUnreachableGenerator) {
  if (!uniqueGen.has(name)) throw new Error(`configured-unreachable generator label disappeared: ${name}`);
  const mnemonic = name.slice(2);
  if (configuredOpcodeSources.some((text) => countToken(text, mnemonic) !== 0))
    throw new Error(`configured-unreachable generator gained an opcode/provider: ${name}`);
  const configuredReferences = countToken(configuredGencomp, name);
  if (configuredUnreachableUaeOnly.has(name) ? configuredReferences !== 0 : configuredReferences !== 1)
    throw new Error(`configured generator preprocessing changed for ${name}: references=${configuredReferences}`);
}
for (const [name, found] of uniqueGen) {
  const audit = acceptedAudit(name);
  const serviced = serviceGenerator.has(name);
  const unreachable = configuredUnreachableGenerator.get(name);
  const status: Status = serviced ? "serviced" : audit ? "audited" : unreachable ? "unreachable" : "unreviewed";
  const evidence = serviced
    ? "post-registration or generated ordered semantic-service table; AARCH64_JIT_AUDIT_ORDERED_SEMANTIC_SERVICES.md"
    : audit ? `BasiliskII/docs/${audit}`
    : unreachable ? `${unreachable}; AARCH64_JIT_AUDIT_MMU_UNREACHABLE.md`
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
if (rawNames.size !== 83)
  throw new Error(`raw-boundary census changed: ${rawNames.size}, expected 83`);
const auditedRaw = /^(?:compemu_raw_(?:branch|call|call_observer_|cmp_pc|endblock_|jmp|maybe_cachemiss|maybe_recompile|observer_|set_pc_)|raw_(?:flags_to_reg|reg_to_flags|jcc|push_regs_to_preserve|pop_preserved_regs))/;
const structuralUnreachableRaw = new Map<string, string>([
  ["raw_fabs_rr", "only its LOWFUNC/LENDFUNC definition remains after configured AArch64 sign selectors service before unreachable fabs_rr"],
  ["raw_fneg_rr", "only its LOWFUNC/LENDFUNC definition remains after configured AArch64 sign selectors service before unreachable fneg_rr"],
  ["raw_fadd_rr", "only its LOWFUNC/LENDFUNC definition remains after configured AArch64 add selectors service before unreachable fadd_rr"],
  ["raw_fsqrt_rr", "only its LOWFUNC/LENDFUNC definition remains after configured AArch64 square-root selectors service before unreachable fsqrt_rr"],
  ["raw_fsub_rr", "only its LOWFUNC/LENDFUNC definition remains after configured AArch64 subtract selectors service before unreachable fsub_rr"],
  ["raw_fmul_rr", "only its LOWFUNC/LENDFUNC definition remains after both configured AArch64 multiply roots service before unreachable fmul_rr"],
  ["raw_fdiv_rr", "only its LOWFUNC/LENDFUNC definition remains after both configured AArch64 divide roots service before unreachable fdiv_rr; later paired remainder retirement also makes FDIV_ddd unreachable"],
  ["raw_ffunc_rr", "only its LOWFUNC/LENDFUNC definition remains after all four configured AArch64 FSIN/FETOX/FLOG2/FCOS roots enter MPFR service before unreachable ffunc_rr; AARCH64_JIT_AUDIT_FFUNC_RETIREMENT.md"],
  ["raw_fmov_d_ri_0", "only its LOWFUNC/LENDFUNC definition remains below unreachable fmov_d_ri_0 after configured FMOVECR selector 15 enters exact MPFR service; MOVI_di remains independently classified; AARCH64_JIT_AUDIT_FMOV_ZERO_ONE_RETIREMENT.md"],
  ["raw_fmov_d_ri_1", "only its LOWFUNC/LENDFUNC definition remains below unreachable fmov_d_ri_1 after configured FMOVECR selector 50 enters exact MPFR service; FMOV_di remains audited and reachable elsewhere; AARCH64_JIT_AUDIT_FMOV_ZERO_ONE_RETIREMENT.md"],
  ["raw_frndint_rr", "only its LOWFUNC/LENDFUNC definition remains below unreachable frndint_rr; FRINTI_dd remains reachable from integer-destination rounding"],
  ["raw_frndintz_rr", "only its LOWFUNC/LENDFUNC definition remains below unreachable frndintz_rr; later paired remainder retirement also makes FRINTZ_dd unreachable"],
  ["raw_fcuts_r", "only its LOWFUNC/LENDFUNC definition remains below unreachable fcuts_r after configured AArch64 FSMOVE/FDMOVE service; FCVT_sd/FCVT_ds remain reachable from other compositions"],
  ["raw_fmov_d_ri_10", "only its LOWFUNC/LENDFUNC definition remains below unreachable fmov_d_ri_10 and fmov_l_ri; FMOV_di remains reachable from other compositions"],
  ["raw_fmov_d_ri_100", "only its LOWFUNC/LENDFUNC definition remains below unreachable fmov_d_ri_100 and fmov_l_ri; SCVTF_dw remains reachable from other compositions"],
  ["raw_fmov_d_rrr", "only its LOWFUNC/LENDFUNC definition remains below unreachable fmov_d_rrr; BFI_xxii and FMOV_dx remain reachable from other compositions"],
  ["raw_fmovs_rm", "only its LOWFUNC/LENDFUNC definition remains below configured-unreachable fmovs_rm; active AArch64 single sources use fmov_s_rr -> raw_fmov_s_rr; LDR_sXi and FCVT_ds remain independently classified; AARCH64_JIT_AUDIT_FMOVS_RM_UNREACHABLE.md"],
  ["raw_fmov_to_d_rrr", "only its LOWFUNC/LENDFUNC definition remains below unreachable fmov_to_d_rrr after configured double destinations enter exact MPFR service before put_fp_value; FMOV_xd and LSR_xxi remain independently classified; AARCH64_JIT_AUDIT_FMOV_TO_D_RRR_UNREACHABLE.md"],
  ["raw_fp_from_double_mr", "only its LOWFUNC/LENDFUNC definition remains below configured-unreachable fp_from_double_mr; the retained fmov_mr source call is in the inactive non-AArch64 ordinary-double destination arm; REV64_dd and STR_dXx remain independently classified; AARCH64_JIT_AUDIT_FP_FROM_DOUBLE_MR_UNREACHABLE.md"],
  ["raw_fp_from_exten_mr", "only its LOWFUNC/LENDFUNC definition remains below service-dominated fp_from_exten_mr; all ordinary/static-FMOVEM store compositions enter exact MPFR service first; AARCH64_JIT_AUDIT_FP_EXTENDED_MEMORY_UNREACHABLE.md"],
  ["raw_fp_to_exten_rm", "only its LOWFUNC/LENDFUNC definition remains below service-dominated fp_to_exten_rm; all ordinary/static-FMOVEM load compositions enter exact MPFR service first; AARCH64_JIT_AUDIT_FP_EXTENDED_MEMORY_UNREACHABLE.md"],
  ["raw_fmod_rr", "only its LOWFUNC/LENDFUNC definition remains below unreachable fmod_rr after configured FMOD service; its retained FDIV_ddd and FMSUB_dddd sites are retired with the paired FREM lower chain"],
  ["raw_fmovs_rr", "only its LOWFUNC/LENDFUNC definition remains below unreachable fmovs_rr; FCVT_sd and FCVT_ds remain reachable from other compositions"],
  ["raw_frem1_rr", "only its LOWFUNC/LENDFUNC definition remains below unreachable frem1_rr after configured FREM service; its retained FDIV_ddd and FMSUB_dddd sites are retired with the paired FMOD lower chain"],
  ["raw_fsgldiv_rr", "only its LOWFUNC/LENDFUNC definition remains below unreachable fsgldiv_rr after configured AArch64 FSGLDIV service; FCVT_sd and FCVT_ds remain reachable from other compositions"],
  ["raw_fsglmul_rr", "only its LOWFUNC/LENDFUNC definition remains below unreachable fsglmul_rr after configured AArch64 FSGLMUL service; FCVT_sd and FCVT_ds remain reachable from other compositions"],
]);
for (const name of [...rawNames].sort()) {
  let file = rawFiles[0]; let text = load(file); let index = text.search(new RegExp(`\\b${esc(name)}\\b`));
  for (const candidate of rawFiles) {
    const candidateText = load(candidate); const candidateIndex = candidateText.search(new RegExp(`\\b${esc(name)}\\b`));
    if (candidateIndex >= 0) { file = candidate; text = candidateText; index = candidateIndex; break; }
  }
  const activeReachableMid = [...reachableMid].map((mid) => activeMidBodies.get(mid) ?? "").join("\n");
  const configuredRawText = `${activeGenerated}\n${activeGencomp}\n${activeCodegen}\n${activeSupport}\n${activeCompat}\n${activeFpp}\n${activeFppCompat}\n${activeReachableMid}`;
  const references = countToken(configuredRawText, name);
  const primitiveAudit = acceptedPrimitiveAudit(name);
  if (structuralUnreachableRaw.has(name) && references !== 2)
    throw new Error(`serviced native raw boundary ${name} references=${references}, expected definition-only count 2`);
  const status: Status = (auditedRaw.test(name) || primitiveAudit) ? "audited"
    : structuralUnreachableRaw.has(name) || references <= 1 ? "unreachable" : "unreviewed";
  const evidence = status === "audited"
    ? primitiveAudit
      ? `BasiliskII/docs/${primitiveAudit}`
      : name === "compemu_raw_call_preserve_nzcv"
        ? "BasiliskII/docs/AARCH64_JIT_AUDIT_FPP_SIGN_SUBTRANCHE.md"
        : "AARCH64_JIT_AUDIT_AREA1_BLOCK_LIFECYCLE.md; AREA2_PC_OWNERSHIP.md; AREA3_FLAGS_LIVENESS.md; AREA4_CALLS_AND_ALLOCATOR.md"
    : status === "unreachable" ? (structuralUnreachableRaw.get(name) ?? "no production caller")
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
const semanticServiceEmitter = new Map<string, string>([
  ["FABS_dd", "only retained raw_fabs_rr emits it, and configured AArch64 sign selectors service before unreachable fabs_rr"],
  ["FNEG_dd", "only retained raw_fneg_rr emits it, and configured AArch64 sign selectors service before unreachable fneg_rr"],
  ["FADD_ddd", "only retained raw_fadd_rr emits it, and configured AArch64 add selectors service before unreachable fadd_rr"],
  ["FSQRT_dd", "only retained raw_fsqrt_rr emits it, and configured AArch64 square-root selectors service before unreachable fsqrt_rr"],
  ["FSUB_ddd", "only retained raw_fsub_rr emits it, and configured AArch64 subtract selectors service before unreachable fsub_rr"],
  ["FMUL_ddd", "only retained raw_fmul_rr emits it, and both configured AArch64 multiply roots service before unreachable fmul_rr"],
  ["FMUL_sss", "only retained raw_fsglmul_rr emits it, and configured AArch64 FSGLMUL services before unreachable fsglmul_rr"],
  ["FDIV_ddd", "all three retained sites are below unreachable raw_fdiv_rr plus paired definition-only raw_fmod_rr/raw_frem1_rr after configured divide/FMOD/FREM service"],
  ["FDIV_sss", "only retained raw_fsgldiv_rr emits it, and configured AArch64 FSGLDIV services before unreachable fsgldiv_rr"],
  ["FMSUB_dddd", "both retained sites are below paired definition-only raw_fmod_rr/raw_frem1_rr after configured FMOD/FREM service"],
  ["FRINTA_dd", "its sole retained site is below definition-only raw_frem1_rr after configured FREM service"],
  ["FRINTZ_dd", "both retained sites are below definition-only raw_frndintz_rr/raw_fmod_rr after configured FINT/FINTRZ and FMOD service"],
]);
const semanticServiceEmitterSites = new Map<string, number>([["FDIV_ddd", 3], ["FMSUB_dddd", 2], ["FRINTZ_dd", 2]]);
const emitterNonCodegenRootText = `${activeGenerated}\n${activeGencomp}\n${activeSupport}\n${activeCompat}\n${activeFpp}\n${activeFppCompat}\n${activeReachableMid}`;
for (const name of semanticServiceEmitter.keys()) {
  const expectedSites = semanticServiceEmitterSites.get(name) ?? 1;
  if (countToken(activeCodegen, name) !== expectedSites || countToken(emitterNonCodegenRootText, name) !== 0)
    throw new Error(`serviced native emitter ${name} sites/callers changed; expected ${expectedSites} retained codegen sites and zero configured external callers`);
}
const reachableEmitter = new Set<string>();
for (const name of emitterNames)
  if (!semanticServiceEmitter.has(name) && countToken(emitterRootText, name) > 0) reachableEmitter.add(name);
for (let changed = true; changed;) {
  changed = false;
  for (const name of [...reachableEmitter]) {
    const chunk = emitterDefinitions.get(name)?.chunk ?? "";
    for (const target of emitterNames)
      if (!semanticServiceEmitter.has(target) && !reachableEmitter.has(target) && countToken(chunk, target) > 0) { reachableEmitter.add(target); changed = true; }
  }
}
const structuralUnreachableEmitter = new Map<string, string>([
  ["SUBS_wwish", "only used by unreachable sub_w_ri; configured DBcc uses dbcc_dec_w -> jnf_SUB_w_imm"],
  ...semanticServiceEmitter,
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
md.push("", "## Accepted closure targets", "", "- `MOVEM` (`i_MVMEL` / `i_MVMLE`) is closed by `AARCH64_JIT_AUDIT_MOVEM_LIFECYCLE.md`. Its four legacy `jnf_MVMEL/MVMLE` MIDFUNC definitions remain unreachable; the repaired live contract is emitted directly by `genmovemel()` / `genmovemle()` and generic memory primitives.", "- `NEGX` (`i_NEGX`) is closed by `AARCH64_JIT_AUDIT_NEGX_LIFECYCLE.md`. Its six `jff_/jnf_NEGX_{b,w,l}` namesakes remain unreachable; the live generator uses the shared repaired `flag_subx` -> `sbb_b/w/l` lifecycle.", "- `ADD` (`i_ADD`) is closed by `AARCH64_JIT_AUDIT_ADD_LIFECYCLE.md` through its 12 reachable flag-live/no-flags and immediate MIDFUNC routes. The unused `jnf_ADD_im8` remains unreachable. The seven reachable generic non-flag-setting ADD encoder APIs are independently closed by `AARCH64_JIT_AUDIT_ADD_EMITTERS.md`; `ADD_xxxLSLi` remains unreachable.", "- `SUB` (`i_SUB`) is closed by `AARCH64_JIT_AUDIT_SUB_LIFECYCLE.md` through its 12 reachable flag-live/no-flags and immediate MIDFUNC routes. The seven reachable generic SUB/SUBS encoder APIs are independently closed by `AARCH64_JIT_AUDIT_SUB_EMITTERS.md`; six configured-root-unreachable SUB/SUBS forms remain unreachable, while `SBCS_www` remains separate.", "- `AND` (`i_AND`) is closed by `AARCH64_JIT_AUDIT_AND_LIFECYCLE.md` through its 12 reachable flag-live/no-flags and immediate MIDFUNC routes. Its shared writable-memory EA repair is independently exercised by the adjacent EOR and OR lifecycle audits. The three reachable generic non-flag-setting AND encoder APIs are independently closed by `AARCH64_JIT_AUDIT_AND_EMITTERS.md`; `AND_ww1f` and `AND_xx1f` remain unreachable, and `ANDS_*` remains separate.", "- `EOR` (`i_EOR`) is closed by `AARCH64_JIT_AUDIT_EOR_LIFECYCLE.md` through its 12 reachable flag-live/no-flags and immediate MIDFUNC routes. The five reachable generic EOR encoder APIs are independently closed by `AARCH64_JIT_AUDIT_EOR_EMITTERS.md`; `EOR_xxx` and `EOR_xxxLSLi` remain unreachable.", "- `OR` (`i_OR`) is closed by `AARCH64_JIT_AUDIT_OR_LIFECYCLE.md` through its 12 reachable flag-live/no-flags and immediate MIDFUNC routes, nine readable source EA classes, and seven writable destination EA classes. Generic `ORR_*` and `immOP_ORR` encoder APIs remain separate.", "", "## Next selected family", "", nextFamilyText, "", "## Mechanical invariants", "", `- unique \`gencomp.c\` mnemonic cases: **${uniqueGen.size}**;`, `- unique AArch64 MIDFUNC definitions: **${midDefs.length}**;`, `- codegen emitter API definitions: **${emitterDefinitions.size}**;`, `- raw boundary functions: **${rawNames.size}**;`, `- runtime helper boundaries: **${runtimeNames.size}**;`, "- FPU roots come from the macro-expanded source selected by the current Makefile defines, not inactive preprocessor branches or unused compatibility macros;", "- the script fails closed if any known layer census or accepted report changes.", "", "## Regeneration", "", "```sh", "bun jit-test/closure-inventory.ts", "git diff --check", "```", "");
writeFileSync(mdPath, md.join("\n"));

console.log(`CLOSURE_INVENTORY rows=${rows.length} generator=${uniqueGen.size} midfunc=${midDefs.length} emitter_api=${emitterDefinitions.size} raw_boundary=${rawNames.size} runtime_boundary=${runtimeNames.size}`);
for (const item of summary) console.log(`CLOSURE_LAYER layer=${item.layer} total=${item.total} audited=${item.counts.audited} serviced=${item.counts.serviced} unreachable=${item.counts.unreachable} unreviewed=${item.counts.unreviewed}`);
console.log(`wrote ${rel(csvPath)} and ${rel(mdPath)}`);
