#!/usr/bin/env bun

import { existsSync, readFileSync } from "node:fs";
import { resolve } from "node:path";

const root = resolve(import.meta.dir, "..");
const load = (path: string) => readFileSync(resolve(root, path), "utf8");
const fail = (message: string): never => {
  console.error(`FPP_LIFECYCLE_CENSUS_FAIL ${message}`);
  process.exit(1);
};
const requireText = (body: string, text: string, context: string) => {
  if (!body.includes(text)) fail(`${context}: missing ${text}`);
};

const gencomp = load("BasiliskII/src/uae_cpu_2026/compiler/gencomp.c");
const fpp = load("BasiliskII/src/uae_cpu_2026/compiler/compemu_fpp.cpp");
const generatorStart = gencomp.indexOf("     case i_FPP:");
const generatorEnd = gencomp.indexOf("     case i_FBcc:", generatorStart);
if (generatorStart < 0 || generatorEnd < 0) fail("missing i_FPP generator route");
const generator = gencomp.slice(generatorStart, generatorEnd);
for (const contract of [
  "uses_fpu;", "mayfail;", "uae_u16 extra=", "swap_opcode();",
  "comp_fpp_opp(opcode,extra);", "failure = 1;",
]) requireText(generator, contract, "i_FPP generator route");

const lifecycleStart = fpp.indexOf("void comp_fpp_opp(uae_u32 opcode, uae_u16 extra)");
if (lifecycleStart < 0) fail("missing comp_fpp_opp lifecycle");
const lifecycle = fpp.slice(lifecycleStart);
const topSwitch = lifecycle.indexOf("switch ((extra >> 13) & 0x7)");
const topBrace = lifecycle.indexOf("{", topSwitch);
if (topSwitch < 0 || topBrace < 0) fail("missing FPP top-level form switch");
let depth = 0;
const topForms: number[] = [];
for (let cursor = topBrace; cursor < lifecycle.length; cursor++) {
  const char = lifecycle[cursor];
  if (char === "{") depth++;
  else if (char === "}") {
    depth--;
    if (depth === 0) break;
  } else if (depth === 1 && lifecycle.startsWith("case ", cursor)) {
    const match = lifecycle.slice(cursor).match(/^case ([0-7]):/);
    if (match) topForms.push(Number(match[1]));
  }
}
const exactTopForms = [...new Set(topForms)].sort((a, b) => a - b);
if (exactTopForms.length !== 8 || exactTopForms.some((value, index) => value !== index))
  fail(`top-level forms=[${exactTopForms.join(",")}], expected=0,1,2,3,4,5,6,7`);
for (const contract of [
  "switch ((extra >> 13) & 0x7)",
  "/* FMOVE Fpn,<ea> */", "/* FMOVEM <ea>,<reglist> */",
  "/* FMOVEM <reglist>,<ea> */", "/* FMOVEM <ea>,<control> */",
  "/* FMOVEM <control>,<ea> */", "if ((extra & 0xfc00) == 0x5c00)",
  "switch (extra & 0x7f)", "default:", "FAIL(1);",
]) requireText(lifecycle, contract, "FPP lifecycle dispatch");

interface Owner {
  name: string;
  selectors: number[];
  matrix: string;
  report: string;
}
const owners: Owner[] = [
  { name: "ordinary-move", selectors: [0x00], matrix: "fpp-fmove-source-matrix.ts", report: "AARCH64_JIT_AUDIT_FPP_FMOVE_SOURCE_SUBTRANCHE.md" },
  { name: "explicit-move", selectors: [0x40, 0x44], matrix: "fpp-explicit-move-fallback-matrix.ts", report: "AARCH64_JIT_AUDIT_FPP_EXPLICIT_MOVE_SUBTRANCHE.md" },
  { name: "integral-decomposition", selectors: [0x01, 0x03, 0x1e, 0x1f], matrix: "fpp-integral-rounding-fallback-matrix.ts", report: "AARCH64_JIT_AUDIT_FPP_UNARY_DECOMPOSITION_BATCH.md" },
  { name: "sqrt", selectors: [0x04, 0x41, 0x45], matrix: "fpp-sqrt-fallback-matrix.ts", report: "AARCH64_JIT_AUDIT_FPP_SQRT_SUBTRANCHE.md" },
  { name: "hyperbolic-log1p", selectors: [0x02, 0x06, 0x08, 0x09], matrix: "fpp-hyperbolic-log1p-fallback-matrix.ts", report: "AARCH64_JIT_AUDIT_FPP_HYPERBOLIC_LOG1P_BATCH.md" },
  { name: "inverse", selectors: [0x0a, 0x0c, 0x0d], matrix: "fpp-inverse-fallback-matrix.ts", report: "AARCH64_JIT_AUDIT_FPP_INVERSE_BATCH.md" },
  { name: "native-transcendental", selectors: [0x0e, 0x10, 0x11, 0x16], matrix: "fpp-native-transcendental-service-matrix.ts", report: "AARCH64_JIT_AUDIT_FPP_NATIVE_TRANSCENDENTAL_BATCH.md" },
  { name: "tan-exp-log", selectors: [0x0f, 0x12, 0x14, 0x15], matrix: "fpp-tan-exp10-log-fallback-matrix.ts", report: "AARCH64_JIT_AUDIT_FPP_TAN_EXP10_LOG_BATCH.md" },
  { name: "sign", selectors: [0x18, 0x58, 0x5c, 0x1a, 0x5a, 0x5e], matrix: "fpp-sign-fallback-matrix.ts", report: "AARCH64_JIT_AUDIT_FPP_SIGN_SUBTRANCHE.md" },
  { name: "cosh-acos-cos", selectors: [0x19, 0x1c, 0x1d], matrix: "fpp-cosh-acos-cos-service-matrix.ts", report: "AARCH64_JIT_AUDIT_FPP_COSH_ACOS_COS_BATCH.md" },
  { name: "divide", selectors: [0x20, 0x60, 0x64], matrix: "fpp-divide-service-matrix.ts", report: "AARCH64_JIT_AUDIT_FPP_DIVIDE_BATCH.md" },
  { name: "mod", selectors: [0x21], matrix: "fpp-fmod-service-matrix.ts", report: "AARCH64_JIT_AUDIT_FPP_FMOD_BATCH.md" },
  { name: "add", selectors: [0x22, 0x62, 0x66], matrix: "fpp-add-service-matrix.ts", report: "AARCH64_JIT_AUDIT_FPP_ADD_BATCH.md" },
  { name: "multiply", selectors: [0x23, 0x63, 0x67], matrix: "fpp-mul-service-matrix.ts", report: "AARCH64_JIT_AUDIT_FPP_MUL_BATCH.md" },
  { name: "single-divide", selectors: [0x24], matrix: "fpp-sgldiv-service-matrix.ts", report: "AARCH64_JIT_AUDIT_FPP_SGLDIV_BATCH.md" },
  { name: "remainder", selectors: [0x25], matrix: "fpp-frem-service-matrix.ts", report: "AARCH64_JIT_AUDIT_FPP_FREM_BATCH.md" },
  { name: "scale", selectors: [0x26], matrix: "fpp-scale-service-matrix.ts", report: "AARCH64_JIT_AUDIT_FPP_SCALE_BATCH.md" },
  { name: "single-multiply", selectors: [0x27], matrix: "fpp-sglmul-service-matrix.ts", report: "AARCH64_JIT_AUDIT_FPP_SGLMUL_BATCH.md" },
  { name: "subtract", selectors: [0x28, 0x68, 0x6c], matrix: "fpp-sub-service-matrix.ts", report: "AARCH64_JIT_AUDIT_FPP_SUB_BATCH.md" },
  { name: "sincos", selectors: [0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37], matrix: "fpp-sincos-service-matrix.ts", report: "AARCH64_JIT_AUDIT_FPP_SINCOS_BATCH.md" },
  { name: "compare", selectors: [0x38], matrix: "fpp-compare-native-matrix.ts", report: "AARCH64_JIT_AUDIT_FPP_COMPARE_FTST_SUBTRANCHE.md" },
  { name: "test", selectors: [0x3a], matrix: "fpp-ftst-native-matrix.ts", report: "AARCH64_JIT_AUDIT_FPP_COMPARE_FTST_SUBTRANCHE.md" },
];

const seen = new Map<number, string>();
for (const owner of owners) {
  const matrixPath = resolve(root, "jit-test", owner.matrix);
  const reportPath = resolve(root, "BasiliskII/docs", owner.report);
  if (!existsSync(matrixPath)) fail(`${owner.name}: missing matrix ${owner.matrix}`);
  if (!existsSync(reportPath)) fail(`${owner.name}: missing report ${owner.report}`);
  const matrix = readFileSync(matrixPath, "utf8");
  const report = readFileSync(reportPath, "utf8");
  requireText(matrix, "process.exit", `${owner.name} matrix fail-closed exit`);
  requireText(report, "## Scope", `${owner.name} report scope`);
  for (const selector of owner.selectors) {
    if (seen.has(selector)) fail(`selector 0x${selector.toString(16)} owned by both ${seen.get(selector)} and ${owner.name}`);
    seen.set(selector, owner.name);
    requireText(lifecycle, `case 0x${selector.toString(16).padStart(2, "0")}:`, `${owner.name} selector`);
  }
}
const expectedSelectors = [...seen.keys()].sort((a, b) => a - b);
if (expectedSelectors.length !== 61) fail(`owned selector count=${expectedSelectors.length}, expected=61`);
const operationSwitches = [...lifecycle.matchAll(/switch \(extra & 0x7f\)/g)];
if (operationSwitches.length !== 2) fail(`operation/constant switch count=${operationSwitches.length}, expected=2`);
const operationDispatch = lifecycle.slice(operationSwitches[1].index!);
const sourceSelectors = [...new Set(
  [...operationDispatch.matchAll(/^\s*case 0x([0-9a-f]{2}):/gmi)].map((match) => Number.parseInt(match[1], 16)),
)].sort((a, b) => a - b);
if (sourceSelectors.length !== expectedSelectors.length || sourceSelectors.some((value, index) => value !== expectedSelectors[index])) {
  const hex = (values: number[]) => values.map((value) => `0x${value.toString(16).padStart(2, "0")}`).join(",");
  fail(`operation selector ownership mismatch source=[${hex(sourceSelectors)}] owners=[${hex(expectedSelectors)}]`);
}

const topOwners = [
  ["ordinary FMOVE sources", "fpp-fmove-source-matrix.ts", "AARCH64_JIT_AUDIT_FPP_FMOVE_SOURCE_SUBTRANCHE.md"],
  ["ordinary FMOVE destinations", "fpp-fmove-double-destination-matrix.ts", "AARCH64_JIT_AUDIT_FPP_FMOVE_DOUBLE_DESTINATION_BATCH.md"],
  ["extended FMOVE", "fpp-fmove-extended-fallback-matrix.ts", "AARCH64_JIT_AUDIT_FPP_FMOVE_EXTENDED_FORMAT_SUBTRANCHE.md"],
  ["packed FMOVE", "fpp-fmove-packed-fallback-matrix.ts", "AARCH64_JIT_AUDIT_FPP_FMOVE_PACKED_FORMAT_SUBTRANCHE.md"],
  ["FMOVECR", "fpp-fmovecr-fallback-matrix.ts", "AARCH64_JIT_AUDIT_FPP_FMOVECR_SUBTRANCHE.md"],
  ["dynamic FMOVEM", "fpp-fmovem-dynamic-service-matrix.ts", "AARCH64_JIT_AUDIT_FPP_FMOVEM_DYNAMIC_BATCH.md"],
  ["static FMOVEM", "fpp-fmovem-static-service-matrix.ts", "AARCH64_JIT_AUDIT_FPP_FMOVEM_STATIC_BATCH.md"],
  ["direct control", "fpp-control-direct-service-matrix.ts", "AARCH64_JIT_AUDIT_FPP_CONTROL_DIRECT_BATCH.md"],
  ["basic memory control", "fpp-control-memory-basic-matrix.ts", "AARCH64_JIT_AUDIT_FPP_CONTROL_MEMORY_BASIC_BATCH.md"],
  ["indexed memory control", "fpp-control-memory-indexed-matrix.ts", "AARCH64_JIT_AUDIT_FPP_CONTROL_MEMORY_INDEXED_BATCH.md"],
] as const;
for (const [name, matrix, report] of topOwners) {
  if (!existsSync(resolve(root, "jit-test", matrix))) fail(`${name}: missing matrix ${matrix}`);
  if (!existsSync(resolve(root, "BasiliskII/docs", report))) fail(`${name}: missing report ${report}`);
}

const epoch = load("BasiliskII/docs/AARCH64_JIT_AUDIT_FPP_32_CHECKPOINT_EPOCH.md");
for (const metric of ["METRIC pass=904", "METRIC fail=0", "selected=31 pass=31 fail=0", "strict_full_jit_negative_gate=1"])
  requireText(epoch, metric, "FPP acceptance epoch");

console.log(`FPP_LIFECYCLE_CENSUS top_forms=8 operation_selectors=${expectedSelectors.length} selector_owners=${owners.length} top_level_owners=${topOwners.length}`);
console.log("FPP_LIFECYCLE_CENSUS integrated_pass=904 integrated_fail=0 regpressure_pass=31 strict_negative=1");
