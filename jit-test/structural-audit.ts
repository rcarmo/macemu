#!/usr/bin/env bun

/**
 * Source-level structural invariants for the ARM64 JIT emitter.
 *
 * These checks deliberately inspect emitter ordering rather than opcode output:
 * an endblock may return to C through several branches, and every one of those
 * branches must publish the retired successor PC first.
 */

const sourcePath = new URL(
  "../BasiliskII/src/uae_cpu_2026/compiler/codegen_arm64.cpp",
  import.meta.url,
);
const source = await Bun.file(sourcePath).text();

function fail(message: string): never {
  console.error(`STRUCTURAL_AUDIT_FAIL ${message}`);
  process.exit(1);
}

function bodyBetween(start: string, end: string): string {
  const begin = source.indexOf(start);
  if (begin < 0) fail(`missing start marker: ${start}`);
  const finish = source.indexOf(end, begin + start.length);
  if (finish < 0) fail(`missing end marker after: ${start}`);
  return source.slice(begin, finish);
}

function requireText(body: string, text: string, context: string): number {
  const offset = body.indexOf(text);
  if (offset < 0) fail(`${context}: missing ${text}`);
  return offset;
}

function requireBefore(
  body: string,
  first: string,
  second: string,
  context: string,
): void {
  const firstOffset = requireText(body, first, context);
  const secondOffset = requireText(body, second, context);
  if (firstOffset >= secondOffset) {
    fail(`${context}: ${first} must precede ${second}`);
  }
}

const makefileTemplate = await Bun.file(new URL(
  "../BasiliskII/src/Unix/Makefile.in",
  import.meta.url,
)).text();
for (const layoutDependency of [
  "JIT_LAYOUT_DEPS = Makefile sysdeps.h $(UAE_PATH)/newcpu.h",
  "$(UAE_PATH)/registers.h $(UAE_PATH)/memory.h $(UAE_PATH)/fpu/types.h",
  "$(UAE_PATH)/compiler/compemu.h",
  "JIT_SUPPORT_DEPS = $(UAE_PATH)/compiler/compemu_support_arm.cpp",
  "$(UAE_PATH)/compiler/compemu_legacy_arm64_compat.cpp",
  "$(UAE_PATH)/compiler/codegen_arm64.cpp",
  "$(UAE_PATH)/compiler/compemu_midfunc_arm64.cpp",
  "$(JIT_LAYOUT_OBJECTS): $(JIT_LAYOUT_DEPS)",
  "JIT_MEMORY_INLINE_OBJECTS =",
  "$(OBJ_DIR)/cpuemu1_nf.o",
  "$(OBJ_DIR)/basilisk_glue.o $(OBJ_DIR)/newcpu.o",
  "$(JIT_MEMORY_INLINE_OBJECTS): $(UAE_PATH)/memory.h",
  "$(OBJ_DIR)/compemu_support.o: $(JIT_SUPPORT_DEPS)",
]) {
  requireText(makefileTemplate, layoutDependency, "JIT object layout epoch");
}
const harnessSource = await Bun.file(new URL("./run.sh", import.meta.url)).text();
const activeRiskySource = await Bun.file(new URL("./active-risky-tests.txt", import.meta.url)).text();
const shiftSource = await Bun.file(new URL(
  "../BasiliskII/src/uae_cpu_2026/compiler/compemu_midfunc_arm64_2.cpp",
  import.meta.url,
)).text();
const strictHarnessSource = await Bun.file(new URL("./strict-full-jit.sh", import.meta.url)).text();
const regallocPressureSource = await Bun.file(new URL("./regalloc-pressure.sh", import.meta.url)).text();
requireText(harnessSource, "rm -f obj/compemu*.o", "JIT object layout epoch");

const callEmitter = bodyBetween(
  "STATIC_INLINE void compemu_raw_call(uintptr t)\n{",
  "STATIC_INLINE void compemu_raw_call_r",
);
requireText(callEmitter, "LOAD_U64(R18_INDEX, t)", "helper-call ABI");
requireText(callEmitter, "BLR_x(R18_INDEX)", "helper-call ABI");
if (callEmitter.includes("LOAD_U64(REG_WORK1, t)")) {
  fail("helper-call ABI: call target clobbers x2/argument 3");
}
requireText(
  source,
  "always_used[] = {2,3,4,5,18,R_MEMSTART,R_REGSTRUCT,-1}",
  "helper-call ABI reserved target register",
);

const observerStart = source.indexOf("STATIC_INLINE void compemu_raw_observer_save(void)");
const observerEnd = source.indexOf("LOWFUNC(WRITE,READ,1,compemu_raw_cmp_pc", observerStart);
if (observerStart < 0 || observerEnd < 0) fail("missing diagnostic observer boundary");
const observerBody = source.slice(observerStart, observerEnd);
for (const preserved of [
  "STP_xxXi(r, r + 1, RSP_INDEX, r * 8)",
  "STR_xXi(R18_INDEX, RSP_INDEX, JIT_OBSERVER_X18_OFF)",
  "MRS_NZCV_x(R18_INDEX)",
  "MRS_FPCR_x(R18_INDEX)",
  "MRS_FPSR_x(R18_INDEX)",
  "STR_dXi(r, RSP_INDEX, JIT_OBSERVER_D0_OFF + r * 8)",
  "MSR_FPSR_x(R18_INDEX)",
  "MSR_FPCR_x(R18_INDEX)",
  "MSR_NZCV_x(R18_INDEX)",
  "LDP_xxXi(r, r + 1, RSP_INDEX, r * 8)",
  "compemu_raw_call_observer_i",
  "compemu_raw_call_observer_ii",
  "compemu_raw_call_observer_ri",
]) {
  requireText(observerBody, preserved, "diagnostic observer preservation");
}

const midfuncPath = new URL(
  "../BasiliskII/src/uae_cpu_2026/compiler/compemu_midfunc_arm64.cpp",
  import.meta.url,
);
const midfuncSource = await Bun.file(midfuncPath).text();
const midfunc2Source = await Bun.file(new URL(
  "../BasiliskII/src/uae_cpu_2026/compiler/compemu_midfunc_arm64_2.cpp",
  import.meta.url,
)).text();
const codegenSource = await Bun.file(new URL(
  "../BasiliskII/src/uae_cpu_2026/compiler/codegen_arm64.cpp",
  import.meta.url,
)).text();
const memorySource = await Bun.file(new URL(
  "../BasiliskII/src/uae_cpu_2026/memory.h",
  import.meta.url,
)).text();
if (
  codegenSource.includes("jit_trace_setpc_value") ||
  midfuncSource.includes("jit_trace_setpc_value")
) {
  fail("diagnostic residue: set-PC tracing remains in production JIT paths");
}
const directByteWriteStart = midfunc2Source.indexOf("MIDFUNC(2,jnf_MEM_WRITE_OFF_b");
const directByteWriteEnd = midfunc2Source.indexOf("MENDFUNC(2,jnf_MEM_WRITE_OFF_b", directByteWriteStart);
if (directByteWriteStart < 0 || directByteWriteEnd < 0) fail("missing direct byte-write helper");
const directByteWriteBody = midfunc2Source.slice(directByteWriteStart, directByteWriteEnd);
for (const contract of [
  "MRS_NZCV_x(REG_WORK4)",
  "LOAD_U32(REG_WORK1, 0xff001fff)",
  "LOAD_U32(REG_WORK3, 0x50000006)",
  "STRB_wXx(b, adr, R_MEMSTART)",
  "MSR_NZCV_x(REG_WORK4)",
]) {
  requireText(directByteWriteBody, contract, "direct byte-write interpreter contract");
}
for (const forbidden of ["NEG_ww", "CSEL_wwwc", "STRB_wXx(REG_WORK3, adr, R_MEMSTART)"]) {
  if (directByteWriteBody.includes(forbidden)) {
    fail(`direct byte-write interpreter contract: transformed source remains: ${forbidden}`);
  }
}
for (const contract of [
  "#define LOW_NUBUS_OPEN_BUS_START 0x0a014000u",
  "#define LOW_NUBUS_OPEN_BUS_END   0x0a815000u",
  "RAMSize <= 0x08000000u",
  "if (is_low_nubus_open_bus_gap(addr))\n        return 0xffffffffu;",
  "if (is_low_nubus_open_bus_gap(addr))\n        return 0xffffu;",
  "if (is_low_nubus_open_bus_gap(addr))\n        return 0xffu;",
  "if (is_low_nubus_open_bus_gap(addr) || addr == 0x5ffffffc)",
  "if (is_low_nubus_open_bus_gap(addr) || is_50f_scanner_data(addr))",
]) {
  requireText(memorySource, contract, "shared low-NuBus open-bus contract");
}
for (const contract of [
  "emit_low_nubus_gap_write_skip",
  "emit_low_nubus_gap_read_value",
  "LOW_NUBUS_OPEN_BUS_START",
  "LOW_NUBUS_OPEN_BUS_END",
  "RAMSize > 0x08000000u",
  "emit_low_nubus_gap_read_value(adr, d, 0xffffffffu)",
]) {
  requireText(midfunc2Source, contract, "emitted low-NuBus open-bus contract");
}
for (const helper of ["jnf_MEM_WRITE_OFF_b", "jnf_MEM_WRITE_OFF_w", "jnf_MEM_WRITE_OFF_l"]) {
  const start = midfunc2Source.indexOf(`MIDFUNC(2,${helper}`);
  const end = midfunc2Source.indexOf(`MENDFUNC(2,${helper}`, start);
  if (start < 0 || end < 0) fail(`missing ${helper}`);
  const body = midfunc2Source.slice(start, end);
  requireText(body, "emit_low_nubus_gap_write_skip(adr)", `${helper} JIT-cache alias protection`);
  requireText(body, "finish_low_nubus_gap_skip(gap_done)", `${helper} JIT-cache alias protection`);
}
if (midfunc2Source.includes("MOV_wi(d, 0x10)")) {
  fail("emitted low-NuBus open-bus contract: address-specific long value remains");
}

for (const contract of [
  "declare -A NATIVE_REPLAY_TESTS",
  "declare -A NATIVE_REPLAY_PC",
  "declare -A NATIVE_REPLAY_COUNT",
  "[io_byte_write_roundtrip]=1",
  'B2_TEST_TWO_PASS=1 B2_TEST_SECOND_PC="$replay_pc"',
  'B2_NATIVE_ASSERT_PC="$replay_pc"',
  "B2_TEST_FORCE_L2_RAM=1",
]) {
  requireText(harnessSource, contract, "native replay opcode gate");
}
requireText(
  harnessSource,
  "46FC 0700 0E90 0800",
  "MOVES privilege-vector interrupt masking",
);

const helperStart = midfuncSource.indexOf("MIDFUNC(1,call_helper,(IMPTR addr))");
const helperEnd = midfuncSource.indexOf("MENDFUNC(1,call_helper", helperStart);
if (helperStart < 0 || helperEnd < 0) fail("missing call_helper midfunc");
const helperBody = midfuncSource.slice(helperStart, helperEnd);
requireBefore(
  helperBody,
  "prepare_for_call_1()",
  "prepare_for_call_2()",
  "helper-call allocator barrier",
);
requireBefore(
  helperBody,
  "prepare_for_call_2()",
  "compemu_raw_call(addr)",
  "helper-call allocator barrier",
);

const regHelper = bodyBetween(
  "STATIC_INLINE void compemu_raw_set_pc_full_from_reg",
  "STATIC_INLINE void compemu_raw_set_pc_full_const",
);
for (const field of ["regs.pc_p", "regs.pc_oldp", "regs.pc"]) {
  requireText(regHelper, field, "register successor-PC helper");
}
requireText(regHelper, "MEMBaseDiff", "register successor-PC helper");

const constHelper = bodyBetween(
  "STATIC_INLINE void compemu_raw_set_pc_full_const",
  "LOWFUNC(NONE,WRITE,2,compemu_raw_mov_l_mi",
);
requireText(
  constHelper,
  "compemu_raw_set_pc_full_from_reg(REG_WORK2)",
  "constant successor-PC helper",
);

const inreg = bodyBetween(
  "LOWFUNC(NONE,NONE,2,compemu_raw_endblock_pc_inreg",
  "LENDFUNC(NONE,NONE,2,compemu_raw_endblock_pc_inreg",
);
requireBefore(
  inreg,
  "compemu_raw_set_pc_full_from_reg(rr_pc)",
  "TBZ_xii(REG_WORK1, 31, 0)",
  "register endblock countdown exit",
);
requireBefore(
  inreg,
  "compemu_raw_set_pc_full_from_reg(rr_pc)",
  "LDR_wXi(REG_WORK4, R_REGSTRUCT, idx_spc_hot)",
  "register endblock spcflags exit",
);
requireBefore(
  inreg,
  "compemu_raw_set_pc_full_from_reg(rr_pc)",
  "popall_do_nothing",
  "register endblock C return",
);
if (source.includes("jit_endblock_inreg_count")) {
  fail("register endblock hot path: unconditional diagnostic counter remains");
}

const isconst = bodyBetween(
  "STATIC_INLINE uae_u32* compemu_raw_endblock_pc_isconst",
  "/*************************************************************************\n* FPU stuff",
);
requireBefore(
  isconst,
  "compemu_raw_set_pc_full_const(v)",
  "TBZ_xii(REG_WORK1, 31, 0)",
  "constant endblock countdown exit",
);
requireBefore(
  isconst,
  "compemu_raw_set_pc_full_const(v)",
  "LDR_wXi(REG_WORK4, R_REGSTRUCT, idx_spc_hot2)",
  "constant endblock spcflags exit",
);
requireBefore(
  isconst,
  "compemu_raw_set_pc_full_const(v)",
  "popall_do_nothing",
  "constant endblock C return",
);

const allocatorPath = new URL(
  "../BasiliskII/src/uae_cpu_2026/compiler/compemu_support_arm.cpp",
  import.meta.url,
);
const allocatorSource = await Bun.file(allocatorPath).text();
if (allocatorSource.includes("jit_trace_setpc_value")) {
  fail("diagnostic residue: set-PC tracing remains in the allocator");
}
const supportSource = await Bun.file(new URL(
  "../BasiliskII/src/uae_cpu_2026/compiler/compemu_support.cpp",
  import.meta.url,
)).text();
const timerSource = await Bun.file(new URL(
  "../BasiliskII/src/timer.cpp",
  import.meta.url,
)).text();
const mainUnixSource = await Bun.file(new URL(
  "../BasiliskII/src/Unix/main_unix.cpp",
  import.meta.url,
)).text();
const compatSource = await Bun.file(new URL(
  "../BasiliskII/src/uae_cpu_2026/compiler/compemu_legacy_arm64_compat.cpp",
  import.meta.url,
)).text();
const compemuHeaderSource = await Bun.file(new URL(
  "../BasiliskII/src/uae_cpu_2026/compiler/compemu.h",
  import.meta.url,
)).text();
const compemuArmHeaderSource = await Bun.file(new URL(
  "../BasiliskII/src/uae_cpu_2026/compiler/compemu_arm.h",
  import.meta.url,
)).text();
const gencompSource = await Bun.file(new URL(
  "../BasiliskII/src/uae_cpu_2026/compiler/gencomp.c",
  import.meta.url,
)).text();
const generatedSource = await Bun.file(new URL(
  "../BasiliskII/src/Unix/compemu.cpp",
  import.meta.url,
)).text();
const newcpuSource = await Bun.file(new URL(
  "../BasiliskII/src/uae_cpu_2026/newcpu.cpp",
  import.meta.url,
)).text();
const gencpuSource = await Bun.file(new URL(
  "../BasiliskII/src/uae_cpu_2026/gencpu.c",
  import.meta.url,
)).text();
const basiliskGlueSource = await Bun.file(new URL(
  "../BasiliskII/src/uae_cpu_2026/basilisk_glue.cpp",
  import.meta.url,
)).text();

function functionBody(
  text: string,
  signature: string,
  nextSignature: string,
  context: string,
): string {
  const start = text.indexOf(signature);
  const end = text.indexOf(nextSignature, start + signature.length);
  if (start < 0 || end < 0) fail(`${context}: missing function boundary`);
  return text.slice(start, end);
}

for (const contract of [
  "declare -A NATIVE_REPLAY_BYTES",
  'env_vars+=(B2_TEST_REPLAY_BYTES="$replay_bytes")',
  '[bcd_abcd_predec_a7_alias]="2082 01 2080 99"',
]) {
  requireText(harnessSource, contract, "exact-PC memory replay state");
}
for (const contract of [
  "static bool restore_test_replay_bytes_glue()",
  'getenv("B2_TEST_REPLAY_BYTES")',
  "put_byte(RAMBaseMac + (uaecptr)offset, (uint8)value);",
  "if (!restore_test_replay_bytes_glue())",
]) {
  requireText(basiliskGlueSource, contract, "exact-PC memory replay state");
}

const legacyNarrowZBody = functionBody(
  compatSource,
  "static inline void legacy_set_z_from_narrow_result(",
  "void adc_b(",
  "legacy narrow Z reconstruction",
);
requireText(legacyNarrowZBody, "CSET_xc(REG_WORK3, NATIVE_CC_EQ)", "branchless narrow Z reconstruction");
requireText(legacyNarrowZBody, "BFI_xxii(REG_WORK4, REG_WORK3, 30, 1)", "branchless narrow Z reconstruction");
if (/\b(?:CBZ|CBNZ|B)_\w+i\s*\(/.test(legacyNarrowZBody)) {
  fail("legacy narrow Z reconstruction reintroduced fixed-displacement internal branching");
}

const legacyAdcBBody = functionBody(compatSource, "void adc_b(", "void adc_w(", "legacy ADC.B");
const legacyAdcWBody = functionBody(compatSource, "void adc_w(", "void adc_l(", "legacy ADC.W");
for (const [body, width] of [[legacyAdcBBody, 8], [legacyAdcWBody, 16]] as const) {
  requireText(body, "MOVN_xi(REG_WORK1, 0)", `legacy ADC.${width}`);
  requireText(body, `legacy_set_z_from_narrow_result(d, ${width})`, `legacy ADC.${width}`);
  if (body.includes("MOV_xi(REG_WORK1, 0)")) {
    fail(`legacy ADC.${width}: zero padding still swallows incoming X below the operand lane`);
  }
}
const legacySbbBBody = functionBody(compatSource, "void sbb_b(", "void sbb_w(", "legacy SBB.B");
const legacySbbWBody = functionBody(compatSource, "void sbb_w(", "void sbb_l(", "legacy SBB.W");
requireText(legacySbbBBody, "legacy_set_z_from_narrow_result(d, 8)", "legacy SBB.B narrow Z");
requireText(legacySbbWBody, "legacy_set_z_from_narrow_result(d, 16)", "legacy SBB.W narrow Z");
const legacySetZeroBody = functionBody(compatSource, "void set_zero(", "int kill_rodent(", "legacy sticky-Z helper");
if (legacySetZeroBody.includes("flags_carry_inverted = false")) {
  fail("legacy sticky-Z helper: Z-only merge destroys the caller's physical-C polarity");
}
for (const generatedCall of ["adc_b(dst,src);", "adc_w(dst,src);", "sbb_b(dst,src);", "sbb_w(dst,src);"]) {
  requireText(generatedSource, generatedCall, "generated ADDX/SUBX legacy-helper reachability");
}

// Immediate-to-CCR instructions are decoded while compiling a block. `src`
// would be a virtual-register identifier after genamode(), not the guest
// immediate; lock the family to direct instruction-stream decoding.
for (const ccrCall of ["jff_ORSR(ARM_CCR_MAP[ccr_imm", "jff_ANDSR(ARM_CCR_MAP[ccr_imm", "jff_EORSR(ARM_CCR_MAP[ccr_imm"]) {
  requireText(gencompSource, ccrCall, "immediate CCR generator decode");
  requireText(generatedSource, ccrCall, "generated immediate CCR decode");
}
for (const forbiddenCcrCall of ["jff_ORSR(ARM_CCR_MAP[src", "jff_ANDSR(ARM_CCR_MAP[src", "jff_EORSR(ARM_CCR_MAP[src"]) {
  if (gencompSource.includes(forbiddenCcrCall) || generatedSource.includes(forbiddenCcrCall)) {
    fail(`immediate CCR generator decodes virtual-register id: ${forbiddenCcrCall}`);
  }
}

// ABCD/SBCD/NBCD are one architectural lifecycle family: decimal correction,
// X/C publication, and sticky Z must run even when the surrounding block does
// not consume flags.  Lock the generator to the flag-live handlers and lock
// every variable-length local correction branch to a patched target.
const bcdMidfuncStart = midfunc2Source.indexOf("/*\n * ABCD/SBCD/NBCD");
const bcdMidfuncEnd = midfunc2Source.indexOf("/*\n * CHK", bcdMidfuncStart);
if (bcdMidfuncStart < 0 || bcdMidfuncEnd < 0) fail("missing native BCD family");
const bcdMidfunc = midfunc2Source.slice(bcdMidfuncStart, bcdMidfuncEnd);
for (const contract of [
  "STATIC_INLINE void emit_bcd_flags(int result, int carry)",
  "BFI_wwii(REG_WORK4, REG_WORK1, 30, 1);",
  "BFI_wwii(REG_WORK4, carry, 29, 1);",
  "MSR_NZCV_x(REG_WORK4);",
  "flags_carry_inverted = false;",
  "MIDFUNC(2,jff_ABCD_b,(RW1 d, RR1 s))",
  "MIDFUNC(2,jff_SBCD_b,(RW1 d, RR1 s))",
  "MIDFUNC(1,jff_NBCD_b,(RW1 d))",
]) {
  requireText(bcdMidfunc, contract, "native BCD flag lifecycle");
}
if ((bcdMidfunc.match(/write_jmp_target\(/g) || []).length !== 7) {
  fail("native BCD branch geometry: every one of seven correction joins must use a patched target");
}
for (const forbidden of ["jnf_ABCD_b", "jnf_SBCD_b", "jnf_NBCD_b"]) {
  if (midfunc2Source.includes(forbidden) || gencompSource.includes(forbidden) || generatedSource.includes(forbidden)) {
    fail(`native BCD flag lifecycle: flag-dead handler remains: ${forbidden}`);
  }
}
for (const call of ["jff_ABCD_b(dstreg, srcreg);", "jff_SBCD_b(dstreg, srcreg);", "jff_NBCD_b(srcreg);"]) {
  requireText(gencompSource, call, "BCD generator flag-live routing");
  requireText(generatedSource, call, "generated BCD flag-live routing");
}
const bcdGeneratorStart = gencompSource.indexOf("     case i_SBCD:");
const bcdGeneratorEnd = gencompSource.indexOf("     case i_NEG:", bcdGeneratorStart);
if (bcdGeneratorStart < 0 || bcdGeneratorEnd < 0) fail("missing BCD generator family");
const bcdGenerator = gencompSource.slice(bcdGeneratorStart, bcdGeneratorEnd);
for (const contract of [
  "lea_l_brr(srcreg + 8, srcreg + 8, (uae_s32)-areg_byteinc[srcreg])",
  "lea_l_brr(dstreg + 8, dstreg + 8, (uae_s32)-areg_byteinc[dstreg])",
]) {
  requireText(bcdGenerator, contract, "BCD A7 byte-predecrement geometry");
  requireText(generatedSource, contract, "generated BCD A7 byte-predecrement geometry");
}
for (const forbidden of [
  "sub_l_ri(srcreg + 8, 1)",
  "sub_l_ri(dstreg + 8, 1)",
]) {
  if (bcdGenerator.includes(forbidden)) {
    fail(`BCD A7 byte-predecrement geometry: fixed one-byte decrement remains: ${forbidden}`);
  }
}
for (const vector of [
  "bcd_abcd_carry_zero",
  "bcd_sbcd_predec_a7_alias",
  "bcd_nbcd_predec_a7",
]) {
  requireText(harnessSource, `[${vector}]=0x`, "BCD exact-opcode replay coverage");
  requireText(harnessSource, `INIT_REGS[${vector}]`, "BCD exact-opcode replay state");
}

// DIVL's zero and overflow joins span variable-length exception/flag code. No
// reachable flag-live or no-flags shape may encode their target as an ARM64
// instruction count. Signed 32/32 division must also widen before SDIV so the
// unique INT32_MIN/-1 overflow remains observable instead of saturating.
const divlFamilyStart = midfunc2Source.indexOf("MIDFUNC(3,jnf_DIVLU32");
const divlFamilyEnd = midfunc2Source.indexOf("/*\n * EOR", divlFamilyStart);
if (divlFamilyStart < 0 || divlFamilyEnd < 0) fail("missing native DIVL family");
const divlFamily = midfunc2Source.slice(divlFamilyStart, divlFamilyEnd);
if (/\bB[A-Z]*_i\(\s*[1-9][0-9]*\s*\)/.test(divlFamily) ||
    /\b(?:CBNZ|CBZ)_[wx]i\([^,\n]+,\s*[1-9][0-9]*\s*\)/.test(divlFamily)) {
  fail("native DIVL branch geometry: fixed nonzero internal displacement remains");
}
if ((divlFamily.match(/write_jmp_target\(/g) || []).length !== 28) {
  fail("native DIVL branch geometry: expected 28 structurally patched joins");
}
for (const forbidden of ["rem = writereg(rem);", "SDIV_www(REG_WORK1, d, s1);"]) {
  if (divlFamily.includes(forbidden)) {
    fail(`native DIVL lifecycle: unsafe zero/overflow shape remains: ${forbidden}`);
  }
}
for (const contract of [
  "MIDFUNC(3,jnf_DIVLU32",
  "MIDFUNC(3,jff_DIVLU32",
  "MIDFUNC(3,jnf_DIVLS32",
  "MIDFUNC(3,jff_DIVLS32",
  "MIDFUNC(3,jnf_DIVLU64",
  "MIDFUNC(3,jff_DIVLU64",
  "MIDFUNC(3,jnf_DIVLS64",
  "MIDFUNC(3,jff_DIVLS64",
  "rem = rmw(rem);",
  "SDIV_xxx(REG_WORK1, REG_WORK3, REG_WORK4);",
  "saved_flags = readreg(FLAGTMP);",
]) {
  requireText(divlFamily, contract, "native DIVL lifecycle");
}
const divsWordBody = functionBody(
  midfunc2Source,
  "MIDFUNC(2,jff_DIVS,(RW4 d, RR4 s))",
  "MIDFUNC(3,jnf_DIVLU32",
  "signed word division overflow flags",
);
requireText(divsWordBody, "MRS_NZCV_x(REG_WORK4);", "signed word division overflow flags");
requireText(divsWordBody, "MOV_xx(REG_WORK1, REG_WORK4);", "signed word division overflow flags");
for (const vector of [
  "divs_w_overflow_preserve_z",
  "divs_w_imm_overflow_preserve_z",
  "divu_l32_zero_distinct",
  "divs_l32_zero_distinct",
  "divu_l32_success_nf",
  "divs_l32_success_nf",
  "divu_l32_same_dq_dr_nf",
  "divs_l32_src_dr_alias_nf",
  "divu_l64_overflow_nf",
  "divs_l64_overflow",
  "divs_l32_overflow",
  "divs_l32_overflow_nf",
]) {
  requireText(harnessSource, `[${vector}]=0x`, "DIVL exact-opcode replay coverage");
  requireText(harnessSource, `INIT_REGS[${vector}]`, "DIVL exact-opcode replay state");
}

const chkGeneratorBody = functionBody(
  gencompSource,
  "\t case i_CHK:",
  "     case i_CHK2:",
  "CHK generator",
);
for (const contract of [
  "isjump;",
  "preserve_flags_before_nzcv_clobber();",
  "jnf_CHK_w(dstreg, src);",
  "jnf_CHK_l(dstreg, src);",
]) {
  requireText(chkGeneratorBody, contract, "CHK exception boundary");
}
const chkMidfuncBody = functionBody(
  midfunc2Source,
  "STATIC_INLINE void emit_chk_trap",
  "/*\n * SWAP",
  "CHK native midfuncs",
);
for (const contract of [
  "JIT_EXCEPTION_CHK_N_VALID",
  "JIT_EXCEPTION_CHK_N_SET",
  "LOAD_U32(REG_WORK3, request)",
  "register_possible_exception();",
]) {
  requireText(chkMidfuncBody, contract, "CHK N/exception publication");
}
if (chkMidfuncBody.split("register_possible_exception();").length - 1 !== 2) {
  fail("CHK N/exception publication: both W and L must register an exception gate");
}
const exceptionRegistrationBody = functionBody(
  allocatorSource,
  "void register_possible_exception(void)",
  "/* Note: get_handler may fail",
  "deferred exception registration",
);
for (const contract of [
  "if (!jit_compile_current_op_host_pc)",
  "jit_compile_current_op_m68k_pc",
  "regs.jit_exception_oldpc",
  "LOAD_U32(REG_WORK3, jit_compile_current_op_m68k_pc)",
  "STR_wXi(REG_WORK3, R_REGSTRUCT, oldpc_idx)",
]) {
  requireText(exceptionRegistrationBody, contract, "CHK exact format-2 instruction PC");
}
const executeExceptionBody = functionBody(
  compatSource,
  "void execute_exception(uae_u32 cycles)",
  "/* --- JIT native-call helpers for SR/CCR opcodes --- */",
  "deferred exception execution",
);
for (const contract of [
  "request & JIT_EXCEPTION_CHK_N_VALID",
  "SET_NFLG((request & JIT_EXCEPTION_CHK_N_SET) != 0)",
  "has_oldpc ? regs.jit_exception_oldpc : 0",
  "regs.jit_exception_oldpc = 0",
]) {
  requireText(executeExceptionBody, contract, "deferred exception-entry flag/PC publication");
}
requireText(
  generatedSource,
  "preserve_flags_before_nzcv_clobber();\n\tjnf_CHK_w(dstreg, src);",
  "generated CHK.W contract",
);
requireText(
  generatedSource,
  "preserve_flags_before_nzcv_clobber();\n\tjnf_CHK_l(dstreg, src);",
  "generated CHK.L contract",
);
for (const replayState of [
  'INIT_REGS[chk_w_in_range]="00000008 00000014',
  'INIT_REGS[chk_w_zero]="00000000 00000064',
  'INIT_REGS[chk_w_equal]="00000032 00000032',
]) {
  requireText(harnessSource, replayState, "CHK exact-anchor operand restoration");
}

/* DIVU.W/DIVS.W, every 68020 DIVL shape, and TRAPV share one tagged request
 * lifecycle.  The frame's ordinary PC is the consumed successor while the
 * format-2 instruction-address field comes from the exact pc_hist[] anchor. */
for (const contract of [
  "JIT_EXCEPTION_OLDPC_VALID 0x20000000u",
  "JIT_EXCEPTION_VECTOR_MASK 0x0000ffffu",
] as const) {
  requireText(compemuArmHeaderSource, contract, "deferred arithmetic request encoding");
}
const arithmeticPreparationBody = functionBody(
  midfunc2Source,
  "STATIC_INLINE void prepare_arithmetic_exception",
  "/*\n * DIVU",
  "deferred arithmetic request helpers",
);
for (const contract of [
  "register_possible_exception_at_successor();",
  "MOV_wi(REG_WORK1, 0);",
  "STR_wXi(REG_WORK1, R_REGSTRUCT, exception_idx);",
  "SET_xxbit(REG_WORK1, REG_WORK1, 29)",
] as const) {
  requireText(arithmeticPreparationBody, contract, "deferred arithmetic request helpers");
}
const arithmeticSuccessorBody = functionBody(
  allocatorSource,
  "void register_possible_exception_at_successor(void)",
  "/* Note: get_handler may fail",
  "deferred arithmetic successor publication",
);
for (const contract of [
  "register_possible_exception();",
  "comp_pc_p + m68k_pc_offset",
  "jit_compile_current_op_m68k_pc",
  "next_host_pc - jit_compile_current_op_host_pc",
  "compemu_raw_set_pc_full_i(next_m68k_pc, next_host_pc);",
] as const) {
  requireText(arithmeticSuccessorBody, contract, "deferred arithmetic successor publication");
}
const divisionMidfuncBody = functionBody(
  midfunc2Source,
  "MIDFUNC(2,jnf_DIVU",
  "/*\n * EOR",
  "native division exception family",
);
if (divisionMidfuncBody.split("prepare_arithmetic_exception(exception_idx);").length - 1 !== 12) {
  fail("native division exception family: every word/long signed/unsigned shape must prepare the shared gate");
}
if (divisionMidfuncBody.split("emit_arithmetic_exception(5, exception_idx);").length - 1 !== 12) {
  fail("native division exception family: every word/long signed/unsigned shape must tag vector 5");
}
/* Flag-publication sequences may grow without changing division control flow.
 * Successful/overflow paths therefore use patched labels, never instruction
 * counts embedded in conditional branches. */
for (const [start, end, contracts, forbidden] of [
  [
    "MIDFUNC(2,jff_DIVU",
    "MENDFUNC(2,jff_DIVU",
    ["branch_success", "CBZ_wi(REG_WORK2, 0)", "write_jmp_target(branch_success", "write_jmp_target(branch_overflow_end"],
    ["CBZ_wi(REG_WORK2, 4)", "B_i(6)"],
  ],
  [
    "MIDFUNC(2,jff_DIVS",
    "MENDFUNC(2,jff_DIVS",
    ["branch_positive_fit", "branch_negative_fit", "BEQ_i(0)", "write_jmp_target(branch_overflow_end"],
    ["BEQ_i(6)", "BEQ_i(4)", "B_i(10)"],
  ],
] as const) {
  const body = functionBody(midfunc2Source, start, end, "word division structural branch targets");
  for (const contract of contracts) {
    requireText(body, contract, "word division structural branch targets");
  }
  for (const staleOffset of forbidden) {
    if (body.includes(staleOffset)) {
      fail(`word division structural branch targets: stale numeric offset ${staleOffset}`);
    }
  }
}
/* m68k_divl stores remainder before quotient.  The order is observable when
 * dr==dq, so every native 64/32 implementation must make quotient the final
 * write rather than treating the result registers as independent. */
for (const [start, end] of [
  ["MIDFUNC(3,jnf_DIVLU64", "MENDFUNC(3,jnf_DIVLU64"],
  ["MIDFUNC(3,jff_DIVLU64", "MENDFUNC(3,jff_DIVLU64"],
  ["MIDFUNC(3,jnf_DIVLS64", "MENDFUNC(3,jnf_DIVLS64"],
  ["MIDFUNC(3,jff_DIVLS64", "MENDFUNC(3,jff_DIVLS64"],
] as const) {
  const body = functionBody(midfunc2Source, start, end, "DIVL same-register result ordering");
  const remainderWrite = body.lastIndexOf("MOV_ww(dr, REG_WORK3);");
  const quotientWrite = body.lastIndexOf("MOV_ww(dq, REG_WORK2);");
  if (remainderWrite < 0 || quotientWrite < remainderWrite) {
    fail(`DIVL same-register result ordering: quotient must follow remainder in ${start}`);
  }
}
const shiftFunctionBody = (name: string): string => functionBody(
  shiftSource,
  `MIDFUNC(2,${name},`,
  `MENDFUNC(2,${name},`,
  `register-count ${name}`,
);

const shiftResultContracts = [
  ["jff_ASL_b_reg", "LSL_xxx"],
  ["jff_ASL_w_reg", "LSL_xxx"],
  ["jff_ASL_l_reg", "LSL_xxx"],
  ["jnf_ASR_b_reg", "ASR_xxx"],
  ["jnf_ASR_w_reg", "ASR_xxx"],
  ["jnf_ASR_l_reg", "ASR_xxx"],
  ["jff_ASR_b_reg", "ASR_xxx"],
  ["jff_ASR_w_reg", "ASR_xxx"],
  ["jff_ASR_l_reg", "ASR_xxx"],
  ["jnf_LSL_b_reg", "LSL_xxx"],
  ["jnf_LSL_w_reg", "LSL_xxx"],
  ["jnf_LSL_l_reg", "LSL_xxx"],
  ["jff_LSL_b_reg", "LSL_xxx"],
  ["jff_LSL_w_reg", "LSL_xxx"],
  ["jff_LSL_l_reg", "LSL_xxx"],
  ["jnf_LSR_b_reg", "LSR_xxx"],
  ["jnf_LSR_w_reg", "LSR_xxx"],
  ["jnf_LSR_l_reg", "LSR_xxx"],
  ["jff_LSR_b_reg", "LSR_xxx"],
  ["jff_LSR_w_reg", "LSR_xxx"],
  ["jff_LSR_l_reg", "LSR_xxx"],
] as const;
for (const [name, hostShift] of shiftResultContracts) {
  const body = shiftFunctionBody(name);
  requireText(body, `${hostShift}(`, `${name} six-bit-count result`);
  if (/\b(?:ASR|LSL|LSR)_www\s*\(/.test(body)) {
    fail(`${name}: 32-bit modulo-32 host shift reintroduced`);
  }
}
for (const name of [
  "jff_ASL_b_reg", "jff_ASL_w_reg", "jff_ASL_l_reg",
  "jff_ASR_b_reg", "jff_ASR_w_reg", "jff_ASR_l_reg",
]) {
  const body = shiftFunctionBody(name);
  requireText(body, "branch_shift_nonzero = (uae_u32*)get_target();", `${name} count-zero join`);
  requireText(body, "BNE_i(0);", `${name} count-zero join`);
  requireText(body, "write_jmp_target(branch_shift_nonzero, (uintptr)get_target());", `${name} count-zero join`);
  if (body.includes("BNE_i(3)")) fail(`${name}: numeric count-zero join reintroduced`);
}
for (const name of ["jff_ASL_b_reg", "jff_ASL_w_reg", "jff_ASL_l_reg"] as const) {
  const body = shiftFunctionBody(name);
  requireText(body, "MOV_wi(REG_WORK3, 63);", `${name} zero-source overflow guard`);
  requireText(body, "CSEL_wwwc(REG_WORK2, REG_WORK3, REG_WORK2, NATIVE_CC_EQ);", `${name} zero-source overflow guard`);
  requireText(body, "CSEL_xxxc(REG_WORK4, REG_WORK4, REG_WORK3, NATIVE_CC_GE);", `${name} branchless overflow publication`);
  if (body.includes("BGE_i(2)")) fail(`${name}: numeric overflow join reintroduced`);
}
for (const name of ["jff_ASL_b_imm", "jff_ASL_w_imm", "jff_ASL_l_imm"] as const) {
  const body = shiftFunctionBody(name);
  requireText(body, "MOV_wi(REG_WORK2, 63);", `${name} constant-count zero-source overflow guard`);
  requireText(body, "CSEL_wwwc(REG_WORK1, REG_WORK2, REG_WORK1, NATIVE_CC_EQ);", `${name} constant-count zero-source overflow guard`);
  requireText(body, "CSEL_xxxc(REG_WORK4, REG_WORK4, REG_WORK3, NATIVE_CC_GE);", `${name} branchless overflow publication`);
  if (body.includes("BGE_i(2)")) fail(`${name}: numeric overflow join reintroduced`);
}
for (const [name, hostShift] of [
  ["jnf_LSL_l_imm", "LSL_wwi"],
  ["jnf_LSR_l_imm", "LSR_wwi"],
  ["jff_LSR_l_imm", "LSR_wwi"],
] as const) {
  const body = shiftFunctionBody(name);
  let order = -1;
  for (const token of ["if(i >= 32)", "MOV_wi(d, 0);", "else", `${hostShift}(d, d, i);`]) {
    order = body.indexOf(token, order + 1);
    if (order < 0) fail(`${name} long immediate saturation: missing or out-of-order ${token}`);
  }
}
const lslLongImmediateBody = shiftFunctionBody("jff_LSL_l_imm");
let lslLongImmediateOrder = -1;
for (const token of ["if(i >= 32)", "MOV_wi(REG_WORK3, 0);", "else", "LSL_wwi(REG_WORK3, d, i);"]) {
  lslLongImmediateOrder = lslLongImmediateBody.indexOf(token, lslLongImmediateOrder + 1);
  if (lslLongImmediateOrder < 0) {
    fail(`jff_LSL_l_imm long immediate saturation: missing or out-of-order ${token}`);
  }
}
requireText(shiftSource, "#define PUBLISH_CARRY_FROM_BIT", "shift-family branchless carry publication");
const shiftFlagHelpers = [
  "jff_ASL_b_imm", "jff_ASL_w_imm", "jff_ASL_l_imm",
  "jff_ASL_b_reg", "jff_ASL_w_reg", "jff_ASL_l_reg",
  "jff_ASR_b_imm", "jff_ASR_w_imm", "jff_ASR_l_imm",
  "jff_ASR_b_reg", "jff_ASR_w_reg", "jff_ASR_l_reg",
  "jff_LSL_b_imm", "jff_LSL_w_imm", "jff_LSL_l_imm",
  "jff_LSL_b_reg", "jff_LSL_w_reg", "jff_LSL_l_reg",
  "jff_LSR_b_imm", "jff_LSR_w_imm", "jff_LSR_l_imm",
  "jff_LSR_b_reg", "jff_LSR_w_reg", "jff_LSR_l_reg",
] as const;
const emittedBranchCall = /\b(B(?:[A-Z]{2})?_i|(?:TBZ|TBNZ)_[wx]ii|(?:CBZ|CBNZ)_[wx]i)\s*\(([^;\n]*)\);/g;
for (const name of shiftFlagHelpers) {
  const body = shiftFunctionBody(name);
  requireText(body, "PUBLISH_CARRY_FROM_BIT(", `${name} branchless carry publication`);
  for (const match of body.matchAll(emittedBranchCall)) {
    const finalArgument = match[2].split(",").at(-1)?.trim();
    if (finalArgument && /^-?[1-9][0-9]*$/.test(finalArgument)) {
      fail(`${name}: fixed non-zero emitter branch reintroduced: ${match[0]}`);
    }
  }
}
for (const name of [
  "jff_LSL_b_reg", "jff_LSL_w_reg",
  "jff_LSR_b_reg", "jff_LSR_w_reg", "jff_LSR_l_reg",
]) {
  const body = shiftFunctionBody(name);
  requireText(body, "branch_shift_end = (uae_u32*)get_target();", `${name} carry-range join`);
  requireText(body, "B_i(0);", `${name} carry-range join`);
  requireText(body, "write_jmp_target(branch_shift_end, (uintptr)get_target());", `${name} carry-range join`);
  if (/\bB_i\s*\([23]\)/.test(body)) fail(`${name}: numeric carry-range join reintroduced`);
}
requireText(
  midfunc2Source,
  "runtime_join_x = rmw(FLAGX)",
  "register-shift runtime-join X materialisation",
);
for (const name of [
  "jff_ASL_b_reg", "jff_ASL_w_reg", "jff_ASL_l_reg",
  "jff_ASR_b_reg", "jff_ASR_w_reg", "jff_ASR_l_reg",
  "jff_LSL_b_reg", "jff_LSL_w_reg",
  "jff_LSR_b_reg", "jff_LSR_w_reg", "jff_LSR_l_reg",
]) {
  const body = shiftFunctionBody(name);
  requireText(body, "LOCK_X_FOR_RUNTIME_JOIN;", `${name} count-zero X allocator join`);
  requireText(body, "UNLOCK_X_FOR_RUNTIME_JOIN;", `${name} count-zero X allocator join`);
}

const generatedShiftOpcodes = [
  ["e120", "jff_ASL_b_reg"], ["e160", "jff_ASL_w_reg"], ["e1a0", "jff_ASL_l_reg"],
  ["e020", "shra_b_rr"], ["e060", "shra_w_rr"], ["e0a0", "shra_l_rr"],
  ["e128", "shll_b_rr"], ["e168", "shll_w_rr"], ["e1a8", "shll_l_rr"],
  ["e028", "shrl_b_rr"], ["e068", "shrl_w_rr"], ["e0a8", "shrl_l_rr"],
] as const;
for (const [opcode, flagLiveHelper] of generatedShiftOpcodes) {
  for (const suffix of ["ff", "nf"] as const) {
    const body = functionBody(
      generatedSource,
      `void REGPARAM2 op_${opcode}_0_comp_${suffix}`,
      "\n/*",
      `generated register-count ${opcode}/${suffix}`,
    );
    if (/srcreg\s*==\s*dstreg/.test(body)) {
      fail(`generated register-count ${opcode}/${suffix}: source/destination alias fallback reintroduced`);
    }
    if (suffix === "ff") requireText(body, `${flagLiveHelper}(`, `generated register-count ${opcode}/ff`);
  }
}
for (const opcode of ["e120", "e160", "e1a0"] as const) {
  const body = functionBody(
    generatedSource,
    `void REGPARAM2 op_${opcode}_0_comp_ff`,
    "\n/*",
    `generated register-count ASL ${opcode}`,
  );
  if (body.includes("needed_flags & FLAG_V")) {
    fail(`generated register-count ASL ${opcode}: V-live interpreter fallback reintroduced`);
  }
}

const activeRiskyNames = new Set(
  activeRiskySource.split(/\r?\n/).map((line) => line.trim()).filter((line) => line && !line.startsWith("#")),
);
const shiftVectorNames: string[] = [];
for (const op of ["asl", "asr", "lsl", "lsr"] as const) {
  for (const width of ["b", "w", "l"] as const) {
    shiftVectorNames.push(`${op}_${width}_reg_count32_boundary`);
    shiftVectorNames.push(`${op}_${width}_reg_count32_nf`);
    shiftVectorNames.push(`${op}_${width}_reg_same_count_data`);
    shiftVectorNames.push(`${op}_${width}_reg_same_count_data_nf`);
    shiftVectorNames.push(`${op}_${width}_reg_count_0_preserves_x`);
  }
}
shiftVectorNames.push(
  "asl_l_reg_zero_count32_v_clear",
  "asl_l_reg_zero_count32_const_v_clear",
  "lsr_l_reg_const_count32",
  "asl_b_reg_zero_count63_v_clear",
  "asl_w_reg_zero_count33_v_clear",
  "asr_l_reg_count0_pressure_preserves_x",
);
for (const name of shiftVectorNames) {
  requireText(harnessSource, `TESTS[${name}]=`, `${name} forced-native vector`);
  requireText(harnessSource, `[${name}]=1`, `${name} exact-native replay`);
  requireText(harnessSource, `SENTINEL_A6[${name}]=`, `${name} register sentinel`);
  if (!activeRiskyNames.has(name)) fail(`${name}: missing from active risky corpus`);
}
const shiftExactVectorNames = new Set(shiftVectorNames);
for (const op of ["asl", "asr", "lsl", "lsr"] as const) {
  for (const width of ["b", "w", "l"] as const) {
    for (const count of [31, 33, 63] as const) {
      const name = `${op}_${width}_reg_count${count}_boundary`;
      shiftExactVectorNames.add(name);
      shiftExactVectorNames.add(`${name}_nf`);
    }
  }
}
if (shiftExactVectorNames.size !== 138) {
  fail(`register-count shift exact-native inventory: expected 138, got ${shiftExactVectorNames.size}`);
}
const activeShiftVectorCount = [...shiftExactVectorNames].filter((name) => activeRiskyNames.has(name)).length;
if (activeShiftVectorCount !== 68) {
  fail(`register-count shift active inventory: expected 68, got ${activeShiftVectorCount}`);
}
requireText(
  harnessSource,
  'TESTS[asl_l_reg_zero_count32_const_v_clear]="7000 7220 E3A0 6804 7401 6002 7402"',
  "in-block constant ASL overflow branch witness",
);
requireText(
  harnessSource,
  'EXPECTED_REG_FIELDS[asl_l_reg_zero_count32_const_v_clear]="D0=00000000 D2=00000002"',
  "in-block constant ASL overflow branch witness",
);
requireText(
  harnessSource,
  'TESTS[lsr_l_reg_const_count32]="70FF 7220 E2A8 6504 7401 6002 7402"',
  "in-block constant LSR generated-path witness",
);
requireText(
  harnessSource,
  'EXPECTED_REG_FIELDS[lsr_l_reg_const_count32]="D0=00000000 D2=00000002"',
  "in-block constant LSR generated-path witness",
);
for (const contract of [
  "declare -a SHIFT_BOUNDARY_MATRIX_NAMES=()",
  "for _shift_count in 31 33 63; do",
  "SHIFT_BOUNDARY_MATRIX_NAMES+=(\"$_shift_name\" \"${_shift_name}_nf\")",
  "NATIVE_REPLAY_TESTS[\"$_shift_name\"]=1",
  "NATIVE_REPLAY_PC[\"$_shift_name\"]=0x100c",
  "NATIVE_REPLAY_COUNT[\"$_shift_name\"]=2",
  "TESTS[\"$_shift_name\"]=\"203C ${_shift_data} 72${_shift_count_hex} 44FC 0015 ${_shift_opcode} 40C6\"",
  "TESTS[\"${_shift_name}_nf\"]=\"203C ${_shift_data} 72${_shift_count_hex} 44FC 0015 ${_shift_opcode} 2400\"",
  "for name in \"${TEST_ORDER[@]}\"; do",
  'if [ -n "${_wanted_tests[$name]+x}" ] && [ -n "${RISKY_TESTS[$name]+x}" ]; then',
]) {
  requireText(harnessSource, contract, "register-count adjacent-boundary matrix");
}
if (!activeRiskyNames.has("asl_l_reg_count63_boundary")) {
  fail("register-count adjacent-boundary matrix: count-63 priority vector is not active");
}

/* Fixed-count memory shifts are a separate generator lifecycle from register
 * shifts: ff wrappers publish X/N/Z/V/C, nf wrappers perform only the memory
 * RMW, and carry/V publication must not depend on fixed code geometry. */
const fixedMemoryShiftContracts = [
  ["ASLW", "PUBLISH_CARRY_FROM_BIT(d, 15, REG_WORK2)"],
  ["ASRW", "PUBLISH_CARRY_FROM_BIT(REG_WORK1, 0, REG_WORK2)"],
  ["LSLW", "PUBLISH_CARRY_FROM_BIT(d, 15, REG_WORK2)"],
  ["LSRW", "PUBLISH_CARRY_FROM_BIT(REG_WORK3, 0, REG_WORK2)"],
] as const;
for (const [helper, carryContract] of fixedMemoryShiftContracts) {
  const ffBody = functionBody(
    shiftSource,
    `MIDFUNC(1,jff_${helper},`,
    `MENDFUNC(1,jff_${helper},`,
    `jff_${helper} fixed-count memory shift`,
  );
  const nfBody = functionBody(
    shiftSource,
    `MIDFUNC(1,jnf_${helper},`,
    `MENDFUNC(1,jnf_${helper},`,
    `jnf_${helper} fixed-count memory shift`,
  );
  for (const [body, lifecycle] of [[ffBody, "jff"], [nfBody, "jnf"]] as const) {
    requireText(body, "d = rmw(d);", `${lifecycle}_${helper} memory RMW`);
    requireText(body, "unlock2(d);", `${lifecycle}_${helper} destination lifecycle`);
  }
  requireText(ffBody, carryContract, `jff_${helper} branchless carry publication`);
  requireText(ffBody, "DUPLICACTE_CARRY", `jff_${helper} X publication`);
  if (/\b(?:TBZ|TBNZ)_[wx]ii\s*\([^;\n]*,\s*[1-9][0-9]*\s*\);/.test(ffBody)) {
    fail(`jff_${helper}: fixed-displacement flag branch reintroduced`);
  }
  if (nfBody.includes("PUBLISH_CARRY_FROM_BIT") || nfBody.includes("DUPLICACTE_CARRY") ||
      nfBody.includes("needed_flags")) {
    fail(`jnf_${helper}: no-flags memory shift publishes flags`);
  }
}
const fixedAslMemoryBody = functionBody(
  shiftSource,
  "MIDFUNC(1,jff_ASLW,",
  "MENDFUNC(1,jff_ASLW,",
  "jff_ASLW fixed-count overflow",
);
for (const contract of [
  "BFI_xxii(REG_WORK4, REG_WORK2, 29, 1)",
  "BFI_xxii(REG_WORK4, REG_WORK2, 28, 1)",
]) {
  requireText(fixedAslMemoryBody, contract, "jff_ASLW branchless C/V publication");
}
for (const [opcode, helper] of [
  ["e1d0", "ASLW"], ["e0d0", "ASRW"], ["e3d0", "LSLW"], ["e2d0", "LSRW"],
] as const) {
  for (const suffix of ["ff", "nf"] as const) {
    const body = functionBody(
      generatedSource,
      `void REGPARAM2 op_${opcode}_0_comp_${suffix}`,
      "\n/*",
      `generated fixed-count memory shift ${opcode}/${suffix}`,
    );
    requireText(body, `${suffix === "ff" ? "jff" : "jnf"}_${helper}(src);`, `generated fixed-count memory shift ${opcode}/${suffix}`);
    requireText(body, "writeword(srca, src, scratchie);", `generated fixed-count memory shift ${opcode}/${suffix}`);
    if (suffix === "ff") {
      requireBefore(body, "start_needflags();", `jff_${helper}(src);`, `generated fixed-count memory shift ${opcode}/ff`);
      requireBefore(body, `jff_${helper}(src);`, "live_flags();", `generated fixed-count memory shift ${opcode}/ff`);
    } else if (body.includes("start_needflags();") || body.includes("live_flags();")) {
      fail(`generated fixed-count memory shift ${opcode}/nf: flag lifecycle reintroduced`);
    }
  }
}

/* Memory ROX consumes and replaces X.  One RMW binding must own both actions;
 * reacquiring it through DUPLICACTE_CARRY creates an allocator double-unlock. */
for (const helper of ["ROXLW", "ROXRW"] as const) {
  const body = functionBody(
    shiftSource,
    `MIDFUNC(1,jff_${helper},`,
    `MENDFUNC(1,jff_${helper},`,
    `jff_${helper} X ownership`,
  );
  requireText(body, "int x = rmw(FLAGX);", `jff_${helper} X RMW ownership`);
  requireText(body, "PUBLISH_CARRY_FROM_BIT(", `jff_${helper} branchless carry publication`);
  if (body.includes("readreg(FLAGX)") || body.includes("DUPLICACTE_CARRY")) {
    fail(`jff_${helper}: X binding is reacquired instead of updated in place`);
  }
  if ((body.match(/unlock2\(x\);/g) ?? []).length !== 1) {
    fail(`jff_${helper}: X binding must have exactly one unlock`);
  }
  if (/\b(?:TBZ|TBNZ)_[wx]ii\s*\([^;\n]*,\s*[1-9][0-9]*\s*\);/.test(body)) {
    fail(`jff_${helper}: fixed-displacement carry branch reintroduced`);
  }
}
for (const width of ["b", "w", "l"] as const) {
  const body = shiftFunctionBody(`jff_ROXR_${width}`);
  requireText(body, "PUBLISH_CARRY_FROM_BIT(x, 0, REG_WORK3);", `jff_ROXR_${width} branchless carry publication`);
  if (/\b(?:TBZ|TBNZ)_[wx]ii\s*\([^;\n]*,\s*[1-9][0-9]*\s*\);/.test(body)) {
    fail(`jff_ROXR_${width}: fixed-displacement carry branch reintroduced`);
  }
}
for (const witness of [
  "[roxrw_mem_x_live_all]=\"2042 30BC 8000 44FC 0010 E4D0",
  "DD85 51CF FFDE",
  "[roxrw_mem_x_live_all]=21",
  "[roxrw_mem_x_live_all]=1",
  "B2_NATIVE_ASSERT_PC=\"$pc\"",
  "[[ \"$NAT\" -gt 0 ]] || RESULT=2",
  "[[ \"${CELL_REQUIRE_PIN[$cell]}\" == 0 || \"$PIN\" -gt 0 ]] || RESULT=3",
] as const) {
  requireText(regallocPressureSource, witness, "memory ROXR X allocator-pressure witness");
}

/* ROL/ROR register counts are architectural six-bit values even though the
 * result is periodic at the operand width. The AArch64 helper owns count-zero
 * C clearing, X preservation, and N/Z/V publication before the generated
 * wrapper marks flags live. */
for (const op of ["ROL", "ROR"] as const) {
  for (const width of ["b", "w", "l"] as const) {
    for (const lifecycle of ["jnf", "jff"] as const) {
      const name = `${lifecycle}_${op}_${width}`;
      const body = shiftFunctionBody(name);
      requireText(body, "live.state[i].val & 0x3f", `${name} constant six-bit count`);
      requireText(body, "i = readreg(i);", `${name} count-before-writeback ordering`);
      requireText(body, "d = rmw(d);", `${name} destination writeback ordering`);
      requireText(body, "unlock2(d);", `${name} destination lifecycle`);
      requireText(body, "unlock2(i);", `${name} count lifecycle`);
      if (body.includes("FLAGX") || body.includes("DUPLICACTE_CARRY")) {
        fail(`${name}: plain rotate must preserve X`);
      }
      if (lifecycle === "jnf") {
        requireText(body, "AND_ww3f(", `${name} runtime six-bit count`);
      } else if (op === "ROL") {
        requireText(body, "ANDS_ww3f(", `${name} runtime six-bit count`);
        requireText(body, "branch_rotate_nonzero", `${name} count-zero carry join`);
        requireText(body, "B_i(0); // <end>", `${name} count-zero carry join`);
        requireText(body, "write_jmp_target(branchadd, (uintptr)get_target());", `${name} count-zero carry join`);
      } else {
        requireText(body, "AND_ww3f(", `${name} runtime six-bit count`);
        requireText(body, "branch_count_zero", `${name} count-zero carry join`);
        requireText(body, "CBZ_wi(", `${name} count-zero carry join`);
        requireText(body, "PUBLISH_CARRY_FROM_BIT(", `${name} non-zero carry publication`);
      }
    }
  }
}

const rotateGeneratorStart = requireText(gencompSource, " case i_ROL:", "rotate generator family");
const rotateGeneratorEnd = requireText(gencompSource, "     case i_ROXL:", "rotate generator family");
const rotateGeneratorBody = gencompSource.slice(rotateGeneratorStart, rotateGeneratorEnd);
for (const contract of [
  "encoded source/destination alias is legal and must stay native",
  "if ((uae_u32)srcreg==(uae_u32)dstreg)",
  "AArch64 rotate helpers own the complete N/Z/V/C lifecycle",
  'comprintf("\\tstart_needflags();\\n");',
  'comprintf("\\tlive_flags();\\n");',
  'comprintf("\\tend_needflags();\\n");',
]) {
  requireText(rotateGeneratorBody, contract, "rotate generator family");
}

for (const [name, carryContract] of [
  ["jff_ROLW", "BFI_wwii(REG_WORK4, d, 29, 1)"],
  ["jff_RORW", "PUBLISH_CARRY_FROM_BIT(d, 31, REG_WORK3)"],
] as const) {
  const body = functionBody(shiftSource, `MIDFUNC(1,${name},`, `MENDFUNC(1,${name},`, `${name} memory rotate`);
  requireText(body, "d = rmw(d);", `${name} memory writeback`);
  requireText(body, "TST_ww(d, d);", `${name} memory N/Z/V flags`);
  requireText(body, carryContract, `${name} memory carry`);
  if (body.includes("FLAGX") || body.includes("DUPLICACTE_CARRY")) fail(`${name}: memory rotate must preserve X`);
}

const generatedRotateOpcodes = [
  ["e138", "rol_b_rr"], ["e178", "rol_w_rr"], ["e1b8", "rol_l_rr"],
  ["e038", "ror_b_rr"], ["e078", "ror_w_rr"], ["e0b8", "ror_l_rr"],
  ["e118", "rol_b_rr"], ["e158", "rol_w_rr"], ["e198", "rol_l_rr"],
  ["e018", "ror_b_rr"], ["e058", "ror_w_rr"], ["e098", "ror_l_rr"],
] as const;
for (const [opcode, helper] of generatedRotateOpcodes) {
  for (const suffix of ["ff", "nf"] as const) {
    const body = functionBody(
      generatedSource,
      `void REGPARAM2 op_${opcode}_0_comp_${suffix}`,
      "\n/*",
      `generated register-count rotate ${opcode}/${suffix}`,
    );
    if (/srcreg\s*==\s*dstreg/.test(body) || body.includes("FAIL(1)")) {
      fail(`generated register-count rotate ${opcode}/${suffix}: alias fallback reintroduced`);
    }
    requireText(body, `${helper}(data,cnt);`, `generated register-count rotate ${opcode}/${suffix}`);
    if (suffix === "ff") {
      requireBefore(body, "start_needflags();", `${helper}(data,cnt);`, `generated register-count rotate ${opcode}/ff`);
      requireBefore(body, `${helper}(data,cnt);`, "live_flags();", `generated register-count rotate ${opcode}/ff`);
      if (body.includes("bt_l_ri(data") || body.includes("test_b_rr(data,data)") ||
          body.includes("test_w_rr(data,data)") || body.includes("test_l_rr(data,data)")) {
        fail(`generated register-count rotate ${opcode}/ff: wrapper overwrites helper count-zero flags`);
      }
    } else if (body.includes("start_needflags();") || body.includes("live_flags();")) {
      fail(`generated register-count rotate ${opcode}/nf: no-flags wrapper publishes flags`);
    }
  }
}
for (const [opcode, helper] of [["e7d0", "ROLW"], ["e6d0", "RORW"]] as const) {
  for (const suffix of ["ff", "nf"] as const) {
    const body = functionBody(
      generatedSource,
      `void REGPARAM2 op_${opcode}_0_comp_${suffix}`,
      "\n/*",
      `generated memory rotate ${opcode}/${suffix}`,
    );
    requireText(body, `${suffix === "ff" ? "jff" : "jnf"}_${helper}(src);`, `generated memory rotate ${opcode}/${suffix}`);
    requireText(body, "writeword(srca, src, scratchie);", `generated memory rotate ${opcode}/${suffix}`);
    if (suffix === "ff") {
      requireBefore(body, "start_needflags();", `jff_${helper}(src);`, `generated memory rotate ${opcode}/ff`);
      requireBefore(body, `jff_${helper}(src);`, "live_flags();", `generated memory rotate ${opcode}/ff`);
    } else if (body.includes("start_needflags();") || body.includes("live_flags();")) {
      fail(`generated memory rotate ${opcode}/nf: no-flags wrapper publishes flags`);
    }
  }
}

for (const contract of [
  "declare -a ROTATE_REGISTER_MATRIX_NAMES=()",
  "for _rotate_count in 0 31 32 33 63; do",
  "ROTATE_REGISTER_MATRIX_NAMES+=(\"$_rotate_name\" \"${_rotate_name}_nf\")",
  "NATIVE_REPLAY_TESTS[\"$_rotate_name\"]=1",
  "NATIVE_REPLAY_PC[\"$_rotate_name\"]=0x1000",
  "TESTS[\"$_rotate_name\"]=\"${_rotate_opcode} 40C6\"",
  "TESTS[\"${_rotate_name}_nf\"]=\"${_rotate_opcode} 7E00 40C6\"",
  "TESTS[\"$_rotate_alias_name\"]=\"${_rotate_alias_opcode} 40C6\"",
]) {
  requireText(harnessSource, contract, "register-count rotate matrix");
}
const rotateExactVectorNames = new Set<string>();
for (const op of ["rol", "ror"] as const) {
  for (const width of ["b", "w", "l"] as const) {
    for (const count of [0, 31, 32, 33, 63] as const) {
      const name = `${op}_${width}_reg_count${count}_boundary`;
      rotateExactVectorNames.add(name);
      rotateExactVectorNames.add(`${name}_nf`);
    }
    rotateExactVectorNames.add(`${op}_${width}_reg_same_count_data`);
    rotateExactVectorNames.add(`${op}_${width}_reg_same_count_data_nf`);
  }
}
const nativeReplayTestsSection = harnessSource.slice(
  requireText(harnessSource, "declare -A NATIVE_REPLAY_TESTS=(", "native replay test inventory"),
  requireText(harnessSource, "declare -A NATIVE_REPLAY_PC=(", "native replay PC inventory"),
);
const nativeReplayPcSection = harnessSource.slice(
  requireText(harnessSource, "declare -A NATIVE_REPLAY_PC=(", "native replay PC inventory"),
  requireText(harnessSource, "declare -A NATIVE_REPLAY_BYTES=(", "native replay memory inventory"),
);
const nativeReplayBytesSection = harnessSource.slice(
  requireText(harnessSource, "declare -A NATIVE_REPLAY_BYTES=(", "native replay memory inventory"),
  requireText(harnessSource, "declare -A NATIVE_REPLAY_COUNT=(", "native replay count inventory"),
);
const nativeReplayCountSection = harnessSource.slice(
  requireText(harnessSource, "declare -A NATIVE_REPLAY_COUNT=(", "native replay count inventory"),
  requireText(harnessSource, "declare -A _SHIFT_BOUNDARY_OPCODES=(", "generated shift test inventory"),
);

const rotateSupplementalVectors = [
  "rol_l_reg_const_count64", "rol_l_reg_const_count64_nf",
  "ror_l_reg_const_count64", "ror_l_reg_const_count64_nf",
  "rol_b_imm_count8", "rol_b_imm_count8_nf",
  "rol_w_imm_count8", "rol_w_imm_count8_nf",
  "rol_l_imm_count8", "rol_l_imm_count8_nf",
  "ror_b_imm_count8", "ror_b_imm_count8_nf",
  "ror_w_imm_count8", "ror_w_imm_count8_nf",
  "ror_l_imm_count8", "ror_l_imm_count8_nf",
  "rolw_mem_native", "rolw_mem_native_nf",
  "rorw_mem_native", "rorw_mem_native_nf",
] as const;
for (const name of rotateSupplementalVectors) {
  rotateExactVectorNames.add(name);
  requireText(harnessSource, `TESTS[${name}]=`, `${name} rotate-path vector`);
  requireText(nativeReplayTestsSection, `[${name}]=1`, `${name} exact-native replay`);
  requireText(nativeReplayPcSection, `[${name}]=0x${name.includes("reg_const_count64") ? "100c" : "1000"}`, `${name} exact replay PC`);
  requireText(nativeReplayCountSection, `[${name}]=2`, `${name} exact replay count`);
  requireText(harnessSource, `SENTINEL_A6[${name}]=`, `${name} register sentinel`);
  if (!activeRiskyNames.has(name)) fail(`${name}: missing from active risky corpus`);
}
for (const memoryName of ["rolw_mem_native", "rolw_mem_native_nf", "rorw_mem_native", "rorw_mem_native_nf"] as const) {
  requireText(nativeReplayBytesSection, `[${memoryName}]=\"A000 80 A001 01\"`, `${memoryName} exact memory replay`);
}
const fixedMemoryVectors = [
  ["aslw_mem_native", "A000 40 A001 00"],
  ["aslw_mem_native_nf", "A000 40 A001 00"],
  ["asrw_mem_native", "A000 80 A001 01"],
  ["asrw_mem_native_nf", "A000 80 A001 01"],
  ["lslw_mem_native", "A000 80 A001 01"],
  ["lslw_mem_native_nf", "A000 80 A001 01"],
  ["lsrw_mem_native", "A000 80 A001 01"],
  ["lsrw_mem_native_nf", "A000 80 A001 01"],
  ["roxlw_mem_x_native", "A000 80 A001 01"],
  ["roxrw_mem_x_native", "A000 80 A001 00"],
] as const;
for (const [name, replayBytes] of fixedMemoryVectors) {
  requireText(harnessSource, `TESTS[${name}]=`, `${name} forced-native vector`);
  requireText(nativeReplayTestsSection, `[${name}]=1`, `${name} exact-native replay`);
  requireText(nativeReplayPcSection, `[${name}]=0x1000`, `${name} exact opcode PC`);
  requireText(nativeReplayBytesSection, `[${name}]=\"${replayBytes}\"`, `${name} deterministic memory replay`);
  requireText(nativeReplayCountSection, `[${name}]=2`, `${name} exact-native execution count`);
  requireText(harnessSource, `SENTINEL_A6[${name}]=`, `${name} register sentinel`);
  if (!activeRiskyNames.has(name)) fail(`${name}: missing from active risky corpus`);
}
for (const name of ["aslw_mem_native_nf", "asrw_mem_native_nf", "lslw_mem_native_nf", "lsrw_mem_native_nf"] as const) {
  requireText(harnessSource, `TESTS[${name}]=\"${name.startsWith("aslw") ? "E1D0" : name.startsWith("asrw") ? "E0D0" : name.startsWith("lslw") ? "E3D0" : "E2D0"} 44FC 0015 3010 40C6\"`, `${name} complete-CCR kill`);
}
if (rotateExactVectorNames.size !== 92) {
  fail(`rotate exact-native inventory: expected 92, got ${rotateExactVectorNames.size}`);
}
const activeRotateVectorCount = [...rotateExactVectorNames].filter((name) => activeRiskyNames.has(name)).length;
if (activeRotateVectorCount !== 68) {
  fail(`rotate active inventory: expected 68, got ${activeRotateVectorCount}`);
}

const trapvMidfuncBody = functionBody(
  midfunc2Source,
  "MIDFUNC(0,jnf_TRAPV",
  "/*\n * ROXLW",
  "native TRAPV exception family",
);
for (const contract of [
  "prepare_arithmetic_exception(exception_idx);",
  "TBZ_xii(REG_WORK1, 28, 4)",
  "emit_arithmetic_exception(7, exception_idx);",
] as const) {
  requireText(trapvMidfuncBody, contract, "native TRAPV exception family");
}
if (trapvMidfuncBody.includes("flags_carry_inverted = false")) {
  fail("native TRAPV exception family: TRAPV must not mutate the carry representation");
}
for (const contract of [
  "make_flags_live();\n\tjnf_TRAPV();",
  "make_flags_live();\n\tstart_needflags();\n\tjff_DIVU(dst, src);",
  "make_flags_live();\n\tstart_needflags();\n\tjff_DIVS(dst, src);",
  "make_flags_live();\n\t    start_needflags();\n\t    jff_DIVLU64(dq, dr, src);",
  "make_flags_live();\n\t    start_needflags();\n\t    jff_DIVLS64(dq, dr, src);",
  "preserve_flags_before_nzcv_clobber();\n\tint dq = (extra >> 12) & 7;",
] as const) {
  requireText(generatedSource, contract, "generated deferred arithmetic flag contract");
}
for (const vector of [
  "divu_w_zero_frame",
  "divs_w_zero_frame",
  "divu_l_zero_frame",
  "divs_l_zero_frame",
  "divu_l64_zero_frame",
  "divs_l64_zero_frame",
  "divu_l64_same_dq_dr",
  "divs_l64_same_dq_dr",
  "divu_l64_same_dq_dr_nf",
  "divs_l64_same_dq_dr_nf",
  "trapv_taken_frame",
  "trapv_not_taken_preserve",
] as const) {
  requireText(harnessSource, `[${vector}]=1`, "deferred arithmetic native replay coverage");
  requireText(harnessSource, `[${vector}]=2`, "deferred arithmetic three-pass replay coverage");
}

/* Ordered whole-instruction helpers receive an exact pc_hist[] opcode PC and
 * a length-derived successor.  This must not be reconstructed by rewinding a
 * flushed PC_P: traced blocks can re-anchor their compile cursor without an
 * equivalent runtime write. */
const orderedEmitterBody = functionBody(
  allocatorSource,
  "void jit_emit_ordered_semantic_helper_call(uintptr helper, uae_u32 instruction_bytes)",
  "static void op_fullsr_orsr_w_comp_ff",
  "ordered semantic-helper emitter",
);
for (const contract of [
  "jit_compile_current_op_host_pc",
  "jit_compile_current_op_m68k_pc",
  "const uae_u32 next_m68k_pc = op_m68k_pc + instruction_bytes;",
  "jit_force_runtime_pc_endblock = true;",
] as const) {
  requireText(orderedEmitterBody, contract, "ordered semantic-helper emitter");
}
requireBefore(orderedEmitterBody, "flush(1);", "compemu_raw_set_pc_full_i(op_m68k_pc, op_host_pc);", "ordered helper opcode PC");
requireBefore(orderedEmitterBody, "compemu_raw_set_pc_full_i(op_m68k_pc, op_host_pc);", "compemu_raw_call(helper);", "ordered helper opcode PC");
requireBefore(orderedEmitterBody, "compemu_raw_mov_l_ri(REG_PAR1, next_m68k_pc);", "compemu_raw_call(helper);", "ordered helper successor ABI");

/* Privileged integer control instructions share one exact-opcode-PC service.
 * Privilege must precede extension fetch, and each family must publish only its
 * canonical success/trap successor rather than inheriting a flushed PC_P. */
const systemControlBody = functionBody(
  allocatorSource,
  "static void jit_runtime_system_control(uae_u32 opcode)",
  "static void jit_runtime_cache_control(uae_u32 opcode)",
  "system-control semantic service",
);
for (const contract of [
  "(opcode & 0xfff8) == 0x4e60",
  "(opcode & 0xfff8) == 0x4e68",
  "case 0x4e70:",
  "case 0x4e72:",
  "case 0x4e73:",
  "case 0x4e7a:",
  "case 0x4e7b:",
  "m68k_setstopped(1);",
  "ex_rte();",
] as const) {
  requireText(systemControlBody, contract, "system-control semantic service");
}
requireBefore(systemControlBody, "if (!regs.s)", "get_iword(2)", "system-control privilege-before-extension contract");
if (systemControlBody.includes("cpufunctbl") || systemControlBody.includes("m68k_incpc(-"))
  fail("system-control semantic service: interpreter dispatch or PC rewind remains");
const stopControlStart = systemControlBody.indexOf("case 0x4e72:");
const stopControlEnd = systemControlBody.indexOf("case 0x4e73:", stopControlStart);
const stopControlBody = systemControlBody.slice(stopControlStart, stopControlEnd);
requireBefore(stopControlBody, "m68k_incpc(4);", "Exception(8, 0);", "STOP clear-S trap successor");
const stopSuccessBody = stopControlBody.slice(stopControlBody.indexOf("regs.sr = new_sr;"));
requireBefore(stopSuccessBody, "MakeFromSR();", "m68k_setstopped(1);", "STOP SR commit ordering");
requireBefore(stopSuccessBody, "m68k_setstopped(1);", "m68k_incpc(4);", "STOP success successor");
const movecControlStart = systemControlBody.indexOf("case 0x4e7a:");
const movecControlBody = systemControlBody.slice(movecControlStart);
requireBefore(movecControlBody, "get_iword(2)", "m68k_movec2", "MOVEC extension-before-service contract");
requireBefore(movecControlBody, "if (valid)", "m68k_incpc(4);", "MOVEC success-only successor");

const cacheControlBody = functionBody(
  allocatorSource,
  "static void jit_runtime_cache_control(uae_u32 opcode)",
  "static void jit_runtime_illegal_advanced(uae_u32 opcode)",
  "cache-control semantic service",
);
requireBefore(cacheControlBody, "if (!regs.s)", "flush_internals();", "cache-control privilege ordering");
requireBefore(cacheControlBody, "if (opcode & 0x80)", "m68k_incpc(2);", "cache-control transition ordering");
for (const contract of [
  'jit_abort("runtime semantic helper: missing exact opcode PC")',
  "jit_emit_runtime_helper_barrier((uintptr)jit_runtime_system_control,\n        jit_compile_current_op_host_pc, opcode, 0, false);",
  "jit_emit_runtime_helper_barrier((uintptr)jit_runtime_cache_control,\n        jit_compile_current_op_host_pc, opcode, 0, false);",
  "jit_emit_runtime_helper_barrier((uintptr)jit_runtime_mvsr2_full,\n        jit_compile_current_op_host_pc, opcode, 0, false);",
  "jit_emit_runtime_helper_barrier((uintptr)jit_runtime_mv2sr_word_full,\n        jit_compile_current_op_host_pc, opcode, 0, false);",
  "jit_emit_runtime_helper_barrier((uintptr)jit_runtime_moves,\n        jit_compile_current_op_host_pc, opcode, 0, false);",
  "jit_emit_runtime_helper_barrier((uintptr)jit_runtime_bitfield,\n        jit_compile_current_op_host_pc, opcode, 0, false);",
  "jit_emit_runtime_helper_barrier((uintptr)jit_runtime_cas,\n        jit_compile_current_op_host_pc, opcode, 0, false);",
  "jit_emit_runtime_helper_barrier((uintptr)jit_runtime_cas2,\n        jit_compile_current_op_host_pc, opcode, 0, false);",
  "mnemonic == i_MVR2USP || mnemonic == i_MVUSP2R",
  "mnemonic == i_RESET || mnemonic == i_STOP || mnemonic == i_RTE",
  "mnemonic == i_MOVEC2 || mnemonic == i_MOVE2C",
  "compfunctbl[cft_map(opcode)] = op_system_control_comp_ff;",
  "mnemonic == i_CPUSHA || mnemonic == i_CPUSHL || mnemonic == i_CPUSHP",
  "compfunctbl[cft_map(opcode)] = op_cache_control_comp_ff;",
  "compfunctbl[cft_map(opcode)] = op_bitfield_comp_ff;",
] as const) {
  requireText(allocatorSource, contract, "system/cache handler registration");
}

const movepWriteBody = functionBody(
  compatSource,
  'extern "C" void jit_op_mvprm(uae_u32 next_pc)',
  'extern "C" void jit_op_mvpmr(uae_u32 next_pc)',
  "MOVEP register-to-memory fault PC",
);
const movepReadBody = functionBody(
  compatSource,
  'extern "C" void jit_op_mvpmr(uae_u32 next_pc)',
  'extern "C" void jit_op_rtr(void)',
  "MOVEP memory-to-register fault PC",
);
for (const [body, firstAccess, finalAccess, context] of [
  [movepWriteBody, "put_byte(addr, (val >> 24)", "put_byte(addr, val & 0xFF);", "MOVEP register-to-memory fault PC"],
  [movepReadBody, "get_byte(addr) << 24", "val |= get_byte(addr);", "MOVEP memory-to-register fault PC"],
] as const) {
  requireBefore(body, firstAccess, "m68k_setpc(next_pc);", context);
  requireBefore(body, finalAccess, "m68k_setpc(next_pc);", context);
  if (body.includes("m68k_incpc(-") || body.split("m68k_setpc(next_pc);").length - 1 !== 1)
    fail(`${context}: helper must publish exactly one explicit successor after all accesses`);
}
requireBefore(movepReadBody, "regs.regs[dn] =", "m68k_setpc(next_pc);", "MOVEP read commit ordering");

const packBody = functionBody(
  compatSource,
  'extern "C" void jit_op_pack(uae_u32 next_pc)',
  'extern "C" void jit_op_unpk(uae_u32 next_pc)',
  "PACK ordered fault PC",
);
const unpkBody = functionBody(
  compatSource,
  'extern "C" void jit_op_unpk(uae_u32 next_pc)',
  'extern "C" void jit_op_bfffo(void)',
  "UNPK ordered fault PC",
);
requireBefore(packBody, "get_byte(source - areg_byteinc[src_reg])", "m68k_setpc(next_pc);", "PACK source fault PC");
requireBefore(packBody, "regs.regs[8 + dst_reg] -= areg_byteinc[dst_reg];", "m68k_setpc(next_pc);", "PACK destination fault PC");
requireBefore(packBody, "m68k_setpc(next_pc);", "put_byte(regs.regs[8 + dst_reg], result);", "PACK destination fault PC");
requireBefore(unpkBody, "val = get_byte(regs.regs[8 + src_reg]);", "m68k_setpc(next_pc);", "UNPK source fault PC");
requireBefore(unpkBody, "regs.regs[8 + dst_reg] -= 2;", "m68k_setpc(next_pc);", "UNPK destination fault PC");
requireBefore(unpkBody, "m68k_setpc(next_pc);", "put_word(regs.regs[8 + dst_reg], result);", "UNPK destination fault PC");
for (const [body, context] of [[packBody, "PACK ordered fault PC"], [unpkBody, "UNPK ordered fault PC"]] as const) {
  if (body.includes("m68k_incpc(-") || body.includes("regs.fault_pc = m68k_getpc() +"))
    fail(`${context}: relative/double-advanced PC reconstruction remains`);
  if (body.split("m68k_setpc(next_pc);").length - 1 !== 2)
    fail(`${context}: register and memory forms do not each publish the explicit successor`);
}
for (const helperCase of ["case i_MVPRM:", "case i_MVPMR:", "case i_PACK:", "case i_UNPK:"]) {
  const start = gencompSource.indexOf(helperCase);
  const end = gencompSource.indexOf("break;", start);
  if (start < 0 || end < 0) fail(`generated helper PC contract: missing ${helperCase}`);
  const body = gencompSource.slice(start, end);
  requireText(body, "jit_emit_ordered_semantic_helper_call", `generated helper PC contract ${helperCase}`);
  requireText(body, "m68k_pc_offset - m68k_pc_offset_thisinst", `generated helper length contract ${helperCase}`);
  if (body.includes("call_helper(") || body.includes("\\tflush(1)"))
    fail(`generated helper PC contract ${helperCase}: legacy successor-first call remains`);
}

if (midfuncSource.includes("arm64_low32_hostptr_imm")) {
  fail("pointer arithmetic contract: numeric host-range inference remains");
}
const hostBaseStart = midfuncSource.indexOf("MIDFUNC(2,arm_ADD_l_ri_hostptr");
const hostBaseEnd = midfuncSource.indexOf("MENDFUNC(2,arm_ADD_l_ri_hostptr", hostBaseStart);
if (hostBaseStart < 0 || hostBaseEnd < 0) fail("missing signed guest-offset + host-base contract");
const hostBaseBody = midfuncSource.slice(hostBaseStart, hostBaseEnd);
for (const contract of ["(uae_s32)(uae_u32)live.state[d].val", "LOAD_U64(REG_WORK1, base)", "EX_SXTW"]) {
  requireText(hostBaseBody, contract, "signed guest-offset + host-base contract");
}
const ptrAddStart = midfuncSource.indexOf("MIDFUNC(2,arm_ADD_ptr_ri");
const ptrAddEnd = midfuncSource.indexOf("MENDFUNC(2,arm_ADD_ptr_ri", ptrAddStart);
if (ptrAddStart < 0 || ptrAddEnd < 0) fail("missing pointer-width immediate-add contract");
const ptrAddBody = midfuncSource.slice(ptrAddStart, ptrAddEnd);
for (const contract of ["ADD_xxi", "SUB_xxi", "ADD_xxx"]) {
  requireText(ptrAddBody, contract, "pointer-width immediate-add contract");
}
const guestAddStart = midfuncSource.indexOf("MIDFUNC(2,arm_ADD_l_ri,(RW4 d, IMPTR i))");
const guestAddEnd = midfuncSource.indexOf("MENDFUNC(2,arm_ADD_l_ri", guestAddStart);
if (guestAddStart < 0 || guestAddEnd < 0) fail("missing 32-bit guest immediate-add contract");
const guestAddBody = midfuncSource.slice(guestAddStart, guestAddEnd);
for (const contract of ["const uae_u32 i32", "(uae_u32)(live.state[d].val + i32)", "ADD_wwi", "ADD_www"]) {
  requireText(guestAddBody, contract, "32-bit guest immediate-add contract");
}
if (guestAddBody.includes("ADD_x") || guestAddBody.includes("PC_P")) {
  fail("32-bit guest immediate-add contract: pointer-width path remains");
}
const registerAddStart = midfuncSource.indexOf("MIDFUNC(2,arm_ADD_l,(RW4 d, RR4 s))");
const registerAddEnd = midfuncSource.indexOf("MENDFUNC(2,arm_ADD_l", registerAddStart);
if (registerAddStart < 0 || registerAddEnd < 0) fail("missing register-sourced long-add contract");
const registerAddBody = midfuncSource.slice(registerAddStart, registerAddEnd);
requireText(
  registerAddBody,
  "COMPCALL(arm_ADD_ptr_ri)(d, (uae_s32)(uae_u32)live.state[s].val)",
  "constant PC_P plus signed guest displacement contract",
);
requireText(registerAddBody, "ADD_xxwEX(d, d, s", "runtime PC_P plus signed guest displacement contract");
for (const contract of [
  "arm_ADD_l_ri_hostptr(src,(uintptr)comp_pc_p)",
  "arm_ADD_l_ri_hostptr(offs,(uintptr)comp_pc_p)",
  "arm_ADD_ptr_ri(src,m68k_pc_offset)",
  "arm_ADD_ptr_ri(offs,m68k_pc_offset)",
  "arm_ADD_ptr_ri(PC_P,m68k_pc_offset)",
]) {
  requireText(gencompSource, contract, "generator pointer arithmetic contract");
  requireText(generatedSource, contract, "generated pointer arithmetic contract");
}
for (const sourceText of [gencompSource, generatedSource]) {
  requireBefore(
    sourceText,
    "preserve_flags_before_nzcv_clobber();",
    "dbf_dec_test_ne_w(src);",
    "DBF architectural CCR preservation",
  );
  requireBefore(
    sourceText,
    "dbf_dec_test_ne_w(src);",
    "discard_flags_in_nzcv();",
    "DBF temporary NZCV discard",
  );
}
for (const contract of [
  "[dbra_ccr_preserve_z_clear]=1",
  "[dbra_ccr_preserve_z_set]=1",
]) {
  requireText(harnessSource, contract, "DBF native replay CCR regression");
}

for (const forbidden of [
  "arm_ADD_l_ri(src,(uintptr)comp_pc_p)",
  "arm_ADD_l_ri(offs,(uintptr)comp_pc_p)",
]) {
  if (gencompSource.includes(forbidden) || generatedSource.includes(forbidden)) {
    fail(`pointer arithmetic contract: ambiguous generated call remains: ${forbidden}`);
  }
}

for (const contract of [
  "jit_block_verify_compiled_ops = i + 1",
  "jit_block_verify_compiled_ops = i;",
  "const int reference_ops = jit_block_verify_compiled_ops > 0",
  "for (int step = 0; step < reference_ops; step++)",
  "native_ops=%d REACHED",
  "native_ops=%d SKIP-NOREACH",
]) {
  requireText(allocatorSource, contract, "block verifier exact retirement bound");
}
if (allocatorSource.includes("const int maxsteps = blocklen * 16 + 64")) {
  fail("block verifier exact retirement bound: first-stop-PC loop remains");
}

for (const contract of [
  "B2_JIT_STRICT_FULL",
  "strict full-JIT: translator unavailable",
  "strict full-JIT: optlev-0 block",
  "strict full-JIT: non-L2 block",
  "strict full-JIT: opcode fallback",
  "strict full-JIT: exact exec_nostats",
  "strict full-JIT: verifier interpreter reference",
  "strict full-JIT: verifier opcode reference",
  "JIT_STRICT_SUMMARY native=%llu trace=%llu warmup=%llu verify=%llu blocks=%llu opt0=0 fallback=0 exec_nostats=0",
  "if (block_m68k_pc < ROMBaseMac && blocklen > 0)",
  "bi->handler_to_use = (cpuop_func*)popall_check_checksum",
  "set_dhtu_validated(bi, bi->direct_pcc)",
  "bi->status = BI_NEED_CHECK",
  "STRICT_RAM_HOT_THRESHOLD = 10",
  "jit_strict_trace_warmups++",
]) {
  requireText(allocatorSource, contract, "strict full-JIT fallback gate");
}
for (const contract of [
  "strict full-JIT: exec_nostats runtime entry",
  "strict full-JIT: exec_nostats_limited runtime entry",
  "if (!jit_strict_full_jit_env())",
  "first-seen tracer observe the code and compile an L2 block normally.",
  "jit_strict_note_trace_op(jit_current_interp_pc, opcode)",
  "jit_strict_defer_cold_ram_trace(pc_hist, blocklen)",
]) {
  requireText(compatSource, contract, "strict full-JIT runtime gate");
}
for (const forbidden of ["jit_execute_ori_b_run_native", "jit_strict_note_native_zero_op"]) {
  if (compatSource.includes(forbidden) || allocatorSource.includes(forbidden))
    fail(`strict full-JIT: zero-RAM semantic helper remains: ${forbidden}`);
}
const emulopStart = allocatorSource.indexOf("static void op_emulop_comp_ff(uae_u32 opcode)\n{");
const emulopEnd = allocatorSource.indexOf("static void op_aline_trap_comp_ff", emulopStart);
if (emulopStart < 0 || emulopEnd < 0) fail("strict full-JIT: missing EMUL_OP compiler handler");
const emulopBody = allocatorSource.slice(emulopStart, emulopEnd);
requireText(emulopBody, "jit_emit_runtime_helper_barrier((uintptr)jit_runtime_emulop", "native EMUL_OP boundary");
if (emulopBody.includes("cpufunctbl") || emulopBody.includes("cputbl")) {
  fail("strict full-JIT: EMUL_OP compiler handler still emits an interpreter-table call");
}
requireText(
  allocatorSource,
  "m68k_dispatch_emulop(opcode);",
  "native EMUL_OP shared dispatcher",
);
for (const contract of [
  "void m68k_dispatch_emulop(uae_u32 opcode)",
  "if (opcode == M68K_EXEC_RETURN)",
  "if (!regs.s)",
  "m68k_emulop_return();",
  "m68k_emulop(opcode);",
  "m68k_incpc(2);",
]) {
  requireText(newcpuSource, contract, "shared EMUL_OP semantics");
}
for (const contract of [
  'm68k_dispatch_emulop(0x7100)',
  'm68k_dispatch_emulop(opcode)',
]) {
  requireText(gencpuSource, contract, "generated reference EMUL_OP dispatcher");
}
for (const forbidden of [
  "jit_force_optlev0_block_exact",
  "B2_JIT_UNFORCE_OPT0_PCS",
  "B2_JIT_NO_FORCE_OPT0",
  "pc >= 0x04000000 && pc <= 0x0400ffff",
  "pc >= 0x040b0000 && pc <= 0x040bffff",
]) {
  if (allocatorSource.includes(forbidden)) {
    fail(`strict full-JIT: hard-coded optlev-0 ROM gate remains: ${forbidden}`);
  }
}
requireText(
  allocatorSource,
  "jit_force_optlev0() || jit_force_optlev0_block_env(block_m68k_pc)",
  "strict full-JIT explicit optlev-0 diagnostics",
);
for (const contract of [
  "static inline bool jit_strict_probe_opcode_fallback(void)",
  "if (!jit_strict_full_jit_env())",
  "jit_strict_probe_opcode_fallback())",
]) {
  requireText(allocatorSource, contract, "strict full-JIT fallback fault injection");
}
if (allocatorSource.split("(*cpufunctbl[opcode])(opcode);").length - 1 !== 2) {
  fail("strict full-JIT: unexpected direct cpufunctbl execution site in ARM64 support");
}
if (compatSource.split("(*cpufunctbl[opcode])(opcode);").length - 1 !== 3) {
  fail("strict full-JIT: unexpected direct cpufunctbl execution site in ARM64 compatibility layer");
}
for (const contract of [
  "[strict_zero_ram_native]=1",
  "B2_JIT_STRICT_FULL=1",
  'B2_NATIVE_ASSERT_PC="$replay_pc"',
  "^NATEXEC pc=$replay_pc_hex ",
  "strict-full-jit.sh",
]) {
  requireText(harnessSource, contract, "strict full-JIT native replay gate");
}
for (const contract of [
  "B2_JIT_FORCE_OPTLEV0=1",
  "B2_JIT_STRICT_PROBE_OPCODE_FALLBACK=1",
  "B2_JIT_VERIFY_BLOCKS=0x1000",
  "grep -q '^REGDUMP:'",
  "METRIC strict_full_jit_negative_gate=1",
]) {
  requireText(strictHarnessSource, contract, "strict full-JIT negative gate");
}
if (supportSource.includes("jit_strict_full_jit_env()\n\t\treturn;")) {
  fail("strict full-JIT: guest CACR/cache-maintenance semantics are conditionally suppressed");
}
for (const contract of [
  "if (jit_strict_full_jit_env())\n\t\tjit_abort(\"strict full-JIT: %s\", reason)",
  "UseJIT = false;",
  "TimerRestoreAsyncOwnership();",
  "if (handler == op_system_control_comp_ff) return \"system_control_helper\";",
  "if (handler == op_cache_control_comp_ff) return \"cache_control_helper\";",
]) {
  requireText(allocatorSource, contract, "strict initialization and coverage taxonomy");
}
requireText(
  allocatorSource,
  "bool uses_fpu = (nftbl[i].specific & COMP_OPCODE_USES_FPU) != 0;",
  "no-flags FPU table registration",
);
for (const contract of [
  "static void jit_runtime_fpu_semantic(uae_u32 opcode)",
  "case i_FPP:",
  "case i_FDBcc:",
  "case i_FScc:",
  "case i_FTRAPcc:",
  "case i_FBcc:",
  "case i_FSAVE:",
  "case i_FRESTORE:",
  "jit_emit_runtime_helper_barrier((uintptr)jit_runtime_fpu_semantic",
  "if (avoid_fpu) {",
  "compfunctbl[cft_map(opcode)] = op_fpu_semantic_comp_ff;",
  "nfcompfunctbl[cft_map(opcode)] = op_fpu_semantic_comp_ff;",
  'if (handler == op_fpu_semantic_comp_ff) return "fpu_semantic_service";',
]) {
  requireText(allocatorSource, contract, "disabled-FPU semantic service coverage");
}
for (const vector of [
  "[fpp_semantic_successor]=1",
  "[fscc_false_byte]=1",
  "[fbcc_false_operand_lengths]=1",
]) {
  requireText(harnessSource, vector, "disabled-FPU focused native replay");
}
requireText(
  allocatorSource,
  'if (legal) trap_count++;',
  "legal-opcode coverage taxonomy",
);
requireText(
  supportSource,
  "if (UseJIT)\n\t\t\tdisable_jit_runtime",
  "ordinary lazy JIT initialization failure",
);
const ordinaryFallback = supportSource.slice(
  requireText(supportSource, "void m68k_compile_execute(void)", "ordinary lazy JIT fallback"),
  requireText(supportSource, "void readbyte(int address", "ordinary lazy JIT fallback"),
);
requireBefore(
  ordinaryFallback,
  "if (!UseJIT) {",
  "m68k_execute();",
  "ordinary lazy JIT initialization fallback",
);
requireBefore(
  ordinaryFallback,
  "m68k_execute();",
  "return;",
  "ordinary lazy JIT initialization fallback",
);
requireText(
  timerSource,
  "Restore60HzAsyncOwnership()",
  "ordinary lazy JIT initialization restores 60 Hz ownership",
);
requireText(
  mainUnixSource,
  "if (tick_thread_active)\n\t\treturn true;",
  "idempotent 60 Hz ownership restoration",
);
for (const contract of [
  "return jit_guest_path_enabled() || jit_retirement_tick_every() != 0;",
  "if (tick_every && (++retirement_count % tick_every) == 0)",
  "jit_guest_instruction_retired(pc);",
]) {
  requireText(allocatorSource, contract, "retirement ticks independent of path capture");
}
requireText(
  supportSource,
  "if (use_sync_ticks && !use_retirement_ticks)",
  "retirement ticks suppress dispatcher wall-clock ticks",
);
if (supportSource.includes("jit_guest_path_is_armed")) {
  fail("retirement tick ownership is still coupled to path-capture arming");
}
const referenceObserverStart = allocatorSource.indexOf('extern "C" void jit_guest_path_record_reference');
const referenceObserverEnd = allocatorSource.indexOf('extern "C" void jit_guest_path_record_nostats', referenceObserverStart);
if (referenceObserverStart < 0 || referenceObserverEnd < 0) fail("missing verifier path observer");
const referenceObserverBody = allocatorSource.slice(referenceObserverStart, referenceObserverEnd);
if (referenceObserverBody.includes("jit_guest_instruction_retired")) {
  fail("verifier replay advances architectural retirement ticks");
}
requireText(referenceObserverBody, "jit_guest_path_record(pc);", "verifier path-only observer");
if (supportSource.includes("B2_PATH_RING_TARGET") ||
    supportSource.includes("SCAN2F98_ENTRY") ||
    supportSource.includes("ROM_TO_RAM") ||
    supportSource.includes("REGDUMP2")) {
  fail("workload-specific dispatch diagnostics remain in active ARM64 support");
}
requireText(
  allocatorSource,
  "jit_collect_edge_profile(bi)",
  "opt-in edge profiling",
);
if (allocatorSource.includes("jit_maybe_promote_stable_edge") ||
    allocatorSource.includes("compemu_raw_call((uintptr)jit_maybe_promote_stable_edge)")) {
  fail("stable direct edges retain a per-exit runtime promotion callback");
}
if (supportSource.includes("jit_abort(\"ARM64 JIT dispatcher stubs were not initialized")) {
  fail("ordinary lazy JIT initialization still aborts instead of falling back");
}
requireText(
  allocatorSource,
  'getenv("B2_JIT_PROBE_CODE_ALLOC_FAIL")',
  "deterministic JIT allocation lifecycle probe",
);
const popallStart = allocatorSource.indexOf("STATIC_INLINE void create_popalls(void)");
const popallEnd = allocatorSource.indexOf("static inline void reset_lists(void)", popallStart);
if (popallStart < 0 || popallEnd < 0) fail("missing popallspace initialization lifecycle");
const popallBody = allocatorSource.slice(popallStart, popallEnd);
if (popallBody.includes("jit_abort(")) {
  fail("ordinary lazy JIT popallspace allocation still aborts before policy fallback");
}
const disableStart = allocatorSource.indexOf("static void disable_jit_runtime(const char* reason)");
const disableEnd = allocatorSource.indexOf("#ifdef NOFLAGS_SUPPORT_GENCOMP", disableStart);
if (disableStart < 0 || disableEnd < 0) fail("missing JIT disable lifecycle");
const disableBody = allocatorSource.slice(disableStart, disableEnd);
requireBefore(
  disableBody,
  "compiler_exit();",
  "cache_size = 0;",
  "partial JIT allocation teardown preserves allocation size",
);
const compilerExitStart = allocatorSource.indexOf("void compiler_exit(void)");
const compilerExitEnd = allocatorSource.indexOf("/********************************************************************", compilerExitStart);
if (compilerExitStart < 0 || compilerExitEnd < 0) fail("missing compiler exit lifecycle");
const compilerExitBody = allocatorSource.slice(compilerExitStart, compilerExitEnd);
for (const contract of [
  "flush_icache_hard(3);",
  "reset_lists();",
  "pushall_call_handler = NULL;",
  "popall_execute_normal = NULL;",
  "current_compile_p = NULL;",
  "memset(cache_tags, 0, sizeof(cache_tags));",
]) {
  requireText(compilerExitBody, contract, "JIT executable-storage teardown");
}
requireText(
  allocatorSource,
  "if (cache_enabled && !strict_cache_disable_boundary_seen)\n            flush_icache_hard(3);\n        cache_enabled = 1;",
  "strict full-JIT guest cache transition preserves invalidation",
);

requireText(gencompSource, "NATIVE_CC_VC,NATIVE_CC_VS", "ARM64 overflow condition codegen");
const arm64OverflowCases = "#if defined(CPU_aarch64) || defined(CPU_AARCH64)\n\t case 8:\n\t case 9:";
if (gencompSource.split(arm64OverflowCases).length - 1 !== 3) {
  fail("ARM64 overflow condition codegen: Bcc/DBcc/Scc must all handle VC/VS natively");
}
if (allocatorSource.split("switch (real_opcode & 0x0038)").length - 1 < 2) {
  fail("full-SR EA decoding: mode field must exclude the register bits in both directions");
}
if (allocatorSource.includes("switch (real_opcode & 0x003f)")) {
  fail("full-SR EA decoding: mode switch still includes register bits");
}
for (const mvsr2Contract of [
  "static void jit_runtime_mvsr2_full(uae_u32 opcode)",
  "if (!ccr_only && !regs.s)",
  "m68k_dreg(regs, dstreg) = (m68k_dreg(regs, dstreg) & 0xffff0000u) | value;",
  "dsta = get_disp_ea_020(m68k_areg(regs, dstreg), next_iword());",
  "regs.fault_pc = m68k_getpc();",
  "if (table68k[opcode].mnemo == i_MVSR2)",
  "jit_emit_runtime_helper_barrier((uintptr)jit_runtime_mvsr2_full",
]) {
  requireText(allocatorSource, mvsr2Contract, "complete MOVE SR/CCR helper family");
}
requireText(
  allocatorSource,
  "cflow = f ? prop[cft_map(table68k[opcode].handler)].cflow\n                      : table68k[opcode].cflow;",
  "fallback architectural control-flow classification",
);
requireText(
  allocatorSource,
  "? compfunctbl[cft_map(base)] : NULL;",
  "explicit compiler-handler propagation",
);
requireText(
  allocatorSource,
  "jit_same_compiler_shape(table68k[opcode], table68k[probe])",
  "shape-safe compiler-handler propagation",
);
for (const shapeField of [
  "a.mnemo == b.mnemo", "a.cc == b.cc", "a.size == b.size",
  "a.smode == b.smode", "a.dmode == b.dmode",
  "a.spos == b.spos", "a.dpos == b.dpos",
  "a.cflow == b.cflow", "a.flagdead == b.flagdead", "a.flaglive == b.flaglive",
]) {
  requireText(allocatorSource, shapeField, "shape-safe compiler-handler propagation");
}
if (allocatorSource.includes("table68k[probe].mnemo == mnemo")) {
  fail("explicit compiler-handler propagation: mnemonic-only handler substitution remains");
}
requireText(
  allocatorSource,
  "if ((prop[cft_map(opcode)].cflow & fl_end_block) != 0) {",
  "fallback control-flow runtime successor",
);

const bitfieldGeneratorStart = gencompSource.indexOf("     case i_BFTST:");
const bitfieldGeneratorEnd = gencompSource.indexOf("     case i_PACK:", bitfieldGeneratorStart);
if (bitfieldGeneratorStart < 0 || bitfieldGeneratorEnd < 0) fail("missing bitfield generator family");
const bitfieldGenerator = gencompSource.slice(bitfieldGeneratorStart, bitfieldGeneratorEnd);
for (const contract of [
  "case i_BFEXTU:", "case i_BFCHG:", "case i_BFEXTS:",
  "case i_BFCLR:", "case i_BFFFO:", "case i_BFSET:", "case i_BFINS:",
  "failure;",
]) {
  requireText(bitfieldGenerator, contract, "bitfield exact-PC service routing");
}
for (const forbidden of [
  "genamode (", "call_helper((uintptr)jit_op_bf", "GENA_GETV_NO_FETCH",
  "mov_l_mr((uintptr)&regs.jit_exception",
]) {
  if (bitfieldGenerator.includes(forbidden)) {
    fail(`bitfield exact-PC service routing: split generated/helper transaction remains: ${forbidden}`);
  }
}
const bitfieldRuntime = functionBody(
  allocatorSource,
  "static void jit_runtime_bitfield(uae_u32 opcode)",
  "static void jit_runtime_cas(uae_u32 opcode)",
  "bitfield exact-PC runtime service",
);
for (const contract of [
  "const uae_u16 extension = (uae_u16)get_iword(2);",
  "m68k_incpc(4);",
  "ea = get_disp_ea_020(m68k_getpc(), next_iword());",
  "regs.scratchregs[1] = is_dreg ? 1 : 0;",
  "case 7: jit_op_bfins(); break;",
  "if (!pc_already_advanced)\n        m68k_incpc(fixed_length);",
]) {
  requireText(bitfieldRuntime, contract, "bitfield exact-PC runtime service");
}
requireBefore(bitfieldRuntime, "case 7: jit_op_bfins(); break;", "m68k_incpc(fixed_length);", "bitfield write/fault PC ordering");
const casRuntime = functionBody(
  allocatorSource,
  "static void jit_runtime_cas(uae_u32 opcode)",
  "static void jit_runtime_cas2(uae_u32 opcode)",
  "CAS ordered transaction",
);
requireBefore(casRuntime, "memory_value = (uae_u8)phys_get_byte(ea);", "m68k_areg(regs, areg) = ea;", "CAS predecrement read fault ordering");
requireText(casRuntime, "#ifdef FULLMMU", "CAS MMU-aware read contract");
if (allocatorSource.includes("(prop[cft_map(opcode)].cflow & fl_end_block) != 0 && i + 1 < blocklen")) {
  fail("fallback control-flow runtime successor: terminal fallback remains position-gated");
}
requireText(
  allocatorSource,
  "const uae_u32 opcode = tagged_opcode & 0xffffu;",
  "diagnostic verifier tagged-opcode decode",
);
for (const observer of [
  "trace_emuneigh_entry",
  "jit_trace_pc_hit",
  "jit_verify_pre",
  "jit_verify_post",
  "jit_flush_delta_compare",
  "jit_trace_add",
  "trace_emulop_resume",
  "b2_test_native_entry",
]) {
  if (allocatorSource.includes(`compemu_raw_call((uintptr)${observer})`)) {
    fail(`diagnostic observer preservation: raw call remains for ${observer}`);
  }
}
const registersPath = new URL(
  "../BasiliskII/src/uae_cpu_2026/registers.h",
  import.meta.url,
);
const registersSource = await Bun.file(registersPath).text();
requireText(registersSource, "uae_u32 jit_exception_oldpc", "deferred exception exact-PC backing");
requireText(registersSource, "uae_u32 scratchregs[5]", "helper scratch backing");
requireText(registersSource, "uintptr_t jit_scratch_vregs[5]", "pointer-width scratch spill backing");
requireText(
  allocatorSource,
  "sizeof(regs.jit_scratch_vregs) / sizeof(regs.jit_scratch_vregs[0]) >= SCRATCH_REGS",
  "scratch spill backing compile-time cardinality assertion",
);
requireText(
  allocatorSource,
  "sizeof(regs.jit_scratch_vregs[0]) == sizeof(uintptr)",
  "scratch spill backing compile-time width assertion",
);
requireText(
  allocatorSource,
  "live.state[i].mem = (uae_u32*)&regs.jit_scratch_vregs[i - S1]",
  "scratch spill mapping",
);
const pointerWidthScratchPaths = allocatorSource.match(/if \(r == PC_P \|\| r >= S1\)/g)?.length ?? 0;
if (pointerWidthScratchPaths < 2) {
  fail("pointer-width scratch spill path: both reload and writeback must be 64-bit");
}
const evictStart = allocatorSource.indexOf("static void evict(int r)");
const evictEnd = allocatorSource.indexOf("static inline void free_nreg", evictStart);
if (evictStart < 0 || evictEnd < 0) fail("missing allocator evict function");
const evictBody = allocatorSource.slice(evictStart, evictEnd);
requireText(
  evictBody,
  'jit_abort("register %d in nreg %d is locked!"',
  "allocator locked-register eviction",
);
if (evictBody.includes("force-unlock") || evictBody.includes("live.nat[rr].locked = 0")) {
  fail("allocator locked-register eviction: silent force-unlock remains");
}

const releaseScratchStart = allocatorSource.indexOf("void release_scratch(int i)");
const releaseScratchEnd = allocatorSource.indexOf("static void freescratch", releaseScratchStart);
if (releaseScratchStart < 0 || releaseScratchEnd < 0) fail("missing release_scratch");
const releaseScratchBody = allocatorSource.slice(releaseScratchStart, releaseScratchEnd);
requireText(
  releaseScratchBody,
  'jit_abort("release_scratch(): %d is not a scratch reg."',
  "scratch range ownership",
);
requireText(
  releaseScratchBody,
  'jit_abort("release_scratch(): %d not in use."',
  "scratch double-release ownership",
);

const freeScratchStart = allocatorSource.indexOf("static void freescratch(void)");
const freeScratchEnd = allocatorSource.indexOf("/********************************", freeScratchStart);
if (freeScratchStart < 0 || freeScratchEnd < 0) fail("missing freescratch");
const freeScratchBody = allocatorSource.slice(freeScratchStart, freeScratchEnd);
requireText(
  freeScratchBody,
  "for (i = 0; i < N_REGS; i++)",
  "scratch lock ownership",
);
requireText(
  freeScratchBody,
  'jit_abort("physical register %d still locked at opcode boundary"',
  "scratch lock ownership",
);
if (freeScratchBody.includes("live.nat[i].locked = 0")) {
  fail("scratch lock ownership: silent lock clearing remains");
}

const dhtuValidatedStart = allocatorSource.indexOf("static inline void set_dhtu_validated");
const dhtuValidatedEnd = allocatorSource.indexOf("void invalidate_block", dhtuValidatedStart);
if (dhtuValidatedStart < 0 || dhtuValidatedEnd < 0) fail("missing validated dependency repatcher");
const dhtuValidatedBody = allocatorSource.slice(dhtuValidatedStart, dhtuValidatedEnd);
requireText(
  dhtuValidatedBody,
  "set_dhtu_policy(bi, dh, false)",
  "validated dependency repatching",
);

const lazyFlushStart = allocatorSource.indexOf("static inline void flush_icache_lazy");
const lazyFlushEnd = allocatorSource.indexOf("int failure;", lazyFlushStart);
if (lazyFlushStart < 0 || lazyFlushEnd < 0) fail("missing flush_icache_lazy");
const lazyFlushBody = allocatorSource.slice(lazyFlushStart, lazyFlushEnd);
requireText(
  lazyFlushBody,
  "set_dhtu_validated(bi, bi->direct_pcc)",
  "lazy-flush direct-edge validation",
);

const invalidateStart = allocatorSource.indexOf("void invalidate_block(blockinfo* bi)");
const invalidateEnd = allocatorSource.indexOf("static inline void create_jmpdep", invalidateStart);
if (invalidateStart < 0 || invalidateEnd < 0) fail("missing invalidate_block");
const invalidateBody = allocatorSource.slice(invalidateStart, invalidateEnd);
requireText(
  invalidateBody,
  "bi->edge_exec_count[i] = 0",
  "invalidated edge profile",
);
requireText(
  invalidateBody,
  "bi->edge_target_pc[i] = 0",
  "invalidated edge profile",
);

const recompileStart = allocatorSource.indexOf("static inline void block_need_recompile");
const recompileEnd = allocatorSource.indexOf("static inline blockinfo* get_blockinfo_addr_new", recompileStart);
if (recompileStart < 0 || recompileEnd < 0) fail("missing block_need_recompile");
const recompileBody = allocatorSource.slice(recompileStart, recompileEnd);
requireBefore(
  recompileBody,
  "bi->direct_handler = bi->direct_pen",
  "set_dhtu(bi, bi->direct_pen)",
  "recompile dependency invalidation",
);

const resetListsStart = allocatorSource.lastIndexOf("static inline void reset_lists(void)");
const resetListsEnd = allocatorSource.indexOf("static void prepare_block", resetListsStart);
if (resetListsStart < 0 || resetListsEnd < 0) fail("missing reset_lists");
const resetListsBody = allocatorSource.slice(resetListsStart, resetListsEnd);
requireBefore(
  resetListsBody,
  "free_blockinfo(hold_bi[i])",
  "hold_bi[i] = NULL",
  "reserved blockinfo reclamation",
);

const finalizationStart = allocatorSource.lastIndexOf("bi->nexthandler = current_compile_p");
const finalizationEnd = allocatorSource.indexOf("jit_end_write_window();", finalizationStart);
if (finalizationStart < 0 || finalizationEnd < 0) fail("missing compile_block finalization");
const finalizationBody = allocatorSource.slice(finalizationStart, finalizationEnd);
requireBefore(
  finalizationBody,
  "bi->status = BI_ACTIVE",
  "flush_icache_hard(3)",
  "cache-exhaustion blockinfo lifetime",
);
requireBefore(
  finalizationBody,
  "if (redo_current_block)",
  "flush_icache_hard(3)",
  "cache-exhaustion blockinfo lifetime",
);

const zeroContainmentStart = allocatorSource.indexOf("/* RAM blocks compiled from zeroed source");
const zeroContainmentEnd = allocatorSource.indexOf("jit_trace_edge_snapshot(\"BUILD\"", zeroContainmentStart);
if (zeroContainmentStart < 0 || zeroContainmentEnd < 0) fail("missing zero-source containment");
const zeroContainmentBody = allocatorSource.slice(zeroContainmentStart, zeroContainmentEnd);
requireBefore(
  zeroContainmentBody,
  "bi->handler_to_use = (cpuop_func*)popall_check_checksum",
  "bi->status = BI_NEED_CHECK",
  "strict zero-source checksum validation",
);
requireBefore(
  zeroContainmentBody,
  "bi->direct_handler = bi->direct_pen",
  "set_dhtu(bi, bi->direct_pen)",
  "ordinary zero-source interpreter containment",
);

const checksumValidationStart = allocatorSource.indexOf("static inline int block_check_checksum");
const checksumValidationEnd = allocatorSource.indexOf("static int called_check_checksum", checksumValidationStart);
if (checksumValidationStart < 0 || checksumValidationEnd < 0) fail("missing checksum validation");
const checksumValidationBody = allocatorSource.slice(checksumValidationStart, checksumValidationEnd);
requireText(
  checksumValidationBody,
  "isgood = bi->csi != NULL",
  "zero-valued checksum validity",
);
if (checksumValidationBody.includes("if (bi->c1 || bi->c2)")) {
  fail("zero-valued checksum validity: checksum value is still overloaded as presence");
}

const blockBuilderPath = new URL(
  "../BasiliskII/src/uae_cpu_2026/compiler/compemu_legacy_arm64_compat.cpp",
  import.meta.url,
);
const blockBuilder = await Bun.file(blockBuilderPath).text();
requireText(blockBuilder, "case 0: return NATIVE_CC_VS;", "complete legacy condition mapping");
requireText(blockBuilder, "case 1: return NATIVE_CC_VC;", "complete legacy condition mapping");
const bfinsHelperStart = blockBuilder.indexOf('extern "C" void jit_op_bfins(void)');
const bfinsHelperEnd = blockBuilder.indexOf("/* --- ROXL/ROXR register helpers --- */", bfinsHelperStart);
if (bfinsHelperStart < 0 || bfinsHelperEnd < 0) fail("missing BFINS helper");
const bfinsHelper = blockBuilder.slice(bfinsHelperStart, bfinsHelperEnd);
for (const contract of [
  "uae_s32 offset = (ext & 0x800)",
  "const uae_u32 dsta = ea_info + (offset >> 3)",
  "if (regs.scratchregs[1])",
  "(void)get_bitfield(dsta, bdata, offset, width)",
  "put_bitfield(dsta, bdata, field, offset, width)",
  "const uae_u32 rotated = roff ?",
  "const uae_u32 keep_mask = width == 32 ? 0",
]) {
  requireText(bfinsHelper, contract, "BFINS signed/wrapping field semantics");
}
if (bfinsHelper.includes("bytes_needed") || bfinsHelper.includes("offset = do_reg ?") ||
    bfinsHelper.includes("ea_info & 0x80000000")) {
  fail("BFINS signed/wrapping field semantics: truncated byte-loop, early modulo, or stolen EA tag bit remains");
}
const blockBuilderStart = blockBuilder.indexOf("void execute_normal(void)");
if (blockBuilderStart < 0) fail("missing execute_normal block builder");
const blockBuilderBody = blockBuilder.slice(blockBuilderStart);
requireText(
  blockBuilderBody,
  "if (!must_end && end_block(opcode))\n\t\t\t\tmust_end = true;",
  "basic-block formation",
);
for (const forbidden of [
  "forbid_trace_follow",
  "new_pcp > cur_insn",
  "cur_guest_pc == 0x0401b70c",
]) {
  if (blockBuilderBody.includes(forbidden)) {
    fail(`basic-block formation: forbidden trace-follow policy remains: ${forbidden}`);
  }
}

for (const contract of [
  "extern void jit_notify_guest_memory_write",
  "JIT_NOTIFY_GUEST_WRITE(addr, 4)",
  "JIT_NOTIFY_GUEST_WRITE(addr, 2)",
  "JIT_NOTIFY_GUEST_WRITE(addr, 1)",
]) {
  requireText(memorySource, contract, "cache-disabled tracer write coherency");
}
for (const contract of [
  "emit_strict_cache_disabled_write_barrier(adr, 1)",
  "emit_strict_cache_disabled_write_barrier(adr, 2)",
  "emit_strict_cache_disabled_write_barrier(adr, 4)",
]) {
  requireText(midfunc2Source, contract, "cache-disabled native integer-write coherency");
}
for (const contract of [
  "emit_strict_cache_disabled_write_barrier(REG_WORK1, 1)",
  "emit_strict_cache_disabled_write_barrier(REG_WORK1, 2)",
  "emit_strict_cache_disabled_write_barrier(REG_WORK1, 4)",
]) {
  requireText(midfunc2Source, contract, "24-bit alias write coherency");
}
const read24ByteStart = midfunc2Source.indexOf("MIDFUNC(2,jnf_MEM_READ24_OFF_b");
const read24ByteEnd = midfunc2Source.indexOf("MENDFUNC(2,jnf_MEM_READ24_OFF_b", read24ByteStart);
if (read24ByteStart < 0 || read24ByteEnd < 0) fail("missing 24-bit byte read emitter");
const read24ByteBody = midfunc2Source.slice(read24ByteStart, read24ByteEnd);
requireBefore(read24ByteBody, "MRS_NZCV_x(REG_WORK4)", "CMP_wi(REG_WORK3, 2)", "24-bit byte-read flag preservation");
requireBefore(read24ByteBody, "CMP_wi(REG_WORK3, 2)", "MSR_NZCV_x(REG_WORK4)", "24-bit byte-read flag preservation");
for (const contract of [
  "emit_strict_cache_disabled_write_barrier(adr, 12)",
  "emit_strict_cache_disabled_write_barrier(adr, 8)",
]) {
  requireText(midfuncSource, contract, "cache-disabled native FPU-write coherency");
}
for (const contract of [
  "if (value_reg <= R18_INDEX)",
  "MOV_xx(REG_PAR1, value_reg)",
  "jit_emitted_guest_memory_write = true",
  "compemu_raw_call_observer_ri((uintptr)jit_notify_guest_memory_write",
]) {
  requireText(codegenSource, contract, "cache-disabled native write barrier");
}
for (const contract of [
  "static int guest_cache_enabled = 0",
  "static bool strict_cache_disable_boundary_seen = false",
  "if (cache_enabled && !strict_cache_disable_boundary_seen)",
  "strict_cache_disable_boundary_seen = true",
  "strict_cache_disable_boundary_seen = false;\n    set_cache_state(0)",
  "void jit_notify_guest_memory_write",
  "jit_write_overlaps_checksum",
  "block_need_recompile(bi)",
  "jit_emitted_guest_memory_write &&",
  "!(prop[cft_map(opcode)].cflow & fl_end_block)",
  "static void jit_runtime_fsave",
  "static void jit_runtime_frestore",
  "table68k[opcode].mnemo == i_FSAVE",
  "table68k[opcode].mnemo == i_FRESTORE",
]) {
  requireText(allocatorSource, contract, "strict native lifecycle services");
}
requireText(
  harnessSource,
  "TESTS[cache_disabled_selfmod_replay]",
  "cache-disabled self-modifying RAM regression",
);
const hostCodeInvalidateStart = allocatorSource.indexOf(
  "void jit_invalidate_host_code_write(uae_u32 address, uae_u32 size)",
);
const hostCodeInvalidateEnd = allocatorSource.indexOf(
  "void jit_notify_guest_memory_write",
  hostCodeInvalidateStart,
);
if (hostCodeInvalidateStart < 0 || hostCodeInvalidateEnd < 0) {
  fail("host-injected code coherency: missing dedicated invalidation path");
}
const hostCodeInvalidateBody = allocatorSource.slice(
  hostCodeInvalidateStart,
  hostCodeInvalidateEnd,
);
requireText(
  hostCodeInvalidateBody,
  "jit_invalidate_guest_code_range(address, size, false)",
  "host-injected code coherency",
);
if (hostCodeInvalidateBody.includes("jit_strict_cache_disabled_coherence")) {
  fail("host-injected code coherency: invalidation still depends on guest CACR/strict mode");
}
for (const contract of [
  "jit_invalidate_host_code_write(test_addr",
  "jit_invalidate_host_code_write(m68k_areg(regs, 7), 4)",
  "jit_invalidate_host_code_write(m68k_areg(regs, 7), 6)",
]) {
  requireText(basiliskGlueSource, contract, "host-injected code coherency");
}
for (const contract of [
  "TESTS[host_code_reuse_coherence]",
  "B2_TEST_REWRITE_HEX",
  'EXPECTED_D0[host_code_reuse_coherence]="00000002"',
]) {
  requireText(harnessSource, contract, "host-injected code reuse regression");
}
for (const contract of [
  "#define JIT_TRACE_SOURCE_BYTES 22",
  "uae_u16 opcode;",
  "uae_u8 source[JIT_TRACE_SOURCE_BYTES];",
]) {
  requireText(compemuHeaderSource, contract, "trace source snapshot");
}
for (const contract of [
  "hist->opcode = (uae_u16)do_get_mem_word(hist->location)",
  "memcpy(hist->source, hist->location, JIT_TRACE_SOURCE_BYTES)",
]) {
  requireText(compatSource, contract, "trace source snapshot");
}
const traceSnapshotStart = requireText(
  allocatorSource,
  "void compile_block(cpu_history* pc_hist",
  "trace source coherency",
);
const traceSnapshotEnd = allocatorSource.indexOf(
  "if (jit_strict_full_jit_env() &&",
  traceSnapshotStart,
);
if (traceSnapshotEnd < 0) fail("trace source coherency: missing strict gate after snapshot guard");
const traceSnapshotGuard = allocatorSource.slice(traceSnapshotStart, traceSnapshotEnd);
requireBefore(
  traceSnapshotGuard,
  "const uae_u16 current_opcode = (uae_u16)DO_GET_OPCODE(pc_hist[i].location)",
  "if (current_opcode != pc_hist[i].opcode ||",
  "trace source coherency",
);
requireText(
  traceSnapshotGuard,
  "memcmp(pc_hist[i].source, pc_hist[i].location,",
  "trace extension-word coherency",
);
requireText(harnessSource, "[cache_disabled_selfmod_replay]=2", "three-pass coherency proof");
requireText(harnessSource, 'B2_TEST_REPLAY_COUNT="$replay_count"', "replay-count plumbing");
requireText(
  harnessSource,
  "TESTS[movea_l_sp_postinc_cov]",
  "runtime-helper logical opcode regression",
);
const runtimeHelperStart = allocatorSource.indexOf("static void jit_runtime_mvsr2_full");
const runtimeHelperEnd = allocatorSource.indexOf("static void op_trap_comp_ff", runtimeHelperStart);
if (runtimeHelperStart < 0 || runtimeHelperEnd < 0)
  fail("missing runtime semantic helper region");
const runtimeHelperBody = allocatorSource.slice(runtimeHelperStart, runtimeHelperEnd);
if (runtimeHelperBody.includes("cft_map(opcode)"))
  fail("runtime semantic helpers must decode the logical opcode, not the compiler-table index");
requireText(harnessSource, "TESTS[branch_flush_bgt_zero]", "cross-op BGT regression");

console.log("METRIC structural_jit_object_layout_epoch=1");
console.log("METRIC structural_bcd_flag_lifecycle=1");
console.log("METRIC structural_bcd_patched_branch_joins=7");
console.log("METRIC structural_bcd_a7_predecrement_geometry=1");
console.log("METRIC structural_bcd_exact_pc_memory_replay=1");
console.log("METRIC structural_division_patched_branch_joins=28");
console.log("METRIC structural_division_overflow_flags=1");
console.log("METRIC structural_register_shift_six_bit_count=1");
console.log("METRIC structural_register_shift_patched_joins=11");
console.log("METRIC structural_register_shift_branchless_carry_sites=24");
console.log("METRIC structural_register_shift_alias_native=1");
console.log("METRIC structural_register_shift_long_immediate_saturation=1");
console.log(`METRIC structural_register_shift_exact_native_vectors=${shiftExactVectorNames.size}`);
console.log(`METRIC structural_register_shift_active_vectors=${activeShiftVectorCount}`);
console.log("METRIC structural_fixed_memory_shift_flag_lifecycle=1");
console.log("METRIC structural_fixed_memory_shift_exact_native_vectors=8");
console.log("METRIC structural_memory_rox_x_ownership=1");
console.log("METRIC structural_memory_rox_exact_native_vectors=2");
console.log("METRIC structural_memory_rox_allocator_pressure=1");
console.log("METRIC structural_shift_rotate_fixed_flag_branches_removed=11");
console.log("METRIC structural_register_rotate_six_bit_count=1");
console.log("METRIC structural_register_rotate_alias_native=1");
console.log("METRIC structural_register_rotate_flag_lifecycle=1");
console.log(`METRIC structural_register_rotate_exact_native_vectors=${rotateExactVectorNames.size}`);
console.log(`METRIC structural_register_rotate_active_vectors=${activeRotateVectorCount}`);
console.log("METRIC structural_fullsr_ea_mode_decode=1");
console.log("METRIC structural_complete_mvsr2_helper_family=1");
console.log("METRIC structural_complete_legacy_condition_mapping=1");
console.log("METRIC structural_arm64_overflow_condition_codegen=1");
console.log("METRIC structural_shape_safe_handler_propagation=1");
console.log("METRIC structural_explicit_handler_propagation=1");
console.log("METRIC structural_fallback_architectural_cflow=1");
console.log("METRIC structural_fallback_controlflow_runtime_pc=1");
console.log("METRIC structural_bfins_runtime_contract=1");
console.log("METRIC structural_bfins_signed_wrapping_semantics=1");
console.log("METRIC structural_helper_call_abi=1");
console.log("METRIC structural_diagnostic_observer_abi=1");
console.log("METRIC structural_diagnostic_verifier_opcode_decode=1");
console.log("METRIC structural_block_verifier_retirement_bound=1");
console.log("METRIC structural_helper_allocator_barrier=1");
console.log("METRIC structural_semantic_helper_fault_pc=1");
console.log("METRIC structural_allocator_locked_evict=1");
console.log("METRIC structural_scratch_spill_cardinality=1");
console.log("METRIC structural_scratch_spill_width=1");
console.log("METRIC structural_scratch_ownership=1");
console.log("METRIC structural_recompile_dependency_invalidation=1");
console.log("METRIC structural_lazy_flush_direct_validation=1");
console.log("METRIC structural_invalidated_edge_profile_reset=1");
console.log("METRIC structural_reserved_blockinfo_reclamation=1");
console.log("METRIC structural_cache_exhaustion_blockinfo_lifetime=1");
console.log("METRIC structural_zero_source_dependency_containment=1");
console.log("METRIC structural_dbf_ccr_preservation=1");
console.log("METRIC structural_strict_full_jit_gate=1");
console.log("METRIC structural_native_emulop_boundary=1");
console.log("METRIC structural_endblock_successor_pc=1");
console.log("METRIC structural_basic_block_control_boundary=1");
console.log("METRIC structural_cache_disabled_write_coherency=1");
console.log("METRIC structural_host_code_reuse_coherency=1");
console.log("METRIC structural_cache_transition_idempotence=1");
console.log("METRIC structural_coverage_taxonomy=1");
console.log("METRIC structural_trace_source_coherency=1");
console.log("METRIC structural_native_fpu_state_boundary=1");
console.log("METRIC structural_disabled_fpu_semantic_service=1");
console.log("METRIC structural_runtime_helper_logical_opcode=1");
