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
requireText(harnessSource, "nogui true", "opcode harness noninteractive execution");
requireText(strictHarnessSource, "nogui true", "strict harness noninteractive execution");

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
const midfuncArmHeaderSource = await Bun.file(new URL(
  "../BasiliskII/src/uae_cpu_2026/compiler/compemu_midfunc_arm.h",
  import.meta.url,
)).text();
const midfuncArm2HeaderSource = await Bun.file(new URL(
  "../BasiliskII/src/uae_cpu_2026/compiler/compemu_midfunc_arm2.h",
  import.meta.url,
)).text();
const codegenHeaderSource = await Bun.file(new URL(
  "../BasiliskII/src/uae_cpu_2026/compiler/codegen_arm64.h",
  import.meta.url,
)).text();
const branchPatchSource = await Bun.file(new URL(
  "../BasiliskII/src/uae_cpu_2026/compiler/arm64_branch_patch.h",
  import.meta.url,
)).text();
const compareEmitterProbeSource = await Bun.file(new URL(
  "./emitter-compare-conformance.cpp",
  import.meta.url,
)).text();
const compareEmitterHarnessSource = await Bun.file(new URL(
  "./emitter-compare-conformance.sh",
  import.meta.url,
)).text();
const addEmitterProbeSource = await Bun.file(new URL(
  "./emitter-add-conformance.cpp",
  import.meta.url,
)).text();
const addEmitterHarnessSource = await Bun.file(new URL(
  "./emitter-add-conformance.sh",
  import.meta.url,
)).text();
const subEmitterProbeSource = await Bun.file(new URL(
  "./emitter-sub-conformance.cpp",
  import.meta.url,
)).text();
const subEmitterHarnessSource = await Bun.file(new URL(
  "./emitter-sub-conformance.sh",
  import.meta.url,
)).text();
const andEmitterProbeSource = await Bun.file(new URL(
  "./emitter-and-conformance.cpp",
  import.meta.url,
)).text();
const andEmitterHarnessSource = await Bun.file(new URL(
  "./emitter-and-conformance.sh",
  import.meta.url,
)).text();
const eorEmitterProbeSource = await Bun.file(new URL(
  "./emitter-eor-conformance.cpp",
  import.meta.url,
)).text();
const eorEmitterHarnessSource = await Bun.file(new URL(
  "./emitter-eor-conformance.sh",
  import.meta.url,
)).text();
const negEmitterProbeSource = await Bun.file(new URL(
  "./emitter-neg-conformance.cpp",
  import.meta.url,
)).text();
const negEmitterHarnessSource = await Bun.file(new URL(
  "./emitter-neg-conformance.sh",
  import.meta.url,
)).text();
const branchEmitterProbeSource = await Bun.file(new URL(
  "./emitter-branch-conformance.cpp",
  import.meta.url,
)).text();
const branchEmitterHarnessSource = await Bun.file(new URL(
  "./emitter-branch-conformance.sh",
  import.meta.url,
)).text();
const fmovEmitterProbeSource = await Bun.file(new URL(
  "./emitter-fmov-conformance.cpp",
  import.meta.url,
)).text();
const fmovEmitterHarnessSource = await Bun.file(new URL(
  "./emitter-fmov-conformance.sh",
  import.meta.url,
)).text();
const fcmpEmitterProbeSource = await Bun.file(new URL(
  "./emitter-fcmp-conformance.cpp",
  import.meta.url,
)).text();
const fcmpEmitterHarnessSource = await Bun.file(new URL(
  "./emitter-fcmp-conformance.sh",
  import.meta.url,
)).text();
const fcvtasEmitterProbeSource = await Bun.file(new URL(
  "./emitter-fcvtas-conformance.cpp",
  import.meta.url,
)).text();
const fcvtasEmitterHarnessSource = await Bun.file(new URL(
  "./emitter-fcvtas-conformance.sh",
  import.meta.url,
)).text();
const fcvtEmitterProbeSource = await Bun.file(new URL(
  "./emitter-fcvt-conformance.cpp",
  import.meta.url,
)).text();
const fcvtEmitterHarnessSource = await Bun.file(new URL(
  "./emitter-fcvt-conformance.sh",
  import.meta.url,
)).text();
const fmovSwWsEmitterProbeSource = await Bun.file(new URL(
  "./emitter-fmov-sw-ws-conformance.cpp",
  import.meta.url,
)).text();
const fmovSwWsEmitterHarnessSource = await Bun.file(new URL(
  "./emitter-fmov-sw-ws-conformance.sh",
  import.meta.url,
)).text();
const fmovDxXdEmitterProbeSource = await Bun.file(new URL(
  "./emitter-fmov-dx-xd-conformance.cpp",
  import.meta.url,
)).text();
const fmovDxXdEmitterHarnessSource = await Bun.file(new URL(
  "./emitter-fmov-dx-xd-conformance.sh",
  import.meta.url,
)).text();
const scvtfEmitterProbeSource = await Bun.file(new URL(
  "./emitter-scvtf-conformance.cpp",
  import.meta.url,
)).text();
const scvtfEmitterHarnessSource = await Bun.file(new URL(
  "./emitter-scvtf-conformance.sh",
  import.meta.url,
)).text();
const frintEmitterProbeSource = await Bun.file(new URL(
  "./emitter-frint-conformance.cpp",
  import.meta.url,
)).text();
const frintEmitterHarnessSource = await Bun.file(new URL(
  "./emitter-frint-conformance.sh",
  import.meta.url,
)).text();
const fmovDiEmitterProbeSource = await Bun.file(new URL(
  "./emitter-fmov-di-conformance.cpp",
  import.meta.url,
)).text();
const fmovDiEmitterHarnessSource = await Bun.file(new URL(
  "./emitter-fmov-di-conformance.sh",
  import.meta.url,
)).text();
const fsqrtEmitterProbeSource = await Bun.file(new URL(
  "./emitter-fsqrt-conformance.cpp",
  import.meta.url,
)).text();
const fsqrtEmitterHarnessSource = await Bun.file(new URL(
  "./emitter-fsqrt-conformance.sh",
  import.meta.url,
)).text();
const fsubEmitterProbeSource = await Bun.file(new URL(
  "./emitter-fsub-conformance.cpp",
  import.meta.url,
)).text();
const fsubEmitterHarnessSource = await Bun.file(new URL(
  "./emitter-fsub-conformance.sh",
  import.meta.url,
)).text();
const fmulEmitterProbeSource = await Bun.file(new URL(
  "./emitter-fmul-conformance.cpp",
  import.meta.url,
)).text();
const fmulEmitterHarnessSource = await Bun.file(new URL(
  "./emitter-fmul-conformance.sh",
  import.meta.url,
)).text();
const fmulSingleEmitterProbeSource = await Bun.file(new URL(
  "./emitter-fmul-s-conformance.cpp",
  import.meta.url,
)).text();
const fmulSingleEmitterHarnessSource = await Bun.file(new URL(
  "./emitter-fmul-s-conformance.sh",
  import.meta.url,
)).text();
const fdivDoubleEmitterProbeSource = await Bun.file(new URL(
  "./emitter-fdiv-d-conformance.cpp",
  import.meta.url,
)).text();
const fdivDoubleEmitterHarnessSource = await Bun.file(new URL(
  "./emitter-fdiv-d-conformance.sh",
  import.meta.url,
)).text();
const fdivSingleEmitterProbeSource = await Bun.file(new URL(
  "./emitter-fdiv-s-conformance.cpp",
  import.meta.url,
)).text();
const fdivSingleEmitterHarnessSource = await Bun.file(new URL(
  "./emitter-fdiv-s-conformance.sh",
  import.meta.url,
)).text();
const fmsubEmitterProbeSource = await Bun.file(new URL(
  "./emitter-fmsub-conformance.cpp",
  import.meta.url,
)).text();
const fmsubEmitterHarnessSource = await Bun.file(new URL(
  "./emitter-fmsub-conformance.sh",
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
const fppCompilerSource = await Bun.file(new URL(
  "../BasiliskII/src/uae_cpu_2026/compiler/compemu_fpp.cpp",
  import.meta.url,
)).text();
const fpuMpfrSource = await Bun.file(new URL(
  "../BasiliskII/src/uae_cpu_2026/fpu/fpu_mpfr.cpp",
  import.meta.url,
)).text();
const nativeFlagsSource = await Bun.file(new URL(
  "../BasiliskII/src/uae_cpu_2026/compiler/flags_arm.h",
  import.meta.url,
)).text();
const fbccMatrixSource = await Bun.file(new URL(
  "./fbcc-native-matrix.ts",
  import.meta.url,
)).text();
const fppCompareMatrixSource = await Bun.file(new URL(
  "./fpp-compare-native-matrix.ts",
  import.meta.url,
)).text();
const fppFtstMatrixSource = await Bun.file(new URL(
  "./fpp-ftst-native-matrix.ts",
  import.meta.url,
)).text();
const fppFmoveSourceMatrix = await Bun.file(new URL(
  "./fpp-fmove-source-matrix.ts",
  import.meta.url,
)).text();
const fppFmoveRegisterServiceMatrix = await Bun.file(new URL(
  "./fpp-fmove-register-service-matrix.ts",
  import.meta.url,
)).text();
const fppFmoveMemoryBasicMatrix = await Bun.file(new URL(
  "./fpp-fmove-memory-basic-matrix.ts",
  import.meta.url,
)).text();
const fppFmoveExtendedEaMatrix = await Bun.file(new URL(
  "./fpp-fmove-memory-extended-ea-matrix.ts",
  import.meta.url,
)).text();
const fppFmoveDestinationBasicMatrix = await Bun.file(new URL(
  "./fpp-fmove-destination-basic-matrix.ts",
  import.meta.url,
)).text();
const fppFmoveDoubleDestinationMatrix = await Bun.file(new URL(
  "./fpp-fmove-double-destination-matrix.ts",
  import.meta.url,
)).text();
const fppFmoveDestinationExtendedEaMatrix = await Bun.file(new URL(
  "./fpp-fmove-destination-extended-ea-matrix.ts",
  import.meta.url,
)).text();
const fppFmoveDestinationInvalidMatrix = await Bun.file(new URL(
  "./fpp-fmove-destination-invalid-matrix.ts",
  import.meta.url,
)).text();
const fppFmoveExtendedFallbackMatrix = await Bun.file(new URL(
  "./fpp-fmove-extended-fallback-matrix.ts",
  import.meta.url,
)).text();
const fppFmovePackedFallbackMatrix = await Bun.file(new URL(
  "./fpp-fmove-packed-fallback-matrix.ts",
  import.meta.url,
)).text();
const fppExplicitMoveFallbackMatrix = await Bun.file(new URL(
  "./fpp-explicit-move-fallback-matrix.ts",
  import.meta.url,
)).text();
const fppFmovecrFallbackMatrix = await Bun.file(new URL(
  "./fpp-fmovecr-fallback-matrix.ts",
  import.meta.url,
)).text();
const fppSignFallbackMatrix = await Bun.file(new URL(
  "./fpp-sign-fallback-matrix.ts",
  import.meta.url,
)).text();
const fppSqrtFallbackMatrix = await Bun.file(new URL(
  "./fpp-sqrt-fallback-matrix.ts",
  import.meta.url,
)).text();
const fppIntegralRoundingFallbackMatrix = await Bun.file(new URL(
  "./fpp-integral-rounding-fallback-matrix.ts",
  import.meta.url,
)).text();
const fppDecompositionFallbackMatrix = await Bun.file(new URL(
  "./fpp-decomposition-fallback-matrix.ts",
  import.meta.url,
)).text();
const fppHyperbolicLog1pFallbackMatrix = await Bun.file(new URL(
  "./fpp-hyperbolic-log1p-fallback-matrix.ts",
  import.meta.url,
)).text();
const fppInverseFallbackMatrix = await Bun.file(new URL(
  "./fpp-inverse-fallback-matrix.ts",
  import.meta.url,
)).text();
const fppTanExp10LogFallbackMatrix = await Bun.file(new URL(
  "./fpp-tan-exp10-log-fallback-matrix.ts",
  import.meta.url,
)).text();
const fppNativeTranscendentalServiceMatrix = await Bun.file(new URL(
  "./fpp-native-transcendental-service-matrix.ts",
  import.meta.url,
)).text();
const fppCoshAcosCosServiceMatrix = await Bun.file(new URL(
  "./fpp-cosh-acos-cos-service-matrix.ts",
  import.meta.url,
)).text();
const fppDivideServiceMatrix = await Bun.file(new URL(
  "./fpp-divide-service-matrix.ts",
  import.meta.url,
)).text();
const fppFmodServiceMatrix = await Bun.file(new URL(
  "./fpp-fmod-service-matrix.ts",
  import.meta.url,
)).text();
const fppFremServiceMatrix = await Bun.file(new URL(
  "./fpp-frem-service-matrix.ts",
  import.meta.url,
)).text();
const fppScaleServiceMatrix = await Bun.file(new URL(
  "./fpp-scale-service-matrix.ts",
  import.meta.url,
)).text();
const fppSgldivServiceMatrix = await Bun.file(new URL(
  "./fpp-sgldiv-service-matrix.ts",
  import.meta.url,
)).text();
const fppSglmulServiceMatrix = await Bun.file(new URL(
  "./fpp-sglmul-service-matrix.ts",
  import.meta.url,
)).text();
const fppSincosServiceMatrix = await Bun.file(new URL(
  "./fpp-sincos-service-matrix.ts",
  import.meta.url,
)).text();
const fppControlDirectServiceMatrix = await Bun.file(new URL(
  "./fpp-control-direct-service-matrix.ts",
  import.meta.url,
)).text();
const fppControlMemoryBasicMatrix = await Bun.file(new URL(
  "./fpp-control-memory-basic-matrix.ts",
  import.meta.url,
)).text();
const fppControlMemoryIndexedMatrix = await Bun.file(new URL(
  "./fpp-control-memory-indexed-matrix.ts",
  import.meta.url,
)).text();
const fppFmovemStaticServiceMatrix = await Bun.file(new URL(
  "./fpp-fmovem-static-service-matrix.ts",
  import.meta.url,
)).text();
const fppFmovemDynamicServiceMatrix = await Bun.file(new URL(
  "./fpp-fmovem-dynamic-service-matrix.ts",
  import.meta.url,
)).text();
const fppAddServiceMatrix = await Bun.file(new URL(
  "./fpp-add-service-matrix.ts",
  import.meta.url,
)).text();
const fppMulServiceMatrix = await Bun.file(new URL(
  "./fpp-mul-service-matrix.ts",
  import.meta.url,
)).text();
const fppSubServiceMatrix = await Bun.file(new URL(
  "./fpp-sub-service-matrix.ts",
  import.meta.url,
)).text();
const fpuHeaderSource = await Bun.file(new URL(
  "../BasiliskII/src/uae_cpu_2026/fpu/fpu.h",
  import.meta.url,
)).text();
const fppFmoveSingleDestinationMatrix = await Bun.file(new URL(
  "./fpp-fmove-single-destination-matrix.ts",
  import.meta.url,
)).text();
for (const contract of [
  'echo "$reason" >&2\n    exit 1',
  'if [ "$TOTAL" -eq 0 ] || [ "$FAIL" -ne 0 ] || [ "$INFRA_FAIL" -ne 0 ]',
  '[ "$RISKY_TOTAL" -ne "$TOTAL" ] || [ "$RISKY_PASS" -ne "$RISKY_TOTAL" ]',
  "exit 1\nfi\nexit 0",
]) requireText(harnessSource, contract, "top-level harness fail-closed status");
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

function matchingFunctionBodies(text: string, signatures: RegExp, context: string): string[] {
  const matches = [...text.matchAll(signatures)];
  if (matches.length === 0) fail(`${context}: no matching functions`);
  return matches.map((match) => {
    const start = match.index!;
    const open = text.indexOf("{", start + match[0].length);
    if (open < 0) fail(`${context}: missing opening brace`);
    let depth = 0;
    for (let cursor = open; cursor < text.length; cursor++) {
      if (text[cursor] === "{") depth++;
      else if (text[cursor] === "}" && --depth === 0) return text.slice(start, cursor + 1);
    }
    fail(`${context}: missing closing brace`);
  });
}

const fbccCompilerBody = functionBody(
  fppCompilerSource,
  "void comp_fbcc_opp(uae_u32 opcode)",
  "    /* Floating point conditions",
  "native FBcc compiler",
);
for (const contract of [
  "preserve_flags_before_nzcv_clobber();",
  "fflags_into_flags();",
  "register_branch(v1, v2, 16 + cc);",
]) requireText(fbccCompilerBody, contract, "native FBcc compiler");
const nativeFpConditions = nativeFlagsSource.match(/^\s*NATIVE_CC_F_[A-Z]+\s*=\s*16\s*\+\s*\d+/gm) ?? [];
if (nativeFpConditions.length !== 16) {
  fail(`native FBcc predicate namespace: expected 16 distinct IDs, found ${nativeFpConditions.length}`);
}
for (const contract of [
  "case NATIVE_CC_F_F:", "case NATIVE_CC_F_EQ:", "case NATIVE_CC_F_OGT:",
  "case NATIVE_CC_F_OGE:", "case NATIVE_CC_F_OLT:", "case NATIVE_CC_F_OLE:",
  "case NATIVE_CC_F_OGL:", "case NATIVE_CC_F_OR:", "case NATIVE_CC_F_UN:",
  "case NATIVE_CC_F_UEQ:", "case NATIVE_CC_F_UGT:", "case NATIVE_CC_F_UGE:",
  "case NATIVE_CC_F_ULT:", "case NATIVE_CC_F_ULE:", "case NATIVE_CC_F_NE:",
  "case NATIVE_CC_F_T:",
]) requireText(codegenSource, contract, "native FBcc condition lowering");
for (const contract of [
  "jit_fpu_sync_to_shadow", "jit_fpu_sync_from_shadow",
  "std::numeric_limits<double>::quiet_NaN()",
  "std::numeric_limits<double>::infinity()",
  "fpu_set_fpsr((fpu_get_fpsr() & ~FPSR_CCB) | fpcc)",
]) requireText(compatSource, contract, "native FBcc architectural FPU boundary");
for (const contract of [
  "compemu_raw_call((uintptr)jit_fpu_sync_to_shadow)",
  "compemu_raw_call((uintptr)jit_fpu_sync_from_shadow)",
  "arm_branch_cc >= NATIVE_CC_F_F && arm_branch_cc <= NATIVE_CC_F_T",
  "(arm_branch_cc - NATIVE_CC_F_F) ^ 0xf",
  "live.flags_in_flags = TRASH",
]) requireText(allocatorSource, contract, "native FBcc block lifecycle");
for (const contract of [
  "for (let cc = 0; cc < 16; cc++)",
  'for (const width of ["word", "long"] as const)',
  "B2_JIT_STRICT_FULL: \"1\"",
  "B2_NATIVE_ASSERT_PC: anchorHex",
  "sr === \"271f\"",
  "pass === 160",
  "cow_clone",
  "cow_release",
]) requireText(fbccMatrixSource, contract, "native FBcc fail-closed matrix");

const fppCompilerBody = matchingFunctionBodies(
  fppCompilerSource,
  /void comp_fpp_opp\(uae_u32 opcode, uae_u16 extra\)/g,
  "native FPP compiler",
)[0];
for (const contract of [
  "case 0x38:", "/* FCMP */", "fcompare_result_rr(FP_RESULT, reg, src);",
  "case 0x3a:", "/* FTST */", "if (src == FP_RESULT)",
  "preserve_flags_before_nzcv_clobber();",
]) requireText(fppCompilerBody, contract, "native FPP compare/test lifecycle");
for (const contract of [
  "void fcompare_result_rr(int result, int d, int s)",
  "fcompare_result_emit(result, d, s)",
]) requireText(compatSource, contract, "native FPP compare ownership");
for (const contract of [
  "LOWFUNC(NONE,NONE,3,fcompare_result_emit",
  "FCMP_dd(d, s)", "0xbff0000000000000ULL", "0x7ff8000000000000ULL",
  "0x8000000000000000ULL", "CMP_xi(REG_WORK2, 2047)",
]) requireText(codegenSource, contract, "native FPP compare classifier");
for (const [matrix, total, context] of [
  [fppCompareMatrixSource, 176, "native FPP FCMP matrix"],
  [fppFtstMatrixSource, 128, "native FPP FTST matrix"],
] as const) {
  for (const contract of [
    "B2_JIT_STRICT_FULL: \"1\"", "B2_NATIVE_ASSERT_PC", "FPSR=",
    "sr === \"271f\"", "cow_clone", "cow_release", `pass === ${total}`,
  ]) requireText(matrix, contract, context);
}
console.log("METRIC structural_fpp_compare_exact_native_vectors=176");
console.log("METRIC structural_fpp_ftst_exact_native_vectors=128");
console.log("METRIC structural_fpp_exact_fpsr_classes=8");
console.log("METRIC structural_fpp_integer_ccr_preservation=1");

const getFpValueBody = functionBody(
  fppCompilerSource,
  "STATIC_INLINE int get_fp_value(uae_u32 opcode, uae_u16 extra)",
  "STATIC_INLINE int put_fp_value",
  "native FPP source conversion",
);
for (const contract of [
  "case 0: /* Dn */", "case 7:", "case 4: /* #imm */",
  "fmov_b_rr(FS1, reg);", "fmov_w_rr(FS1, reg);",
  "fmov_l_rr(FS1, reg);", "fmov_s_rr(FS1, reg);",
  "fmov_b_rr(FS1, S2);", "fmov_w_rr(FS1, S2);",
  "fmov_l_rr(FS1, S2);", "fmov_s_rr(FS1, S2);",
]) requireText(getFpValueBody, contract, "native FPP source conversion");
for (const contract of [
  "type FmoveCase", "FP${fpReg}=", "initD7",
  'name: "imm_double_fraction"', 'name: "imm_double_negative_inf"',
  "B2_TEST_DUMP_FP: \"1\"", "B2_JIT_STRICT_FULL: \"1\"",
  "B2_NATIVE_ASSERT_PC: anchorHex", "sr === \"271f\"",
  "cow_clone", "cow_release", 'group !== undefined && group !== "single" && group !== "integer"',
  'throw new Error(`unknown GROUP=${group}`)',
  'expectedTotal = process.env.CASE ? 1 : process.env.GROUP === "single" ? 8 : process.env.GROUP === "integer" ? 18 : 29',
]) requireText(fppFmoveSourceMatrix, contract, "native ordinary FMOVE source matrix");
for (const stale of ["fp1_to_fp0", "fp_all_live_fp0_to_fp7", "fpRegistersMatch"])
  if (fppFmoveSourceMatrix.includes(stale)) fail(`native ordinary FMOVE source matrix retains superseded register-source case ${stale}`);
if (/\b(?:FSMOVE|FDMOVE)\b/.test(fppFmoveSourceMatrix)) {
  fail("ordinary FMOVE source matrix: explicit precision subfamily leaked into bounded scope");
}
console.log("METRIC structural_fpp_fmove_source_exact_native_vectors=29");
console.log("METRIC structural_fpp_fmove_source_formats=5");
console.log("METRIC structural_fpp_fmove_register_routes=0");
console.log("METRIC structural_fpp_fmove_integer_ccr_preservation=1");
for (const contract of [
  'group !== undefined && group !== "single" && group !== "integer"',
  'group === "integer" ? cases.filter((item) => {',
  'return size === 0 || size === 4 || size === 6;',
  'process.env.GROUP === "integer" ? 18 : 29',
]) requireText(fppFmoveSourceMatrix, contract, "native integer-to-FP FMOVE subset");
const integerFmoveCaseNames = [
  "dn_byte_negative", "dn_byte_positive", "dn_word_negative", "dn_word_positive",
  "dn_long_negative", "dn_long_positive", "imm_byte_negative", "imm_word_negative",
  "imm_long_negative", "dn_byte_min", "dn_word_min", "dn_long_minus_one",
  "imm_byte_positive", "imm_word_positive", "imm_long_positive",
  "dn_byte_d7_max_field", "dn_word_d7_max_field", "dn_long_d7_max_field",
] as const;
for (const name of integerFmoveCaseNames)
  requireText(fppFmoveSourceMatrix, `name: "${name}"`, "native integer-to-FP FMOVE subset");
for (const [width, sourceType, signHelper] of [
  ["b", "RR1", "SIGNED8_REG_2_REG(REG_WORK1, s);"],
  ["w", "RR2", "SIGNED16_REG_2_REG(REG_WORK1, s);"],
  ["l", "RR4", ""],
] as const) {
  const midBody = functionBody(
    midfuncSource, `MIDFUNC(2,fmov_${width}_rr,(FW d, ${sourceType} s))`,
    `MENDFUNC(2,fmov_${width}_rr,(FW d, ${sourceType} s))`, `integer-to-FP FMOVE.${width} MIDFUNC`,
  );
  for (const contract of ["s = readreg(s);", "d = f_writereg(d);", `raw_fmov_${width}_rr(d, s);`, "f_unlock(d);", "unlock2(s);"])
    requireText(midBody, contract, `integer-to-FP FMOVE.${width} MIDFUNC`);
  requireBefore(midBody, "s = readreg(s);", "d = f_writereg(d);", `integer-to-FP FMOVE.${width} source acquisition`);
  requireBefore(midBody, `raw_fmov_${width}_rr(d, s);`, "f_unlock(d);", `integer-to-FP FMOVE.${width} result lifetime`);
  requireBefore(midBody, "f_unlock(d);", "unlock2(s);", `integer-to-FP FMOVE.${width} unlock order`);
  const rawBody = functionBody(
    codegenSource, `LOWFUNC(NONE,NONE,2,raw_fmov_${width}_rr,(FW d, ${sourceType} s))`,
    `LENDFUNC(NONE,NONE,2,raw_fmov_${width}_rr,(FW d, ${sourceType} s))`, `integer-to-FP FMOVE.${width} raw`,
  );
  if (signHelper) {
    requireBefore(rawBody, signHelper, "SCVTF_dw(d, REG_WORK1);", `integer-to-FP FMOVE.${width} sign-extension order`);
  } else {
    requireText(rawBody, "SCVTF_dw(d, s);", "integer-to-FP FMOVE.l conversion");
  }
  const rootSites = (fppCompilerSource.match(new RegExp(`\\bfmov_${width}_rr\\(`, "g")) || []).length;
  if (rootSites !== 2) fail(`integer-to-FP FMOVE.${width} configured roots=${rootSites}, expected=2`);
}
for (const contract of [
  "STATIC_INLINE void SIGNED8_REG_2_REG", "SXTB_ww(d, s);",
  "STATIC_INLINE void SIGNED16_REG_2_REG", "SXTH_ww(d, s);",
  "Use 32-bit sign extension to keep upper 32 bits clean.",
]) requireText(codegenSource, contract, "integer-to-FP FMOVE sign extension");
const integerFmoveScvtfSites = (codegenSource.match(/\bSCVTF_dw\(/g) || []).length;
const integerFmoveSxtbSites = (codegenSource.match(/\bSXTB_ww\(/g) || []).length;
const integerFmoveSxthCodegenSites = (codegenSource.match(/\bSXTH_ww\(/g) || []).length;
const integerFmoveSxthMidSites = (midfunc2Source.match(/\bSXTH_ww\(/g) || []).length;
if (integerFmoveScvtfSites !== 6 || integerFmoveSxtbSites !== 1 || integerFmoveSxthCodegenSites !== 1 || integerFmoveSxthMidSites !== 3)
  fail(`integer-to-FP FMOVE shared emitter sites SCVTF/SXTB/SXTH-codegen/SXTH-mid=${integerFmoveScvtfSites}/${integerFmoveSxtbSites}/${integerFmoveSxthCodegenSites}/${integerFmoveSxthMidSites}, expected 6/1/1/3`);
console.log("METRIC structural_fpp_fmove_integer_source_vectors=18");
console.log("METRIC structural_fpp_fmove_integer_source_midfuncs=3");
console.log("METRIC structural_fpp_fmove_integer_source_raw_boundaries=3");
console.log("METRIC structural_fpp_fmove_integer_source_shared_emitters=3");
const fppCompilerOperationForMove = functionBody(
  fppCompilerSource,
  "void comp_fpp_opp(uae_u32 opcode, uae_u16 extra)",
  "\n\tFAIL(1);\n}\n\n#endif",
  "FPP operation compiler",
);
const ordinaryMoveStartForRegister = fppCompilerOperationForMove.indexOf("case 0x00:\t\t\t\t\t\t/* FMOVE */");
const ordinaryMoveEndForRegister = fppCompilerOperationForMove.indexOf("case 0x01:", ordinaryMoveStartForRegister);
if (ordinaryMoveStartForRegister < 0 || ordinaryMoveEndForRegister < 0)
  fail("FPP ordinary register FMOVE compiler boundary is incomplete");
const ordinaryRegisterMoveBlock = fppCompilerOperationForMove.slice(ordinaryMoveStartForRegister, ordinaryMoveEndForRegister);
for (const contract of [
  "#if defined(CPU_aarch64) || defined(CPU_AARCH64)", "(extra & 0x4000) == 0",
  "Register-source FMOVE", "binary64-shadow copy", "before acquiring either FP operand",
  "FAIL(1);", "return;",
]) requireText(ordinaryRegisterMoveBlock, contract, "FPP register FMOVE exact service boundary");
const registerMoveGate = ordinaryRegisterMoveBlock.indexOf("(extra & 0x4000) == 0");
const registerMoveAcquire = ordinaryRegisterMoveBlock.indexOf("get_fp_value(opcode, extra)");
if (registerMoveGate < 0 || registerMoveAcquire < 0 || registerMoveGate >= registerMoveAcquire)
  fail("FPP register FMOVE service gate does not precede operand acquisition");
for (const contract of [
  "case 0: // FMOVE", "bool ordinary_move = operation == 0;",
  "bool extended_source = ordinary_move ||", "get_fp_value (opcode, extra, value)",
  "Ordinary FMOVE is an exact architectural extended copy", "set_format (EXTENDED_PREC);",
  "set_fp_register (reg, value, t, MPFR_RNDN, true);", "set_format (prec);", "update_exceptions ();",
]) requireText(fpuMpfrSource, contract, "MPFR register FMOVE precision/metadata contract");
for (const contract of [
  "for (let source = 0; source < 8; source++) for (let destination = 0; destination < 8; destination++)",
  'name: "low_significand"', 'name: "maximum_finite"', 'name: "below_binary64_range"',
  'name: "negative_zero"', 'name: "positive_infinity"', 'name: "quiet_nan_payload"',
  'name: "signalling_nan_payload"', 'name: "negative_extended"',
  'name: "fp0_to_fp7_low_significand_fpcr_single"',
  'name: "fp0_to_fp7_low_significand_fpcr_double"',
  'B2_TEST_REPLAY_FPCR: item.fpcr ?? "0"', 'B2_TEST_REPLAY_FP${reg}_EXT', 'F206 A800', 'F239 ${sourceStore} 0000 A020',
  'F239 ${destinationStore} 0000 A030', 'expectedSource(item)',
  'B2_TEST_REPLAY_FPSR: "0c55ff08"', 'B2_TEST_SECOND_PC: "0x1008"',
  'B2_NATIVE_ASSERT_PC: "0x1008"', 'output.includes("JIT_FALLBACK op=f200 pc=00001008")',
  'strict full-JIT: opcode fallback pc=00001000 op=f200',
  'const expectedService = process.env.CASE ? selectedCases.length : 66',
  'const expectedStrict = process.env.CASE ? selectedStrict.length : 3',
]) requireText(fppFmoveRegisterServiceMatrix, contract, "FPP register FMOVE service matrix");
console.log("METRIC structural_fpp_fmove_register_service_vectors=66");
console.log("METRIC structural_fpp_fmove_register_strict_rejections=3");
console.log("METRIC structural_fpp_fmove_register_pairs=64");
console.log("METRIC structural_fpp_fmove_register_exact80_classes=8");
const fmovDoublePairStart = midfuncSource.indexOf("MIDFUNC(3,fmov_d_rrr,(FW d, RR4 s1, RR4 s2))");
const fmovDoublePairEnd = midfuncSource.indexOf("MENDFUNC(3,fmov_d_rrr,(FW d, RR4 s1, RR4 s2))", fmovDoublePairStart);
if (fmovDoublePairStart < 0 || fmovDoublePairEnd < 0) fail("missing retired split-double MIDFUNC fmov_d_rrr");
requireText(midfuncSource.slice(fmovDoublePairStart, fmovDoublePairEnd), "raw_fmov_d_rrr(d, s1, s2);", "retired split-double MIDFUNC fmov_d_rrr");
if ((midfuncSource.match(/\bfmov_d_rrr\b/g) || []).length !== 2)
  fail("split-double MIDFUNC fmov_d_rrr gained a configured caller");
const fmovDoubleRawStart = codegenSource.indexOf("LOWFUNC(NONE,NONE,2,raw_fmov_d_rrr,(FW d, RR4 s1, RR4 s2))");
const fmovDoubleRawEnd = codegenSource.indexOf("LENDFUNC(NONE,NONE,2,raw_fmov_d_rrr,(FW d, RR4 s1, RR4 s2))", fmovDoubleRawStart);
if (fmovDoubleRawStart < 0 || fmovDoubleRawEnd < 0) fail("missing retired split-double raw boundary raw_fmov_d_rrr");
const fmovDoubleRawBody = codegenSource.slice(fmovDoubleRawStart, fmovDoubleRawEnd);
const fmovDoubleCombine = fmovDoubleRawBody.indexOf("BFI_xxii(s1, s2, 32, 32);");
const fmovDoubleTransfer = fmovDoubleRawBody.indexOf("FMOV_dx(d, s1);");
if (fmovDoubleCombine < 0 || fmovDoubleTransfer <= fmovDoubleCombine)
  fail("retired split-double raw boundary combine/transfer contract changed");
if ((codegenSource.match(/\braw_fmov_d_rrr\b/g) || []).length !== 2)
  fail("split-double raw boundary raw_fmov_d_rrr gained a configured caller");
const fmovDoubleBfiSites = (codegenSource.match(/\bBFI_xxii\(/g) || []).length;
const fmovDoubleTransferSites = (codegenSource.match(/\bFMOV_dx\(/g) || []).length;
if (fmovDoubleBfiSites !== 2 || fmovDoubleTransferSites !== 6)
  fail(`split-double residual BFI/FMOV_dx sites=${fmovDoubleBfiSites}/${fmovDoubleTransferSites}, expected 2/6`);
console.log("METRIC structural_fpp_fmove_unreachable_split_double_raw_boundaries=1");
console.log("METRIC structural_fpp_fmove_reachable_split_double_emitters=2");
for (const contract of [
  'for (const mode of [', 'name: "aind"', 'name: "postinc"', 'name: "predec"',
  'name: `byte_${mode.name}_a7_geometry`', 'effective: 0xa000, want: 0xa002',
  'effective: 0xa00e, want: 0xa00e',
  'name: "long_aind_a7_to_fp7_max_fields"',
  'B2_TEST_MEMORY_BYTES: memoryBytes(effective, item.bytes)',
  'B2_TEST_DUMP_FP: "1"', 'B2_JIT_STRICT_FULL: "1"',
  'B2_NATIVE_ASSERT_PC: "0x1000"', 'sr === "271f"',
  'address === wantAddress', 'cow_clone', 'cow_release',
  'process.env.GROUP === "single"',
  '((Number.parseInt(item.extra, 16) >> 10) & 7) === 1',
  'process.env.GROUP === "single" ? 3 : 18',
]) requireText(fppFmoveMemoryBasicMatrix, contract, "native ordinary FMOVE basic-memory matrix");
for (const format of ['name: "byte"', 'name: "word"', 'name: "long"', 'name: "single"', 'name: "double"'])
  requireText(fppFmoveMemoryBasicMatrix, format, "native ordinary FMOVE basic-memory formats");
console.log("METRIC structural_fpp_fmove_memory_basic_exact_native_vectors=18");
console.log("METRIC structural_fpp_fmove_memory_basic_formats=5");
console.log("METRIC structural_fpp_fmove_memory_basic_ea_modes=3");
console.log("METRIC structural_fpp_fmove_memory_a7_geometry=1");
for (const contract of [
  'name: `${format.name}_d16_a0_positive`',
  'name: `${format.name}_indexed_a0_d1_long_scale2_negative_disp`',
  'name: `${format.name}_absolute_short`', 'name: `${format.name}_absolute_long`',
  'name: `${format.name}_pc_d16_forward`',
  'name: "long_indexed_full_direct_word_bd"',
  'name: "long_indexed_full_preindexed_word_outer"',
  'name: "long_indexed_full_postindexed_word_outer"',
  'name: `${format.name}_pc_indexed_brief_d1_long`',
  'name: "long_pc_indexed_full_direct_word_bd"',
  'name: "long_pc_indexed_full_preindexed_indirect"',
  'name: "long_d16_a7_negative_to_fp7_max_fields"',
  'B2_TEST_MEMORY_BYTES:', 'B2_TEST_DUMP_FP: "1"',
  'B2_JIT_STRICT_FULL: "1"', 'B2_NATIVE_ASSERT_PC: "0x1000"',
  'regsPreserved && addressRegsPreserved && native && strict',
  'cow_clone', 'cow_release', 'expected = process.env.CASE ? 1 : 39',
]) requireText(fppFmoveExtendedEaMatrix, contract, "native ordinary FMOVE extended-EA matrix");
const getFpValueExtendedEa = functionBody(
  fppCompilerSource,
  "STATIC_INLINE int get_fp_value(uae_u32 opcode, uae_u16 extra)",
  "STATIC_INLINE int put_fp_value",
  "native FPP extended source EA",
);
for (const contract of [
  "case 5: /* d16(An) */", "case 6: /* d8(An,Xn) */",
  "case 0: /* abs.w */", "case 1: /* abs.l */", "case 2: /* d16(pc) */",
  "case 3: /* d8(pc,Xn) */", "mov_l_ri(S2, address);",
  "calc_disp_ea_020(S2, dp, ad, S3);",
]) requireText(getFpValueExtendedEa, contract, "native FPP extended source EA");
console.log("METRIC structural_fpp_fmove_extended_ea_exact_native_vectors=39");
console.log("METRIC structural_fpp_fmove_extended_ea_modes=6");
console.log("METRIC structural_fpp_fmove_indexed_formats=2");
console.log("METRIC structural_fpp_fmove_pc_indexed=1");

const putFpValueBody = functionBody(
  fppCompilerSource,
  "STATIC_INLINE int put_fp_value(int val, uae_u32 opcode, uae_u16 extra)",
  "STATIC_INLINE int get_fp_ad",
  "native FPP destination conversion",
);
for (const contract of [
  "STATIC_INLINE void clear_fp_exception_status(void)", "mov_l_mr((uintptr)&fpu.fpsr.exception_status, S5);",
]) requireText(fppCompilerSource, contract, "native FPP destination exception reset");
for (const contract of [
  "case 0: /* Dn */", "case 2: /* (An) */", "case 3: /* (An)+ */", "case 4: /* -(An) */",
  "fmov_to_b_rr(reg, val);", "fmov_to_w_rr(reg, val);", "fmov_to_l_rr(reg, val);",
  "fmov_to_s_rr(reg, val);", "fmov_to_b_rr(S2, val);", "fmov_to_w_rr(S2, val);",
  "fmov_to_l_rr(S2, val);", "fmov_to_s_rr(S2, val);", "fmov_to_d_rrr(S2, S3, val);",
  "writelong_clobber(ad, S2, S3);", "writeword_clobber(ad, S2, S3);", "writebyte(ad, S2, S3);",
]) requireText(putFpValueBody, contract, "native FPP basic destination conversion");
const fmoveIntegerEmitter = functionBody(
  codegenSource,
  "STATIC_INLINE void fmov_to_int_emit(W4 d, FR s, int width)",
  "LOWFUNC(NONE,NONE,2,raw_fmov_to_l_rr",
  "native FPP integer destination classifier",
);
for (const contract of [
  "FRINTI_dd(SCRATCH_F64_1, s);", "FCVTAS_wd(REG_WORK1, SCRATCH_F64_1);",
  "SCVTF_dw(SCRATCH_F64_2, REG_WORK1);", "FMOV_xd(REG_WORK3, s);",
  "FPSR_EXCEPTION_OPERR", "FPSR_ACCR_IOP", "FPSR_EXCEPTION_INEX2", "FPSR_ACCR_INEX",
  "MRS_NZCV_x(REG_WORK4);", "MSR_NZCV_x(REG_WORK4);",
]) requireText(fmoveIntegerEmitter, contract, "native FPP integer destination classifier");
for (const contract of [
  "regs.jit_host_fpcr = host_fpcr", "static const unsigned arm_round[4] = { 0, 3, 2, 1 }",
  "if (fpu.registers[i].nan_sign)", "fpu.registers[i].nan_sign = (bits >> 63) != 0",
  'B2_TEST_REPLAY_FPCR', 'B2_TEST_REPLAY_FPSR',
]) requireText(`${compatSource}\n${basiliskGlueSource}`, contract, "native FPP destination architectural boundary");
for (const contract of [
  'name: "byte_fraction_round_nearest_even"', 'name: "byte_fraction_round_zero"',
  'name: "byte_fraction_round_minus_inf"', 'name: "byte_fraction_round_plus_inf"',
  'name: "byte_exact_min_no_operr"', 'name: "byte_one_below_saturates"',
  'name: "byte_fractional_overflow_operr_inex"',
  'name: "word_exact_min_no_operr"', 'name: "word_one_above_saturates"',
  'name: "long_positive_infinity_saturates"', 'name: "long_negative_infinity_saturates"',
  'name: "long_positive_nan_saturates"', 'name: "long_negative_nan_saturates"',
  'name: "fp7_to_d7_max_fields"', 'name: "single_exact_clears_prior_status"',
  'name: "double_aind_exact_clears_prior_status"', 'name: `byte_${mode.name}_a7_geometry`',
  'B2_TEST_REPLAY_FPSR: "0c55ff08"', 'B2_TEST_REPLAY_FPCR: item.replayFpcr ?? "0"',
  'B2_JIT_STRICT_FULL: "1"', 'B2_NATIVE_ASSERT_PC:', 'sr === "271f"',
  'cow_clone', 'cow_release',
  'const expected = process.env.CASE ? 1 : process.env.GROUP === "integer" ? 36 : 45',
]) requireText(fppFmoveDestinationBasicMatrix, contract, "native ordinary FMOVE basic-destination matrix");
if (/\b(?:FSMOVE|FDMOVE)\b/.test(fppFmoveDestinationBasicMatrix))
  fail("ordinary FMOVE destination matrix: explicit precision subfamily leaked into bounded scope");
console.log("METRIC structural_fpp_fmove_destination_basic_exact_native_vectors=45");
console.log("METRIC structural_fpp_fmove_destination_integer_formats=3");
console.log("METRIC structural_fpp_fmove_destination_fpcr_modes=4");
console.log("METRIC structural_fpp_fmove_destination_basic_ea_modes=3");
console.log("METRIC structural_fpp_fmove_destination_exception_contracts=2");
console.log("METRIC structural_fpp_fmove_destination_nan_sign_boundary=1");

const fmoveMemoryCompilerStart = fppCompilerSource.indexOf("case 3:\t\t\t\t\t\t\t/* FMOVE Fpn,<ea> */");
const fmoveMemoryCompilerEnd = fppCompilerSource.indexOf("case 6:", fmoveMemoryCompilerStart);
if (fmoveMemoryCompilerStart < 0 || fmoveMemoryCompilerEnd < 0)
  fail("FPP ordinary FMOVE destination compiler boundary is incomplete");
const fmoveMemoryCompilerBlock = fppCompilerSource.slice(fmoveMemoryCompilerStart, fmoveMemoryCompilerEnd);
for (const contract of [
  "#if defined(CPU_AARCH64) || defined(CPU_aarch64)", "((extra >> 10) & 7) == 5",
  "architectural extended register", "binary64 shadow", "before EA mutation", "FAIL(1);", "return;",
]) requireText(fmoveMemoryCompilerBlock, contract, "FPP double-destination exact service boundary");
const fmoveDoubleGate = fmoveMemoryCompilerBlock.indexOf("((extra >> 10) & 7) == 5");
const fmovePut = fmoveMemoryCompilerBlock.indexOf("put_fp_value(");
if (fmoveDoubleGate < 0 || fmovePut < 0 || fmoveDoubleGate >= fmovePut)
  fail("FPP double-destination service gate does not precede put_fp_value/EA acquisition");
for (const contract of [
  "static bool\nfpuop_fmove_memory", "mpfr_clear_flags ();", "cur_exceptions = 0;",
  "case 5:", "extract_to_double (value, words);", "put_long (addr, words[0]);",
  "put_long (addr + 4, words[1]);", "update_exceptions ();",
  "uae_u64 nan_bits = value.nan_bits;", "nan_bits |= 1ULL << 62;",
  "Destination conversion quiets the emitted NaN but must not mutate",
]) requireText(fpuMpfrSource, contract, "MPFR double-destination conversion contract");
const extractDoubleBody = functionBody(fpuMpfrSource, "static void\nextract_to_double", "static void\nextract_to_extended", "MPFR double extractor");
if (extractDoubleBody.includes("value.nan_bits |= 1ULL << 62"))
  fail("MPFR double destination mutates its architectural NaN source metadata");
for (const contract of [
  'name: "double_positive_zero"', 'name: "double_negative_zero"',
  'name: "double_half_nearest_even"', 'name: "double_half_plus_infinity"',
  'name: "double_negative_half_minus_infinity"', 'name: "double_maximum_finite_exact"',
  'name: "double_positive_overflow_nearest"', 'name: "double_positive_overflow_zero"',
  'name: "double_negative_overflow_minus"', 'name: "double_minimum_normal_exact"',
  'name: "double_minimum_subnormal_exact"', 'name: "double_half_minimum_subnormal_nearest"',
  'name: "double_half_minimum_subnormal_plus"', 'name: "double_negative_half_minimum_subnormal_minus"',
  'name: "double_quiet_nan_payload"', 'name: "double_negative_quiet_nan_payload_fp7"',
  'name: "double_signalling_nan_quiets_without_source_mutation"', 'preserveSource: true',
  'F206 A800 F239 6800 0000 A020', 'sourcePreserved', 'conversionFpsrPreserved',
  'name: "double_a7_postincrement"',
  'name: "double_a7_predecrement"', 'name: "double_d16_a0"', 'name: "double_brief_a0_d1"',
  'name: "double_full_direct"', 'name: "double_full_preindexed"', 'name: "double_full_postindexed"',
  'name: "double_absolute_short"', 'name: "double_absolute_long"',
  'B2_TEST_REPLAY_FPCR: item.fpcr ?? "0"', 'B2_TEST_REPLAY_FPSR: "0c55ff08"',
  'B2_TEST_REPLAY_FP7_EXT" : "B2_TEST_REPLAY_FP0_EXT"', 'B2_TEST_SECOND_PC: "0x1008"',
  'B2_NATIVE_ASSERT_PC: "0x1008"', 'output.includes(`JIT_FALLBACK op=${opcode.toLowerCase()} pc=00001008`)',
  'strict full-JIT: opcode fallback pc=00001000 op=${item.opcode}',
  'const expectedService = process.env.CASE ? selectedCases.length : 28',
  'const expectedStrict = process.env.CASE ? selectedStrict.length : 3',
]) requireText(fppFmoveDoubleDestinationMatrix, contract, "FPP double-destination service matrix");
console.log("METRIC structural_fpp_fmove_double_destination_service_vectors=28");
console.log("METRIC structural_fpp_fmove_double_destination_strict_rejections=3");
console.log("METRIC structural_fpp_fmove_double_destination_fpcr_modes=4");
console.log("METRIC structural_fpp_fmove_double_destination_ea_classes=10");
console.log("METRIC structural_fpp_fmove_double_destination_special_classes=3");

for (const contract of [
  "case 5: /* d16(An) */", "case 6: /* d8(An,Xn) */",
  "case 0: /* abs.w */", "case 1: /* abs.l */",
  "calc_disp_ea_020(reg + 8, dp, ad, S2);",
]) requireText(putFpValueBody, contract, "native FPP extended destination EA");
for (const contract of [
  'name: `${format.name}_d16_a0_positive`',
  'name: `${format.name}_indexed_a0_d1_long_scale2_negative_disp`',
  'name: `${format.name}_absolute_short`', 'name: `${format.name}_absolute_long`',
  'name: "long_d16_a7_negative_from_fp7_max_fields"',
  'name: "word_indexed_a0_d7_word_scale8_max_index_field"',
  'name: "long_indexed_full_direct_word_bd"',
  'name: "long_indexed_full_preindexed_word_outer"',
  'name: "long_indexed_full_postindexed_word_outer"',
  'name: "long_indexed_brief_all_integer_registers_live"',
  'B2_TEST_REPLAY_FPSR: "0c55ff08"', 'B2_TEST_REPLAY_FPCR: "0"',
  'B2_TEST_MEMDUMP:', 'B2_JIT_STRICT_FULL: "1"', 'B2_NATIVE_ASSERT_PC:',
  'sr === "271f"', 'regsPreserved', 'addressRegsPreserved',
  'cow_clone', 'cow_release', 'const expected = process.env.CASE ? 1 : 26',
]) requireText(fppFmoveDestinationExtendedEaMatrix, contract, "native ordinary FMOVE extended-destination matrix");
if (/stream:\s*[`"]F23[ABC]\b/.test(fppFmoveDestinationExtendedEaMatrix))
  fail("ordinary FMOVE extended destination matrix: non-writable PC-relative/immediate destination leaked into scope");
for (const contract of [
  "case 2: /* d16(pc) */", "case 3: /* d8(pc,Xn) */", "case 4: /* #imm */",
  "PC-relative and immediate effective addresses are source-only", "return -1;",
]) requireText(putFpValueBody, contract, "native FPP invalid destination rejection");
for (const contract of [
  'name: "d16_pc_is_not_writable"', 'name: "indexed_pc_is_not_writable"',
  'name: "immediate_is_not_writable"', 'B2_JIT_STRICT_FULL: "1"',
  'output.includes("strict full-JIT: opcode fallback")', '!output.includes("NATEXEC pc=00001008")',
  'cow_clone', 'cow_release', 'const expected = process.env.CASE ? 1 : 3',
]) requireText(fppFmoveDestinationInvalidMatrix, contract, "native ordinary FMOVE invalid-destination matrix");
console.log("METRIC structural_fpp_fmove_destination_extended_ea_exact_native_vectors=26");
console.log("METRIC structural_fpp_fmove_destination_extended_ea_modes=4");
console.log("METRIC structural_fpp_fmove_destination_indexed_formats=2");
console.log("METRIC structural_fpp_fmove_destination_guarded_writes=1");
console.log("METRIC structural_fpp_fmove_destination_invalid_rejections=3");

for (const body of [getFpValueBody, putFpValueBody]) {
  for (const contract of [
    "case 2: /* extended precision */", "The native FP shadow", "return -1;",
  ]) requireText(body, contract, "native FPP extended-format retirement");
  const rejection = body.indexOf("The native FP shadow");
  const memoryEa = body.indexOf("case 2: /* (An) */", rejection);
  if (rejection < 0 || memoryEa < 0 || rejection >= memoryEa)
    fail("native FPP extended-format retirement does not precede memory EA calculation");
}
for (const contract of [
  'name: "fraction_low_bit_beyond_binary64"', 'name: "maximum_finite"',
  'name: "minimum_normal"', 'name: "negative_zero"',
  'name: "immediate_source"', 'name: "postinc_source"',
  'name: "postinc_destination"', 'name: "predec_destination"',
  'B2_TEST_MEMDUMP: "0x9ffe:16"', 'B2_TEST_SECOND_PC: "0x1000"',
  'output.includes("JIT_FALLBACK")', 'output.includes("strict full-JIT: opcode fallback")',
  '!output.includes("Caught SIGSEGV")', 'cow_clone', 'cow_release',
  'expectedService = process.env.CASE ? selectedService.length : 8',
  'expectedStrict = process.env.CASE ? selectedStrict.length : 4',
]) requireText(fppFmoveExtendedFallbackMatrix, contract, "FPP extended-format serviced fallback matrix");
console.log("METRIC structural_fpp_fmove_extended_service_vectors=8");
console.log("METRIC structural_fpp_fmove_extended_strict_rejections=4");
console.log("METRIC structural_fpp_fmove_extended_native_retired=1");

for (const body of [getFpValueBody, putFpValueBody]) {
  const packedReject = body.indexOf("case 3: /* packed decimal static */");
  const memoryEa = body.indexOf("case 2: /* (An) */", packedReject);
  if (packedReject < 0 || memoryEa < 0 || packedReject >= memoryEa)
    fail("native FPP packed-format rejection does not precede memory EA calculation");
  requireText(body.slice(packedReject, memoryEa), "return -1;", "native FPP packed-format service boundary");
}
for (const contract of [
  'name: "static_17_positive"', 'name: "dynamic_17_positive"',
  'name: "static_5_rounding"', 'name: "dynamic_5_rounding"',
  'name: "negative_mantissa_negative_exponent"', 'name: "positive_zero"',
  'name: "negative_zero"', 'name: "positive_infinity"', 'name: "negative_infinity"',
  'fpsr: "00000208"', 'fpsr: "08000208"', 'fpsr: "0c000000"', 'fpsr: "02000000"',
  'fpsr === item.fpsr', 'name: "immediate_source"', 'name: "postinc_source"',
  'name: "postinc_static_destination"', 'name: "predec_dynamic_destination"',
  'B2_TEST_MEMDUMP: "0x9ffe:16"', 'B2_TEST_SECOND_PC: "0x1000"',
  'output.match(/JIT_FALLBACK/g)', 'output.includes("strict full-JIT: opcode fallback")',
  '!output.includes("Caught SIGSEGV")', 'cow_clone', 'cow_release',
  'expectedService = process.env.CASE ? selectedService.length : 9',
  'expectedStrict = process.env.CASE ? selectedStrict.length : 4',
]) requireText(fppFmovePackedFallbackMatrix, contract, "FPP packed-format serviced fallback matrix");
console.log("METRIC structural_fpp_fmove_packed_service_vectors=9");
console.log("METRIC structural_fpp_fmove_packed_strict_rejections=4");
console.log("METRIC structural_fpp_fmove_packed_native_retired=1");

const fppCompilerOperation = functionBody(
  fppCompilerSource,
  "void comp_fpp_opp(uae_u32 opcode, uae_u16 extra)",
  "\n\tFAIL(1);\n}\n\n#endif",
  "native FPP operation dispatcher",
);
const explicitMoveStart = fppCompilerOperation.indexOf("case 0x40:");
const ordinaryMoveStart = fppCompilerOperation.indexOf("case 0x00:", explicitMoveStart);
const explicitMoveBlock = fppCompilerOperation.slice(explicitMoveStart, ordinaryMoveStart);
for (const contract of [
  "case 0x40:", "case 0x44:", "The binary64 shadow", "FAIL(1);", "return;",
]) requireText(explicitMoveBlock, contract, "FPP explicit-precision move service boundary");
if (explicitMoveStart < 0 || ordinaryMoveStart < 0 || explicitMoveStart >= ordinaryMoveStart)
  fail("FPP explicit-precision move service boundary does not precede ordinary FMOVE");
if (explicitMoveBlock.includes("get_fp_value") || explicitMoveBlock.includes("fmov_rr"))
  fail("FPP explicit-precision move service boundary emits native operand/copy work");
for (const contract of [
  'name: "fsmove_positive_half_nearest"', 'name: "fsmove_positive_half_plus"',
  'name: "fsmove_negative_half_minus"', 'name: "fdmove_positive_half_nearest"',
  'name: "fdmove_positive_half_plus"', 'name: "fdmove_maximum_extended_overflow"',
  'name: "fsmove_positive_infinity_exact"', 'name: "fdmove_negative_zero_exact"',
  'name: "fsmove_fp7_self_alias_max_fields"', 'name: "fdmove_fp7_self_alias_max_fields"',
  'B2_TEST_MEMDUMP: "0x9ffe:16"', 'B2_TEST_SECOND_PC: "0x1000"',
  'B2_TEST_REPLAY_FPCR: item.fpcr', 'fpsr === item.fpsr',
  'output.match(/JIT_FALLBACK/g)', 'output.includes("strict full-JIT: opcode fallback")',
  '!output.includes("Caught SIGSEGV")', 'cow_clone', 'cow_release',
  'expectedService = process.env.CASE ? selectedService.length : 13',
  'expectedStrict = process.env.CASE ? selectedStrict.length : 2',
]) requireText(fppExplicitMoveFallbackMatrix, contract, "FPP explicit-precision move serviced fallback matrix");
console.log("METRIC structural_fpp_explicit_move_service_vectors=13");
console.log("METRIC structural_fpp_explicit_move_strict_rejections=2");
console.log("METRIC structural_fpp_explicit_move_native_retired=1");
const fcutsMidStart = midfuncSource.indexOf("MIDFUNC(1,fcuts_r,(FRW r))");
const fcutsMidEnd = midfuncSource.indexOf("MENDFUNC(1,fcuts_r,(FRW r))", fcutsMidStart);
if (fcutsMidStart < 0 || fcutsMidEnd < 0) fail("missing retired cut-to-single MIDFUNC fcuts_r");
requireText(midfuncSource.slice(fcutsMidStart, fcutsMidEnd), "raw_fcuts_r(r);", "retired cut-to-single MIDFUNC fcuts_r");
if ((midfuncSource.match(/\bfcuts_r\b/g) || []).length !== 2)
  fail("cut-to-single MIDFUNC fcuts_r gained a configured caller");
const fcutsRawStart = codegenSource.indexOf("LOWFUNC(NONE,NONE,1,raw_fcuts_r,(FRW r))");
const fcutsRawEnd = codegenSource.indexOf("LENDFUNC(NONE,NONE,1,raw_fcuts_r,(FRW r))", fcutsRawStart);
if (fcutsRawStart < 0 || fcutsRawEnd < 0) fail("missing retired cut-to-single raw boundary raw_fcuts_r");
const fcutsRawBody = codegenSource.slice(fcutsRawStart, fcutsRawEnd);
for (const contract of ["FCVT_sd(SCRATCH_F64_1, r);", "FCVT_ds(r, SCRATCH_F64_1);"])
  requireText(fcutsRawBody, contract, "retired cut-to-single raw boundary raw_fcuts_r");
if ((codegenSource.match(/\braw_fcuts_r\b/g) || []).length !== 2)
  fail("cut-to-single raw boundary raw_fcuts_r gained a configured caller");
const fcutsFcvtSdSites = (codegenSource.match(/\bFCVT_sd\(/g) || []).length;
const fcutsFcvtDsSites = (codegenSource.match(/\bFCVT_ds\(/g) || []).length;
if (fcutsFcvtSdSites !== 7 || fcutsFcvtDsSites !== 6)
  fail(`cut-to-single residual FCVT sites sd/ds=${fcutsFcvtSdSites}/${fcutsFcvtDsSites}, expected 7/6`);
console.log("METRIC structural_fpp_explicit_move_unreachable_raw_boundaries=1");
console.log("METRIC structural_fpp_explicit_move_reachable_fcvt_emitters=2");
const fmovsMidStart = midfuncSource.indexOf("MIDFUNC(2,fmovs_rr,(FW d, FR s))");
const fmovsMidEnd = midfuncSource.indexOf("MENDFUNC(2,fmovs_rr,(FW d, FR s))", fmovsMidStart);
if (fmovsMidStart < 0 || fmovsMidEnd < 0) fail("missing retired distinct-destination single-round MIDFUNC fmovs_rr");
requireText(midfuncSource.slice(fmovsMidStart, fmovsMidEnd), "raw_fmovs_rr(d, s);", "retired distinct-destination single-round MIDFUNC fmovs_rr");
if ((midfuncSource.match(/\bfmovs_rr\b/g) || []).length !== 2)
  fail("distinct-destination single-round MIDFUNC fmovs_rr gained a configured caller");
const fmovsRawStart = codegenSource.indexOf("LOWFUNC(NONE,NONE,2,raw_fmovs_rr,(FW d, FR s))");
const fmovsRawEnd = codegenSource.indexOf("LENDFUNC(NONE,NONE,2,raw_fmovs_rr,(FW d, FR s))", fmovsRawStart);
if (fmovsRawStart < 0 || fmovsRawEnd < 0) fail("missing retired distinct-destination single-round raw boundary raw_fmovs_rr");
const fmovsRawBody = codegenSource.slice(fmovsRawStart, fmovsRawEnd);
const fmovsNarrow = fmovsRawBody.indexOf("FCVT_sd(SCRATCH_F64_1, s);");
const fmovsWiden = fmovsRawBody.indexOf("FCVT_ds(d, SCRATCH_F64_1);");
if (fmovsNarrow < 0 || fmovsWiden <= fmovsNarrow)
  fail("retired distinct-destination single-round raw boundary conversion order changed");
if ((codegenSource.match(/\braw_fmovs_rr\b/g) || []).length !== 2)
  fail("distinct-destination single-round raw boundary raw_fmovs_rr gained a configured caller");
const fmovsFcvtSdSites = (codegenSource.match(/\bFCVT_sd\(/g) || []).length;
const fmovsFcvtDsSites = (codegenSource.match(/\bFCVT_ds\(/g) || []).length;
if (fmovsFcvtSdSites !== 7 || fmovsFcvtDsSites !== 6)
  fail(`distinct-destination single-round residual FCVT sites sd/ds=${fmovsFcvtSdSites}/${fmovsFcvtDsSites}, expected 7/6`);
console.log("METRIC structural_fpp_fmovs_unreachable_raw_boundaries=1");
console.log("METRIC structural_fpp_fmovs_reachable_fcvt_emitters=2");
const fsccMidStart = midfuncSource.indexOf("MIDFUNC(2,fp_fscc_ri,(RW4 d, int cc))");
const fsccMidEnd = midfuncSource.indexOf("MENDFUNC(2,fp_fscc_ri,(RW4 d, int cc))", fsccMidStart);
if (fsccMidStart < 0 || fsccMidEnd < 0) fail("missing retired legacy FScc MIDFUNC fp_fscc_ri");
requireText(midfuncSource.slice(fsccMidStart, fsccMidEnd), "raw_fp_fscc_ri(d, cc);", "retired legacy FScc MIDFUNC fp_fscc_ri");
if ((midfuncSource.match(/\bfp_fscc_ri\b/g) || []).length !== 2)
  fail("legacy FScc MIDFUNC fp_fscc_ri gained a configured caller");
const fsccRawStart = codegenSource.indexOf("LOWFUNC(NONE,NONE,2,raw_fp_fscc_ri,(RW4 d, int cc))");
const fsccRawEnd = codegenSource.indexOf("LENDFUNC(NONE,NONE,2,raw_fp_fscc_ri,(RW4 d, int cc))", fsccRawStart);
if (fsccRawStart < 0 || fsccRawEnd < 0) fail("missing retired legacy FScc raw boundary raw_fp_fscc_ri");
const fsccRawBody = codegenSource.slice(fsccRawStart, fsccRawEnd);
for (const contract of [
  "switch (cc)", "case NATIVE_CC_F_NEVER:", "case NATIVE_CC_NE:", "case NATIVE_CC_EQ:",
  "case NATIVE_CC_F_OGT:", "case NATIVE_CC_F_OGE:", "case NATIVE_CC_F_OLT:", "case NATIVE_CC_F_OLE:",
  "case NATIVE_CC_F_OGL:", "case NATIVE_CC_F_OR:", "case NATIVE_CC_F_UN:", "case NATIVE_CC_F_UEQ:",
  "case NATIVE_CC_F_UGT:", "case NATIVE_CC_F_UGE:", "case NATIVE_CC_F_ULT:", "case NATIVE_CC_F_ULE:",
]) requireText(fsccRawBody, contract, "retired legacy FScc raw condition table");
const fsccRawCounts = [
  ["case NATIVE_CC_", 15], ["CLEAR_LOW8_xx(", 11], ["SET_LOW8_xx(", 10],
  ["CSETM_wc(", 4], ["BFXIL_xxii(", 4], ["BVS_i(", 10], ["B_i(", 10],
] as const;
for (const [token, expected] of fsccRawCounts) {
  const count = fsccRawBody.split(token).length - 1;
  if (count !== expected) fail(`retired legacy FScc raw ${token} count=${count}, expected=${expected}`);
}
if ((codegenSource.match(/\braw_fp_fscc_ri\b/g) || []).length !== 2)
  fail("legacy FScc raw boundary raw_fp_fscc_ri gained a configured caller");
const liveFsccStart = fppCompilerSource.indexOf("void comp_fscc_opp(uae_u32 opcode, uae_u16 extra)");
const liveFsccEnd = fppCompilerSource.indexOf("void comp_ftrapcc_opp", liveFsccStart);
if (liveFsccStart < 0 || liveFsccEnd < 0) fail("configured FScc compiler route is incomplete");
const liveFsccBody = fppCompilerSource.slice(liveFsccStart, liveFsccEnd);
for (const contract of ["fflags_into_flags();", "switch (extra & 0x0f)", "cmov_l_rr(", "mov_b_rr(reg, S4);"])
  requireText(liveFsccBody, contract, "configured FScc compiler route");
for (const forbidden of ["fp_fscc_ri(", "raw_fp_fscc_ri("])
  if (liveFsccBody.includes(forbidden)) fail(`configured FScc route gained retired legacy ${forbidden}`);
const fsccRawEmitterSites = new Map<string, number>([["CLEAR_LOW8_xx", 11], ["SET_LOW8_xx", 10]]);
for (const [name, expected] of fsccRawEmitterSites) {
  const sites = (codegenSource.match(new RegExp(`\\b${name}\\(`, "g")) || []).length;
  if (sites !== expected) fail(`legacy FScc raw emitter ${name} codegen sites=${sites}, expected=${expected}`);
}
for (const name of ["jnf_CLR_b", "jff_CLR_b"]) {
  const start = midfunc2Source.indexOf(`MIDFUNC(1,${name},`);
  const end = midfunc2Source.indexOf(`MENDFUNC(1,${name},`, start);
  if (start < 0 || end < 0) fail(`missing unreachable CLR namesake ${name}`);
  const sites = (midfunc2Source.slice(start, end).match(/\bCLEAR_LOW8_xx\(/g) || []).length;
  if (sites !== 1) fail(`unreachable CLR namesake ${name} CLEAR_LOW8_xx sites=${sites}, expected=1`);
}
const fsccDeadLow8Corpus = `${codegenSource}\n${midfuncSource}\n${midfunc2Source}\n${compatSource}\n${generatedSource}`;
const fsccGlobalClearSites = (fsccDeadLow8Corpus.match(/\bCLEAR_LOW8_xx\(/g) || []).length;
const fsccGlobalSetSites = (fsccDeadLow8Corpus.match(/\bSET_LOW8_xx\(/g) || []).length;
if (fsccGlobalClearSites !== 13 || fsccGlobalSetSites !== 10)
  fail(`dead low-byte emitter global sites clear/set=${fsccGlobalClearSites}/${fsccGlobalSetSites}, expected 13/10`);
const fsccConfiguredNonRawText = `${midfuncSource}\n${midfunc2Source}\n${compatSource}\n${generatedSource}`;
for (const [name, minimum] of [["CSETM_wc", 5], ["BFXIL_xxii", 25]] as const) {
  const sites = (fsccConfiguredNonRawText.match(new RegExp(`\\b${name}\\(`, "g")) || []).length;
  if (sites < minimum) fail(`legacy FScc live shared emitter ${name} external sites=${sites}, expected at least ${minimum}`);
}
console.log("METRIC structural_fpp_legacy_fscc_unreachable_raw_boundaries=1");
console.log("METRIC structural_fpp_legacy_fscc_condition_cases=15");
console.log("METRIC structural_fpp_live_fscc_generator_unreviewed=1");
console.log("METRIC structural_fpp_legacy_fscc_live_shared_emitters_unreviewed=2");

const fmovecrStart = fppCompilerOperation.indexOf("if ((extra & 0xfc00) == 0x5c00)");
const fmovecrSelector = fppCompilerOperation.indexOf("switch (extra & 0x7f)", fmovecrStart);
const fmovecrGate = fppCompilerOperation.slice(fmovecrStart, fmovecrSelector);
for (const contract of [
  "The architectural constant ROM is extended precision", "FAIL(1);", "return;",
]) requireText(fmovecrGate, contract, "FPP FMOVECR exact service boundary");
if (fmovecrStart < 0 || fmovecrSelector < 0 || fmovecrStart >= fmovecrSelector)
  fail("FPP FMOVECR exact service boundary does not precede selector dispatch");
for (const contract of [
  '[0, "pi", "40 00 00 00 c9 0f da a2 21 68 c2 35"]',
  '[11, "log10_2"', '[15, "zero"', '[48, "ln_2"', '[49, "ln_10"',
  '[50, "ten_pow_0"', '[63, "ten_pow_4096", "75 25 00 00 c4 60 52 02 8a 20 97 9b"]',
  '"single_nearest"', '"single_zero"', '"single_minus"', '"single_plus"',
  '"double_nearest"', '"double_zero"', '"double_minus"', '"double_plus"',
  'name: `undefined_selector_${selector}_zero`',
  'name: "pi_fp7_max_destination"', 'name: "ten_pow_4096_fp7_max_destination"',
  'name: "undefined_127_fp7_max_destination"',
  'B2_TEST_MEMDUMP: "0x9ffe:16"', 'B2_TEST_REPLAY_FPCR: item.fpcr ?? "0"',
  'fpsr === item.fpsr', 'output.includes("JIT_FALLBACK op=f200 pc=00001000")',
  'output.includes("strict full-JIT: opcode fallback")', '!output.includes("Caught SIGSEGV")',
  'cow_clone', 'cow_release',
  'expectedService = process.env.CASE ? selectedService.length : 36',
  'expectedStrict = process.env.CASE ? selectedStrict.length : 3',
]) requireText(fppFmovecrFallbackMatrix, contract, "FPP FMOVECR serviced fallback matrix");
console.log("METRIC structural_fpp_fmovecr_defined_selectors=22");
console.log("METRIC structural_fpp_fmovecr_service_vectors=36");
console.log("METRIC structural_fpp_fmovecr_strict_rejections=3");
console.log("METRIC structural_fpp_fmovecr_native_retired=1");
const fmovLongImmStart = midfuncSource.indexOf("MIDFUNC(2,fmov_l_ri,(FW d, IM32 i))");
const fmovLongImmEnd = midfuncSource.indexOf("MENDFUNC(2,fmov_l_ri,(FW d, IM32 i))", fmovLongImmStart);
if (fmovLongImmStart < 0 || fmovLongImmEnd < 0) fail("missing retired fmov_l_ri intermediate MIDFUNC");
const fmovLongImmBody = midfuncSource.slice(fmovLongImmStart, fmovLongImmEnd);
for (const contract of ["case 10:", "fmov_d_ri_10(d);", "case 100:", "fmov_d_ri_100(d);"])
  requireText(fmovLongImmBody, contract, "retired fmov_l_ri constant dispatch");
if ((midfuncSource.match(/\bfmov_l_ri\b/g) || []).length !== 2)
  fail("fmov_l_ri gained a configured caller");
for (const [midName, rawName, rawContracts] of [
  ["fmov_d_ri_10", "raw_fmov_d_ri_10", ["FMOV_di(r, 0b00100100);"]],
  ["fmov_d_ri_100", "raw_fmov_d_ri_100", ["MOV_wi(REG_WORK1, 100);", "SCVTF_dw(r, REG_WORK1);"]],
] as const) {
  const midStart = midfuncSource.indexOf(`MIDFUNC(1,${midName},(FW r))`);
  const midEnd = midfuncSource.indexOf(`MENDFUNC(1,${midName},(FW r))`, midStart);
  if (midStart < 0 || midEnd < 0) fail(`missing retired constant MIDFUNC ${midName}`);
  requireText(midfuncSource.slice(midStart, midEnd), `${rawName}(r);`, `retired constant MIDFUNC ${midName}`);
  if ((midfuncSource.match(new RegExp(`\\b${midName}\\b`, "g")) || []).length !== 3)
    fail(`retired constant MIDFUNC ${midName} caller graph changed`);
  const rawStart = codegenSource.indexOf(`LOWFUNC(NONE,NONE,1,${rawName},(FW r))`);
  const rawEnd = codegenSource.indexOf(`LENDFUNC(NONE,NONE,1,${rawName},(FW r))`, rawStart);
  if (rawStart < 0 || rawEnd < 0) fail(`missing retired constant raw boundary ${rawName}`);
  const rawBody = codegenSource.slice(rawStart, rawEnd);
  let previous = -1;
  for (const contract of rawContracts) {
    requireText(rawBody, contract, `retired constant raw boundary ${rawName}`);
    const position = rawBody.indexOf(contract);
    if (position <= previous) fail(`retired constant raw boundary ${rawName} lower-body order changed`);
    previous = position;
  }
  if ((codegenSource.match(new RegExp(`\\b${rawName}\\b`, "g")) || []).length !== 2)
    fail(`constant raw boundary ${rawName} gained a configured caller`);
}
const constantFmovDiSites = (codegenSource.match(/\bFMOV_di\(/g) || []).length;
const constantScvtfSites = (codegenSource.match(/\bSCVTF_dw\(/g) || []).length;
if (constantFmovDiSites !== 5 || constantScvtfSites !== 6)
  fail(`constant residual emitter sites FMOV_di/SCVTF_dw=${constantFmovDiSites}/${constantScvtfSites}, expected 5/6`);
console.log("METRIC structural_fpp_fmovecr_unreachable_constant_raw_boundaries=2");
console.log("METRIC structural_fpp_fmovecr_reachable_constant_emitters=2");

const fabsStart = fppCompilerOperation.indexOf("case 0x18:");
const fabsEnd = fppCompilerOperation.indexOf("case 0x19:", fabsStart);
const fnegStart = fppCompilerOperation.indexOf("case 0x1a:", fabsEnd);
const fnegEnd = fppCompilerOperation.indexOf("case 0x1c:", fnegStart);
if (fabsStart < 0 || fabsEnd < 0 || fnegStart < 0 || fnegEnd < 0)
  fail("FPP sign-family service boundaries are incomplete");
const fabsBlock = fppCompilerOperation.slice(fabsStart, fabsEnd);
const fnegBlock = fppCompilerOperation.slice(fnegStart, fnegEnd);
for (const contract of [
  "case 0x18:", "case 0x58:", "case 0x5c:", "binary64 shadow",
  "forced precision", "FAIL(1);", "return;",
]) requireText(fabsBlock, contract, "FPP FABS family exact service boundary");
for (const contract of [
  "case 0x1a:", "case 0x5a:", "case 0x5e:", "binary64 shadow",
  "forced precision", "FAIL(1);", "return;",
]) requireText(fnegBlock, contract, "FPP FNEG family exact service boundary");
for (const [name, block] of [["fabs_rr", fabsBlock], ["fneg_rr", fnegBlock]] as const) {
  const gate = block.indexOf("#if defined(CPU_aarch64) || defined(CPU_AARCH64)");
  const service = block.indexOf("FAIL(1);", gate);
  const ret = block.indexOf("return;", service);
  const operand = block.indexOf("get_fp_value");
  const nativeCall = block.indexOf(`${name}(`);
  if (gate < 0 || service < gate || ret < service || operand < ret || nativeCall < operand)
    fail(`FPP sign-family service gate must retire ${name} before native operand acquisition`);
}
const signNativeContracts = [
  ["fabs_rr", "raw_fabs_rr", "FABS_dd"],
  ["fneg_rr", "raw_fneg_rr", "FNEG_dd"],
] as const;
for (const [midName, rawName, emitterName] of signNativeContracts) {
  const configuredRootSpellings = (fppCompilerSource.match(new RegExp(`\\b${midName}\\(`, "g")) || []).length;
  if (configuredRootSpellings !== 1)
    fail(`retired sign MIDFUNC ${midName} configured-root spellings=${configuredRootSpellings} expected=1`);
  const midfuncCallerSpellings = (midfuncSource.match(new RegExp(`\\b${midName}\\(`, "g")) || []).length;
  if (midfuncCallerSpellings !== 0)
    fail(`retired sign MIDFUNC ${midName} gained ${midfuncCallerSpellings} MIDFUNC caller spellings`);
  const midStart = midfuncSource.indexOf(`MIDFUNC(2,${midName},(FW d, FR s))`);
  const midEnd = midfuncSource.indexOf(`MENDFUNC(2,${midName}`, midStart);
  if (midStart < 0 || midEnd < 0) fail(`missing retired sign MIDFUNC ${midName}`);
  const midBody = midfuncSource.slice(midStart, midEnd);
  requireText(midBody, `${rawName}(d, s);`, `retired sign MIDFUNC ${midName}`);
  const rawStart = codegenSource.indexOf(`LOWFUNC(NONE,NONE,2,${rawName},(FW d, FR s))`);
  const rawEnd = codegenSource.indexOf(`LENDFUNC(NONE,NONE,2,${rawName}`, rawStart);
  if (rawStart < 0 || rawEnd < 0) fail(`missing retired sign raw boundary ${rawName}`);
  requireText(codegenSource.slice(rawStart, rawEnd), `${emitterName}(d, s);`, `retired sign raw boundary ${rawName}`);
  requireText(codegenHeaderSource, `#define ${emitterName}(Dd,Dn)`, `retired sign emitter ${emitterName}`);
}
console.log("METRIC structural_fpp_sign_unreachable_midfuncs=2");
console.log("METRIC structural_fpp_sign_unreachable_raw_boundaries=2");
console.log("METRIC structural_fpp_sign_unreachable_emitters=2");
const fpuSyncToShadow = functionBody(
  compatSource,
  'extern "C" void jit_fpu_sync_to_shadow(void)',
  'extern "C" void jit_fpu_sync_from_shadow(void)',
  "FPP MPFR-to-shadow ownership import",
);
const fpuSyncFromShadow = functionBody(
  compatSource,
  'extern "C" void jit_fpu_sync_from_shadow(void)',
  '#endif /* USE_JIT_FPU */',
  "FPP dirty-shadow publication",
);
for (const contract of [
  "regs.jit_fp_dirty_mask = 0", "mpfr_get_d", "fpu_get_fpsr() & FPSR_CCB",
]) requireText(fpuSyncToShadow, contract, "FPP MPFR-to-shadow ownership import");
for (const contract of [
  "const uae_u32 dirty = regs.jit_fp_dirty_mask", "if ((dirty & (1u << i)) == 0)",
  "if (dirty & (1u << FP_RESULT))", "regs.jit_fp_dirty_mask = 0",
]) requireText(fpuSyncFromShadow, contract, "FPP dirty-shadow publication");
const fMarkDirty = functionBody(
  allocatorSource,
  "static inline void f_mark_runtime_dirty(int r)",
  "static inline int f_writereg(int r)",
  "FPP runtime dirty ownership",
);
for (const contract of [
  "r >= 0 && r <= FP_RESULT", "1u << r", "ORR_www", "regs.jit_fp_dirty_mask",
]) requireText(fMarkDirty, contract, "FPP runtime dirty ownership");
const mixedFallbackStart = allocatorSource.indexOf("/* Every raw C call below follows AAPCS64");
const mixedFallbackEnd = allocatorSource.indexOf("make_flags_live_internal();", mixedFallbackStart);
if (mixedFallbackStart < 0 || mixedFallbackEnd < 0)
  fail("FPP mixed native/interpreter ownership barrier is missing");
const mixedFallback = allocatorSource.slice(mixedFallbackStart, mixedFallbackEnd);
for (const contract of [
  "prepare_for_call_1();", "prepare_for_call_2();",
  "compemu_raw_call_preserve_nzcv((uintptr)jit_fpu_sync_from_shadow)",
  "compemu_raw_call((uintptr)cputbl[cft_map(opcode)])",
  "compemu_raw_call_preserve_nzcv((uintptr)jit_fpu_sync_to_shadow)",
  "live.flags_in_flags = TRASH", "live.flags_on_stack = VALID",
]) requireText(mixedFallback, contract, "FPP mixed native/interpreter ownership barrier");
requireBefore(mixedFallback, "prepare_for_call_2();", "jit_fpu_sync_from_shadow", "fallback allocator barrier before C");
requireBefore(mixedFallback, "jit_fpu_sync_from_shadow", "compemu_raw_mov_l_ri(REG_PAR1", "fallback arguments after FP publication");
requireBefore(mixedFallback, "cputbl[cft_map(opcode)]", "jit_fpu_sync_to_shadow", "fallback interpreter before MPFR import");
for (const contract of [
  'name: "fabs_wide_negative"', 'name: "fneg_negative_zero"',
  'name: "fabs_negative_infinity"', 'name: "fneg_positive_qnan"',
  'name: `fabs_single_${suffix}`', 'name: `fneg_double_${suffix}`',
  'name: `fsabs_${suffix}`', 'name: `fsneg_${suffix}`',
  'name: "fdabs_negative_half_plus"', 'name: "fdneg_positive_half_minus"',
  'name: "fsabs_maximum_extended_overflow"', 'name: "fdneg_maximum_extended_overflow"',
  'name: "fneg_fp7_self_wide_max_fields"', 'name: "fsabs_fp7_self_max_fields"',
  'name: "fneg_accrued_preserve"', 'B2_TEST_REPLAY_FPSR: item.replayFpsr ?? "0"',
  'fallbackCount === 3', 'sr === "271f"', 'fpsr === item.fpsr',
  'output.includes("strict full-JIT: opcode fallback pc=00001008 op=f200")',
  '!output.includes("Caught SIGSEGV")', 'cow_clone', 'cow_release',
  'expectedService = process.env.CASE ? selectedService.length : 31',
  'expectedStrict = process.env.CASE ? selectedStrict.length : 6',
]) requireText(fppSignFallbackMatrix, contract, "FPP sign-family serviced fallback matrix");
console.log("METRIC structural_fpp_sign_service_vectors=31");
console.log("METRIC structural_fpp_sign_strict_rejections=6");
console.log("METRIC structural_fpp_sign_native_retired=1");

const fsqrtStart = fppCompilerOperation.indexOf("case 0x04:");
const fsqrtEnd = fppCompilerOperation.indexOf("case 0x06:", fsqrtStart);
if (fsqrtStart < 0 || fsqrtEnd < 0)
  fail("FPP square-root family service boundary is incomplete");
const fsqrtBlock = fppCompilerOperation.slice(fsqrtStart, fsqrtEnd);
for (const contract of [
  "case 0x04:", "case 0x41:", "case 0x45:", "binary64 shadow",
  "forced single/double rounding", "FAIL(1);", "return;",
]) requireText(fsqrtBlock, contract, "FPP square-root family exact service boundary");
const fsqrtGate = fsqrtBlock.indexOf("#if defined(CPU_aarch64) || defined(CPU_AARCH64)");
const fsqrtService = fsqrtBlock.indexOf("FAIL(1);", fsqrtGate);
const fsqrtReturn = fsqrtBlock.indexOf("return;", fsqrtService);
const fsqrtOperand = fsqrtBlock.indexOf("get_fp_value");
const fsqrtNativeCall = fsqrtBlock.indexOf("fsqrt_rr(");
if (fsqrtGate < 0 || fsqrtService < fsqrtGate || fsqrtReturn < fsqrtService ||
    fsqrtOperand < fsqrtReturn || fsqrtNativeCall < fsqrtOperand)
  fail("FPP square-root guarded service exit does not retire fsqrt_rr before operand acquisition");
const fsqrtRootSpellings = (fppCompilerSource.match(/\bfsqrt_rr\(/g) || []).length;
if (fsqrtRootSpellings !== 1)
  fail(`retired square-root MIDFUNC fsqrt_rr configured-root spellings=${fsqrtRootSpellings} expected=1`);
const fsqrtMidfuncCallers = (midfuncSource.match(/\bfsqrt_rr\(/g) || []).length;
if (fsqrtMidfuncCallers !== 0)
  fail(`retired square-root MIDFUNC fsqrt_rr gained ${fsqrtMidfuncCallers} MIDFUNC caller spellings`);
const fsqrtMidStart = midfuncSource.indexOf("MIDFUNC(2,fsqrt_rr,(FW d, FR s))");
const fsqrtMidEnd = midfuncSource.indexOf("MENDFUNC(2,fsqrt_rr", fsqrtMidStart);
if (fsqrtMidStart < 0 || fsqrtMidEnd < 0) fail("missing retired square-root MIDFUNC fsqrt_rr");
const fsqrtMidBody = midfuncSource.slice(fsqrtMidStart, fsqrtMidEnd);
for (const contract of ["s = f_readreg(s);", "d = f_writereg(d);", "raw_fsqrt_rr(d, s);"])
  requireText(fsqrtMidBody, contract, "retired square-root MIDFUNC fsqrt_rr");
const fsqrtRawStart = codegenSource.indexOf("LOWFUNC(NONE,NONE,2,raw_fsqrt_rr,(FW d, FR s))");
const fsqrtRawEnd = codegenSource.indexOf("LENDFUNC(NONE,NONE,2,raw_fsqrt_rr", fsqrtRawStart);
if (fsqrtRawStart < 0 || fsqrtRawEnd < 0) fail("missing retired square-root raw boundary raw_fsqrt_rr");
requireText(codegenSource.slice(fsqrtRawStart, fsqrtRawEnd), "FSQRT_dd(d, s);", "retired square-root raw boundary raw_fsqrt_rr");
requireText(codegenHeaderSource, "#define FSQRT_dd(Dd,Dn)", "retired square-root emitter FSQRT_dd");
for (const contract of [
  'name: "fsqrt_positive_zero"', 'name: "fsqrt_negative_zero"',
  'name: "fsqrt_negative_invalid"', 'name: "fsqrt_signalling_nan_quiet"',
  'name: "fsqrt_maximum_extended"', 'name: "fsqrt_minimum_normal_extended"',
  'name: "fsqrt_wide_low_bit"', 'name: `fsqrt_extended_${suffix}`',
  'name: `fsqrt_single_${suffix}`', 'name: `fsqrt_double_${suffix}`',
  'name: `fssqrt_${suffix}`', 'name: `fdsqrt_${suffix}`',
  '["0", "nearest", x.sqrtTwo]', '["30", "plus", x.sqrtTwoUp]',
  '["40", "nearest", x.positiveOne]', '["70", "plus", x.positiveSingleNext]',
  '["80", "nearest", x.positiveOne]', '["b0", "plus", x.positiveDoubleNext]',
  'name: "fsqrt_fp7_self_max_fields"', 'name: "fsqrt_accrued_preserve"',
  'name: "fssqrt_extended_source_range"', 'name: "fdsqrt_extended_source_range"',
  'fssqrtExtendedRangeSource: "40 fd 00 00 80 00 00 00 00 00 00 00"',
  'fssqrtExtendedRangeResult: "40 7e 00 00 80 00 00 00 00 00 00 00"',
  'fdsqrtExtendedRangeSource: "47 fd 00 00 80 00 00 00 00 00 00 00"',
  'fdsqrtExtendedRangeResult: "43 fe 00 00 80 00 00 00 00 00 00 00"',
  'name: `${prefix}_negative_zero`', 'name: `${prefix}_negative_invalid`',
  'name: `${prefix}_infinity`', 'name: `${prefix}_quiet_nan`',
  'name: `${prefix}_signalling_nan`', 'name: `${prefix}_maximum_overflow`',
  'name: `${prefix}_minimum_underflow`', 'name: `${prefix}_opposite_precision_override`',
  'name: `${prefix}_accrued_preserve`',
  '["fssqrt", "0441", "80", x.sqrtTwoSingle]',
  '["fdsqrt", "0445", "40", x.sqrtTwoDouble]',
  'input: x.singleHalfSquare, output: prefix === "fssqrt" ? x.positiveOne : x.sqrtSingleHalfExtended',
  'fpsr: prefix === "fssqrt" ? "00000008" : "00000000"',
  'fpsr === item.fpsr', "fallbackCount === 3", 'sr === "271f"',
  'output.includes("strict full-JIT: opcode fallback pc=00001008 op=f200")',
  '!output.includes("NATEXEC pc=00001008")', '!output.includes("JIT_STRICT_SUMMARY ")',
  '!output.includes("Caught SIGSEGV")',
  'name: "fsqrt_fp7_self_strict"', 'name: "fssqrt_fp7_self_strict"',
  'name: "fdsqrt_fp7_self_strict"',
  "expectedService = process.env.CASE ? selectedService.length : 54",
  "expectedStrict = process.env.CASE ? selectedStrict.length : 3",
]) requireText(fppSqrtFallbackMatrix, contract, "FPP square-root serviced fallback matrix");
console.log("METRIC structural_fpp_sqrt_service_vectors=54");
console.log("METRIC structural_fpp_sqrt_strict_rejections=3");
console.log("METRIC structural_fpp_sqrt_native_retired=1");
console.log("METRIC structural_fpp_sqrt_unreachable_midfuncs=1");
console.log("METRIC structural_fpp_sqrt_unreachable_raw_boundaries=1");
console.log("METRIC structural_fpp_sqrt_unreachable_emitters=1");
const forcedFppStart = fpuMpfrSource.indexOf("else if (extra & 0x40)");
const forcedFppEnd = fpuMpfrSource.indexOf("else if ((extra & 0x30) == 0x30)", forcedFppStart);
if (forcedFppStart < 0 || forcedFppEnd < 0)
  fail("MPFR forced-precision operation branch is incomplete");
const forcedFppBlock = fpuMpfrSource.slice(forcedFppStart, forcedFppEnd);
const forcedResult = forcedFppBlock.indexOf("MPFR_DECL_INIT (value2, prec);");
const forcedSource = forcedFppBlock.indexOf("mpfr_set_prec (value.f, EXTENDED_PREC);");
const forcedSourceFormat = forcedFppBlock.indexOf("set_format (EXTENDED_PREC);", forcedSource);
const forcedAcquire = forcedFppBlock.indexOf("get_fp_value (opcode, extra, value)");
const forcedFailure = forcedFppBlock.indexOf("if (!get_fp_value (opcode, extra, value))", forcedSourceFormat);
const forcedFailureEnd = forcedFppBlock.indexOf("set_format (prec);", forcedFailure);
const forcedResultFormat = forcedFppBlock.indexOf("set_format (prec);", forcedFailureEnd + 1);
const forcedOperation = forcedFppBlock.indexOf("switch (extra & 0x3f)", forcedResultFormat);
if (forcedResult < 0 || forcedSource < 0 || forcedSourceFormat < 0 ||
    forcedAcquire < 0 || forcedFailure < 0 || forcedFailureEnd < 0 ||
    forcedResultFormat < 0 || forcedOperation < 0 ||
    forcedResult >= forcedSource || forcedSource >= forcedSourceFormat ||
    forcedSourceFormat >= forcedAcquire || forcedAcquire >= forcedFailureEnd ||
    forcedFailureEnd >= forcedResultFormat || forcedResultFormat >= forcedOperation)
  fail("MPFR forced operations do not load under extended format before 24/53-bit result work");
console.log("METRIC structural_fpp_forced_source_extended=1");

const fintStart = fppCompilerOperation.indexOf("case 0x01:");
const fintEnd = fppCompilerOperation.indexOf("case 0x02:", fintStart);
const fintrzStart = fppCompilerOperation.indexOf("case 0x03:", fintEnd);
const fintrzEnd = fppCompilerOperation.indexOf("case 0x04:", fintrzStart);
if (fintStart < 0 || fintEnd < 0 || fintrzStart < 0 || fintrzEnd < 0)
  fail("FPP integral-rounding service boundaries are incomplete");
const fintBlock = fppCompilerOperation.slice(fintStart, fintEnd);
const fintrzBlock = fppCompilerOperation.slice(fintrzStart, fintrzEnd);
for (const contract of ["case 0x01:", "FAIL(1);", "return;"])
  requireText(fintBlock, contract, "FPP FINT exact service boundary");
for (const contract of ["case 0x03:", "#ifdef USE_X86_FPUCW", "FAIL(1);", "return;"])
  requireText(fintrzBlock, contract, "FPP FINTRZ configured service boundary");
const fintrzLegacyCall = fintrzBlock.indexOf("frndint_rr(reg, src);");
const fintrzInactiveGuard = fintrzBlock.indexOf("#ifdef USE_X86_FPUCW");
const fintrzConfiguredService = fintrzBlock.indexOf("FAIL(1);", fintrzLegacyCall);
if (fintrzInactiveGuard < 0 || fintrzLegacyCall < fintrzInactiveGuard || fintrzConfiguredService < fintrzLegacyCall)
  fail("FPP FINTRZ legacy frndint_rr call is no longer confined before configured service");
for (const [midName, rawName, signature, rawCall, emitter] of [
  ["frndint_rr", "raw_frndint_rr", "(FW d, FR s)", "raw_frndint_rr(d, s);", "FRINTI_dd(d, s);"],
  ["frndintz_rr", "raw_frndintz_rr", "(FW d, FR s)", "raw_frndintz_rr(d, s);", "FRINTZ_dd(d, s);"],
] as const) {
  const midStart = midfuncSource.indexOf(`MIDFUNC(2,${midName},${signature})`);
  const midEnd = midfuncSource.indexOf(`MENDFUNC(2,${midName}`, midStart);
  if (midStart < 0 || midEnd < 0) fail(`missing retired integral MIDFUNC ${midName}`);
  requireText(midfuncSource.slice(midStart, midEnd), rawCall, `retired integral MIDFUNC ${midName}`);
  const rawStart = codegenSource.indexOf(`LOWFUNC(NONE,NONE,2,${rawName},${signature})`);
  const rawEnd = codegenSource.indexOf(`LENDFUNC(NONE,NONE,2,${rawName}`, rawStart);
  if (rawStart < 0 || rawEnd < 0) fail(`missing retired integral raw boundary ${rawName}`);
  requireText(codegenSource.slice(rawStart, rawEnd), emitter, `retired integral raw boundary ${rawName}`);
}
const frintiSites = (codegenSource.match(/\bFRINTI_dd\(/g) || []).length;
const frintzSites = (codegenSource.match(/\bFRINTZ_dd\(/g) || []).length;
if (frintiSites !== 2 || frintzSites !== 2)
  fail(`integral emitter sites FRINTI/FRINTZ=${frintiSites}/${frintzSites}, expected 2/2`);
const fgetexpStart = fppCompilerOperation.indexOf("case 0x1e:", fintrzEnd);
const fgetexpEnd = fppCompilerOperation.indexOf("case 0x1f:", fgetexpStart);
const fgetmanEnd = fppCompilerOperation.indexOf("case 0x20:", fgetexpEnd);
if (fgetexpStart < 0 || fgetexpEnd < 0 || fgetmanEnd < 0)
  fail("FPP decomposition service boundaries are incomplete");
const fgetexpBlock = fppCompilerOperation.slice(fgetexpStart, fgetexpEnd);
const fgetmanBlock = fppCompilerOperation.slice(fgetexpEnd, fgetmanEnd);
for (const contract of ["case 0x1e:", "jit_disable.fgetexp", "FAIL(1);", "return;"])
  requireText(fgetexpBlock, contract, "FPP FGETEXP configured service boundary");
for (const contract of ["case 0x1f:", "jit_disable.fgetman", "FAIL(1);", "return;"])
  requireText(fgetmanBlock, contract, "FPP FGETMAN configured service boundary");
const ordinaryFppStart = fpuMpfrSource.indexOf("else\n    {", forcedFppEnd);
const ordinaryFppEnd = fpuMpfrSource.indexOf("update_exceptions ();", ordinaryFppStart);
if (ordinaryFppStart < 0 || ordinaryFppEnd < 0)
  fail("MPFR ordinary FPP operation branch is incomplete");
const ordinaryFppBlock = fpuMpfrSource.slice(ordinaryFppStart, ordinaryFppEnd);
for (const contract of [
  "int operation = extra & 0x3f;",
  "bool extended_source = ordinary_move || operation == 1 || operation == 3",
  "|| operation == 30 || operation == 31 || operation == 33\n\t|| operation == 37 || operation == 38 || single_extended_result;",
  "mpfr_set_prec (value.f, EXTENDED_PREC);", "set_format (EXTENDED_PREC);",
  "if (!get_fp_value (opcode, extra, value))", "set_format (prec);",
  "case 1: // FINT", "mpfr_rint (value.f, value.f, rnd)",
  "case 3: // FINTRZ", "mpfr_rint (value.f, value.f, MPFR_RNDZ)",
  "case 30: // FGETEXP", "do_getexp (value, rnd)",
  "case 31: // FGETMAN", "do_getman (value)",
  "MPFR_DECL_INIT (rounded, prec);", "mpfr_set (rounded, value.f, rnd)",
  "mpfr_check_range (rounded, rounded_t, rnd)",
]) requireText(ordinaryFppBlock, contract, "MPFR unary decomposition extended-source/result contract");
const integralSource = ordinaryFppBlock.indexOf("mpfr_set_prec (value.f, EXTENDED_PREC);");
const integralFormat = ordinaryFppBlock.indexOf("set_format (EXTENDED_PREC);", integralSource);
const integralAcquire = ordinaryFppBlock.indexOf("get_fp_value (opcode, extra, value)", integralFormat);
const integralFailureRestore = ordinaryFppBlock.indexOf("set_format (prec);", integralAcquire);
const integralSwitch = ordinaryFppBlock.indexOf("switch (extra & 0x3f)", integralFailureRestore);
const integralSuccessRestore = ordinaryFppBlock.indexOf("set_format (prec);", integralSwitch);
const integralResult = ordinaryFppBlock.indexOf("MPFR_DECL_INIT (rounded, prec);", integralSuccessRestore);
if (integralSource < 0 || integralFormat < 0 || integralAcquire < 0 ||
    integralFailureRestore < 0 || integralSwitch < 0 || integralSuccessRestore < 0 ||
    integralResult < 0 || integralSource >= integralFormat || integralFormat >= integralAcquire ||
    integralAcquire >= integralFailureRestore || integralFailureRestore >= integralSwitch ||
    integralSwitch >= integralSuccessRestore || integralSuccessRestore >= integralResult)
  fail("MPFR unary decomposition does not load extended then restore FPCR result format");
const setFromExtended = functionBody(
  fpuMpfrSource, "set_from_extended (fpu_register &value", "#define from_bcd",
  "MPFR extended input conversion",
);
for (const contract of [
  "if (e == 0)", "e++;", "e -= EXTENDED_BIAS;",
  "e - (EXTENDED_PREC - 1)",
]) requireText(setFromExtended, contract, "MPFR extended-denormal exponent conversion");
const getExpBody = functionBody(fpuMpfrSource, "do_getexp (fpu_register &value", "static int\ndo_getman", "MPFR FGETEXP");
const getManBody = functionBody(fpuMpfrSource, "do_getman (fpu_register &value)", "static int\ndo_scale", "MPFR FGETMAN");
for (const contract of ["int sign = mpfr_signbit (value.f);", "mpfr_set_nan (value.f);", "mpfr_clear_nanflag ();", "mpfr_setsign (value.f, value.f, sign", "value.nan_sign = sign;", "FPSR_EXCEPTION_OPERR"])
  requireText(getExpBody, contract, "MPFR FGETEXP infinity status/sign metadata");
for (const contract of ["int sign = mpfr_signbit (value.f);", "mpfr_set_nan (value.f);", "mpfr_clear_nanflag ();", "mpfr_setsign (value.f, value.f, sign", "value.nan_sign = sign;", "FPSR_EXCEPTION_OPERR"])
  requireText(getManBody, contract, "MPFR FGETMAN infinity status/sign metadata");
for (const contract of [
  'name: `fint_${name}_${suffix}`', 'name: `fintrz_${name}_${suffix}`',
  'name: "fint_positive_zero"', 'name: "fintrz_negative_zero"',
  'name: "fint_positive_infinity"', 'name: "fintrz_negative_infinity"',
  'name: "fint_quiet_nan_payload"', 'name: "fintrz_signalling_nan_quiet"',
  'name: "fint_half_plus_ulp_fpcr_single"', 'name: "fint_half_plus_ulp_fpcr_double"',
  'name: "fintrz_below_one_fpcr_single_plus"', 'name: "fintrz_below_one_fpcr_double_plus"',
  'name: "fint_huge_integral_fpcr_single_rounds"', 'name: "fintrz_huge_integral_fpcr_single_rounds"',
  'name: "fint_fp7_self_alias"', 'name: "fintrz_fp7_self_alias"',
  'name: "fint_accrued_preserve"', 'name: "fintrz_accrued_preserve"',
  'fallbackCount === (item.registerAlias ? 3 : 2)', 'fpsr === item.fpsr', 'sr === "271f"',
  'output.includes("strict full-JIT: opcode fallback pc=00001000 op=f239")',
  '!output.includes("NATEXEC pc=00001000")', '!output.includes("Caught SIGSEGV")',
  "expectedService = process.env.CASE ? selectedService.length : 55",
  "expectedStrict = process.env.CASE ? selectedStrict.length : 2",
]) requireText(fppIntegralRoundingFallbackMatrix, contract, "FPP integral-rounding serviced fallback matrix");
console.log("METRIC structural_fpp_integral_rounding_service_vectors=55");
console.log("METRIC structural_fpp_integral_rounding_strict_rejections=2");
console.log("METRIC structural_fpp_integral_rounding_extended_source=1");
console.log("METRIC structural_fpp_integral_rounding_unreachable_raw_boundaries=2");
console.log("METRIC structural_fpp_integral_rounding_reachable_emitters=2");
for (const contract of [
  'name: "fgetexp_positive_zero"', 'name: "fgetexp_negative_zero"',
  'name: "fgetexp_minimum_normal"', 'name: "fgetexp_maximum_finite"',
  'name: "fgetexp_minimum_subnormal"', 'name: "fgetexp_positive_infinity_operr"',
  'name: "fgetexp_negative_infinity_operr"', 'name: "fgetexp_negative_infinity_fneg_metadata"',
  'name: "fgetexp_quiet_nan_payload"',
  'name: "fgetexp_signalling_nan_quiet"', 'name: "fgetexp_fp7_self_alias"',
  'name: "fgetexp_fpcr_single_plus_independent"', 'name: "fgetexp_accrued_preserve"',
  'name: "fgetman_positive_zero"', 'name: "fgetman_negative_zero"',
  'name: "fgetman_minimum_normal"', 'name: "fgetman_maximum_finite"',
  'name: "fgetman_minimum_subnormal"', 'name: "fgetman_positive_infinity_operr"',
  'name: "fgetman_negative_infinity_operr"', 'name: "fgetman_negative_infinity_fneg_metadata"',
  'name: "fgetman_quiet_nan_payload"',
  'name: "fgetman_signalling_nan_quiet"', 'name: "fgetman_fp7_self_alias"',
  'name: "fgetman_fpcr_single_rounds"', 'name: "fgetman_fpcr_double_rounds"',
  'name: "fgetman_accrued_preserve"', 'name: "fgetexp_fp7_strict"',
  'name: "fgetman_fp7_strict"', 'F200 A800', 'F200 1F9A',
  'd0 === operationFpsr', 'item.negateSuccessor ? 1 : 0',
  'output.includes("strict full-JIT: opcode fallback pc=00001000 op=f239")',
  '!output.includes("NATEXEC pc=00001000")', '!output.includes("Caught SIGSEGV")',
  "expectedService = process.env.CASE ? selectedService.length : 38",
  "expectedStrict = process.env.CASE ? selectedStrict.length : 2",
]) requireText(fppDecompositionFallbackMatrix, contract, "FPP decomposition serviced fallback matrix");
console.log("METRIC structural_fpp_decomposition_service_vectors=38");
console.log("METRIC structural_fpp_decomposition_strict_rejections=2");
console.log("METRIC structural_fpp_decomposition_extended_denormal=1");
console.log("METRIC structural_fpp_decomposition_operation_fpsr=1");

const servicedMonadicCases = [
  ["case 0x02:", "jit_disable.fsinh", "FSINH"],
  ["case 0x06:", "jit_disable.flognp1", "FLOGNP1"],
  ["case 0x08:", "jit_disable.fetoxm1", "FETOXM1"],
  ["case 0x09:", "jit_disable.ftanh", "FTANH"],
] as const;
for (const [label, disable, name] of servicedMonadicCases) {
  const start = fppCompilerOperation.indexOf(label);
  const next = fppCompilerOperation.indexOf("case 0x", start + label.length);
  if (start < 0 || next < 0) fail(`FPP ${name} service boundary is incomplete`);
  const block = fppCompilerOperation.slice(start, next);
  for (const contract of [label, disable, "FAIL(1);", "return;"])
    requireText(block, contract, `FPP ${name} configured service boundary`);
}
for (const contract of [
  "bool direct_result = operation == 2 || operation == 6",
  "|| operation == 8 || operation == 9 || operation == 10",
  "|| operation == 12 || operation == 13 || operation == 14",
  "|| operation == 15 || operation == 16 || operation == 17",
  "|| operation == 18 || operation == 20 || operation == 21",
  "|| operation == 22 || operation == 25 || operation == 28",
  "|| operation == 29 || operation == 32 || operation == 34\n\t|| operation == 35 || operation == 40;",
  "|| direct_result || operation == 30 || operation == 31 || operation == 33\n\t|| operation == 37 || operation == 38 || single_extended_result;",
  "MPFR_DECL_INIT (direct, prec);",
  "case 2: // FSINH", "mpfr_sinh (direct, value.f, rnd)",
  "case 6: // FLOGNP1", "mpfr_log1p (direct, value.f, rnd)",
  "case 8: // FETOXM1", "mpfr_expm1 (direct, value.f, rnd)",
  "case 9: // FTANH", "mpfr_tanh (direct, value.f, rnd)",
  "if (mpfr_nan_p (direct))",
  "mpfr_setsign (direct, direct, nan_sign, MPFR_RNDN);",
  "mpfr_check_range (direct, t, rnd)",
  "set_fp_register (reg, direct, nan_bits, nan_sign",
]) requireText(ordinaryFppBlock, contract, "MPFR serviced monadic extended-source/direct-result contract");
for (const contract of [
  'name: `${item.name}_extended_source_single_${suffix}`',
  'name: `${item.name}_extended_source_double_nearest`',
  'name: `${name}_positive_zero`', 'name: `${name}_negative_zero`',
  'name: "fsinh_positive_infinity"', 'name: "fsinh_negative_infinity"',
  'name: "flognp1_negative_one_dz"', 'name: "flognp1_less_than_negative_one_operr"',
  'name: "fetoxm1_negative_infinity"', 'name: "ftanh_positive_infinity"',
  'name: "fsinh_negative_qnan_payload"', 'name: "flognp1_signalling_nan_quiet"',
  'name: "fetoxm1_quiet_nan_payload"', 'name: "ftanh_signalling_nan_quiet"',
  'name: "fsinh_extended_min_single_underflow"',
  'name: "flognp1_extended_min_single_underflow"',
  'name: "fetoxm1_extended_min_single_underflow"',
  'name: "ftanh_extended_min_single_underflow"',
  'name: "fsinh_fp7_self_alias"', 'name: "ftanh_fp7_self_alias"',
  'name: "fetoxm1_accrued_preserve"',
  'd0 === operationFpsr', 'fallbackCount === (item.registerAlias ? 4 : 3)',
  'output.includes("strict full-JIT: opcode fallback pc=00001000 op=f239")',
  '!output.includes("NATEXEC pc=00001000")', '!output.includes("Caught SIGSEGV")',
  "expectedService = process.env.CASE ? selectedService.length : 48",
  "expectedStrict = process.env.CASE ? selectedStrict.length : 4",
]) requireText(fppHyperbolicLog1pFallbackMatrix, contract, "FPP serviced monadic fallback matrix");
console.log("METRIC structural_fpp_hyperbolic_log1p_service_vectors=48");
console.log("METRIC structural_fpp_hyperbolic_log1p_strict_rejections=4");
console.log("METRIC structural_fpp_hyperbolic_log1p_extended_source=1");
console.log("METRIC structural_fpp_hyperbolic_log1p_direct_result=1");
let inverseCompilerCursor = fppCompilerOperation.indexOf("case 0x09:");
for (const [label, disable, name] of [
  ["case 0x0a:", "jit_disable.fatan", "FATAN"],
  ["case 0x0c:", "jit_disable.fasin", "FASIN"],
  ["case 0x0d:", "jit_disable.fatanh", "FATANH"],
] as const) {
  const start = fppCompilerOperation.indexOf(label, inverseCompilerCursor);
  const next = fppCompilerOperation.indexOf("case 0x", start + label.length);
  if (start < 0 || next < 0) fail(`FPP ${name} service boundary is incomplete`);
  const block = fppCompilerOperation.slice(start, next);
  for (const contract of [label, disable, "FAIL(1);", "return;"])
    requireText(block, contract, `FPP ${name} configured service boundary`);
  inverseCompilerCursor = next;
}
for (const contract of [
  "operation == 8 || operation == 9 || operation == 10",
  "|| operation == 12 || operation == 13 || operation == 14",
  "case 10: // FATAN", "mpfr_atan (direct, value.f, rnd)",
  "case 12: // FASIN", "mpfr_asin (direct, value.f, rnd)",
  "case 13: // FATANH", "mpfr_cmpabs (value.f, FPU_CONSTANT_ONE)",
  "cur_exceptions |= FPSR_EXCEPTION_DZ;", "cur_exceptions |= FPSR_EXCEPTION_OPERR;",
  "mpfr_atanh (direct, value.f, rnd)",
]) requireText(ordinaryFppBlock, contract, "MPFR inverse-function extended-source/direct-result contract");
for (const contract of [
  'name: `${item.name}_extended_source_single_${suffix}`',
  'name: `${item.name}_extended_source_double_nearest`',
  'name: `${name}_positive_zero`', 'name: `${name}_negative_zero`',
  'name: "fatan_positive_infinity"', 'name: "fatan_negative_infinity"',
  'name: "fasin_positive_one"', 'name: "fasin_outside_domain_operr"',
  'name: "fatanh_positive_one_dz"', 'name: "fatanh_negative_one_dz"',
  'name: "fatanh_outside_domain_operr"', 'name: "fatan_negative_qnan_payload"',
  'name: "fasin_signalling_nan_quiet"', 'name: "fatanh_quiet_nan_payload"',
  'name: "fatan_extended_min_single_underflow"', 'name: "fasin_extended_min_single_underflow"',
  'name: "fatanh_extended_min_single_underflow"', 'name: "fatan_fp7_self_alias"',
  'name: "fatanh_fp7_self_alias"', 'name: "fasin_accrued_preserve"',
  'd0 === (item.operationFpsr ?? item.fpsr)', 'fallbackCount === (item.alias ? 4 : 3)',
  'strict full-JIT: opcode fallback pc=00001000 op=f239', '!output.includes("NATEXEC pc=00001000")',
  "expectedService = process.env.CASE ? selectedCases.length : 38",
  "expectedStrict = process.env.CASE ? selectedStrict.length : 3",
]) requireText(fppInverseFallbackMatrix, contract, "FPP inverse-function fallback matrix");
console.log("METRIC structural_fpp_inverse_service_vectors=38");
console.log("METRIC structural_fpp_inverse_strict_rejections=3");
console.log("METRIC structural_fpp_inverse_extended_source=1");
console.log("METRIC structural_fpp_inverse_direct_result=1");
console.log("METRIC structural_fpp_inverse_atanh_dz=1");
let tanLogCompilerCursor = inverseCompilerCursor;
for (const [label, disable, name] of [
  ["case 0x0f:", "jit_disable.ftan", "FTAN"],
  ["case 0x12:", "jit_disable.ftentox", "FTENTOX"],
  ["case 0x14:", "jit_disable.flogn", "FLOGN"],
  ["case 0x15:", "jit_disable.flog10", "FLOG10"],
] as const) {
  const start = fppCompilerOperation.indexOf(label, tanLogCompilerCursor);
  const next = fppCompilerOperation.indexOf("case 0x", start + label.length);
  if (start < 0 || next < 0) fail(`FPP ${name} service boundary is incomplete`);
  const block = fppCompilerOperation.slice(start, next);
  for (const contract of [label, disable, "FAIL(1);", "return;"])
    requireText(block, contract, `FPP ${name} configured service boundary`);
  tanLogCompilerCursor = next;
}
for (const contract of [
  "operation == 12 || operation == 13 || operation == 14",
  "|| operation == 15 || operation == 16 || operation == 17",
  "|| operation == 18 || operation == 20 || operation == 21",
  "case 15: // FTAN", "mpfr_inf_p (value.f)", "mpfr_tan (direct, value.f, rnd)",
  "case 18: // FTENTOX", "mpfr_ui_pow (direct, 10, value.f, rnd)",
  "case 20: // FLOGN", "mpfr_log (direct, value.f, rnd)",
  "case 21: // FLOG10", "mpfr_log10 (direct, value.f, rnd)",
  "mpfr_zero_p (value.f)", "mpfr_sgn (value.f) < 0",
]) requireText(ordinaryFppBlock, contract, "MPFR tangent/exp10/log extended-source/direct-result contract");
for (const contract of [
  'name:`${a.name}_extended_source_single_${s}`',
  'name:`${a.name}_extended_source_double_nearest`',
  'name:`${name}_positive_zero`', 'name:`${name}_negative_zero`',
  'name:"ftan_positive_infinity_operr"', 'name:"ftan_negative_infinity_operr"',
  'name:"ftentox_positive_infinity"', 'name:"ftentox_negative_infinity"',
  'name:"flogn_positive_infinity"', 'name:"flog10_positive_infinity"',
  'name:"flogn_negative_domain_operr"', 'name:"flog10_negative_domain_operr"',
  'name:"ftan_negative_qnan_payload"', 'name:"ftentox_signalling_nan_quiet"',
  'name:"flogn_quiet_nan_payload"', 'name:"flog10_signalling_nan_quiet"',
  'name:"ftan_extended_min_single_underflow"', 'name:"ftentox_finite_single_underflow"',
  'name:"ftan_fp7_self_alias"', 'name:"flogn_fp7_self_alias"',
  'name:"flog10_accrued_preserve"',
  'd0===(a.operationFpsr??a.fpsr)', 'fc===(a.alias?4:3)',
  'strict full-JIT: opcode fallback pc=00001000 op=f239', '!o.includes("NATEXEC pc=00001000")',
  "const es=process.env.CASE?sc.length:45", "et=process.env.CASE?ss.length:4",
]) requireText(fppTanExp10LogFallbackMatrix, contract, "FPP tangent/exp10/log fallback matrix");
console.log("METRIC structural_fpp_tan_exp10_log_service_vectors=45");
console.log("METRIC structural_fpp_tan_exp10_log_strict_rejections=4");
console.log("METRIC structural_fpp_tan_exp10_log_extended_source=1");
console.log("METRIC structural_fpp_tan_exp10_log_direct_result=1");
for (const [label, disable, name] of [
  ["case 0x0e:\t\t\t\t\t\t/* FSIN */", "jit_disable.fsin", "FSIN"],
  ["case 0x10:\t\t\t\t\t\t/* FETOX */", "jit_disable.fetox", "FETOX"],
  ["case 0x11:\t\t\t\t\t\t/* FTWOTOX */", "jit_disable.ftwotox", "FTWOTOX"],
  ["case 0x16:\t\t\t\t\t\t/* FLOG2 */", "jit_disable.flog2", "FLOG2"],
] as const) {
  const start = fppCompilerOperation.indexOf(label);
  const next = fppCompilerOperation.indexOf("case 0x", start + label.length);
  if (start < 0 || next < 0) fail(`FPP ${name} service boundary is incomplete`);
  const block = fppCompilerOperation.slice(start, next);
  for (const contract of [label, disable, "#if defined(CPU_aarch64) || defined(CPU_AARCH64)", "FAIL(1);", "return;"])
    requireText(block, contract, `FPP ${name} configured AArch64 service boundary`);
  const guard = block.indexOf("#if defined(CPU_aarch64) || defined(CPU_AARCH64)");
  const acquire = block.indexOf("get_fp_value(opcode, extra)");
  if (guard < 0 || acquire < 0 || guard > acquire)
    fail(`FPP ${name} AArch64 service guard does not precede operand acquisition`);
}
for (const contract of [
  "operation == 12 || operation == 13 || operation == 14",
  "|| operation == 15 || operation == 16 || operation == 17",
  "|| operation == 18 || operation == 20 || operation == 21",
  "|| operation == 22 || operation == 25 || operation == 28",
  "|| operation == 29 || operation == 32 || operation == 34\n\t|| operation == 35 || operation == 40;",
  "case 14: // FSIN", "mpfr_sin (direct, value.f, rnd)",
  "case 16: // FETOX", "mpfr_exp (direct, value.f, rnd)",
  "case 17: // FTWOTOX", "mpfr_exp2 (direct, value.f, rnd)",
  "case 22: // FLOG2", "mpfr_log2 (direct, value.f, rnd)",
  "mpfr_zero_p (value.f)", "mpfr_sgn (value.f) < 0",
]) requireText(ordinaryFppBlock, contract, "MPFR native-transcendental extended-source/direct-result contract");
for (const contract of [
  'name:`${a.name}_direct_single_${s}`', 'name:`${a.name}_direct_double_nearest`',
  'name:`${name}_positive_zero`', 'name:`${name}_negative_zero`',
  'name:"fsin_positive_infinity_operr"', 'name:"fsin_negative_infinity_operr"',
  'name:"fetox_positive_infinity"', 'name:"fetox_negative_infinity"',
  'name:"ftwotox_positive_infinity"', 'name:"ftwotox_negative_infinity"',
  'name:"flog2_positive_infinity"', 'name:"flog2_negative_domain_operr"',
  'name:"fsin_negative_qnan_payload"', 'name:"fetox_signalling_nan_quiet"',
  'name:"ftwotox_quiet_nan_payload"', 'name:"flog2_signalling_nan_quiet"',
  'name:"fsin_extended_min_single_underflow"', 'name:"fetox_finite_single_overflow"',
  'name:"fetox_finite_single_underflow"', 'name:"ftwotox_finite_single_overflow"',
  'name:"ftwotox_finite_single_underflow"', 'name:"flog2_extended_min_exact"',
  'name:"fsin_fp7_self_alias"', 'name:"ftwotox_fp7_self_alias"', 'name:"flog2_accrued_preserve"',
  'd0===(a.operationFpsr??a.fpsr)', 'fc===(a.alias?4:3)',
  'B2_NATIVE_ASSERT_PC:"0x1000"',
  'fc===(a.alias?4:3)&&o.includes("NATEXEC pc=00001000")&&o.includes("JIT_FALLBACK op=f239 pc=00001000")&&!o.includes("Caught SIGSEGV")',
  'strict full-JIT: opcode fallback pc=00001000 op=f239',
  "const es=process.env.CASE?sc.length:49", "et=process.env.CASE?ss.length:4",
]) requireText(fppNativeTranscendentalServiceMatrix, contract, "FPP native-transcendental service matrix");
console.log("METRIC structural_fpp_native_transcendental_service_vectors=49");
console.log("METRIC structural_fpp_native_transcendental_strict_rejections=4");
console.log("METRIC structural_fpp_native_transcendental_extended_source=1");
console.log("METRIC structural_fpp_native_transcendental_direct_result=1");
for (const [label, disable, name] of [
  ["case 0x19:\t\t\t\t\t\t/* FCOSH */", "jit_disable.fcosh", "FCOSH"],
  ["case 0x1c:\t\t\t\t\t\t/* FACOS */", "jit_disable.facos", "FACOS"],
  ["case 0x1d:\t\t\t\t\t\t/* FCOS */", "jit_disable.fcos", "FCOS"],
] as const) {
  const start = fppCompilerOperation.indexOf(label);
  const next = fppCompilerOperation.indexOf("case 0x", start + label.length);
  if (start < 0 || next < 0) fail(`FPP ${name} service boundary is incomplete`);
  const block = fppCompilerOperation.slice(start, next);
  for (const contract of [label, disable, "FAIL(1);", "return;"])
    requireText(block, contract, `FPP ${name} configured service boundary`);
  const acquire = block.indexOf("get_fp_value(opcode, extra)");
  if (name === "FCOS") {
    const guardStart = block.indexOf("#if defined(CPU_aarch64) || defined(CPU_AARCH64)");
    const guardEnd = block.indexOf("#endif", guardStart);
    const guarded = guardStart >= 0 && guardEnd > guardStart
      ? block.slice(guardStart, guardEnd) : "";
    for (const contract of ["FAIL(1);", "return;"])
      requireText(guarded, contract, "FPP FCOS guarded AArch64 service exit");
    if (acquire < 0 || guardEnd > acquire)
      fail("FPP FCOS guarded AArch64 service exit does not precede operand acquisition");
  } else {
    const disable = block.indexOf("jit_disable.");
    const disableEnd = block.indexOf("\n\t\t\t}", disable);
    const configured = block.indexOf("FAIL(1);\n\t\t\treturn;", disableEnd);
    if (disable < 0 || disableEnd < 0 || configured < 0 || acquire >= 0)
      fail(`FPP ${name} configured service case can acquire an operand`);
  }
}
for (const contract of [
  "operation == 22 || operation == 25 || operation == 28", "|| operation == 29 || operation == 32 || operation == 34\n\t|| operation == 35 || operation == 40;",
  "case 25: // FCOSH", "mpfr_cosh (direct, value.f, rnd)",
  "case 28: // FACOS", "mpfr_cmpabs (value.f, FPU_CONSTANT_ONE)",
  "mpfr_acos (direct, value.f, rnd)", "case 29: // FCOS",
  "mpfr_inf_p (value.f)", "mpfr_cos (direct, value.f, rnd)",
]) requireText(ordinaryFppBlock, contract, "MPFR cosh/acos/cos extended-source/direct-result contract");
for (const contract of [
  'name:`${a.name}_extended_source_single_${s}`', 'name:`${a.name}_extended_source_double_nearest`',
  'name:`${name}_positive_zero`', 'name:`${name}_negative_zero`',
  'name:"fcosh_positive_infinity"', 'name:"fcosh_negative_infinity"',
  'name:"facos_positive_one"', 'name:"facos_negative_one"',
  'name:"facos_outside_domain_operr"', 'name:"facos_infinity_operr"',
  'name:"fcos_positive_infinity_operr"', 'name:"fcos_negative_infinity_operr"',
  'name:"fcosh_negative_qnan_payload"', 'name:"facos_signalling_nan_quiet"',
  'name:"fcos_quiet_nan_payload"', 'name:"fcosh_finite_single_overflow"',
  'name:"fcosh_fp7_self_alias"', 'name:"fcos_fp7_self_alias"', 'name:"facos_accrued_preserve"',
  'B2_NATIVE_ASSERT_PC:"0x1000"',
  'fc===(a.alias?4:3)&&o.includes("NATEXEC pc=00001000")&&o.includes("JIT_FALLBACK op=f239 pc=00001000")&&!o.includes("Caught SIGSEGV")',
  'strict full-JIT: opcode fallback pc=00001000 op=f239',
  "const es=process.env.CASE?sc.length:36", "et=process.env.CASE?ss.length:3",
]) requireText(fppCoshAcosCosServiceMatrix, contract, "FPP cosh/acos/cos service matrix");
console.log("METRIC structural_fpp_cosh_acos_cos_service_vectors=36");
console.log("METRIC structural_fpp_cosh_acos_cos_strict_rejections=3");
console.log("METRIC structural_fpp_cosh_acos_cos_extended_source=1");
console.log("METRIC structural_fpp_cosh_acos_cos_direct_result=1");
const divideCompilerStart = fppCompilerOperation.indexOf("case 0x20:\t\t\t\t\t\t/* FDIV */");
const divideCompilerEnd = fppCompilerOperation.indexOf("case 0x21:\t\t\t\t\t\t/* FMOD */", divideCompilerStart);
if (divideCompilerStart < 0 || divideCompilerEnd < 0) fail("FPP divide compiler boundary is incomplete");
const divideCompilerBlock = fppCompilerOperation.slice(divideCompilerStart, divideCompilerEnd);
for (const contract of [
  "case 0x20:", "case 0x60:", "case 0x64:",
  "#if defined(CPU_aarch64) || defined(CPU_AARCH64)", "FAIL(1);", "return;",
]) requireText(divideCompilerBlock, contract, "FPP divide AArch64 service boundary");
const divideGuardStart = divideCompilerBlock.indexOf("#if defined(CPU_aarch64) || defined(CPU_AARCH64)");
const divideService = divideCompilerBlock.indexOf("FAIL(1);", divideGuardStart);
const divideReturn = divideCompilerBlock.indexOf("return;", divideService);
const divideAcquire = divideCompilerBlock.indexOf("get_fp_value(opcode, extra)");
const divideNativeCall = divideCompilerBlock.indexOf("fdiv_rr(");
if (divideGuardStart < 0 || divideService < divideGuardStart || divideReturn < divideService ||
    divideAcquire < divideReturn || divideNativeCall < divideAcquire)
  fail("FPP divide guarded service exit does not retire fdiv_rr before operand acquisition");
const divideRootSpellings = (fppCompilerSource.match(/\bfdiv_rr\(/g) || []).length;
if (divideRootSpellings !== 2)
  fail(`retired divide MIDFUNC fdiv_rr configured-root spellings=${divideRootSpellings} expected=2`);
const divideMidfuncCallers = (midfuncSource.match(/\bfdiv_rr\(/g) || []).length;
if (divideMidfuncCallers !== 0)
  fail(`retired divide MIDFUNC fdiv_rr gained ${divideMidfuncCallers} MIDFUNC caller spellings`);
const divideMidStart = midfuncSource.indexOf("MIDFUNC(2,fdiv_rr,(FRW d, FR s))");
const divideMidEnd = midfuncSource.indexOf("MENDFUNC(2,fdiv_rr", divideMidStart);
if (divideMidStart < 0 || divideMidEnd < 0) fail("missing retired divide MIDFUNC fdiv_rr");
const divideMidBody = midfuncSource.slice(divideMidStart, divideMidEnd);
for (const contract of ["s = f_readreg(s);", "d = f_rmw(d);", "raw_fdiv_rr(d, s);"])
  requireText(divideMidBody, contract, "retired divide MIDFUNC fdiv_rr");
const divideRawStart = codegenSource.indexOf("LOWFUNC(NONE,NONE,2,raw_fdiv_rr,(FRW d, FR s))");
const divideRawEnd = codegenSource.indexOf("LENDFUNC(NONE,NONE,2,raw_fdiv_rr", divideRawStart);
if (divideRawStart < 0 || divideRawEnd < 0) fail("missing retired divide raw boundary raw_fdiv_rr");
requireText(codegenSource.slice(divideRawStart, divideRawEnd), "FDIV_ddd(d, d, s);", "retired divide raw boundary raw_fdiv_rr");
for (const contract of [
  "|| operation == 29 || operation == 32 || operation == 34\n\t|| operation == 35 || operation == 40;", "case 32: // FDIV",
  "mpfr_div (direct, fpu.registers[reg].f, value.f, rnd)",
  "case 32: // FSDIV", "case 36: // FDDIV",
  "mpfr_div (value2, fpu.registers[reg].f, value.f, rnd)",
  "select_binary_nan (reg, value, &nan_bits, &nan_sign)",
  "If both", "NaNs, 6888x rules return the destination",
  "FPSR_EXCEPTION_DZ", "FPSR_EXCEPTION_OPERR",
  "FPSR_EXCEPTION_OVFL | FPSR_EXCEPTION_INEX2",
  "FPSR_EXCEPTION_UNFL | FPSR_EXCEPTION_INEX2",
]) requireText(fpuMpfrSource, contract, "MPFR FDIV/FSDIV/FDDIV service contract");
for (const contract of [
  "fpu_test_set_register_extended", "set_format(EXTENDED_PREC)", "set_format(get_cur_prec())",
  "regs.jit_fp_dirty_mask &= ~(1u << reg)",
]) requireText(fpuMpfrSource, contract, "FPP replay extended-register ownership contract");
for (const contract of ["#ifdef FPU_MPFR", "bool fpu_test_set_register_extended"])
  requireText(fpuHeaderSource, contract, "FPP replay seed declaration");
for (const contract of [
  "#ifdef FPU_MPFR",
  'snprintf(env_name, sizeof(env_name), "B2_TEST_REPLAY_FP%d_EXT", fpreg)',
  "parse_test_hex_longs_glue", "count != 3",
  "fpu_test_set_register_extended(fpreg, words[0], words[1], words[2])",
]) requireText(basiliskGlueSource, contract, "FPP replay extended-register harness boundary");
for (const contract of [
  'name: "fdiv_extended_one_third"', 'name: "fdiv_extended_source_low_bit"',
  'name: "fdiv_single_nearest"', 'name: "fdiv_double_plus"',
  'name: "fsdiv_forced_single_nearest"', 'name: "fddiv_forced_double_plus"',
  'name: "fdiv_positive_divide_by_zero"', 'name: "fdiv_zero_by_zero_invalid"',
  'name: "fsdiv_infinity_by_infinity_invalid"', 'name: "fddiv_zero_by_infinity"',
  'name: "fsdiv_finite_overflow"', 'name: "fddiv_finite_overflow"',
  'name: "fsdiv_finite_underflow"', 'name: "fdiv_destination_qnan_suppresses_dz"',
  'name: "fdiv_equal_qnan_destination_precedence"',
  'name: "fdiv_source_snan_quiet_then_destination_precedence"',
  'name: "fdiv_destination_snan_quiet_then_destination_precedence"',
  'name: "fdiv_equal_snan_destination_precedence"',
  'name: "fdiv_fp7_self_alias"', 'name: "fsdiv_fp7_self_alias"',
  'name: "fdiv_fp7_destination_reseed"', 'name: "fsdiv_fp7_destination_reseed"',
  'name: "fdiv_postincrement_source"', 'name: "fddiv_predecrement_source"',
  'name: "fdiv_accrued_preserve"',
  '"B2_TEST_REPLAY_FP7_EXT" : "B2_TEST_REPLAY_FP0_EXT"', 'B2_NATIVE_ASSERT_PC: "0x1008"',
  'const profile = [...output.matchAll(/JIT_FALLBACK op=([0-9a-f]+) pc=([0-9a-f]+)/gi)]',
  'const capturePc = auditedOpcode === "f239" ? "00001010" : "0000100c"',
  'const storePc = auditedOpcode === "f239" ? "00001014" : "00001010"',
  'const passProfile = `${auditedOpcode}@00001008 f200@${capturePc} f239@${storePc}`',
  'const expectedProfile = `f239@00001000 ${passProfile} ${passProfile}`',
  'profile === expectedProfile',
  'output.includes("NATEXEC pc=00001008")',
  'strict full-JIT: opcode fallback pc=00001000 op=f200',
  'service_pass=${servicePass} strict_pass=${strictPass}',
]) requireText(fppDivideServiceMatrix, contract, "FPP divide service matrix");
console.log("METRIC structural_fpp_divide_service_vectors=37");
console.log("METRIC structural_fpp_divide_strict_rejections=3");
console.log("METRIC structural_fpp_divide_binary_nan_ownership=1");
console.log("METRIC structural_fpp_divide_forced_range=1");
console.log("METRIC structural_fpp_divide_serviced_root_calls=2");
console.log("METRIC structural_fpp_divide_unreachable_midfuncs=1");
console.log("METRIC structural_fpp_divide_unreachable_raw_boundaries=1");
console.log("METRIC structural_fpp_divide_reachable_emitters=2");
const fmodCompilerStart = fppCompilerOperation.indexOf("case 0x21:\t\t\t\t\t\t/* FMOD */");
const fmodCompilerEnd = fppCompilerOperation.indexOf("case 0x22:\t\t\t\t\t\t/* FADD */", fmodCompilerStart);
if (fmodCompilerStart < 0 || fmodCompilerEnd < 0) fail("FPP FMOD compiler boundary is incomplete");
const fmodCompilerBlock = fppCompilerOperation.slice(fmodCompilerStart, fmodCompilerEnd);
for (const contract of ["case 0x21:", "jit_disable.fmod", "FAIL(1);", "return;"])
  requireText(fmodCompilerBlock, contract, "FPP FMOD exact service boundary");
for (const forbidden of ["get_fp_value(opcode, extra)", "fmod_rr(", "frem_rr(", "MAKE_FPSR("])
  if (fmodCompilerBlock.includes(forbidden)) fail(`FPP FMOD compiler case retains forbidden ${forbidden}`);
for (const contract of [
  "do_fmod (fpu_register &value, int reg, mpfr_rnd_t rnd)",
  "select_binary_nan (reg, value, &nan_bits, &nan_sign)",
  "mpfr_setsign (value.f, value.f, nan_sign, MPFR_RNDN)",
  "mpfr_zero_p (value.f) || mpfr_inf_p (fpu.registers[reg].f)",
  "cur_exceptions |= FPSR_EXCEPTION_OPERR", "FPSR_QUOTIENT_SIGN",
  "mpfr_rem1 (value.f, &quo, fpu.registers[reg].f, value.f, rnd)",
  "fpu.fpsr.quotient = quo << 16", "operation == 31 || operation == 33",
  "case 33: // FMOD", "do_fmod (value, reg, rnd)",
]) requireText(fpuMpfrSource, contract, "MPFR FMOD truncating quotient/service contract");
for (const contract of [
  'name:"fmod_positive_7_by_3"', 'name:"fmod_negative_7_by_3"',
  'name:"fmod_quotient_low_seven_wrap"', 'name:"fmod_truncates_not_nearest"',
  'destination:x.p7,source:"40 01 00 00 80 00 00 00 00 00 00 00",output:x.p3',
  'name:"fmod_extended_destination_low_bit"', 'name:"fmod_extended_source_low_bit"',
  'name:"fmod_single_nearest"', 'name:"fmod_double_zero"',
  'name:"fmod_single_overflow"', 'name:"fmod_single_underflow"',
  'name:"fmod_negative_zero_quotient_sign"', 'name:"fmod_zero_by_negative_source"',
  'name:"fmod_finite_by_positive_infinity"', 'name:"fmod_finite_by_negative_infinity"',
  'name:"fmod_source_zero_invalid_preserves_quotient"',
  'name:"fmod_destination_infinity_invalid_preserves_quotient"',
  'name:"fmod_destination_qnan_precedence"',
  'name:"fmod_source_snan_quiet_then_destination_precedence"',
  'name:"fmod_destination_snan_quiet_then_destination_precedence"',
  'name:"fmod_source_only_snan"', 'name:"fmod_fp7_self_alias"',
  'name:"fmod_fp7_destination_reseed"', 'name:"fmod_postincrement_source"',
  'name:"fmod_predecrement_source"', 'name:"fmod_quotient_replaced_accrued_preserved"',
  'profile=[...o.matchAll(/JIT_FALLBACK op=([0-9a-f]+) pc=([0-9a-f]+)/gi)]',
  'auditedOpcode=a.aliasFp7?"f200":a.ea==="postinc"?"f218":a.ea==="predec"?"f220":"f239"',
  'capturePc=auditedOpcode==="f239"?"00001010":"0000100c"', 'storePc=auditedOpcode==="f239"?"00001014":"00001010"',
  'passProfile=`${auditedOpcode}@00001008 f200@${capturePc} f239@${storePc}`',
  'expectedProfile=`f239@00001000 ${passProfile} ${passProfile}`', 'profile===expectedProfile',
  'B2_NATIVE_ASSERT_PC:"0x1008"', 'strict full-JIT: opcode fallback pc=00001000 op=f200',
  'service_pass=${sp} strict_pass=${st}', 'sc.length:31', 'ss.length:1',
]) requireText(fppFmodServiceMatrix, contract, "FPP FMOD service matrix");
console.log("METRIC structural_fpp_fmod_service_vectors=31");
console.log("METRIC structural_fpp_fmod_strict_rejections=1");
console.log("METRIC structural_fpp_fmod_truncating_quotient=1");
const fremCompilerStart = fppCompilerOperation.indexOf("case 0x25:\t\t\t\t\t\t/* FREM */");
const fremCompilerEnd = fppCompilerOperation.indexOf("case 0x26:\t\t\t\t\t\t/* FSCALE */", fremCompilerStart);
if (fremCompilerStart < 0 || fremCompilerEnd < 0) fail("FPP FREM compiler boundary is incomplete");
const fremCompilerBlock = fppCompilerOperation.slice(fremCompilerStart, fremCompilerEnd);
for (const contract of ["case 0x25:", "jit_disable.frem", "exact semantic service", "FAIL(1);", "return;"])
  requireText(fremCompilerBlock, contract, "FPP FREM service boundary");
for (const forbidden of ["get_fp_value(opcode, extra)", "frem_rr(", "frem1_rr(", "MAKE_FPSR("])
  if (fremCompilerBlock.includes(forbidden)) fail(`FPP FREM compiler case retains forbidden ${forbidden}`);
for (const contract of [
  "|| operation == 37 || operation == 38 || single_extended_result;", "case 37: // FREM", "do_remainder (value, reg, rnd)",
  "do_remainder (fpu_register &value, int reg, mpfr_rnd_t rnd)",
  "mpfr_remquo (value.f, &quo, fpu.registers[reg].f, value.f, rnd)",
  "quo = (-quo & 0x7f) | 0x80", "quo &= 0x7f", "fpu.fpsr.quotient = quo << 16",
  "select_binary_nan (reg, value, &nan_bits, &nan_sign)", "FPSR_EXCEPTION_OPERR",
  "? FPSR_QUOTIENT_SIGN : 0", "mpfr_set (value.f, fpu.registers[reg].f, rnd)",
]) requireText(fpuMpfrSource, contract, "MPFR FREM service contract");
for (const contract of [
  'name:"frem_nearest_not_truncating",destination:x.p7,source:"40 01 00 00 80 00 00 00 00 00 00 00",output:x.n1,operationFpsr:"08020000",fpsr:"08020000"',
  'name:"frem_tie_even_2p5"', 'name:"frem_tie_even_3p5"',
  'name:"frem_quotient_low_seven_wrap",destination:x.p195,source:x.p3,output:x.pz,operationFpsr:"04410000",fpsr:"04410000"',
  'name:"frem_extended_destination_low_bit"', 'name:"frem_extended_source_low_bit"',
  'name:"frem_single_nearest"', 'name:"frem_single_zero"', 'name:"frem_single_minus"', 'name:"frem_single_plus"',
  'name:"frem_double_nearest"', 'name:"frem_double_zero"',
  'name:"frem_single_overflow",destination:x.max,source:x.hugeModulus,output:x.ninf,fpcr:"40",operationFpsr:"0a041248",fpsr:"0a040048"',
  'name:"frem_single_underflow"', 'name:"frem_negative_zero_quotient_sign"',
  'name:"frem_zero_by_negative_source"', 'name:"frem_finite_by_positive_infinity"', 'name:"frem_finite_by_negative_infinity"',
  'name:"frem_source_zero_invalid_preserves_quotient"', 'name:"frem_destination_infinity_invalid_preserves_quotient"',
  'name:"frem_destination_qnan_precedence"', 'name:"frem_source_snan_quiet_then_destination_precedence"',
  'name:"frem_destination_snan_quiet_then_destination_precedence"', 'name:"frem_source_only_snan"',
  'name:"frem_fp7_self_alias"', 'name:"frem_fp7_destination_reseed"',
  'name:"frem_postincrement_source"', 'name:"frem_predecrement_source"', 'name:"frem_quotient_replaced_accrued_preserved"',
  'profile=[...o.matchAll(/JIT_FALLBACK op=([0-9a-f]+) pc=([0-9a-f]+)/gi)]',
  'auditedOpcode=a.aliasFp7?"f200":a.ea==="postinc"?"f218":a.ea==="predec"?"f220":"f239"',
  'capturePc=auditedOpcode==="f239"?"00001010":"0000100c"', 'storePc=auditedOpcode==="f239"?"00001014":"00001010"',
  'passProfile=`${auditedOpcode}@00001008 f200@${capturePc} f239@${storePc}`',
  'expectedProfile=`f239@00001000 ${passProfile} ${passProfile}`', 'profile===expectedProfile',
  'B2_NATIVE_ASSERT_PC:"0x1008"', 'strict full-JIT: opcode fallback pc=00001000 op=f200',
  'service_pass=${sp} strict_pass=${st}', 'sc.length:33', 'ss.length:1',
]) requireText(fppFremServiceMatrix, contract, "FPP FREM service matrix");
console.log("METRIC structural_fpp_frem_service_vectors=33");
console.log("METRIC structural_fpp_frem_strict_rejections=1");
console.log("METRIC structural_fpp_frem_nearest_even_quotient=2");
console.log("METRIC structural_fpp_frem_quotient_bits=7");
for (const [name, rawName] of [["fmod_rr", "raw_fmod_rr"], ["frem1_rr", "raw_frem1_rr"]] as const) {
  const midStart = midfuncSource.indexOf(`MIDFUNC(2,${name},(FRW d, FR s))`);
  const midEnd = midfuncSource.indexOf(`MENDFUNC(2,${name},(FRW d, FR s))`, midStart);
  if (midStart < 0 || midEnd < 0) fail(`missing retired remainder MIDFUNC ${name}`);
  requireText(midfuncSource.slice(midStart, midEnd), `${rawName}(d, s);`, `retired remainder MIDFUNC ${name}`);
  if ((midfuncSource.match(new RegExp(`\\b${name}\\b`, "g")) || []).length !== 2)
    fail(`remainder MIDFUNC ${name} gained a configured caller`);
}
const remainderRawContracts = [
  {
    name: "raw_fmod_rr",
    contracts: ["FDIV_ddd(SCRATCH_F64_1, d, s);", "FRINTZ_dd(SCRATCH_F64_1, SCRATCH_F64_1);", "FMSUB_dddd(d, SCRATCH_F64_1, s, d);"],
  },
  {
    name: "raw_frem1_rr",
    contracts: ["FDIV_ddd(SCRATCH_F64_2, d, s);", "FRINTA_dd(SCRATCH_F64_2, SCRATCH_F64_2);", "FMSUB_dddd(d, SCRATCH_F64_2, s, d);"],
  },
] as const;
for (const raw of remainderRawContracts) {
  const rawStart = codegenSource.indexOf(`LOWFUNC(NONE,NONE,2,${raw.name},(FRW d, FR s))`);
  const rawEnd = codegenSource.indexOf(`LENDFUNC(NONE,NONE,2,${raw.name},(FRW d, FR s))`, rawStart);
  if (rawStart < 0 || rawEnd < 0) fail(`missing retired remainder raw boundary ${raw.name}`);
  const rawBody = codegenSource.slice(rawStart, rawEnd);
  let previous = -1;
  for (const contract of raw.contracts) {
    requireText(rawBody, contract, `retired remainder raw boundary ${raw.name}`);
    const position = rawBody.indexOf(contract);
    if (position <= previous) fail(`retired remainder raw order changed in ${raw.name}`);
    previous = position;
  }
  if ((codegenSource.match(new RegExp(`\\b${raw.name}\\b`, "g")) || []).length !== 2)
    fail(`remainder raw boundary ${raw.name} gained a configured caller`);
}
const remainderFdivSites = (codegenSource.match(/\bFDIV_ddd\(/g) || []).length;
const remainderFmsubSites = (codegenSource.match(/\bFMSUB_dddd\(/g) || []).length;
const remainderFrintzSites = (codegenSource.match(/\bFRINTZ_dd\(/g) || []).length;
const remainderFrintaSites = (codegenSource.match(/\bFRINTA_dd\(/g) || []).length;
if (remainderFdivSites !== 3 || remainderFmsubSites !== 2 || remainderFrintzSites !== 2 || remainderFrintaSites !== 1)
  fail(`remainder residual sites FDIV/FMSUB/FRINTZ/FRINTA=${remainderFdivSites}/${remainderFmsubSites}/${remainderFrintzSites}/${remainderFrintaSites}, expected 3/2/2/1`);
console.log("METRIC structural_fpp_remainder_unreachable_raw_boundaries=2");
console.log("METRIC structural_fpp_remainder_unreachable_emitters=4");
console.log("METRIC structural_fpp_remainder_historical_direct_emitter_clusters=3");
const scaleCompilerStart = fppCompilerOperation.indexOf("case 0x26:\t\t\t\t\t\t/* FSCALE */");
const scaleCompilerEnd = fppCompilerOperation.indexOf("case 0x27:\t\t\t\t\t\t/* FSGLMUL */", scaleCompilerStart);
if (scaleCompilerStart < 0 || scaleCompilerEnd < 0) fail("FPP FSCALE compiler boundary is incomplete");
const scaleCompilerBlock = fppCompilerOperation.slice(scaleCompilerStart, scaleCompilerEnd);
for (const contract of ["case 0x26:", "jit_disable.fscale", "FAIL(1);", "return;"])
  requireText(scaleCompilerBlock, contract, "FPP FSCALE service boundary");
for (const forbidden of ["get_fp_value(opcode, extra)", "fscale_rr(", "MAKE_FPSR("])
  if (scaleCompilerBlock.includes(forbidden)) fail(`FPP FSCALE compiler case retains forbidden ${forbidden}`);
for (const contract of [
  "|| operation == 37 || operation == 38 || single_extended_result;", "case 38: // FSCALE", "do_scale (value, reg, rnd)",
  "do_scale (fpu_register &value, int reg, mpfr_rnd_t rnd)", "mpfr_get_si (value.f, MPFR_RNDZ)",
  "mpfr_mul_2si (value.f, fpu.registers[reg].f, scale, rnd)",
  "long destination_exp = mpfr_get_exp (fpu.registers[reg].f)",
  "EXTENDED_MIN_EXP - EXTENDED_PREC - destination_exp", "EXTENDED_MAX_EXP + EXTENDED_PREC - destination_exp",
  "select_binary_nan (reg, value, &nan_bits, &nan_sign)",
  "mpfr_inf_p (value.f) || mpfr_inf_p (fpu.registers[reg].f)",
  "mpfr_setsign (value.f, value.f, nan_sign, MPFR_RNDN)", "value.nan_sign = nan_sign",
  "mpfr_zero_p (fpu.registers[reg].f) || mpfr_zero_p (value.f)",
]) requireText(fpuMpfrSource, contract, "MPFR FSCALE service contract");
for (const contract of [
  'name:"fscale_positive_fraction_truncates"', 'name:"fscale_negative_fraction_truncates"',
  'name:"fscale_extended_source_below_one"', 'name:"fscale_extended_source_above_negative_one"',
  'name:"fscale_extended_destination_low_bit"',
  'name:"fscale_single_nearest"', 'name:"fscale_single_plus"', 'name:"fscale_double_nearest"', 'name:"fscale_double_plus"',
  'name:"fscale_single_overflow"', 'name:"fscale_extended_overflow"', 'name:"fscale_extended_underflow"',
  'name:"fscale_huge_positive_minimum_destination_overflow",destination:x.halfMinNormal,source:x.hugePositive,output:x.pinf,operationFpsr:"02001248",fpsr:"02000048"',
  'name:"fscale_huge_negative_maximum_destination_underflow",destination:x.max,source:x.hugeNegative,output:x.pz,operationFpsr:"04000a28",fpsr:"04000028"',
  'name:"fscale_exact_subnormal"', 'name:"fscale_positive_zero_preserved"', 'name:"fscale_negative_zero_preserved"',
  'name:"fscale_destination_infinity_invalid"',
  'name:"fscale_negative_destination_infinity_invalid",destination:x.ninf,source:x.p1,output:"ff ff 00 00 ff ff ff ff ff ff ff ff",operationFpsr:"09002080",fpsr:"09000080"',
  'name:"fscale_source_positive_infinity_invalid"',
  'name:"fscale_source_negative_infinity_invalid",destination:x.n3,source:x.ninf,output:"ff ff 00 00 ff ff ff ff ff ff ff ff",operationFpsr:"09002080",fpsr:"09000080"',
  'name:"fscale_source_qnan"', 'name:"fscale_source_snan_quiet"', 'name:"fscale_destination_qnan"', 'name:"fscale_destination_snan_quiet"',
  'name:"fscale_fp7_self_alias"', 'name:"fscale_fp7_destination_reseed"',
  'name:"fscale_postincrement_source"', 'name:"fscale_predecrement_source"', 'name:"fscale_accrued_preserve"',
  'o.includes(`JIT_FALLBACK op=${auditedOpcode} pc=00001008`)', 'B2_NATIVE_ASSERT_PC:"0x1008"',
  'strict full-JIT: opcode fallback pc=00001000 op=f200', 'service_pass=${sp} strict_pass=${st}', 'sc.length:30', 'ss.length:1',
]) requireText(fppScaleServiceMatrix, contract, "FPP FSCALE service matrix");
console.log("METRIC structural_fpp_scale_service_vectors=30");
console.log("METRIC structural_fpp_scale_strict_rejections=1");
console.log("METRIC structural_fpp_scale_huge_finite_ranges=2");
console.log("METRIC structural_fpp_scale_truncation_boundaries=4");
const sgldivCompilerStart = fppCompilerOperation.indexOf("case 0x24:\t\t\t\t\t\t/* FSGLDIV */");
const sgldivCompilerEnd = fppCompilerOperation.indexOf("case 0x25:\t\t\t\t\t\t/* FREM */", sgldivCompilerStart);
if (sgldivCompilerStart < 0 || sgldivCompilerEnd < 0) fail("FPP FSGLDIV compiler boundary is incomplete");
const sgldivCompilerBlock = fppCompilerOperation.slice(sgldivCompilerStart, sgldivCompilerEnd);
for (const contract of ["case 0x24:", "jit_disable.fsgldiv", "#if defined(CPU_aarch64) || defined(CPU_AARCH64)", "FAIL(1);", "return;"])
  requireText(sgldivCompilerBlock, contract, "FPP FSGLDIV AArch64 service boundary");
const sgldivGuardStart = sgldivCompilerBlock.indexOf("#if defined(CPU_aarch64) || defined(CPU_AARCH64)");
const sgldivService = sgldivCompilerBlock.indexOf("FAIL(1);", sgldivGuardStart);
const sgldivReturn = sgldivCompilerBlock.indexOf("return;", sgldivService);
const sgldivAcquire = sgldivCompilerBlock.indexOf("get_fp_value(opcode, extra)");
const sgldivNativeCall = sgldivCompilerBlock.indexOf("fdiv_rr(");
if (sgldivGuardStart < 0 || sgldivService < sgldivGuardStart || sgldivReturn < sgldivService ||
    sgldivAcquire < sgldivReturn || sgldivNativeCall < sgldivAcquire)
  fail("FPP FSGLDIV guarded service exit does not retire fdiv_rr before operand acquisition");
for (const contract of [
  "bool single_extended_result = operation == 36", "|| operation == 38 || single_extended_result;",
  "MPFR_DECL_INIT (single_extended, SINGLE_PREC)", "case 36: // FSGLDIV",
  "mpfr_div (single_extended, fpu.registers[reg].f, value.f, rnd)",
  "set_format (EXTENDED_PREC)", "mpfr_check_range (single_extended, t, rnd)",
  "select_binary_nan (reg, value, &nan_bits, &nan_sign)",
  "set_fp_register (reg, single_extended, nan_bits, nan_sign",
]) requireText(fpuMpfrSource, contract, "MPFR FSGLDIV single-significand/extended-exponent contract");
for (const contract of [
  'name: "fsgldiv_extended_destination_one_sided"', 'name: "fsgldiv_extended_source_one_sided"',
  'name: "fsgldiv_double_round_midpoint", selector: "24", destination: "3f ff 00 00 80 00 00 80 01 00 00 00", source: "3f ff 00 00 80 00 00 00 00 ff ff ff", output: "3f ff 00 00 80 00 01 00 00 00 00 00"',
  'name: "fsgldiv_negative_minus"', 'name: "fsgldiv_single_nearest_independent_fpcr"',
  'name: "fsgldiv_extended_exponent_no_single_overflow"', 'name: "fsgldiv_extended_exponent_no_single_underflow"',
  'name: "fsgldiv_divide_by_zero"', 'name: "fsgldiv_zero_by_zero_invalid"', 'name: "fsgldiv_infinity_by_infinity_invalid"',
  'name: "fsgldiv_destination_qnan_suppresses_dz"', 'name: "fsgldiv_source_qnan_suppresses_invalid"',
  'name: "fsgldiv_source_snan_quiet_destination_precedence"', 'name: "fsgldiv_destination_snan_quiet"',
  'name: "fsgldiv_fp7_self_alias"', 'name: "fsgldiv_fp7_destination_reseed"',
  'name: "fsgldiv_postincrement_source"', 'name: "fsgldiv_predecrement_source"', 'name: "fsgldiv_accrued_preserve"',
  'const profile = [...output.matchAll(/JIT_FALLBACK op=([0-9a-f]+) pc=([0-9a-f]+)/gi)]',
  'const capturePc = auditedOpcode === "f239" ? "00001010" : "0000100c"',
  'const storePc = auditedOpcode === "f239" ? "00001014" : "00001010"',
  'const passProfile = `${auditedOpcode}@00001008 f200@${capturePc} f239@${storePc}`',
  'const expectedProfile = `f239@00001000 ${passProfile} ${passProfile}`',
  'profile === expectedProfile',
  'const auditedOpcode = item.aliasFp7 ? "f200"', 'output.includes(`JIT_FALLBACK op=${auditedOpcode} pc=00001008`)',
  'B2_NATIVE_ASSERT_PC: "0x1008"', 'strict full-JIT: opcode fallback pc=00001000 op=f200',
  'service_pass=${servicePass} strict_pass=${strictPass}',
]) requireText(fppSgldivServiceMatrix, contract, "FPP FSGLDIV service matrix");
console.log("METRIC structural_fpp_sgldiv_service_vectors=23");
console.log("METRIC structural_fpp_sgldiv_strict_rejections=1");
console.log("METRIC structural_fpp_sgldiv_one_sided_operands=2");
console.log("METRIC structural_fpp_sgldiv_direct_single_round=1");
const sgldivMidStart = midfuncSource.indexOf("MIDFUNC(2,fsgldiv_rr,(FRW d, FR s))");
const sgldivMidEnd = midfuncSource.indexOf("MENDFUNC(2,fsgldiv_rr,(FRW d, FR s))", sgldivMidStart);
if (sgldivMidStart < 0 || sgldivMidEnd < 0) fail("missing retired FSGLDIV MIDFUNC fsgldiv_rr");
requireText(midfuncSource.slice(sgldivMidStart, sgldivMidEnd), "raw_fsgldiv_rr(d, s);", "retired FSGLDIV MIDFUNC fsgldiv_rr");
if ((midfuncSource.match(/\bfsgldiv_rr\b/g) || []).length !== 2)
  fail("FSGLDIV MIDFUNC fsgldiv_rr gained a configured caller");
const sgldivRawStart = codegenSource.indexOf("LOWFUNC(NONE,NONE,2,raw_fsgldiv_rr,(FRW d, FR s))");
const sgldivRawEnd = codegenSource.indexOf("LENDFUNC(NONE,NONE,2,raw_fsgldiv_rr,(FRW d, FR s))", sgldivRawStart);
if (sgldivRawStart < 0 || sgldivRawEnd < 0) fail("missing retired FSGLDIV raw boundary raw_fsgldiv_rr");
const sgldivRawBody = codegenSource.slice(sgldivRawStart, sgldivRawEnd);
let sgldivPrevious = -1;
for (const contract of [
  "FCVT_sd(SCRATCH_F64_1, d);", "FCVT_sd(SCRATCH_F64_2, s);",
  "FDIV_sss(SCRATCH_F64_1, SCRATCH_F64_1, SCRATCH_F64_2);", "FCVT_ds(d, SCRATCH_F64_1);",
]) {
  requireText(sgldivRawBody, contract, "retired FSGLDIV raw boundary raw_fsgldiv_rr");
  const position = sgldivRawBody.indexOf(contract);
  if (position <= sgldivPrevious) fail("retired FSGLDIV raw conversion/division order changed");
  sgldivPrevious = position;
}
if ((codegenSource.match(/\braw_fsgldiv_rr\b/g) || []).length !== 2)
  fail("FSGLDIV raw boundary raw_fsgldiv_rr gained a configured caller");
const sgldivFdivSingleSites = (codegenSource.match(/\bFDIV_sss\(/g) || []).length;
const sgldivFdivDoubleSites = (codegenSource.match(/\bFDIV_ddd\(/g) || []).length;
const sgldivFcvtSdSites = (codegenSource.match(/\bFCVT_sd\(/g) || []).length;
const sgldivFcvtDsSites = (codegenSource.match(/\bFCVT_ds\(/g) || []).length;
if (sgldivFdivSingleSites !== 1 || sgldivFdivDoubleSites !== 3 || sgldivFcvtSdSites !== 7 || sgldivFcvtDsSites !== 6)
  fail(`FSGLDIV residual sites FDIV_s/d FCVT_sd/ds=${sgldivFdivSingleSites}/${sgldivFdivDoubleSites} ${sgldivFcvtSdSites}/${sgldivFcvtDsSites}, expected 1/3 7/6`);
console.log("METRIC structural_fpp_sgldiv_unreachable_raw_boundaries=1");
console.log("METRIC structural_fpp_sgldiv_unreachable_single_emitters=1");
console.log("METRIC structural_fpp_sgldiv_reachable_double_emitters=1");
const sglmulCompilerStart = fppCompilerOperation.indexOf("case 0x27:\t\t\t\t\t\t/* FSGLMUL */");
const sglmulCompilerEnd = fppCompilerOperation.indexOf("case 0x28:\t\t\t\t\t\t/* FSUB */", sglmulCompilerStart);
if (sglmulCompilerStart < 0 || sglmulCompilerEnd < 0) fail("FPP FSGLMUL compiler boundary is incomplete");
const sglmulCompilerBlock = fppCompilerOperation.slice(sglmulCompilerStart, sglmulCompilerEnd);
for (const contract of ["case 0x27:", "jit_disable.fsglmul", "#if defined(CPU_aarch64) || defined(CPU_AARCH64)", "FAIL(1);", "return;"])
  requireText(sglmulCompilerBlock, contract, "FPP FSGLMUL AArch64 service boundary");
const sglmulGuardStart = sglmulCompilerBlock.indexOf("#if defined(CPU_aarch64) || defined(CPU_AARCH64)");
const sglmulService = sglmulCompilerBlock.indexOf("FAIL(1);", sglmulGuardStart);
const sglmulReturn = sglmulCompilerBlock.indexOf("return;", sglmulService);
const sglmulAcquire = sglmulCompilerBlock.indexOf("get_fp_value(opcode, extra)");
const sglmulNativeCall = sglmulCompilerBlock.indexOf("fmul_rr(");
if (sglmulGuardStart < 0 || sglmulService < sglmulGuardStart || sglmulReturn < sglmulService ||
    sglmulAcquire < sglmulReturn || sglmulNativeCall < sglmulAcquire)
  fail("FPP FSGLMUL guarded service exit does not retire fmul_rr before operand acquisition");
for (const contract of [
  "bool single_extended_result = operation == 36 || operation == 39", "case 39: // FSGLMUL",
  "mpfr_mul (single_extended, fpu.registers[reg].f, value.f, rnd)",
  "mpfr_zero_p (value.f) && mpfr_inf_p (fpu.registers[reg].f)",
  "mpfr_inf_p (value.f) && mpfr_zero_p (fpu.registers[reg].f)",
  "set_format (EXTENDED_PREC)", "mpfr_check_range (single_extended, t, rnd)",
]) requireText(fpuMpfrSource, contract, "MPFR FSGLMUL single-significand/extended-exponent contract");
for (const contract of [
  'name: "fsglmul_extended_destination_one_sided"', 'name: "fsglmul_extended_source_one_sided"',
  'name: "fsglmul_double_round_midpoint", selector: "27", destination: "3f ff 00 00 80 00 00 80 80 00 00 81", source: "3f fe 00 00 ff ff ff ff 00 00 00 00", output: "3f ff 00 00 80 00 01 00 00 00 00 00"',
  'name: "fsglmul_single_nearest_independent_fpcr"', 'name: "fsglmul_single_plus"', 'name: "fsglmul_negative_minus"',
  'name: "fsglmul_extended_exponent_no_single_overflow"', 'name: "fsglmul_extended_exponent_no_single_underflow"',
  'name: "fsglmul_zero_infinity_invalid"', 'name: "fsglmul_infinity_zero_invalid"',
  'name: "fsglmul_destination_qnan"', 'name: "fsglmul_source_qnan"',
  'name: "fsglmul_source_snan_destination_precedence"', 'name: "fsglmul_destination_snan_quiet"',
  'name: "fsglmul_fp7_self_alias"', 'name: "fsglmul_fp7_destination_reseed"',
  'name: "fsglmul_postincrement_source"', 'name: "fsglmul_predecrement_source"', 'name: "fsglmul_accrued_preserve"',
  'const profile = [...output.matchAll(/JIT_FALLBACK op=([0-9a-f]+) pc=([0-9a-f]+)/gi)]',
  'const capturePc = auditedOpcode === "f239" ? "00001010" : "0000100c"',
  'const storePc = auditedOpcode === "f239" ? "00001014" : "00001010"',
  'const passProfile = `${auditedOpcode}@00001008 f200@${capturePc} f239@${storePc}`',
  'const expectedProfile = `f239@00001000 ${passProfile} ${passProfile}`',
  'profile === expectedProfile',
  'const auditedOpcode = item.aliasFp7 ? "f200"', 'output.includes(`JIT_FALLBACK op=${auditedOpcode} pc=00001008`)',
  'B2_NATIVE_ASSERT_PC: "0x1008"', 'strict full-JIT: opcode fallback pc=00001000 op=f200',
  'service_pass=${servicePass} strict_pass=${strictPass}',
]) requireText(fppSglmulServiceMatrix, contract, "FPP FSGLMUL service matrix");
console.log("METRIC structural_fpp_sglmul_service_vectors=22");
console.log("METRIC structural_fpp_sglmul_strict_rejections=1");
console.log("METRIC structural_fpp_sglmul_one_sided_operands=2");
console.log("METRIC structural_fpp_sglmul_direct_single_round=1");
const sglmulMidStart = midfuncSource.indexOf("MIDFUNC(2,fsglmul_rr,(FRW d, FR s))");
const sglmulMidEnd = midfuncSource.indexOf("MENDFUNC(2,fsglmul_rr,(FRW d, FR s))", sglmulMidStart);
if (sglmulMidStart < 0 || sglmulMidEnd < 0) fail("missing retired FSGLMUL MIDFUNC fsglmul_rr");
requireText(midfuncSource.slice(sglmulMidStart, sglmulMidEnd), "raw_fsglmul_rr(d, s);", "retired FSGLMUL MIDFUNC fsglmul_rr");
if ((midfuncSource.match(/\bfsglmul_rr\b/g) || []).length !== 2)
  fail("FSGLMUL MIDFUNC fsglmul_rr gained a configured caller");
const sglmulRawStart = codegenSource.indexOf("LOWFUNC(NONE,NONE,2,raw_fsglmul_rr,(FRW d, FR s))");
const sglmulRawEnd = codegenSource.indexOf("LENDFUNC(NONE,NONE,2,raw_fsglmul_rr,(FRW d, FR s))", sglmulRawStart);
if (sglmulRawStart < 0 || sglmulRawEnd < 0) fail("missing retired FSGLMUL raw boundary raw_fsglmul_rr");
const sglmulRawBody = codegenSource.slice(sglmulRawStart, sglmulRawEnd);
let sglmulPrevious = -1;
for (const contract of [
  "FCVT_sd(SCRATCH_F64_1, d);", "FCVT_sd(SCRATCH_F64_2, s);",
  "FMUL_sss(SCRATCH_F64_1, SCRATCH_F64_1, SCRATCH_F64_2);", "FCVT_ds(d, SCRATCH_F64_1);",
]) {
  requireText(sglmulRawBody, contract, "retired FSGLMUL raw boundary raw_fsglmul_rr");
  const position = sglmulRawBody.indexOf(contract);
  if (position <= sglmulPrevious) fail("retired FSGLMUL raw conversion/multiply order changed");
  sglmulPrevious = position;
}
if ((codegenSource.match(/\braw_fsglmul_rr\b/g) || []).length !== 2)
  fail("FSGLMUL raw boundary raw_fsglmul_rr gained a configured caller");
const sglmulFmulSingleSites = (codegenSource.match(/\bFMUL_sss\(/g) || []).length;
const sglmulFmulDoubleSites = (codegenSource.match(/\bFMUL_ddd\(/g) || []).length;
const sglmulFcvtSdSites = (codegenSource.match(/\bFCVT_sd\(/g) || []).length;
const sglmulFcvtDsSites = (codegenSource.match(/\bFCVT_ds\(/g) || []).length;
if (sglmulFmulSingleSites !== 1 || sglmulFmulDoubleSites !== 1 || sglmulFcvtSdSites !== 7 || sglmulFcvtDsSites !== 6)
  fail(`FSGLMUL residual sites FMUL_s/d FCVT_sd/ds=${sglmulFmulSingleSites}/${sglmulFmulDoubleSites} ${sglmulFcvtSdSites}/${sglmulFcvtDsSites}, expected 1/1 7/6`);
console.log("METRIC structural_fpp_sglmul_unreachable_raw_boundaries=1");
console.log("METRIC structural_fpp_sglmul_unreachable_single_emitters=1");
console.log("METRIC structural_fpp_sglmul_unreachable_double_emitters=1");
const sincosCompilerStart = fppCompilerOperation.indexOf("case 0x30:\t\t\t\t\t\t/* FSINCOS */");
const sincosCompilerEnd = fppCompilerOperation.indexOf("case 0x38:\t\t\t\t\t\t/* FCMP */", sincosCompilerStart);
if (sincosCompilerStart < 0 || sincosCompilerEnd < 0) fail("FPP FSINCOS compiler boundary is incomplete");
const sincosCompilerBlock = fppCompilerOperation.slice(sincosCompilerStart, sincosCompilerEnd);
for (const contract of ["case 0x30:", "case 0x37:", "jit_disable.fsincos", "FAIL(1);", "return;"])
  requireText(sincosCompilerBlock, contract, "FPP FSINCOS configured service boundary");
for (const forbidden of ["get_fp_value(opcode, extra)", "fsin_rr(", "fcos_rr("])
  if (sincosCompilerBlock.includes(forbidden)) fail(`FPP FSINCOS compiler case retains forbidden ${forbidden}`);
for (const contract of [
  "if (operation < 8)", "mpfr_set_prec (value.f, EXTENDED_PREC)", "set_format (EXTENDED_PREC)",
  "MPFR_DECL_INIT (sin_result, prec)", "MPFR_DECL_INIT (cos_result, prec)",
  "mpfr_sin_cos (sin_result, cos_result, value.f, rnd)",
  "mpfr_setsign (sin_result, sin_result, value.nan_sign, MPFR_RNDN)",
  "mpfr_setsign (cos_result, cos_result, value.nan_sign, MPFR_RNDN)",
  "if (reg2 != reg)", "set_fp_register (reg2, cos_result", "t >> 2, rnd, false",
  "set_fp_register (reg, sin_result", "t & 3, rnd, true",
]) requireText(fpuMpfrSource, contract, "MPFR FSINCOS dual-result service contract");
for (const contract of [
  'name:"fsincos_positive_zero"', 'name:"fsincos_negative_zero"', 'name:"fsincos_pio2"', 'name:"fsincos_pi"',
  'name:"fsincos_extended_source_single"', 'name:"fsincos_extended_source_double"',
  'name:"fsincos_directed_single_plus"', 'name:"fsincos_directed_single_minus"',
  'name:"fsincos_same_register_sine_wins"', 'name:"fsincos_fp7_sine_destination"',
  'name:"fsincos_positive_infinity"', 'name:"fsincos_negative_infinity"',
  'name:"fsincos_qnan_payload",cosreg:3,input:x.nqnan,sine:x.nqnan,cosine:x.nqnan,operationFpsr:"09000000",fpsr:"09000000"',
  'name:"fsincos_snan_quiet"', 'name:"fsincos_single_underflow_sine"',
  'name:"fsincos_postincrement_source"', 'name:"fsincos_predecrement_source"', 'name:"fsincos_accrued_preserve"',
  'const sinreg=a.sinreg??0', 'same=a.cosreg===sinreg',
  'o.includes(`JIT_FALLBACK op=${auditedOpcode} pc=00001008`)', 'B2_NATIVE_ASSERT_PC:"0x1008"',
  'strict full-JIT: opcode fallback pc=00001000 op=f200', 'service_pass=${sp} strict_pass=${st}', 'sc.length:18', 'ss.length:1',
]) requireText(fppSincosServiceMatrix, contract, "FPP FSINCOS service matrix");
console.log("METRIC structural_fpp_sincos_service_vectors=18");
console.log("METRIC structural_fpp_sincos_strict_rejections=1");
console.log("METRIC structural_fpp_sincos_dual_results=1");
console.log("METRIC structural_fpp_sincos_destination_registers=8");
const controlCompilerStart = fppCompilerOperation.indexOf("case 4:\t\t\t\t\t\t\t/* FMOVEM <ea>,<control> */");
const controlCompilerEnd = fppCompilerOperation.indexOf("case 0:", controlCompilerStart);
if (controlCompilerStart < 0 || controlCompilerEnd < 0) fail("FPP direct control compiler boundary is incomplete");
const controlCompilerBlock = fppCompilerOperation.slice(controlCompilerStart, controlCompilerEnd);
for (const contract of [
  "case 4:", "case 5:", "jit_disable.fmovec", "#if defined(CPU_AARCH64) || defined(CPU_aarch64)",
  "(opcode & 0x30) == 0 || (opcode & 0x3f) == 0x3c", "mixed masks", "FAIL(1);", "return;",
]) requireText(controlCompilerBlock, contract, "FPP direct/immediate control service boundary");
const controlGuardStart = controlCompilerBlock.indexOf("#if defined(CPU_AARCH64) || defined(CPU_aarch64)");
const controlDirectStart = controlCompilerBlock.indexOf("/* rare */");
if (controlGuardStart < 0 || controlDirectStart < 0 || controlGuardStart >= controlDirectStart)
  fail("FPP direct/immediate control service gate does not precede residual mutation paths");
for (const contract of [
  "list = (extra >> 10) & 7", "if (list == 0)", "case 1:", "case 2:", "case 4:",
  "m68k_dreg (regs, reg) = fpu.instruction_address", "m68k_areg (regs, reg) = fpu.instruction_address",
  "set_fpsr (m68k_dreg (regs, reg))", "set_fpcr (m68k_dreg (regs, reg))",
  "fpu.instruction_address = m68k_areg (regs, reg)", "fpu.instruction_address = next_ilong ()",
]) requireText(fpuMpfrSource, contract, "MPFR direct/immediate control transfer contract");
for (const contract of [
  'name: "fpcr_to_d7_masks_68040"', 'name: "d7_to_fpcr_then_d1"', 'name: "immediate_to_fpcr_then_d2"',
  'name: "fpsr_to_d6_masks_reserved_bits"', 'name: "d6_to_fpsr_then_d0"', 'name: "immediate_to_fpsr_then_d3"',
  'name: "fpiar_to_d5_full_width"', 'name: "fpiar_to_a7_full_width"', 'name: "d5_to_fpiar_then_d4"',
  'name: "a5_to_fpiar_then_d4"', 'name: "immediate_to_fpiar_then_d4"',
  'B2_TEST_SECOND_PC: "0x1008"', 'B2_NATIVE_ASSERT_PC: "0x1008"',
  'output.includes(`JIT_FALLBACK op=${item.auditedOpcode} pc=00001008`)',
  'strict full-JIT: opcode fallback pc=00001000 op=${item.opcode}',
  "expectedService = process.env.CASE ? selectedCases.length : 11",
  "expectedStrict = process.env.CASE ? selectedStrict.length : 4",
]) requireText(fppControlDirectServiceMatrix, contract, "FPP direct/immediate control service matrix");
console.log("METRIC structural_fpp_control_direct_service_vectors=11");
console.log("METRIC structural_fpp_control_direct_strict_rejections=4");
console.log("METRIC structural_fpp_control_direct_registers=3");
console.log("METRIC structural_fpp_control_direct_ea_classes=3");
for (const contract of [
  "if (!get_fp_addr (opcode, &addr, true))", "if (!get_fp_addr (opcode, &addr, false))",
  "nwords = (list & 1) + ((list >> 1) & 1) + ((list >> 2) & 1)",
  "if (mode == 4)", "addr -= nwords * 4", "if (list & 4)", "put_long (addr, get_fpcr ())",
  "if (list & 2)", "put_long (addr, get_fpsr ())", "if (list & 1)",
  "put_long (addr, fpu.instruction_address)", "set_fpcr (get_long (addr))",
  "set_fpsr (get_long (addr))", "fpu.instruction_address = get_long (addr)",
  "else if (mode == 3)", "m68k_areg (regs, reg) = addr",
]) requireText(fpuMpfrSource, contract, "MPFR basic control-memory ordering and EA contract");
for (const contract of [
  'name: "to_aind_all_order"', 'name: "to_aind_sparse_order"', 'name: "to_postinc_a7_all"',
  'name: "to_predec_a7_all"', 'name: "to_d16_a0_all"', 'name: "to_absw_all"', 'name: "to_absl_all"',
  'name: "from_aind_all_order"', 'name: "from_aind_sparse_order"', 'name: "from_postinc_a7_all"',
  'name: "from_predec_a7_all"', 'name: "from_d16_a0_all"', 'name: "from_absw_all"',
  'name: "from_absl_all"', 'name: "from_pc_d16_all"',
  'const all = "00 00 ff b0 0b cd ef a8 ca fe ba be"',
  'const sparse = "00 00 ff b0 ca fe ba be"',
  'B2_TEST_MEMDUMP:', 'B2_TEST_SECOND_PC: "0x1008"', 'B2_NATIVE_ASSERT_PC: "0x1008"',
  'output.includes(`JIT_FALLBACK op=${item.opcode} pc=00001008`)',
  'strict full-JIT: opcode fallback pc=00001000 op=${item.opcode}',
  "expectedService = process.env.CASE ? selected.length : 15",
  "expectedStrict = process.env.CASE ? selectedStrict.length : 3",
]) requireText(fppControlMemoryBasicMatrix, contract, "FPP basic control-memory service matrix");
for (const forbidden of ["F236", "F237"])
  if (fppControlMemoryBasicMatrix.includes(forbidden)) fail(`FPP basic control-memory scope leaked indexed opcode ${forbidden}`);
console.log("METRIC structural_fpp_control_memory_basic_service_vectors=15");
console.log("METRIC structural_fpp_control_memory_basic_strict_rejections=3");
console.log("METRIC structural_fpp_control_memory_basic_masks=2");
console.log("METRIC structural_fpp_control_memory_basic_ea_classes=7");
for (const contract of [
  "case 6:", "*addr = get_disp_ea_020 (m68k_areg (regs, reg), next_iword())",
  "case 3:", "pc = m68k_getpc ()", "*addr = get_disp_ea_020 (pc, next_iword())",
]) requireText(fpuMpfrSource, contract, "MPFR indexed control-memory EA contract");
for (const contract of [
  'name:"to_brief_a0_d1_long_scale2_all"', 'name:"to_brief_a0_d7_word_scale8_sparse"',
  'name:"to_full_direct_word_bd_all"', 'name:"to_full_preindexed_word_outer_all"',
  'name:"to_full_postindexed_word_outer_sparse"', 'name:"from_brief_a0_d1_long_scale2_all"',
  'name:"from_brief_a0_d7_word_scale8_sparse"', 'name:"from_full_direct_word_bd_all"',
  'name:"from_full_preindexed_word_outer_all"', 'name:"from_full_postindexed_word_outer_sparse"',
  'name:"from_pc_brief_d1_long_all"', 'name:"from_pc_full_direct_word_bd_sparse"',
  'name:"from_pc_full_preindexed_word_outer_all"', 'name:"from_pc_full_postindexed_word_outer_sparse"',
  '1926 0FF4 0000', 'poisonFpiar="F23C 8400 0BAD C0DE"',
  'B2_TEST_REPLAY_FPCR:a.expected?"30":fpcr', 'B2_TEST_REPLAY_FPSR:a.expected?"04000000":fpsr',
  'B2_TEST_MEMDUMP:', 'B2_TEST_SECOND_PC:"0x1008"',
  'B2_NATIVE_ASSERT_PC:"0x1008"', 'o.includes(`JIT_FALLBACK op=${a.opcode} pc=00001008`)',
  'strict full-JIT: opcode fallback pc=00001000 op=${a.opcode}',
  "const es=process.env.CASE?sc.length:14", "et=process.env.CASE?ss.length:3",
]) requireText(fppControlMemoryIndexedMatrix, contract, "FPP indexed control-memory service matrix");
console.log("METRIC structural_fpp_control_memory_indexed_service_vectors=14");
console.log("METRIC structural_fpp_control_memory_indexed_strict_rejections=3");
console.log("METRIC structural_fpp_control_memory_indexed_indirect_forms=4");
console.log("METRIC structural_fpp_control_memory_indexed_pc_forms=4");
const fmovemCompilerStart = fppCompilerOperation.indexOf("case 6:\t\t\t\t\t\t\t/* FMOVEM <ea>,<reglist> */");
const fmovemCompilerEnd = fppCompilerOperation.indexOf("case 4:", fmovemCompilerStart);
if (fmovemCompilerStart < 0 || fmovemCompilerEnd < 0) fail("FPP FMOVEM compiler boundary is incomplete");
const fmovemCompilerBlock = fppCompilerOperation.slice(fmovemCompilerStart, fmovemCompilerEnd);
for (const contract of [
  "case 6:", "case 7:", "jit_disable.fmovem", "#if defined(CPU_AARCH64) || defined(CPU_aarch64)",
  "if ((extra & 0x0800) == 0)", "binary64", "Static FMOVEM lists", "FAIL(1);", "return;",
]) requireText(fmovemCompilerBlock, contract, "FPP static FMOVEM exact service boundary");
const fmovemGate = fmovemCompilerBlock.indexOf("if ((extra & 0x0800) == 0)");
const fmovemAcquire = fmovemCompilerBlock.indexOf("get_fp_ad(opcode)");
if (fmovemGate < 0 || fmovemAcquire < 0 || fmovemGate >= fmovemAcquire)
  fail("FPP static FMOVEM service gate does not precede EA acquisition");
for (const contract of [
  "static bool\nfpuop_fmovem_register", "set_format (EXTENDED_PREC)",
  "if (extra & 0x800)", "list = extra & 0xff", "case 040:", "if (extra & 0x1000)",
  "for (i = 7; i >= 0; i--)", "addr -= 12", "for (i = 0; i < 8; i++)",
  "if (list & (0x80 >> i))", "extract_to_extended", "set_from_extended",
]) requireText(fpuMpfrSource, contract, "MPFR static FMOVEM list/order contract");
for (const contract of [
  'name:"static_to_aind_all_exact80"', 'name:"static_to_predec_all_direct_mask"',
  'name:"static_to_brief_sparse_reversed_mask"', 'name:"static_to_full_preindexed_all"',
  'name:"static_from_aind_all_exact80"', 'name:"static_from_postinc_all_exact80"',
  'name:"static_from_brief_sparse_reversed_mask"', 'name:"static_from_full_postindexed_all"',
  'name:"static_from_pc_brief_all"', 'name:"static_from_pc_full_preindexed_sparse"',
  'v0="3f ff 00 00 80 00 00 00 00 00 00 01"',
  'v1="7f fe 00 00 ff ff ff ff ff ff ff ff"',
  'v7="ff ff 00 00 c0 00 de ad be ef 12 34"',
  'B2_TEST_REPLAY_FP0_EXT:E(a.direction==="to"?v0:poison0)',
  'B2_TEST_SECOND_PC:"0x1008"', 'B2_NATIVE_ASSERT_PC:"0x1008"',
  'o.includes(`JIT_FALLBACK op=${a.opcode} pc=00001008`)',
  'strict full-JIT: opcode fallback pc=00001000 op=${a.opcode}',
  "const es=process.env.CASE?sc.length:10", "et=process.env.CASE?ss.length:3",
]) requireText(fppFmovemStaticServiceMatrix, contract, "FPP static FMOVEM service matrix");
console.log("METRIC structural_fpp_fmovem_static_service_vectors=10");
console.log("METRIC structural_fpp_fmovem_static_strict_rejections=3");
console.log("METRIC structural_fpp_fmovem_static_exact80_registers=3");
console.log("METRIC structural_fpp_fmovem_static_masks=2");
const fmovemDynamicFails = [...fmovemCompilerBlock.matchAll(/case 1:\s*\/\* dynamic pred \*\//g)].map((match) => match.index);
const fmovemAcquires = [...fmovemCompilerBlock.matchAll(/get_fp_ad\(opcode\)/g)].map((match) => match.index);
if (fmovemDynamicFails.length !== 4 || fmovemAcquires.length !== 2 ||
    fmovemDynamicFails[0] >= fmovemAcquires[0] || fmovemDynamicFails[2] >= fmovemAcquires[1])
  fail("FPP dynamic FMOVEM service boundaries do not precede both EA acquisitions");
for (const contract of [
  "if (extra & 0x800)", "(extra >> 4) & 7", "& 0xff",
  "if (extra & 0x1000)", "case 040:", "addr -= 12",
  "if (list & (1 << i))", "if (list & (0x80 >> i))",
  "extract_to_extended", "set_from_extended",
]) requireText(fpuMpfrSource, contract, "MPFR dynamic FMOVEM list/order contract");
for (const contract of [
  'name:"dynamic_to_aind_all_exact80_d7"',
  'name:"dynamic_to_predec_all_direct_mask_d3"',
  'name:"dynamic_to_brief_sparse_reversed_mask_d0"',
  'name:"dynamic_to_full_preindexed_all_d7"',
  'name:"dynamic_from_aind_all_exact80_d0"',
  'name:"dynamic_from_postinc_all_exact80_d7"',
  'name:"dynamic_from_brief_sparse_reversed_mask_d3"',
  'name:"dynamic_from_full_postindexed_all_d7"',
  'name:"dynamic_from_pc_brief_all_d0"',
  'name:"dynamic_from_pc_full_preindexed_sparse_d7"',
  'name:"dynamic_to_predec_empty_low_byte_d7"',
  'name:"dynamic_from_postinc_empty_low_byte_d0"',
  'v0="3f ff 00 00 80 00 00 00 00 00 00 01"',
  'v1="7f fe 00 00 ff ff ff ff ff ff ff ff"',
  'v7="ff ff 00 00 c0 00 de ad be ef 12 34"',
  'regs:{7:0x000001c1}', 'regs:{0:0x000001c1}',
  'B2_TEST_REPLAY_FP0_EXT:E(a.direction==="to"?v0:poison0)',
  'B2_TEST_SECOND_PC:"0x1008"', 'B2_NATIVE_ASSERT_PC:"0x1008"',
  'o.includes(`JIT_FALLBACK op=${a.opcode} pc=00001008`)',
  'strict full-JIT: opcode fallback pc=00001000 op=${a.opcode}',
  "const es=process.env.CASE?sc.length:12", "et=process.env.CASE?ss.length:3",
]) requireText(fppFmovemDynamicServiceMatrix, contract, "FPP dynamic FMOVEM service matrix");
console.log("METRIC structural_fpp_fmovem_dynamic_service_vectors=12");
console.log("METRIC structural_fpp_fmovem_dynamic_strict_rejections=3");
console.log("METRIC structural_fpp_fmovem_dynamic_mask_registers=3");
console.log("METRIC structural_fpp_fmovem_dynamic_empty_masks=2");
const addCompilerStart = fppCompilerOperation.indexOf("case 0x22:\t\t\t\t\t\t/* FADD */");
const addCompilerEnd = fppCompilerOperation.indexOf("case 0x23:\t\t\t\t\t\t/* FMUL */", addCompilerStart);
if (addCompilerStart < 0 || addCompilerEnd < 0) fail("FPP add compiler boundary is incomplete");
const addCompilerBlock = fppCompilerOperation.slice(addCompilerStart, addCompilerEnd);
for (const contract of [
  "case 0x22:", "case 0x62:", "case 0x66:", "jit_disable.fadd",
  "#if defined(CPU_aarch64) || defined(CPU_AARCH64)", "FAIL(1);", "return;",
]) requireText(addCompilerBlock, contract, "FPP add AArch64 service boundary");
const addGuardStart = addCompilerBlock.indexOf("#if defined(CPU_aarch64) || defined(CPU_AARCH64)");
const addService = addCompilerBlock.indexOf("FAIL(1);", addGuardStart);
const addReturn = addCompilerBlock.indexOf("return;", addService);
const addAcquire = addCompilerBlock.indexOf("get_fp_value(opcode, extra)");
const addNativeCall = addCompilerBlock.indexOf("fadd_rr(");
if (addGuardStart < 0 || addService < addGuardStart || addReturn < addService ||
    addAcquire < addReturn || addNativeCall < addAcquire)
  fail("FPP add guarded service exit does not retire fadd_rr before operand acquisition");
const addRootSpellings = (fppCompilerSource.match(/\bfadd_rr\(/g) || []).length;
if (addRootSpellings !== 1)
  fail(`retired add MIDFUNC fadd_rr configured-root spellings=${addRootSpellings} expected=1`);
const addMidfuncCallers = (midfuncSource.match(/\bfadd_rr\(/g) || []).length;
if (addMidfuncCallers !== 0)
  fail(`retired add MIDFUNC fadd_rr gained ${addMidfuncCallers} MIDFUNC caller spellings`);
const addMidStart = midfuncSource.indexOf("MIDFUNC(2,fadd_rr,(FRW d, FR s))");
const addMidEnd = midfuncSource.indexOf("MENDFUNC(2,fadd_rr", addMidStart);
if (addMidStart < 0 || addMidEnd < 0) fail("missing retired add MIDFUNC fadd_rr");
requireText(midfuncSource.slice(addMidStart, addMidEnd), "raw_fadd_rr(d, s);", "retired add MIDFUNC fadd_rr");
const addRawStart = codegenSource.indexOf("LOWFUNC(NONE,NONE,2,raw_fadd_rr,(FRW d, FR s))");
const addRawEnd = codegenSource.indexOf("LENDFUNC(NONE,NONE,2,raw_fadd_rr", addRawStart);
if (addRawStart < 0 || addRawEnd < 0) fail("missing retired add raw boundary raw_fadd_rr");
requireText(codegenSource.slice(addRawStart, addRawEnd), "FADD_ddd(d, d, s);", "retired add raw boundary raw_fadd_rr");
requireText(codegenHeaderSource, "#define FADD_ddd(Dd,Dn,Dm)", "retired add emitter FADD_ddd");
console.log("METRIC structural_fpp_add_unreachable_midfuncs=1");
console.log("METRIC structural_fpp_add_unreachable_raw_boundaries=1");
console.log("METRIC structural_fpp_add_unreachable_emitters=1");
for (const contract of [
  "case 34: // FSADD", "case 38: // FDADD",
  "mpfr_add (value2, fpu.registers[reg].f, value.f, rnd)",
  "(extra & 0x3f) == 34 || (extra & 0x3f) == 38",
  "mpfr_zero_p (value2) && t != 0", "select_binary_nan (reg, value, &nan_bits, &nan_sign)",
  "|| operation == 32 || operation == 34", "case 34: // FADD",
  "mpfr_add (direct, fpu.registers[reg].f, value.f, rnd)",
  "operation == 32 || operation == 34 || operation == 35",
]) requireText(fpuMpfrSource, contract, "MPFR FADD/FSADD/FDADD service contract");
for (const contract of [
  'name:"fadd_extended_low_bit"', 'name:"fadd_exact_extended"',
  'name:"fadd_single_nearest"', 'name:"fadd_single_plus"',
  'name:"fadd_double_nearest"', 'name:"fadd_double_plus"',
  'name:"fsadd_forced_nearest"', 'name:"fsadd_forced_plus"',
  'name:"fsadd_forced_extended_operand",selector:"62",destination:x.p1,source:x.singleHalfPlusExtendedBit,output:x.singleNext,operationFpsr:"00000208",fpsr:"00000008"',
  'name:"fdadd_forced_nearest"', 'name:"fdadd_forced_plus"',
  'name:"fdadd_forced_extended_operand",selector:"66",destination:x.p1,source:x.doubleHalfPlusExtendedBit,output:x.doubleNext,operationFpsr:"00000208",fpsr:"00000008"',
  'name:"fadd_exact_cancellation_nearest"', 'name:"fadd_exact_cancellation_minus"',
  'name:"fsadd_exact_cancellation_no_underflow",selector:"62",destination:x.p1,source:x.n1,output:x.pz,operationFpsr:"04000000",fpsr:"04000000"',
  'name:"fdadd_exact_cancellation_minus_no_underflow",selector:"66",destination:x.p1,source:x.n1,output:x.nz,fpcr:"20",operationFpsr:"0c000000",fpsr:"0c000000"',
  'name:"fadd_negative_zero_pair"', 'name:"fadd_mixed_zero_nearest"',
  'name:"fsadd_forced_overflow",selector:"62",destination:x.max,source:x.max,output:x.pinf,operationFpsr:"02001248",fpsr:"02000048"',
  'name:"fdadd_forced_overflow",selector:"66",destination:x.max,source:x.max,output:x.pinf,operationFpsr:"02001248",fpsr:"02000048"',
  'name:"fsadd_forced_underflow",selector:"62",destination:x.minNormal,source:x.negLargestSubnormal,output:x.pz,operationFpsr:"04000a28",fpsr:"04000028"',
  'name:"fdadd_forced_underflow",selector:"66",destination:x.minNormal,source:x.negLargestSubnormal,output:x.pz,operationFpsr:"04000a28",fpsr:"04000028"',
  'name:"fadd_opposite_infinities_invalid",selector:"22",destination:x.pinf,source:x.ninf,output:x.canonical,operationFpsr:"01002080",fpsr:"01000080"',
  'name:"fsadd_same_infinities"',
  'name:"fadd_destination_qnan_precedence",selector:"22",destination:x.qnanA,source:x.nqnanB,output:x.qnanA,operationFpsr:"01000000",fpsr:"01000000"',
  'name:"fadd_source_snan_quiet_then_destination_precedence",selector:"22",destination:x.qnanA,source:x.nsnanB,output:x.qnanA,operationFpsr:"01004080",fpsr:"01000080"',
  'name:"fadd_destination_snan_quiet_then_destination_precedence",selector:"22",destination:x.snanA,source:x.nqnanB,output:x.quietA,operationFpsr:"01004080",fpsr:"01000080",destinationSnan:true',
  'name:"fsadd_source_only_snan",selector:"62",destination:x.p1,source:x.nsnanB,output:"ff ff 00 00 c0 00 de ad be ef 12 34",operationFpsr:"09004080",fpsr:"09000080"',
  'name:"fadd_fp7_self_alias"',
  'name:"fsadd_fp7_destination_reseed"', 'name:"fadd_postincrement_source"',
  'name:"fdadd_predecrement_source"', 'name:"fadd_accrued_preserve"',
  'B2_NATIVE_ASSERT_PC:"0x1008"', 'strict full-JIT: opcode fallback pc=00001000 op=f200',
  'fm=[...o.matchAll(/JIT_FALLBACK op=([0-9a-f]+) pc=([0-9a-f]+)/gi)]',
  'snanProfile="f239@00001000 f239@00001008 f200@00001010 f239@00001014 f239@00001008 f200@00001010 f239@00001014"',
  'attributionOk=!a.destinationSnan||fm.join(" ")===snanProfile',
  'service_pass=${sp} strict_pass=${st}', 'sc.length:35', 'ss.length:3',
]) requireText(fppAddServiceMatrix, contract, "FPP add service matrix");
console.log("METRIC structural_fpp_add_service_vectors=35");
console.log("METRIC structural_fpp_add_strict_rejections=3");
console.log("METRIC structural_fpp_add_extended_operands=1");
console.log("METRIC structural_fpp_add_cancellation_range=1");
const mulCompilerStart = fppCompilerOperation.indexOf("case 0x23:\t\t\t\t\t\t/* FMUL */");
const mulCompilerEnd = fppCompilerOperation.indexOf("case 0x24:\t\t\t\t\t\t/* FSGLDIV */", mulCompilerStart);
if (mulCompilerStart < 0 || mulCompilerEnd < 0) fail("FPP multiply compiler boundary is incomplete");
const mulCompilerBlock = fppCompilerOperation.slice(mulCompilerStart, mulCompilerEnd);
for (const contract of ["case 0x23:", "case 0x63:", "case 0x67:", "jit_disable.fmul", "#if defined(CPU_aarch64) || defined(CPU_AARCH64)", "FAIL(1);", "return;"])
  requireText(mulCompilerBlock, contract, "FPP multiply AArch64 service boundary");
const mulGuardStart = mulCompilerBlock.indexOf("#if defined(CPU_aarch64) || defined(CPU_AARCH64)");
const mulService = mulCompilerBlock.indexOf("FAIL(1);", mulGuardStart);
const mulReturn = mulCompilerBlock.indexOf("return;", mulService);
const mulAcquire = mulCompilerBlock.indexOf("get_fp_value(opcode, extra)");
const mulNativeCall = mulCompilerBlock.indexOf("fmul_rr(");
if (mulGuardStart < 0 || mulService < mulGuardStart || mulReturn < mulService ||
    mulAcquire < mulReturn || mulNativeCall < mulAcquire)
  fail("FPP multiply guarded service exit does not retire fmul_rr before operand acquisition");
const mulRootSpellings = (fppCompilerSource.match(/\bfmul_rr\(/g) || []).length;
if (mulRootSpellings !== 2)
  fail(`retired multiply MIDFUNC fmul_rr configured-root spellings=${mulRootSpellings} expected=2`);
const mulMidfuncCallers = (midfuncSource.match(/\bfmul_rr\(/g) || []).length;
if (mulMidfuncCallers !== 0)
  fail(`retired multiply MIDFUNC fmul_rr gained ${mulMidfuncCallers} MIDFUNC caller spellings`);
const mulMidStart = midfuncSource.indexOf("MIDFUNC(2,fmul_rr,(FRW d, FR s))");
const mulMidEnd = midfuncSource.indexOf("MENDFUNC(2,fmul_rr", mulMidStart);
if (mulMidStart < 0 || mulMidEnd < 0) fail("missing retired multiply MIDFUNC fmul_rr");
const mulMidBody = midfuncSource.slice(mulMidStart, mulMidEnd);
for (const contract of ["s = f_readreg(s);", "d = f_rmw(d);", "raw_fmul_rr(d, s);"])
  requireText(mulMidBody, contract, "retired multiply MIDFUNC fmul_rr");
const mulRawStart = codegenSource.indexOf("LOWFUNC(NONE,NONE,2,raw_fmul_rr,(FRW d, FR s))");
const mulRawEnd = codegenSource.indexOf("LENDFUNC(NONE,NONE,2,raw_fmul_rr", mulRawStart);
if (mulRawStart < 0 || mulRawEnd < 0) fail("missing retired multiply raw boundary raw_fmul_rr");
requireText(codegenSource.slice(mulRawStart, mulRawEnd), "FMUL_ddd(d, d, s);", "retired multiply raw boundary raw_fmul_rr");
requireText(codegenHeaderSource, "#define FMUL_ddd(Dd,Dn,Dm)", "retired multiply emitter FMUL_ddd");
for (const contract of [
  "case 35: // FSMUL", "case 39: // FDMUL", "mpfr_mul (value2, fpu.registers[reg].f, value.f, rnd)",
  "(extra & 0x3f) == 35 || (extra & 0x3f) == 39", "|| operation == 35 || operation == 40;",
  "case 35: // FMUL", "mpfr_mul (direct, fpu.registers[reg].f, value.f, rnd)",
  "operation == 32 || operation == 34 || operation == 35 || operation == 40",
]) requireText(fpuMpfrSource, contract, "MPFR FMUL/FSMUL/FDMUL service contract");
for (const contract of [
  'name:"fmul_exact_extended"', 'name:"fmul_extended_low_bit"',
  'name:"fmul_single_nearest"', 'name:"fmul_single_plus"', 'name:"fmul_double_nearest"', 'name:"fmul_double_plus"',
  'name:"fsmul_forced_destination_extended",selector:"63",destination:x.singleMulDest,source:x.singleMulSource,output:"3f ff 00 00 cc de 6b 00 00 00 00 00"',
  'name:"fsmul_forced_source_extended",selector:"63",destination:x.singleMulDestB,source:x.singleMulSourceB,output:"3f ff 00 00 dd 28 c1 00 00 00 00 00"',
  'name:"fdmul_forced_destination_extended",selector:"67",destination:x.doubleMulDest,source:x.doubleMulSource,output:"40 00 00 00 a6 04 cf 49 25 ec 00 00"',
  'name:"fdmul_forced_source_extended",selector:"67",destination:x.doubleMulDestB,source:x.doubleMulSourceB,output:"3f ff 00 00 fa 37 36 d1 8f c2 78 00"',
  'name:"fmul_zero_infinity_invalid"', 'name:"fmul_infinity_zero_invalid"',
  'name:"fsmul_forced_overflow"', 'name:"fdmul_forced_overflow"', 'name:"fsmul_forced_underflow"', 'name:"fdmul_forced_underflow"',
  'name:"fmul_destination_qnan_precedence"', 'name:"fmul_source_snan_quiet_then_destination_precedence"',
  'name:"fmul_destination_snan_quiet_then_destination_precedence"', 'name:"fsmul_source_only_snan"',
  'name:"fmul_fp7_self_alias"', 'name:"fsmul_fp7_destination_reseed"', 'name:"fmul_postincrement_source"',
  'name:"fdmul_predecrement_source"', 'name:"fmul_accrued_preserve"',
  'profile=[...o.matchAll(/JIT_FALLBACK op=([0-9a-f]+) pc=([0-9a-f]+)/gi)]',
  'capturePc=auditedOpcode==="f239"?"00001010":"0000100c"',
  'storePc=auditedOpcode==="f239"?"00001014":"00001010"',
  'passProfile=`${auditedOpcode}@00001008 f200@${capturePc} f239@${storePc}`',
  'expectedProfile=`f239@00001000 ${passProfile} ${passProfile}`',
  'profile===expectedProfile',
  'B2_NATIVE_ASSERT_PC:"0x1008"', 'strict full-JIT: opcode fallback pc=00001000 op=f200',
  'service_pass=${sp} strict_pass=${st}', 'sc.length:30', 'ss.length:3',
]) requireText(fppMulServiceMatrix, contract, "FPP multiply service matrix");
console.log("METRIC structural_fpp_mul_service_vectors=30");
console.log("METRIC structural_fpp_mul_strict_rejections=3");
console.log("METRIC structural_fpp_mul_one_sided_extended_operands=4");
console.log("METRIC structural_fpp_mul_serviced_root_calls=2");
console.log("METRIC structural_fpp_mul_unreachable_midfuncs=1");
console.log("METRIC structural_fpp_mul_unreachable_raw_boundaries=1");
console.log("METRIC structural_fpp_mul_unreachable_emitters=1");
const subCompilerStart = fppCompilerOperation.indexOf("case 0x28:\t\t\t\t\t\t/* FSUB */");
const subCompilerEnd = fppCompilerOperation.indexOf("case 0x30:\t\t\t\t\t\t/* FSINCOS */", subCompilerStart);
if (subCompilerStart < 0 || subCompilerEnd < 0) fail("FPP subtract compiler boundary is incomplete");
const subCompilerBlock = fppCompilerOperation.slice(subCompilerStart, subCompilerEnd);
for (const contract of ["case 0x28:", "case 0x68:", "case 0x6c:", "jit_disable.fsub", "#if defined(CPU_aarch64) || defined(CPU_AARCH64)", "FAIL(1);", "return;"])
  requireText(subCompilerBlock, contract, "FPP subtract AArch64 service boundary");
const subGuardStart = subCompilerBlock.indexOf("#if defined(CPU_aarch64) || defined(CPU_AARCH64)");
const subService = subCompilerBlock.indexOf("FAIL(1);", subGuardStart);
const subReturn = subCompilerBlock.indexOf("return;", subService);
const subAcquire = subCompilerBlock.indexOf("get_fp_value(opcode, extra)");
const subNativeCall = subCompilerBlock.indexOf("fsub_rr(");
if (subGuardStart < 0 || subService < subGuardStart || subReturn < subService ||
    subAcquire < subReturn || subNativeCall < subAcquire)
  fail("FPP subtract guarded service exit does not retire fsub_rr before operand acquisition");
const subRootSpellings = (fppCompilerSource.match(/\bfsub_rr\(/g) || []).length;
if (subRootSpellings !== 2)
  fail(`retired subtract MIDFUNC fsub_rr source spellings=${subRootSpellings} expected=2`);
const configuredFcmpStart = subCompilerEnd;
const configuredFcmpEnd = fppCompilerOperation.indexOf("case 0x3a:", configuredFcmpStart);
const configuredFcmpBlock = fppCompilerOperation.slice(configuredFcmpStart, configuredFcmpEnd);
requireText(configuredFcmpBlock, "#if defined(CPU_aarch64) || defined(CPU_AARCH64)", "configured AArch64 FCMP path");
requireText(configuredFcmpBlock, "fcompare_result_rr(FP_RESULT, reg, src);", "configured AArch64 FCMP path");
const fcmpElse = configuredFcmpBlock.indexOf("#else");
const fcmpLegacySub = configuredFcmpBlock.indexOf("fsub_rr(FP_RESULT, src);");
if (fcmpElse < 0 || fcmpLegacySub < fcmpElse)
  fail("legacy FCMP fsub_rr spelling is no longer confined to the non-AArch64 branch");
const subMidfuncCallers = (midfuncSource.match(/\bfsub_rr\(/g) || []).length;
if (subMidfuncCallers !== 0)
  fail(`retired subtract MIDFUNC fsub_rr gained ${subMidfuncCallers} MIDFUNC caller spellings`);
const subMidStart = midfuncSource.indexOf("MIDFUNC(2,fsub_rr,(FRW d, FR s))");
const subMidEnd = midfuncSource.indexOf("MENDFUNC(2,fsub_rr", subMidStart);
if (subMidStart < 0 || subMidEnd < 0) fail("missing retired subtract MIDFUNC fsub_rr");
const subMidBody = midfuncSource.slice(subMidStart, subMidEnd);
for (const contract of ["s = f_readreg(s);", "d = f_rmw(d);", "raw_fsub_rr(d, s);"])
  requireText(subMidBody, contract, "retired subtract MIDFUNC fsub_rr");
const subRawStart = codegenSource.indexOf("LOWFUNC(NONE,NONE,2,raw_fsub_rr,(FRW d, FR s))");
const subRawEnd = codegenSource.indexOf("LENDFUNC(NONE,NONE,2,raw_fsub_rr", subRawStart);
if (subRawStart < 0 || subRawEnd < 0) fail("missing retired subtract raw boundary raw_fsub_rr");
requireText(codegenSource.slice(subRawStart, subRawEnd), "FSUB_ddd(d, d, s);", "retired subtract raw boundary raw_fsub_rr");
requireText(codegenHeaderSource, "#define FSUB_ddd(Dd,Dn,Dm)", "retired subtract emitter FSUB_ddd");
for (const contract of [
  "case 40: // FSUB", "case 40: // FSSUB", "case 44: // FDSUB",
  "mpfr_sub (direct, fpu.registers[reg].f, value.f, rnd)",
  "mpfr_sub (value2, fpu.registers[reg].f, value.f, rnd)",
  "(extra & 0x3f) == 40 || (extra & 0x3f) == 44", "|| operation == 40;",
  "mpfr_zero_p (value2) && t != 0", "select_binary_nan (reg, value, &nan_bits, &nan_sign)",
  "operation == 32 || operation == 34 || operation == 35 || operation == 40",
]) requireText(fpuMpfrSource, contract, "MPFR FSUB/FSSUB/FDSUB service contract");
for (const contract of [
  'name:"fsub_extended_low_bit"', 'name:"fsub_exact_extended"',
  'name:"fsub_single_nearest"', 'name:"fsub_single_plus"', 'name:"fsub_double_nearest"', 'name:"fsub_double_plus"',
  'name:"fsub_single_source_extended",selector:"28",destination:x.singleSubDestB,source:x.singleSubSourceB,output:"3f fe 00 00 8a ae 9b 00 00 00 00 00",fpcr:"40"',
  'name:"fsub_double_destination_extended",selector:"28",destination:x.doubleSubDest,source:x.doubleSubSource,output:"3f fd 00 00 f3 e7 a9 6e 58 bd 20 00",fpcr:"80"',
  'name:"fssub_forced_destination_extended",selector:"68",destination:x.singleSubDest,source:x.singleSubSource,output:"3f fe 00 00 a0 a6 58 00 00 00 00 00"',
  'name:"fssub_forced_source_extended",selector:"68",destination:x.singleSubDestB,source:x.singleSubSourceB,output:"3f fe 00 00 8a ae 9b 00 00 00 00 00"',
  'name:"fdsub_forced_destination_extended",selector:"6c",destination:x.doubleSubDest,source:x.doubleSubSource,output:"3f fd 00 00 f3 e7 a9 6e 58 bd 20 00"',
  'name:"fdsub_forced_source_extended",selector:"6c",destination:x.doubleSubDestB,source:x.doubleSubSourceB,output:"3f fe 00 00 a0 13 9b 5a 74 7a b0 00"',
  'name:"fsub_exact_cancellation_nearest"', 'name:"fsub_exact_cancellation_minus"',
  'name:"fssub_exact_cancellation_no_underflow"', 'name:"fdsub_exact_cancellation_minus_no_underflow"',
  'name:"fssub_forced_overflow"', 'name:"fdsub_forced_overflow"', 'name:"fssub_forced_underflow"', 'name:"fdsub_forced_underflow"',
  'name:"fsub_same_infinities_invalid"', 'name:"fsub_opposite_infinities"',
  'name:"fssub_same_infinities_invalid"', 'name:"fdsub_opposite_infinities"',
  'name:"fsub_destination_qnan_precedence"', 'name:"fsub_source_snan_quiet_then_destination_precedence"',
  'name:"fsub_destination_snan_quiet_then_destination_precedence"', 'name:"fssub_source_only_snan"',
  'name:"fssub_destination_qnan_precedence"', 'name:"fdsub_source_snan_quiet_then_destination_precedence"',
  'name:"fsub_fp7_self_alias"', 'name:"fssub_fp7_destination_reseed"',
  'name:"fsub_postincrement_source"', 'name:"fdsub_predecrement_source"', 'name:"fsub_accrued_preserve"',
  'profile=[...o.matchAll(/JIT_FALLBACK op=([0-9a-f]+) pc=([0-9a-f]+)/gi)]',
  'auditedOpcode=a.aliasFp7?"f200":a.ea==="postinc"?"f218":a.ea==="predec"?"f220":"f239"',
  'capturePc=auditedOpcode==="f239"?"00001010":"0000100c"',
  'storePc=auditedOpcode==="f239"?"00001014":"00001010"',
  'passProfile=`${auditedOpcode}@00001008 f200@${capturePc} f239@${storePc}`',
  'expectedProfile=`f239@00001000 ${passProfile} ${passProfile}`',
  'profile===expectedProfile',
  'o.includes(`JIT_FALLBACK op=${auditedOpcode} pc=00001008`)',
  'B2_NATIVE_ASSERT_PC:"0x1008"', 'strict full-JIT: opcode fallback pc=00001000 op=f200',
  'service_pass=${sp} strict_pass=${st}', 'sc.length:40', 'ss.length:3',
]) requireText(fppSubServiceMatrix, contract, "FPP subtract service matrix");
console.log("METRIC structural_fpp_sub_service_vectors=40");
console.log("METRIC structural_fpp_sub_strict_rejections=3");
console.log("METRIC structural_fpp_sub_one_sided_extended_operands=6");
console.log("METRIC structural_fpp_sub_unreachable_midfuncs=1");
console.log("METRIC structural_fpp_sub_unreachable_raw_boundaries=1");
console.log("METRIC structural_fpp_sub_unreachable_emitters=1");
console.log("METRIC structural_fpp_shadow_dirty_ownership=1");
console.log("METRIC structural_fpp_fallback_ccr_rematerialization=1");

const fmoveSingleEmitter = functionBody(
  codegenSource,
  "LOWFUNC(NONE,NONE,2,raw_fmov_to_s_rr",
  "LENDFUNC(NONE,NONE,2,raw_fmov_to_s_rr",
  "native FPP IEEE-single destination conversion",
);
for (const contract of [
  "MRS_NZCV_x(REG_WORK4);", "MRS_FPSR_x(REG_WORK3);", "MSR_FPSR_x(REG_WORK1);",
  "FCVT_sd(SCRATCH_F64_1, s);", "FMOV_ws(d, SCRATCH_F64_1);",
  "FPSR_EXCEPTION_SNAN", "FPSR_EXCEPTION_OVFL", "FPSR_EXCEPTION_UNFL", "FPSR_EXCEPTION_INEX2",
  "FPSR_ACCR_IOP", "FPSR_ACCR_OVFL | FPSR_ACCR_INEX", "FPSR_ACCR_UNFL", "FPSR_ACCR_INEX",
  "MSR_NZCV_x(REG_WORK4);",
]) requireText(fmoveSingleEmitter, contract, "native FPP IEEE-single destination conversion");
for (const contract of [
  "fpu.registers[i].nan_bits >> 11", "std::memcpy(&regs.jit_fpregs[i], &bits, sizeof(bits))",
  "fpu.registers[i].nan_bits = (bits & 0x000fffffffffffffULL) << 11",
]) requireText(compatSource, contract, "native FPP NaN payload boundary");
for (const contract of [
  'name: "positive_zero"', 'name: "negative_zero"',
  'name: "positive_infinity"', 'name: "negative_infinity"',
  'name: "max_finite_exact"', 'name: "min_normal_exact"', 'name: "min_subnormal_exact"',
  'name: "normal_inexact_nearest"', 'name: "normal_inexact_plus_inf"',
  'name: "positive_overflow_nearest"', 'name: "positive_overflow_zero"',
  'name: "positive_overflow_minus_inf"', 'name: "positive_overflow_plus_inf"',
  'name: "negative_overflow_zero"', 'name: "negative_overflow_minus_inf"',
  'name: "half_min_subnormal_nearest"', 'name: "half_min_subnormal_plus_inf"',
  'name: "negative_half_min_subnormal_minus_inf"',
  'name: "quiet_nan_payload_positive"', 'name: "quiet_nan_payload_negative"',
  'name: "memory_aind_overflow"', 'B2_TEST_REPLAY_FPSR: "0c55ff08"',
  'B2_TEST_REPLAY_FPCR: item.fpcr ?? "0"', 'B2_JIT_STRICT_FULL: "1"',
  'B2_NATIVE_ASSERT_PC:', 'sr === "271f"', 'cow_clone', 'cow_release',
  'const expected = process.env.CASE ? 1 : 21',
]) requireText(fppFmoveSingleDestinationMatrix, contract, "native FPP IEEE-single destination matrix");
console.log("METRIC structural_fpp_fmove_single_destination_exact_native_vectors=21");
console.log("METRIC structural_fpp_fmove_single_destination_fpcr_modes=4");
console.log("METRIC structural_fpp_fmove_single_destination_range_classes=4");
console.log("METRIC structural_fpp_fmove_single_destination_nan_payloads=2");
console.log("METRIC structural_fpp_fmove_single_destination_fpsr_contracts=4");

/* Generator-level ownership remains deliberately singular. Two-operand ADD
 * ownership belongs to INIT_REGS/EXIT_REGS inside the MIDFUNC; only the private
 * pre-write memory EA crosses that call and uses this explicit pin. */
for (const contract of [
  "int g_jvlock_reg=-1;",
  "int g_jvlock_active=0;",
  "g_jvlock_active = 1;",
  "setlock(hr);",
  "if (hr >= 0) unlock2(hr);",
]) requireText(compatSource, contract, "singular generator JIT value ownership");
for (const contract of [
  "extern int g_jvlock_reg; extern int g_jvlock_active;",
  "g_jvlock_active && g_jvlock_reg >= 0",
  "live.state[r].realreg == g_jvlock_reg",
  "disassociate(r);",
]) requireText(allocatorSource, contract, "singular generator JIT value ownership");

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

/* MOVEM is emitted directly by gencomp rather than through the four legacy
 * MOVEM MIDFUNC definitions. Keep the transfer cursor private from all sixteen
 * architectural registers: a list may name the EA base itself. Writeback is a
 * single publication after the loop, while no-update control modes discard the
 * cursor. The mask word must also be decoded before any PC-relative EA words. */
const movemLoadGenerator = functionBody(
  gencompSource,
  "static void\ngenmovemel (uae_u16 opcode)",
  "static void\ngenmovemle (uae_u16 opcode)",
  "MOVEM memory-to-register generator",
);
const movemStoreGenerator = functionBody(
  gencompSource,
  "static void\ngenmovemle (uae_u16 opcode)",
  "static void\nduplicate_carry (void)",
  "MOVEM register-to-memory generator",
);
for (const [body, context] of [
  [movemLoadGenerator, "MOVEM memory-to-register generator"],
  [movemStoreGenerator, "MOVEM register-to-memory generator"],
] as const) {
  requireBefore(body, "gen_nextiword ()", "genamode (", `${context} extension order`);
  requireText(body, "GENA_MOVEM_NO_INC", `${context} EA ownership`);
}
for (const contract of [
  'const char *movem_srca = "movem_srca";',
  'comprintf("\\tint movem_srca=scratchie++;\\n"',
  '"\\tmov_l_rr(movem_srca,srca);\\n");',
  '"\\t\\t\\treadlong(%s,i,scratchie);\\n"',
  '"\\t\\t\\treadword(%s,i,scratchie);\\n"',
  'comprintf("\\t\\t\\tmov_l_rr(8+dstreg,movem_srca);\\n");',
]) {
  requireText(movemLoadGenerator, contract, "MOVEM private load cursor");
}
requireBefore(
  movemLoadGenerator,
  '"\\t\\t\\treadlong(%s,i,scratchie);\\n"',
  'comprintf("\\t\\t\\tmov_l_rr(8+dstreg,movem_srca);\\n");',
  "MOVEM postincrement load writeback",
);
for (const contract of [
  'const char *movem_dsta = "movem_dsta";',
  'comprintf("\\tint movem_dsta=scratchie++;\\n"',
  '"\\tmov_l_rr(movem_dsta,srca);\\n");',
  '"\\t\\t\\tsub_l_ri(%s,4);\\n"',
  '"\\t\\t\\tmov_l_rr(tmp,15-i);\\n"',
  '"\\t\\t\\twritelong(%s,tmp,scratchie);\\n"',
  'comprintf("\\t\\t\\tmov_l_rr(8+dstreg,movem_dsta);\\n");',
]) {
  requireText(movemStoreGenerator, contract, "MOVEM private store cursor");
}
requireBefore(
  movemStoreGenerator,
  '"\\t\\t\\tsub_l_ri(%s,4);\\n"',
  '"\\t\\t\\tmov_l_rr(tmp,15-i);\\n"',
  "MOVEM predecrement address-before-value order",
);
requireBefore(
  movemStoreGenerator,
  '"\\t\\t\\twritelong(%s,tmp,scratchie);\\n"',
  'comprintf("\\t\\t\\tmov_l_rr(8+dstreg,movem_dsta);\\n");',
  "MOVEM predecrement writeback publication",
);
const movemA64LoadStart = requireText(movemLoadGenerator, "#if defined(CPU_AARCH64)", "MOVEM AArch64 load path");
const movemA64LoadEnd = requireText(movemLoadGenerator.slice(movemA64LoadStart), "#else", "MOVEM AArch64 load path") + movemA64LoadStart;
const movemA64StoreStart = requireText(movemStoreGenerator, "#if defined(CPU_AARCH64)", "MOVEM AArch64 store path");
const movemA64StoreEnd = requireText(movemStoreGenerator.slice(movemA64StoreStart), "#else", "MOVEM AArch64 store path") + movemA64StoreStart;
for (const [body, forbidden, context] of [
  [movemLoadGenerator.slice(movemA64LoadStart, movemA64LoadEnd), "add_l_ri(srca", "MOVEM AArch64 load cursor"],
  [movemStoreGenerator.slice(movemA64StoreStart, movemA64StoreEnd), "sub_l_ri(srca", "MOVEM AArch64 store cursor"],
] as const) {
  if (body.includes(forbidden)) fail(`${context}: architectural base is still walked directly`);
}
const countText = (text: string, needle: string): number => text.split(needle).length - 1;
if (countText(generatedSource, "int movem_srca=scratchie++") !== 32)
  fail("generated MOVEM load cursor coverage changed from 32 handlers");
if (countText(generatedSource, "int movem_dsta=scratchie++") !== 24)
  fail("generated MOVEM store cursor coverage changed from 24 handlers");
if (countText(generatedSource, "mov_l_rr(8+dstreg,movem_srca)") !== 4)
  fail("generated MOVEM postincrement load writeback coverage changed from 4 handlers");
if (countText(generatedSource, "mov_l_rr(8+dstreg,movem_dsta)") !== 4)
  fail("generated MOVEM predecrement store writeback coverage changed from 4 handlers");
const movemExactVectors = [
  "movem_l_postinc_base_alias_native",
  "movem_w_postinc_base_alias_native",
  "movem_l_predec_base_alias_native",
  "movem_w_predec_base_alias_native",
  "movem_l_aind_load_base_alias_native",
  "movem_l_aind_store_base_alias_native",
  "movem_l_all_live_roundtrip_native",
  "movem_l_all_live_special_native",
  "movem_zero_mask_native",
  "movem_l_control_modes_native",
  "movem_l_pc_modes_native",
];
for (const name of movemExactVectors) {
  requireText(harnessSource, `TESTS[${name}]`, `MOVEM exact-native vector ${name}`);
  requireText(harnessSource, `[${name}]=1`, `MOVEM exact-native gate ${name}`);
  requireText(harnessSource, `[${name}]=2`, `MOVEM exact-PC replay count ${name}`);
  requireText(harnessSource, `[${name}]=0x`, `MOVEM exact-PC anchor ${name}`);
  requireText(activeRiskySource, name, `MOVEM active-risky vector ${name}`);
}
requireText(harnessSource, "B2_JIT_ALL_SPECIAL_MEM=1", "MOVEM forced special-memory path");
for (const contract of [
  "movem_predec_cursor_base_locked",
  "[movem_predec_cursor_base_locked]=13",
  "[movem_predec_cursor_base_locked]=22",
  "[movem_predec_cursor_base_locked]=1",
]) {
  requireText(regallocPressureSource, contract, "MOVEM forced cursor/base allocator collision");
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

/* ADD's MIDFUNC register initialisers own both operands while arithmetic
 * allocates its destination. Memory destinations additionally pin the private
 * pre-write EA through X publication and ordered storage; this is the value
 * that cannot be reconstructed after postincrement/predecrement writeback. */
const addGenerator = functionBody(gencompSource, "     case i_ADD:", "     case i_ADDA:", "ADD generator");
for (const contract of [
  'genamode (curi->smode, "srcreg", curi->size, "src", GENA_GETV_FETCH, GENA_MOVEM_DO_INC);',
  'genamode (curi->dmode, "dstreg", curi->size, "dst", GENA_GETV_FETCH, GENA_MOVEM_DO_INC);',
  'comprintf("\\tint __adddstealock=jit_value_lock(dsta);\\n");',
  'genflags (flag_add, curi->size, "", "src", "dst");',
  'genastore ("dst", curi->dmode, "dstreg", curi->size, "dst");',
  'comprintf("\\tjit_value_unlock(__adddstealock);\\n");',
]) requireText(addGenerator, contract, "ADD EA lifecycle");
if (addGenerator.includes("__addsrclock")) {
  fail("ADD generator reintroduced a redundant source lock outside MIDFUNC operand ownership");
}
requireBefore(addGenerator, "jit_value_lock(dsta)", "genflags (flag_add", "ADD EA before arithmetic");
requireBefore(addGenerator, 'genastore ("dst"', "jit_value_unlock(__adddstealock)", "ADD EA through store");
const generatedAddFunctions = (generatedSource.match(/void REGPARAM2 op_[0-9a-f]+_0_comp_(?:ff|nf)[^{]*\/\* ADD \*\//g) || []).length;
const generatedAddSourceLocks = (generatedSource.match(/int __addsrclock=jit_value_lock\(src\);/g) || []).length;
const generatedAddSourceUnlocks = (generatedSource.match(/jit_value_unlock\(__addsrclock\);/g) || []).length;
const generatedAddEaLocks = (generatedSource.match(/int __adddstealock=jit_value_lock\(dsta\);/g) || []).length;
const generatedAddEaUnlocks = (generatedSource.match(/jit_value_unlock\(__adddstealock\);/g) || []).length;
if (generatedAddFunctions !== 208 || generatedAddSourceLocks !== 0 || generatedAddSourceUnlocks !== 0 ||
    generatedAddEaLocks !== 126 || generatedAddEaUnlocks !== 126) {
  fail(`generated ADD ownership: functions=${generatedAddFunctions} source=${generatedAddSourceLocks}/${generatedAddSourceUnlocks} ea=${generatedAddEaLocks}/${generatedAddEaUnlocks}`);
}
for (const contract of [
  "MIDFUNC(2,jnf_ADD_b,(RW1 d, RR1 s))",
  "MIDFUNC(2,jnf_ADD_w,(RW2 d, RR2 s))",
  "MIDFUNC(2,jnf_ADD_l,(RW4 d, RR4 s))",
  "MIDFUNC(2,jff_ADD_b,(RW1 d, RR1 s))",
  "MIDFUNC(2,jff_ADD_w,(RW2 d, RR2 s))",
  "MIDFUNC(2,jff_ADD_l,(RW4 d, RR4 s))",
  "BFI_wwii(d, REG_WORK1, 0, 8);",
  "BFI_wwii(d, REG_WORK1, 0, 16);",
  "BFXIL_xxii(d, REG_WORK1, 24, 8);",
  "BFXIL_xxii(d, REG_WORK1, 16, 16);",
  "ADDS_www(d, d, s);",
  "DUPLICACTE_CARRY",
]) requireText(midfunc2Source, contract, "ADD width/flags lowering");
for (const [variant, width] of [
  ["jnf", "b"], ["jnf", "w"], ["jnf", "l"],
  ["jff", "b"], ["jff", "w"], ["jff", "l"],
] as const) {
  const body = functionBody(
    midfunc2Source,
    `MIDFUNC(2,${variant}_ADD_${width},`,
    `MENDFUNC(2,${variant}_ADD_${width},`,
    `${variant}_ADD_${width} operand ownership`,
  );
  requireText(body, `INIT_REGS_${width}(d, s);`, `${variant}_ADD_${width} operand acquisition`);
  requireText(body, "EXIT_REGS(d, s);", `${variant}_ADD_${width} operand release`);
  requireBefore(body, `INIT_REGS_${width}(d, s);`, "EXIT_REGS(d, s);", `${variant}_ADD_${width} operand lifecycle`);
}
for (const contract of [
  "add_b_postinc_source_dreg_collision",
  '[add_b_postinc_source_dreg_collision]=21',
  '[add_b_postinc_source_dreg_collision]=0',
  '[add_b_postinc_source_dreg_collision]=1',
  "add_b_postinc_x_ea_collision",
  '[add_b_postinc_x_ea_collision]=20',
  '[add_b_postinc_x_ea_collision]=17',
  '[add_b_postinc_x_ea_collision]=1',
]) requireText(regallocPressureSource, contract, "ADD source/EA/X allocator pressure");

const addExactVectors = [
  "add_core_b_reg_zero_native", "add_core_w_reg_overflow_native", "add_core_l_reg_carry_native",
  "add_core_b_self_alias_native", "add_core_w_self_alias_native", "add_core_l_self_alias_native",
  "add_core_b_imm_overflow_native", "add_core_w_imm_carry_native",
  "add_core_l_imm_large_native", "add_core_l_imm_negative_native",
  "add_core_b_reg_noflags_native", "add_core_w_reg_noflags_native", "add_core_l_reg_noflags_native",
  "add_core_b_aind_source_special_native", "add_core_w_postinc_source_native",
  "add_core_l_predec_source_native", "add_core_b_d16_source_native",
  "add_core_w_index_source_special_native", "add_core_l_absw_source_native",
  "add_core_b_absl_source_special_native", "add_core_w_pc16_source_native",
  "add_core_l_pcindex_source_native", "add_core_b_aind_dest_special_native",
  "add_core_w_postinc_dest_native", "add_core_l_predec_dest_native",
  "add_core_b_d16_dest_native", "add_core_w_index_dest_special_native",
  "add_core_l_absw_dest_native", "add_core_b_absl_dest_special_native",
  "add_core_b_a7_postinc_dest_native", "add_core_b_a7_predec_dest_native",
  "add_core_b_addi_postinc_dest_native", "add_core_b_postinc_dest_native",
  "add_core_b_postinc_dest_noflags_native",
];
for (const fragment of [
  "declare -a ADD_NATIVE_MATRIX_NAMES=(",
  'TEST_ORDER+=("${ADD_NATIVE_MATRIX_NAMES[@]}")',
  'for _add_name in "${ADD_NATIVE_MATRIX_NAMES[@]}"; do\n    NATIVE_REPLAY_TESTS["$_add_name"]=1\n    NATIVE_REPLAY_PC["$_add_name"]=0x1000\n    NATIVE_REPLAY_COUNT["$_add_name"]=2',
  'for _add_name in "${ADD_NATIVE_MATRIX_NAMES[@]}"; do\n    RISKY_TESTS["$_add_name"]=1',
]) requireText(harnessSource, fragment, "ADD exact-native matrix/replay contract");
for (const name of addExactVectors) {
  for (const fragment of [
    `TESTS[${name}]=`,
    `EXPECTED_REG_FIELDS[${name}]=`,
    `INIT_REGS[${name}]=`,
  ]) requireText(harnessSource, fragment, `ADD exact-native vector ${name}`);
}
const addMemoryVectors = [
  "add_core_b_aind_source_special_native", "add_core_w_postinc_source_native",
  "add_core_l_predec_source_native", "add_core_b_d16_source_native",
  "add_core_w_index_source_special_native", "add_core_l_absw_source_native",
  "add_core_b_absl_source_special_native", "add_core_w_pc16_source_native",
  "add_core_l_pcindex_source_native", "add_core_b_aind_dest_special_native",
  "add_core_w_postinc_dest_native", "add_core_l_predec_dest_native",
  "add_core_b_d16_dest_native", "add_core_w_index_dest_special_native",
  "add_core_l_absw_dest_native", "add_core_b_absl_dest_special_native",
  "add_core_b_a7_postinc_dest_native", "add_core_b_a7_predec_dest_native",
  "add_core_b_addi_postinc_dest_native", "add_core_b_postinc_dest_native",
  "add_core_b_postinc_dest_noflags_native",
];
for (const name of addMemoryVectors) {
  requireText(harnessSource, `TEST_MEMORY_BYTES[${name}]=`, `ADD memory bytes ${name}`);
  requireText(harnessSource, `NATIVE_REPLAY_BYTES[${name}]=`, `ADD native memory replay ${name}`);
}
for (const name of [
  "add_core_b_aind_source_special_native", "add_core_w_index_source_special_native",
  "add_core_b_absl_source_special_native", "add_core_b_aind_dest_special_native",
  "add_core_w_index_dest_special_native", "add_core_b_absl_dest_special_native",
]) requireText(harnessSource, `SPECIAL_MEMORY_TESTS[${name}]=1`, `ADD special-memory route ${name}`);
for (const name of [
  "add_core_b_reg_noflags_native", "add_core_w_reg_noflags_native",
  "add_core_l_reg_noflags_native", "add_core_b_postinc_dest_noflags_native",
]) requireText(harnessSource, `TESTS[${name}]=`, `ADD no-flags vector ${name}`);
requireText(
  harnessSource,
  'TESTS[add_core_b_postinc_dest_native]="D118 40C2 1028 FFFF"',
  "ADD.B D0,(A0)+ exact-native regression",
);
requireText(
  activeRiskySource,
  "add_core_b_postinc_dest_native",
  "ADD.B D0,(A0)+ active mismatch-first regression",
);

/* ADDA is a no-flags, full-address-register lifecycle. ADDA.W must sign-extend
 * its source and both widths must retain a fetched value across aliased
 * postincrement and destination RMW without publishing or consuming XNZVC. */
const addaGenerator = functionBody(gencompSource, "     case i_ADDA:", "     case i_ADDX:", "ADDA generator");
for (const contract of [
  "global_preserve_postinc_source = 1;",
  'genamode (curi->smode, "srcreg", curi->size, "src", GENA_GETV_FETCH, GENA_MOVEM_DO_INC);',
  "global_preserve_postinc_source = 0;",
  'comprintf("\\tint __addasrclock=is_const(src) ? -1 : jit_value_lock(src);\\n");',
  'case sz_word: comprintf("\\tjnf_ADDA_w(dst,src);\\n"); break;',
  'case sz_long: comprintf("\\tjnf_ADDA_l(dst,src);\\n"); break;',
  'comprintf("\\tif (__addasrclock >= 0) jit_value_unlock(__addasrclock);\\n");',
]) requireText(addaGenerator, contract, "ADDA generator lifecycle");
requireBefore(addaGenerator, "global_preserve_postinc_source = 1;", "genamode (curi->smode", "ADDA postincrement ownership request");
requireBefore(addaGenerator, "genamode (curi->smode", "global_preserve_postinc_source = 0;", "ADDA postincrement ownership reset");
requireBefore(addaGenerator, "jit_value_lock(src)", "jnf_ADDA_w(dst,src)", "ADDA source before word destination RMW");
requireBefore(addaGenerator, "jnf_ADDA_l(dst,src)", "jit_value_unlock(__addasrclock)", "ADDA source through long destination RMW");
for (const contract of [
  "static int global_preserve_postinc_source;",
  "mode == Aipi && global_preserve_postinc_source",
  'comprintf("\\tint __adda_writebacksrclock = dodgy ? jit_value_lock(%s) : -1;\\n", name);',
  'comprintf("\\tif (__adda_writebacksrclock >= 0) jit_value_unlock(__adda_writebacksrclock);\\n");',
]) requireText(gencompSource, contract, "ADDA aliased postincrement ownership");
const generatedAddaFunctions = (generatedSource.match(/void REGPARAM2 op_[0-9a-f]+_0_comp_(?:ff|nf)[^{]*\/\* ADDA \*\//g) || []).length;
const generatedAddaFlagLive = (generatedSource.match(/^void REGPARAM2 op_[0-9a-f]+_0_comp_ff[^\n]*\/\* ADDA \*\//gm) || []).length;
const generatedAddaNoFlags = (generatedSource.match(/^void REGPARAM2 op_[0-9a-f]+_0_comp_nf[^\n]*\/\* ADDA \*\//gm) || []).length;
const generatedAddaWordCalls = (generatedSource.match(/jnf_ADDA_w\(dst,src\);/g) || []).length;
const generatedAddaLongCalls = (generatedSource.match(/jnf_ADDA_l\(dst,src\);/g) || []).length;
const generatedAddaSourceLocks = (generatedSource.match(/int __addasrclock=is_const\(src\) \? -1 : jit_value_lock\(src\);/g) || []).length;
const generatedAddaSourceUnlocks = (generatedSource.match(/if \(__addasrclock >= 0\) jit_value_unlock\(__addasrclock\);/g) || []).length;
const generatedAddaWritebackLocks = (generatedSource.match(/int __adda_writebacksrclock = dodgy \? jit_value_lock\(src\) : -1;/g) || []).length;
const generatedAddaWritebackUnlocks = (generatedSource.match(/if \(__adda_writebacksrclock >= 0\) jit_value_unlock\(__adda_writebacksrclock\);/g) || []).length;
if (generatedAddaFunctions !== 52 || generatedAddaFlagLive !== 26 || generatedAddaNoFlags !== 26 ||
    generatedAddaWordCalls !== 26 || generatedAddaLongCalls !== 26 ||
    generatedAddaSourceLocks !== 52 || generatedAddaSourceUnlocks !== 52 ||
    generatedAddaWritebackLocks !== 4 || generatedAddaWritebackUnlocks !== 4) {
  fail(`generated ADDA ownership: functions=${generatedAddaFunctions} split=${generatedAddaFlagLive}/${generatedAddaNoFlags} calls=${generatedAddaWordCalls}/${generatedAddaLongCalls} source=${generatedAddaSourceLocks}/${generatedAddaSourceUnlocks} writeback=${generatedAddaWritebackLocks}/${generatedAddaWritebackUnlocks}`);
}
const addaWordImmBody = functionBody(midfunc2Source, "MIDFUNC(2,jnf_ADDA_w_imm,", "MENDFUNC(2,jnf_ADDA_w_imm,", "ADDA.W immediate");
for (const contract of [
  "if (isconst(d))", "set_const(d, (uae_u32)(live.state[d].val + (uae_s32)(uae_s16)v));",
  "uae_s16 tmp = (uae_s16)v;", "ADD_wwi(d, d, tmp);", "SUB_wwi(d, d, -tmp);",
  "SIGNED16_IMM_2_REG(REG_WORK1, tmp);", "ADD_www(d, d, REG_WORK1);",
]) requireText(addaWordImmBody, contract, "ADDA.W immediate/sign-extension lifecycle");
const addaLongImmBody = functionBody(midfunc2Source, "MIDFUNC(2,jnf_ADDA_l_imm,", "MENDFUNC(2,jnf_ADDA_l_imm,", "ADDA.L immediate");
for (const contract of [
  "if (isconst(d))", "set_const(d, live.state[d].val + v);", "ADD_wwi(d, d, v);",
  "SUB_wwi(d, d, -v);", "LOAD_U32(REG_WORK1, v);", "ADD_www(d, d, REG_WORK1);",
]) requireText(addaLongImmBody, contract, "ADDA.L immediate/full-width lifecycle");
const addaWordBody = functionBody(midfunc2Source, "MIDFUNC(2,jnf_ADDA_w,", "MENDFUNC(2,jnf_ADDA_w,", "ADDA.W dynamic");
for (const contract of [
  "COMPCALL(jnf_ADDA_w_imm)(d, live.state[s].val & 0xffff);",
  "INIT_REGS_w(d, s);", "ADD_wwwEX(d, d, s, EX_SXTH);", "EXIT_REGS(d, s);",
]) requireText(addaWordBody, contract, "ADDA.W dynamic/sign-extension lifecycle");
const addaLongBody = functionBody(midfunc2Source, "MIDFUNC(2,jnf_ADDA_l,", "MENDFUNC(2,jnf_ADDA_l,", "ADDA.L dynamic");
for (const contract of [
  "COMPCALL(jnf_ADDA_l_imm)(d, live.state[s].val);",
  "INIT_REGS_l(d, s);", "ADD_www(d, d, s);", "EXIT_REGS(d, s);",
]) requireText(addaLongBody, contract, "ADDA.L dynamic/full-width lifecycle");
for (const [name, body] of [
  ["ADDA.W immediate", addaWordImmBody], ["ADDA.L immediate", addaLongImmBody],
  ["ADDA.W dynamic", addaWordBody], ["ADDA.L dynamic", addaLongBody],
] as const) {
  for (const forbidden of ["ADDS_", "SUBS_", "DUPLICACTE_CARRY", "make_flags_live", "flags_carry_inverted"])
    if (body.includes(forbidden)) fail(`${name} unexpectedly mutates or materialises XNZVC through ${forbidden}`);
}
for (const contract of [
  "adda_w_postinc_source_dst_collision", "adda_l_postinc_source_dst_collision",
  "[adda_w_postinc_source_dst_collision]=21", "[adda_l_postinc_source_dst_collision]=21",
  "[adda_w_postinc_source_dst_collision]=8", "[adda_l_postinc_source_dst_collision]=8",
  "[adda_w_postinc_source_dst_collision]=0", "[adda_l_postinc_source_dst_collision]=0",
  "[adda_w_postinc_source_dst_collision]=1", "[adda_l_postinc_source_dst_collision]=1",
]) requireText(regallocPressureSource, contract, "ADDA source/writeback/destination allocator pressure");
const addaVectors = [
  "adda_core_w_dreg_positive_native", "adda_core_w_dreg_negative_native", "adda_core_l_dreg_wrap_native",
  "adda_core_w_areg_alias_native", "adda_core_l_areg_alias_native", "adda_core_w_max_fields_native",
  "adda_core_w_imm_small_positive_native", "adda_core_w_imm_small_negative_native",
  "adda_core_w_imm_large_positive_native", "adda_core_w_imm_large_negative_native",
  "adda_core_l_imm_small_positive_native", "adda_core_l_imm_small_negative_native",
  "adda_core_l_imm_large_positive_native", "adda_core_l_imm_large_negative_native",
  "adda_core_w_const_dst_wrap", "adda_core_l_const_dst_wrap", "adda_core_w_aind_alias_native",
  "adda_core_w_postinc_alias_native", "adda_core_w_predec_alias_native",
  "adda_core_l_postinc_alias_native", "adda_core_l_predec_alias_native", "adda_core_w_d16_source_native",
  "adda_core_w_index_source_special_native", "adda_core_l_absw_source_native",
  "adda_core_w_absl_source_special_native", "adda_core_w_pc16_source_native",
  "adda_core_l_pcindex_source_native", "adda_core_w_dreg_noflags_native", "adda_core_l_dreg_noflags_native",
];
const addaExactVectors = addaVectors.filter((name) => !name.includes("_const_dst_wrap"));
for (const fragment of [
  "declare -a ADDA_NATIVE_MATRIX_NAMES=(", 'TEST_ORDER+=("${ADDA_NATIVE_MATRIX_NAMES[@]}")',
  'for _adda_name in "${ADDA_NATIVE_MATRIX_NAMES[@]}"; do\n    NATIVE_REPLAY_TESTS["$_adda_name"]=1\n    NATIVE_REPLAY_PC["$_adda_name"]=0x1000\n    NATIVE_REPLAY_COUNT["$_adda_name"]=2',
  "unset 'NATIVE_REPLAY_TESTS[adda_core_w_const_dst_wrap]'",
  "unset 'NATIVE_REPLAY_TESTS[adda_core_l_const_dst_wrap]'",
  'for _adda_name in "${ADDA_NATIVE_MATRIX_NAMES[@]}"; do\n    RISKY_TESTS["$_adda_name"]=1',
]) requireText(harnessSource, fragment, "ADDA matrix/replay contract");
for (const name of addaVectors) {
  for (const fragment of [`TESTS[${name}]=`, `EXPECTED_REG_FIELDS[${name}]=`, `INIT_REGS[${name}]=`])
    requireText(harnessSource, fragment, `ADDA vector ${name}`);
  requireText(activeRiskySource, name, `ADDA active mismatch-first vector ${name}`);
}
const addaMemoryVectors = [
  "adda_core_w_aind_alias_native", "adda_core_w_postinc_alias_native", "adda_core_w_predec_alias_native",
  "adda_core_l_postinc_alias_native", "adda_core_l_predec_alias_native", "adda_core_w_d16_source_native",
  "adda_core_w_index_source_special_native", "adda_core_l_absw_source_native",
  "adda_core_w_absl_source_special_native", "adda_core_w_pc16_source_native", "adda_core_l_pcindex_source_native",
];
for (const name of addaMemoryVectors) {
  requireText(harnessSource, `TEST_MEMORY_BYTES[${name}]=`, `ADDA memory bytes ${name}`);
  requireText(harnessSource, `NATIVE_REPLAY_BYTES[${name}]=`, `ADDA native memory replay ${name}`);
}
for (const name of ["adda_core_w_index_source_special_native", "adda_core_w_absl_source_special_native"])
  requireText(harnessSource, `SPECIAL_MEMORY_TESTS[${name}]=1`, `ADDA special-memory route ${name}`);

/* Bcc is a flags-consuming, flags-preserving dynamic block edge. Every
 * generated target is compile-time pointer arithmetic: byte/word explicit sign
 * extension and arm_ADD_l_ri_hostptr's SXTW contract cover all signed widths,
 * while conditional handlers register both targets without owning guest data. */
const bccGenerator = functionBody(gencompSource, "     case i_Bcc:", "     case i_LEA:", "Bcc generator");
for (const contract of [
  'comprintf("\\tuintptr v,v1,v2;\\n");',
  'genamode (curi->smode, "srcreg", curi->size, "src", GENA_GETV_FETCH, GENA_MOVEM_DO_INC);',
  'case sz_byte: comprintf("\\tsign_extend_8_rr(src,src);\\n"); break;',
  'case sz_word: comprintf("\\tsign_extend_16_rr(src,src);\\n"); break;',
  'case sz_long: break;',
  'comprintf("\\tsub_l_ri(src,m68k_pc_offset-m68k_pc_offset_thisinst-2);\\n");',
  'comprintf("\\tarm_ADD_l_ri_hostptr(src,(uintptr)comp_pc_p);\\n");',
  'comprintf("\\tarm_ADD_ptr_ri(src,m68k_pc_offset);\\n");',
  'comprintf("\\tarm_ADD_ptr_ri(PC_P,m68k_pc_offset);\\n");',
  '"\\tregister_branch(v1,v2,%d);\\n",',
  'comprintf("\\tmake_flags_live();\\n");',
  'comprintf("\\tmov_l_rr(PC_P,src);\\n");',
  'comprintf("\\tcomp_pc_p=(uae_u8*)(uintptr)get_const(PC_P);\\n");',
]) requireText(bccGenerator, contract, "Bcc generator lifecycle");
requireBefore(bccGenerator, "sign_extend_8_rr", "arm_ADD_l_ri_hostptr", "Bcc displacement before host pointer base");
requireBefore(bccGenerator, "arm_ADD_l_ri_hostptr", "arm_ADD_ptr_ri(src", "Bcc host base before cursor fold");
requireBefore(bccGenerator, "register_branch(v1,v2", "make_flags_live", "Bcc targets before flag materialisation");
for (const forbidden of ["jit_value_lock", "jit_value_unlock", "genastore ("])
  if (bccGenerator.includes(forbidden)) fail(`Bcc generator unexpectedly owns guest allocator/storage state through ${forbidden}`);
for (const contract of [
  "static int cond_codes[]={-1,-1,",
  "NATIVE_CC_HI,NATIVE_CC_LS,",
  "NATIVE_CC_CC,NATIVE_CC_CS,",
  "NATIVE_CC_NE,NATIVE_CC_EQ,",
  "NATIVE_CC_VC,NATIVE_CC_VS,",
  "NATIVE_CC_PL,NATIVE_CC_MI,",
  "NATIVE_CC_GE,NATIVE_CC_LT,",
  "NATIVE_CC_GT,NATIVE_CC_LE",
]) requireText(gencompSource, contract, "Bcc condition map");
const bccHostPointerBody = functionBody(midfuncSource, "MIDFUNC(2,arm_ADD_l_ri_hostptr,", "MENDFUNC(2,arm_ADD_l_ri_hostptr,", "Bcc signed host-pointer addition");
for (const contract of [
  "const uae_s64 displacement = (uae_s32)(uae_u32)live.state[d].val;",
  "live.state[d].val = base + (uintptr)displacement;",
  "ADD_xxwEX(d, REG_WORK1, d, EX_SXTW);",
]) requireText(bccHostPointerBody, contract, "Bcc signed host-pointer addition");
const bccPointerIncrementBody = functionBody(midfuncSource, "MIDFUNC(2,arm_ADD_ptr_ri,", "MENDFUNC(2,arm_ADD_ptr_ri,", "Bcc pointer-width cursor addition");
for (const contract of [
  "live.state[d].val += (uintptr)(uae_s64)offset;",
  "ADD_xxi(d, d, offset);", "SUB_xxi(d, d, -offset);", "ADD_xxx(d, d, REG_WORK1);",
]) requireText(bccPointerIncrementBody, contract, "Bcc pointer-width cursor addition");
const generatedBccBodies = matchingFunctionBodies(
  generatedSource,
  /^void REGPARAM2 op_[0-9a-f]+_0_comp_(?:ff|nf)[^\n]*\/\* Bcc \*\//gm,
  "generated Bcc handlers",
);
const generatedBccFlagLive = generatedBccBodies.filter((body) => body.includes("_comp_ff")).length;
const generatedBccNoFlags = generatedBccBodies.filter((body) => body.includes("_comp_nf")).length;
const generatedBccCount = (needle: string) => generatedBccBodies.reduce((total, body) => total + countText(body, needle), 0);
if (generatedBccBodies.length !== 90 || generatedBccFlagLive !== 45 || generatedBccNoFlags !== 45 ||
    generatedBccCount("sign_extend_8_rr(src,src);") !== 30 ||
    generatedBccCount("sign_extend_16_rr(src,src);") !== 30 ||
    generatedBccCount("arm_ADD_l_ri_hostptr(src,(uintptr)comp_pc_p);") !== 90 ||
    generatedBccCount("arm_ADD_ptr_ri(src,m68k_pc_offset);") !== 90 ||
    generatedBccCount("arm_ADD_ptr_ri(PC_P,m68k_pc_offset);") !== 90 ||
    generatedBccCount("register_branch(v1,v2,") !== 84 ||
    generatedBccCount("make_flags_live();") !== 84 ||
    generatedBccCount("mov_l_rr(PC_P,src);") !== 6) {
  fail(`generated Bcc lifecycle: functions=${generatedBccBodies.length} split=${generatedBccFlagLive}/${generatedBccNoFlags} sign=${generatedBccCount("sign_extend_8_rr(src,src);")}/${generatedBccCount("sign_extend_16_rr(src,src);")} pointers=${generatedBccCount("arm_ADD_l_ri_hostptr(src,(uintptr)comp_pc_p);")}/${generatedBccCount("arm_ADD_ptr_ri(src,m68k_pc_offset);")}/${generatedBccCount("arm_ADD_ptr_ri(PC_P,m68k_pc_offset);")} conditional=${generatedBccCount("register_branch(v1,v2,")}/${generatedBccCount("make_flags_live();")} bra=${generatedBccCount("mov_l_rr(PC_P,src);")}`);
}
/* gencomp itself is built against the historical x86 condition numbering;
 * both the mid-block side-exit and final-edge paths must translate that exact
 * set before emitting AArch64 conditions. Values 10/11 are x86 aliases not
 * used by integer Bcc, while 12..15 carry LT/GE/LE/GT. */
for (const cc of [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 12, 13, 14, 15]) {
  if (generatedBccCount(`register_branch(v1,v2,${cc});`) !== 6)
    fail(`generated Bcc x86 condition ${cc} does not have six width/table routes`);
}
for (const cc of [10, 11]) {
  if (generatedBccCount(`register_branch(v1,v2,${cc});`) !== 0)
    fail(`generated Bcc unexpectedly uses x86 alias condition ${cc}`);
}
for (const contract of [
  "static const int x86_to_arm[] = {",
  "NATIVE_CC_VS, NATIVE_CC_VC, NATIVE_CC_CS, NATIVE_CC_CC,",
  "NATIVE_CC_EQ, NATIVE_CC_NE, NATIVE_CC_LS, NATIVE_CC_HI,",
  "NATIVE_CC_MI, NATIVE_CC_PL, NATIVE_CC_VS, NATIVE_CC_VC,",
  "NATIVE_CC_LT, NATIVE_CC_GE, NATIVE_CC_LE, NATIVE_CC_GT,",
  "arm_branch_cc = x86_to_arm[arm_branch_cc];",
  "static const int x86_to_arm_cc[] = {",
  "cc = x86_to_arm_cc[cc];",
]) requireText(allocatorSource, contract, "Bcc x86-to-AArch64 condition translation");
for (const body of generatedBccBodies) {
  for (const contract of ["arm_ADD_l_ri_hostptr(src,(uintptr)comp_pc_p);", "arm_ADD_ptr_ri(src,m68k_pc_offset);", "arm_ADD_ptr_ri(PC_P,m68k_pc_offset);", "m68k_pc_offset=0;"])
    requireText(body, contract, "generated Bcc pointer/PC lifecycle");
  for (const forbidden of ["jit_value_lock", "jit_value_unlock", "ADDS_", "SUBS_", "TST_", "CMP_", "jff_"])
    if (body.includes(forbidden)) fail(`generated Bcc handler unexpectedly mutates flags or owns dynamic allocator state through ${forbidden}`);
  if (body.includes("register_branch(v1,v2,"))
    requireBefore(body, "register_branch(v1,v2,", "make_flags_live();", "generated conditional Bcc flags");
}
const bccConditions = [
  ["hi", "62"], ["ls", "63"], ["cc", "64"], ["cs", "65"],
  ["ne", "66"], ["eq", "67"], ["vc", "68"], ["vs", "69"],
  ["pl", "6A"], ["mi", "6B"], ["ge", "6C"], ["lt", "6D"],
  ["gt", "6E"], ["le", "6F"],
] as const;
const bccVectors: string[] = [];
for (const [condition, opcode] of bccConditions) {
  for (const outcome of ["taken", "not_taken"] as const) {
    const name = `bcc_core_${condition}_${outcome}_b_native`;
    bccVectors.push(name);
    requireText(harnessSource, `TESTS[${name}]="${opcode}06 227C 1111 1111 247C 2222 2222"`, `Bcc ${condition} ${outcome} byte vector`);
  }
}
for (const [name, encoding] of [
  ["bcc_core_bra_b_forward_native", "6006 227C 1111 1111 247C 2222 2222"],
  ["bcc_core_bra_w_forward_native", "6000 0008 227C 1111 1111 247C 2222 2222"],
  ["bcc_core_bra_l_forward_native", "60FF 0000 000A 227C 1111 1111 247C 2222 2222"],
  ["bcc_core_bne_b_backward_native", "7002 5380 66FC 227C 1111 1111"],
  ["bcc_core_bne_w_backward_native", "7002 5380 6600 FFFC 227C 1111 1111"],
  ["bcc_core_bne_l_backward_native", "7002 5380 66FF FFFF FFFC 227C 1111 1111"],
] as const) {
  bccVectors.push(name);
  requireText(harnessSource, `TESTS[${name}]="${encoding}"`, `Bcc displacement vector ${name}`);
}
if (bccVectors.length !== 34) fail(`Bcc vector count changed: ${bccVectors.length}`);
for (const fragment of [
  "declare -a BCC_NATIVE_MATRIX_NAMES=(", 'TEST_ORDER+=("${BCC_NATIVE_MATRIX_NAMES[@]}")',
  'for _bcc_name in "${BCC_NATIVE_MATRIX_NAMES[@]}"; do\n    NATIVE_REPLAY_TESTS["$_bcc_name"]=1\n    NATIVE_REPLAY_PC["$_bcc_name"]=0x1000\n    NATIVE_REPLAY_COUNT["$_bcc_name"]=2',
  "for _bcc_name in bcc_core_bne_b_backward_native bcc_core_bne_w_backward_native bcc_core_bne_l_backward_native; do\n    NATIVE_REPLAY_PC[\"$_bcc_name\"]=0x1004",
  'for _bcc_name in "${BCC_NATIVE_MATRIX_NAMES[@]}"; do\n    RISKY_TESTS["$_bcc_name"]=1',
  'A1=0000A100 A2=22222222', 'A1=11111111 A2=22222222',
  'A1=0000A100 A2=22222222 SR=271F', 'D0=00000000 A1=11111111 SR=2704',
]) requireText(harnessSource, fragment, "Bcc matrix/replay/result contract");
for (const name of bccVectors) {
  if (countText(harnessSource, name) < 4) fail(`Bcc vector ${name} is not wired through matrix/test/result/init contracts`);
  requireText(activeRiskySource, name, `Bcc active mismatch-first vector ${name}`);
}

/* CLR is emitted directly by its generator; its six namesake MIDFUNCs are
 * unreachable. The generator writes zero before fixed logical flag publication,
 * so memory-helper NZCV side effects cannot escape into the architectural CCR. */
const clrGenerator = functionBody(gencompSource, "     case i_CLR:", "     case i_NOT:", "CLR generator");
for (const contract of [
  'genamode (curi->smode, "srcreg", curi->size, "src", GENA_GETV_FETCH_ALIGN, GENA_MOVEM_DO_INC);',
  'comprintf("\\tint dst=scratchie++;\\n");',
  'comprintf("\\tmov_l_ri(dst,0);\\n");',
  'genastore ("dst", curi->smode, "srcreg", curi->size, "src");',
  'genflags (flag_logical, curi->size, "dst", "", "");',
]) requireText(clrGenerator, contract, "CLR generator lifecycle");
requireBefore(clrGenerator, 'mov_l_ri(dst,0)', 'genastore ("dst"', "CLR zero before storage");
requireBefore(clrGenerator, 'genastore ("dst"', 'genflags (flag_logical', "CLR storage before fixed flags");
for (const forbidden of ["jff_CLR_", "jnf_CLR_", "jit_value_lock", "jit_value_unlock"])
  if (clrGenerator.includes(forbidden)) fail(`CLR generator unexpectedly uses ${forbidden}`);
const clrLogicalFlags = functionBody(gencompSource, "     case flag_logical:", "     case flag_add:", "CLR logical flag publication");
for (const contract of [
  'comprintf("\\tdont_care_flags();\\n");',
  'test_b_rr(%s,%s);', 'test_w_rr(%s,%s);', 'test_l_rr(%s,%s);',
  'comprintf("\\tlive_flags();\\n");', 'comprintf("\\tend_needflags();\\n");',
]) requireText(clrLogicalFlags, contract, "CLR logical flag publication");
const generatedClrBodies = matchingFunctionBodies(
  generatedSource,
  /^void REGPARAM2 op_[0-9a-f]+_0_comp_(?:ff|nf)[^\n]*\/\* CLR \*\//gm,
  "generated CLR handlers",
);
const generatedClrFlagLive = generatedClrBodies.filter((body) => body.includes("_comp_ff")).length;
const generatedClrNoFlags = generatedClrBodies.filter((body) => body.includes("_comp_nf")).length;
const generatedClrCount = (needle: string) => generatedClrBodies.reduce((total, body) => total + countText(body, needle), 0);
if (generatedClrBodies.length !== 48 || generatedClrFlagLive !== 24 || generatedClrNoFlags !== 24 ||
    generatedClrCount("mov_l_ri(dst,0);") !== 48 || generatedClrCount("writebyte(") !== 14 ||
    generatedClrCount("writeword(") !== 14 || generatedClrCount("writelong(") !== 14 ||
    generatedClrCount("test_b_rr(dst,dst);") !== 8 || generatedClrCount("test_w_rr(dst,dst);") !== 8 ||
    generatedClrCount("test_l_rr(dst,dst);") !== 8 || generatedClrCount("live_flags();") !== 24) {
  fail(`generated CLR lifecycle: functions=${generatedClrBodies.length} split=${generatedClrFlagLive}/${generatedClrNoFlags} zero=${generatedClrCount("mov_l_ri(dst,0);")} stores=${generatedClrCount("writebyte(")}/${generatedClrCount("writeword(")}/${generatedClrCount("writelong(")} tests=${generatedClrCount("test_b_rr(dst,dst);")}/${generatedClrCount("test_w_rr(dst,dst);")}/${generatedClrCount("test_l_rr(dst,dst);")} live=${generatedClrCount("live_flags();")}`);
}
for (const body of generatedClrBodies) {
  requireText(body, "mov_l_ri(dst,0);", "generated CLR zero source");
  for (const forbidden of ["jff_CLR_", "jnf_CLR_", "jit_value_lock", "jit_value_unlock"])
    if (body.includes(forbidden)) fail(`generated CLR unexpectedly uses ${forbidden}`);
  if (body.includes("_comp_ff")) {
    requireText(body, "dont_care_flags();", "generated CLR flag-live publication");
    requireBefore(body, "mov_l_ri(dst,0);", "dont_care_flags();", "generated CLR zero before flags");
    for (const store of ["writebyte(", "writeword(", "writelong("])
      if (body.includes(store)) requireBefore(body, store, "dont_care_flags();", "generated CLR store before flags");
  } else if (body.includes("dont_care_flags();") || body.includes("test_b_rr(") || body.includes("test_w_rr(") || body.includes("test_l_rr(")) {
    fail("generated no-flags CLR handler publishes flags");
  }
}
for (const name of ["jnf_CLR_b", "jnf_CLR_w", "jnf_CLR_l", "jff_CLR_b", "jff_CLR_w", "jff_CLR_l"]) {
  const row = new RegExp(`^midfunc,${name},unreachable,CLR,68,0,`, "m");
  if (!row.test(await Bun.file(new URL("../BasiliskII/docs/AARCH64_JIT_CLOSURE_INVENTORY.csv", import.meta.url)).text()))
    fail(`CLR namesake MIDFUNC ${name} is not retained as unreachable`);
}
for (const contract of [
  "clr_b_postinc_zero_ea_collision", "[clr_b_postinc_zero_ea_collision]=20",
  "[clr_b_postinc_zero_ea_collision]=21", "[clr_b_postinc_zero_ea_collision]=0",
  "[clr_b_postinc_zero_ea_collision]=1",
]) requireText(regallocPressureSource, contract, "CLR EA/zero allocator pressure");
const clrVectors = [
  "clr_core_b_dreg_native", "clr_core_w_dreg_native", "clr_core_l_dreg_native",
  "clr_core_b_aind_special_native", "clr_core_w_postinc_native", "clr_core_l_predec_native",
  "clr_core_b_d16_native", "clr_core_w_index_special_native", "clr_core_l_absw_native",
  "clr_core_b_absl_special_native", "clr_core_b_a7_postinc_native", "clr_core_b_a7_predec_native",
  "clr_core_b_postinc_successor_bne_native", "clr_core_w_dreg_noflags_native", "clr_core_l_postinc_noflags_native",
];
for (const fragment of [
  "declare -a CLR_NATIVE_MATRIX_NAMES=(", 'TEST_ORDER+=("${CLR_NATIVE_MATRIX_NAMES[@]}")',
  'for _clr_name in "${CLR_NATIVE_MATRIX_NAMES[@]}"; do\n    NATIVE_REPLAY_TESTS["$_clr_name"]=1\n    NATIVE_REPLAY_PC["$_clr_name"]=0x1000\n    NATIVE_REPLAY_COUNT["$_clr_name"]=2',
  'for _clr_name in "${CLR_NATIVE_MATRIX_NAMES[@]}"; do\n    RISKY_TESTS["$_clr_name"]=1',
]) requireText(harnessSource, fragment, "CLR matrix/replay contract");
for (const name of clrVectors) {
  for (const fragment of [`TESTS[${name}]=`, `EXPECTED_REG_FIELDS[${name}]=`])
    requireText(harnessSource, fragment, `CLR vector ${name}`);
  requireText(activeRiskySource, name, `CLR active mismatch-first vector ${name}`);
}
for (const contract of [
  "for _clr_name in clr_core_b_dreg_native clr_core_w_dreg_native clr_core_l_dreg_native clr_core_b_aind_special_native clr_core_w_postinc_native clr_core_l_predec_native clr_core_b_d16_native clr_core_l_absw_native clr_core_b_absl_special_native clr_core_b_a7_postinc_native clr_core_b_a7_predec_native; do INIT_REGS[\"$_clr_name\"]",
  "INIT_REGS[clr_core_w_index_special_native]=",
  "INIT_REGS[clr_core_b_postinc_successor_bne_native]=",
  "INIT_REGS[clr_core_w_dreg_noflags_native]=",
  "INIT_REGS[clr_core_l_postinc_noflags_native]=",
]) requireText(harnessSource, contract, "CLR initial-state contract");
const clrMemoryVectors = [
  "clr_core_b_aind_special_native", "clr_core_w_postinc_native", "clr_core_l_predec_native",
  "clr_core_b_d16_native", "clr_core_w_index_special_native", "clr_core_l_absw_native",
  "clr_core_b_absl_special_native", "clr_core_b_a7_postinc_native", "clr_core_b_a7_predec_native",
  "clr_core_b_postinc_successor_bne_native", "clr_core_l_postinc_noflags_native",
];
for (const name of clrMemoryVectors) {
  requireText(harnessSource, `TEST_MEMORY_BYTES[${name}]=`, `CLR memory bytes ${name}`);
  requireText(harnessSource, `NATIVE_REPLAY_BYTES[${name}]=`, `CLR native memory replay ${name}`);
}
for (const name of ["clr_core_b_aind_special_native", "clr_core_w_index_special_native", "clr_core_b_absl_special_native"])
  requireText(harnessSource, `SPECIAL_MEMORY_TESTS[${name}]=1`, `CLR special-memory route ${name}`);
for (const contract of [
  'EXPECTED_REG_FIELDS[clr_core_b_dreg_native]="D0=A5A5FF00 SR=2714"',
  'EXPECTED_REG_FIELDS[clr_core_w_dreg_native]="D0=A5A50000 SR=2714"',
  'EXPECTED_REG_FIELDS[clr_core_l_dreg_native]="D0=00000000 SR=2714"',
  'EXPECTED_REG_FIELDS[clr_core_b_postinc_successor_bne_native]="D1=00000007 D2=00000008 A0=0000A001 SR=2710"',
  'EXPECTED_REG_FIELDS[clr_core_w_dreg_noflags_native]="D0=A5A50000 D2=00000001 SR=2700"',
  'EXPECTED_REG_FIELDS[clr_core_l_postinc_noflags_native]="D2=00000001 A0=0000A004 SR=2700"',
]) requireText(harnessSource, contract, "CLR exact result/flags contract");

/* EXG is emitted directly and must preserve both originals until the second
 * architectural write, including same-class self aliases. It never owns CCR. */
const exgGenerator = functionBody(gencompSource, "     case i_EXG:", "\t case i_EXT:", "EXG generator");
for (const contract of [
  'genamode (curi->smode, "srcreg", curi->size, "src", GENA_GETV_FETCH, GENA_MOVEM_DO_INC);',
  'genamode (curi->dmode, "dstreg", curi->size, "dst", GENA_GETV_FETCH, GENA_MOVEM_DO_INC);',
  'comprintf("\\tint tmp=scratchie++;\\n"',
  '"\\tmov_l_rr(tmp,src);\\n");',
  'genastore ("dst", curi->smode, "srcreg", curi->size, "src");',
  'genastore ("tmp", curi->dmode, "dstreg", curi->size, "dst");',
]) requireText(exgGenerator, contract, "EXG generator lifecycle");
requireBefore(exgGenerator, "mov_l_rr(tmp,src)", 'genastore ("dst"', "EXG original source before first write");
requireBefore(exgGenerator, 'genastore ("dst"', 'genastore ("tmp"', "EXG first write before saved source write");
for (const forbidden of ["genflags", "make_flags_live", "live_flags", "dont_care_flags", "jit_value_lock", "jit_value_unlock"])
  if (exgGenerator.includes(forbidden)) fail(`EXG generator unexpectedly uses ${forbidden}`);
const generatedExgBodies = matchingFunctionBodies(
  generatedSource,
  /^void REGPARAM2 op_[0-9a-f]+_0_comp_(?:ff|nf)[^\n]*\/\* EXG \*\//gm,
  "generated EXG handlers",
);
const generatedExgFlagLive = generatedExgBodies.filter((body) => body.includes("_comp_ff")).length;
const generatedExgNoFlags = generatedExgBodies.filter((body) => body.includes("_comp_nf")).length;
const generatedExgCount = (needle: string) => generatedExgBodies.reduce((total, body) => total + countText(body, needle), 0);
if (generatedExgBodies.length !== 6 || generatedExgFlagLive !== 3 || generatedExgNoFlags !== 3 ||
    generatedExgCount("int tmp=scratchie++;") !== 6 || generatedExgCount("mov_l_rr(tmp,src);") !== 6 ||
    generatedExgCount("mov_l_rr(srcreg, dst);") !== 4 || generatedExgCount("mov_l_rr(srcreg + 8, dst);") !== 2 ||
    generatedExgCount("mov_l_rr(dstreg, tmp);") !== 2 || generatedExgCount("mov_l_rr(dstreg + 8, tmp);") !== 4 ||
    generatedExgCount("dodgy=(srcreg==(uae_s32)dstreg)") !== 2) {
  fail(`generated EXG lifecycle: functions=${generatedExgBodies.length} split=${generatedExgFlagLive}/${generatedExgNoFlags} tmp=${generatedExgCount("int tmp=scratchie++;")}/${generatedExgCount("mov_l_rr(tmp,src);")} first=${generatedExgCount("mov_l_rr(srcreg, dst);")}/${generatedExgCount("mov_l_rr(srcreg + 8, dst);")} second=${generatedExgCount("mov_l_rr(dstreg, tmp);")}/${generatedExgCount("mov_l_rr(dstreg + 8, tmp);")} alias=${generatedExgCount("dodgy=(srcreg==(uae_s32)dstreg)")}`);
}
for (const body of generatedExgBodies) {
  requireBefore(body, "mov_l_rr(tmp,src);", "mov_l_rr(srcreg", "generated EXG save before first write");
  requireBefore(body, "mov_l_rr(srcreg", "mov_l_rr(dstreg", "generated EXG first before second write");
  if (body.includes("/* EXG */") && body.includes("op_c188_")) {
    if (body.includes("dodgy=(srcreg==(uae_s32)dstreg)"))
      fail("generated Dn/An EXG incorrectly treats equal register indices as an alias");
  }
  if (body.includes("op_c148_") && !body.includes("dodgy=(srcreg==(uae_s32)dstreg)"))
    fail("generated An/An EXG lost same-register alias handling");
  for (const forbidden of ["genflags", "make_flags_live", "live_flags", "dont_care_flags", "jit_value_lock", "jit_value_unlock", "TST_", "CMP_"])
    if (body.includes(forbidden)) fail(`generated EXG unexpectedly uses ${forbidden}`);
}
for (const contract of [
  "exg_l_tmp_source_collision", "[exg_l_tmp_source_collision]=0",
  "[exg_l_tmp_source_collision]=20", "[exg_l_tmp_source_collision]=1",
]) requireText(regallocPressureSource, contract, "EXG temporary/source allocator pressure");
const exgVectors = [
  "exg_core_dn_dn_native", "exg_core_an_an_native", "exg_core_dn_an_native",
  "exg_core_dn_dn_self_native", "exg_core_an_an_self_native",
  "exg_core_dn_dn_max_native", "exg_core_an_an_max_native", "exg_core_dn_an_max_native",
  "exg_core_dn_dn_roundtrip_native", "exg_core_an_an_roundtrip_native",
  "exg_core_dn_an_roundtrip_native", "exg_core_dn_an_noflags_native",
];
for (const fragment of [
  "declare -a EXG_NATIVE_MATRIX_NAMES=(", 'TEST_ORDER+=("${EXG_NATIVE_MATRIX_NAMES[@]}")',
  'for _exg_name in "${EXG_NATIVE_MATRIX_NAMES[@]}"; do\n    NATIVE_REPLAY_TESTS["$_exg_name"]=1\n    NATIVE_REPLAY_PC["$_exg_name"]=0x1000\n    NATIVE_REPLAY_COUNT["$_exg_name"]=2',
  'for _exg_name in "${EXG_NATIVE_MATRIX_NAMES[@]}"; do\n    RISKY_TESTS["$_exg_name"]=1',
]) requireText(harnessSource, fragment, "EXG matrix/replay contract");
for (const name of exgVectors) {
  for (const fragment of [`TESTS[${name}]=`, `EXPECTED_REG_FIELDS[${name}]=`])
    requireText(harnessSource, fragment, `EXG vector ${name}`);
  requireText(activeRiskySource, name, `EXG active mismatch-first vector ${name}`);
}
for (const contract of [
  "for _exg_name in exg_core_dn_dn_native exg_core_an_an_native exg_core_dn_an_native exg_core_dn_dn_self_native exg_core_an_an_self_native exg_core_dn_dn_max_native exg_core_an_an_max_native exg_core_dn_an_max_native exg_core_dn_dn_roundtrip_native exg_core_an_an_roundtrip_native exg_core_dn_an_roundtrip_native; do INIT_REGS[\"$_exg_name\"]",
  "INIT_REGS[exg_core_dn_an_noflags_native]=",
  'EXPECTED_REG_FIELDS[exg_core_dn_dn_native]="D0=AABBCCDD D1=11223344 SR=271F"',
  'EXPECTED_REG_FIELDS[exg_core_an_an_native]="A0=0000B000 A1=0000A000 SR=271F"',
  'EXPECTED_REG_FIELDS[exg_core_dn_an_native]="D0=0000B000 A1=11223344 SR=271F"',
  'EXPECTED_REG_FIELDS[exg_core_an_an_max_native]="A5=0000F700 A7=0000F500 SR=271F"',
  'EXPECTED_REG_FIELDS[exg_core_dn_an_noflags_native]="D0=0000B000 D2=00000001 A1=11223344 SR=2700"',
]) requireText(harnessSource, contract, "EXG initial/result/flags contract");

/* EXT is emitted directly: EXT.W widens byte->word into a private scratch and
 * preserves Dn[31:16], while EXT.L and EXTB.L widen in place to full 32 bits. */
const extGenerator = functionBody(gencompSource, "\t case i_EXT:", "\t case i_MVMEL:", "EXT generator");
for (const contract of [
  'genamode (curi->smode, "srcreg", sz_long, "src", GENA_GETV_FETCH, GENA_MOVEM_DO_INC);',
  'case sz_byte:', '"\\tsign_extend_8_rr(src,src);\\n");',
  'case sz_word:', '"\\tsign_extend_8_rr(dst,src);\\n");',
  'case sz_long:', '"\\tsign_extend_16_rr(src,src);\\n");',
  'curi->size == sz_word ? sz_word : sz_long, "dst", "", ""',
  'genastore ("dst", curi->smode, "srcreg",',
  'curi->size == sz_word ? sz_word : sz_long, "src");',
]) requireText(extGenerator, contract, "EXT generator lifecycle");
for (const forbidden of ["jff_EXT", "jnf_EXT", "jit_value_lock", "jit_value_unlock"])
  if (extGenerator.includes(forbidden)) fail(`EXT generator unexpectedly uses ${forbidden}`);
const generatedExtBodies = matchingFunctionBodies(
  generatedSource,
  /^void REGPARAM2 op_[0-9a-f]+_0_comp_(?:ff|nf)[^\n]*\/\* EXT \*\//gm,
  "generated EXT handlers",
);
const generatedExtFlagLive = generatedExtBodies.filter((body) => body.includes("_comp_ff")).length;
const generatedExtNoFlags = generatedExtBodies.filter((body) => body.includes("_comp_nf")).length;
const generatedExtCount = (needle: string) => generatedExtBodies.reduce((total, body) => total + countText(body, needle), 0);
if (generatedExtBodies.length !== 6 || generatedExtFlagLive !== 3 || generatedExtNoFlags !== 3 ||
    generatedExtCount("int dst = scratchie++;") !== 2 || generatedExtCount("int dst = src;") !== 4 ||
    generatedExtCount("sign_extend_8_rr(dst,src);") !== 2 ||
    generatedExtCount("sign_extend_8_rr(src,src);") !== 2 ||
    generatedExtCount("sign_extend_16_rr(src,src);") !== 2 ||
    generatedExtCount("test_w_rr(dst,dst);") !== 1 || generatedExtCount("test_l_rr(dst,dst);") !== 2 ||
    generatedExtCount("mov_w_rr(srcreg, dst);") !== 2 || generatedExtCount("mov_l_rr(srcreg, dst);") !== 4 ||
    generatedExtCount("live_flags();") !== 3) {
  fail(`generated EXT lifecycle: functions=${generatedExtBodies.length} split=${generatedExtFlagLive}/${generatedExtNoFlags} dst=${generatedExtCount("int dst = scratchie++;")}/${generatedExtCount("int dst = src;")} extends=${generatedExtCount("sign_extend_8_rr(dst,src);")}/${generatedExtCount("sign_extend_8_rr(src,src);")}/${generatedExtCount("sign_extend_16_rr(src,src);")} tests=${generatedExtCount("test_w_rr(dst,dst);")}/${generatedExtCount("test_l_rr(dst,dst);")} writes=${generatedExtCount("mov_w_rr(srcreg, dst);")}/${generatedExtCount("mov_l_rr(srcreg, dst);")} live=${generatedExtCount("live_flags();")}`);
}
for (const body of generatedExtBodies) {
  const width = body.includes("op_4880_") ? "word" : "long";
  const extend = body.includes("op_4880_") ? "sign_extend_8_rr(dst,src);" : body.includes("op_48c0_") ? "sign_extend_16_rr(src,src);" : "sign_extend_8_rr(src,src);";
  requireText(body, extend, `generated EXT ${width} sign extension`);
  if (body.includes("op_4880_")) requireText(body, "int dst = scratchie++;", "generated EXT.W private widened-word destination");
  else requireText(body, "int dst = src;", "generated EXT.L/EXTB.L in-place destination alias");
  if (body.includes("_comp_ff")) {
    requireBefore(body, extend, width === "word" ? "test_w_rr(dst,dst);" : "test_l_rr(dst,dst);", `generated EXT ${width} result before flags`);
    requireBefore(body, "test_", "live_flags();", `generated EXT ${width} flags publication`);
  } else if (body.includes("test_w_rr(") || body.includes("test_l_rr(") || body.includes("live_flags();")) {
    fail(`generated no-flags EXT ${width} publishes flags`);
  }
  for (const forbidden of ["jff_EXT", "jnf_EXT", "jit_value_lock", "jit_value_unlock"])
    if (body.includes(forbidden)) fail(`generated EXT unexpectedly uses ${forbidden}`);
}
for (const contract of [
  "ext_w_scratch_source_collision", "[ext_w_scratch_source_collision]=0",
  "[ext_w_scratch_source_collision]=20", "[ext_w_scratch_source_collision]=1",
]) requireText(regallocPressureSource, contract, "EXT.W scratch/source allocator pressure");
const extVectors = [
  "ext_core_w_negative_native", "ext_core_w_zero_native", "ext_core_w_positive_native", "ext_core_w_max_native",
  "ext_core_l_negative_native", "ext_core_l_zero_native", "ext_core_l_positive_native", "ext_core_l_max_native",
  "extb_core_l_negative_native", "extb_core_l_zero_native", "extb_core_l_positive_native", "extb_core_l_max_native",
  "ext_core_wl_chain_negative_native", "ext_core_w_noflags_native", "ext_core_l_noflags_native", "extb_core_l_noflags_native",
];
for (const fragment of [
  "declare -a EXT_NATIVE_MATRIX_NAMES=(", 'TEST_ORDER+=("${EXT_NATIVE_MATRIX_NAMES[@]}")',
  'for _ext_name in "${EXT_NATIVE_MATRIX_NAMES[@]}"; do\n    NATIVE_REPLAY_TESTS["$_ext_name"]=1\n    NATIVE_REPLAY_PC["$_ext_name"]=0x1000\n    NATIVE_REPLAY_COUNT["$_ext_name"]=2',
  'for _ext_name in "${EXT_NATIVE_MATRIX_NAMES[@]}"; do\n    RISKY_TESTS["$_ext_name"]=1',
  'if [ -n "${NATIVE_REPLAY_TESTS[$name]+x}" ]; then',
  'env_vars+=(B2_TEST_TWO_PASS=1 B2_TEST_SECOND_PC="$replay_pc")',
  'env_vars+=(B2_TEST_FORCE_L2_RAM=1 B2_JIT_STRICT_FULL=1 B2_NATIVE_ASSERT_PC="$replay_pc")',
]) requireText(harnessSource, fragment, "EXT matrix/replay contract");
for (const name of extVectors) {
  for (const fragment of [`TESTS[${name}]=`, `EXPECTED_REG_FIELDS[${name}]=`, `INIT_REGS[${name}]=`])
    requireText(harnessSource, fragment, `EXT vector ${name}`);
  requireText(activeRiskySource, name, `EXT active mismatch-first vector ${name}`);
}
for (const contract of [
  'EXPECTED_REG_FIELDS[ext_core_w_negative_native]="D0=A5A5FF80 SR=2718"',
  'EXPECTED_REG_FIELDS[ext_core_w_zero_native]="D0=A5A50000 SR=2714"',
  'EXPECTED_REG_FIELDS[ext_core_l_negative_native]="D0=FFFF8000 SR=2718"',
  'EXPECTED_REG_FIELDS[extb_core_l_negative_native]="D0=FFFFFF80 SR=2718"',
  'EXPECTED_REG_FIELDS[ext_core_w_noflags_native]="D0=A5A5FF80 D2=00000001 SR=2700"',
  'EXPECTED_REG_FIELDS[ext_core_l_noflags_native]="D0=FFFF8000 D2=00000001 SR=2700"',
  'EXPECTED_REG_FIELDS[extb_core_l_noflags_native]="D0=FFFFFF80 D2=00000001 SR=2700"',
]) requireText(harnessSource, contract, "EXT exact lane/result/flags contract");

/* SUB mirrors ADD's source/destination shapes but has independent inverted
 * carry/borrow and X publication. Its writable-memory forms must retain the
 * private pre-write EA through arithmetic, carry duplication and storage. */
const subGenerator = functionBody(gencompSource, "     case i_SUB:", "     case i_SUBA:", "SUB generator");
for (const contract of [
  'genamode (curi->smode, "srcreg", curi->size, "src", GENA_GETV_FETCH, GENA_MOVEM_DO_INC);',
  'genamode (curi->dmode, "dstreg", curi->size, "dst", GENA_GETV_FETCH, GENA_MOVEM_DO_INC);',
  'comprintf("\\tint __subdstealock=jit_value_lock(dsta);\\n");',
  'genflags (flag_sub, curi->size, "", "src", "dst");',
  'genastore ("dst", curi->dmode, "dstreg", curi->size, "dst");',
  'comprintf("\\tjit_value_unlock(__subdstealock);\\n");',
]) requireText(subGenerator, contract, "SUB EA lifecycle");
if (subGenerator.includes("__subsrclock"))
  fail("SUB generator reintroduced a redundant source lock outside MIDFUNC operand ownership");
requireBefore(subGenerator, "jit_value_lock(dsta)", "genflags (flag_sub", "SUB EA before arithmetic");
requireBefore(subGenerator, 'genastore ("dst"', "jit_value_unlock(__subdstealock)", "SUB EA through store");
const generatedSubFunctions = (generatedSource.match(/void REGPARAM2 op_[0-9a-f]+_0_comp_(?:ff|nf)[^{]*\/\* SUB \*\//g) || []).length;
const generatedSubFlagLive = (generatedSource.match(/^void REGPARAM2 op_[0-9a-f]+_0_comp_ff[^\n]*\/\* SUB \*\//gm) || []).length;
const generatedSubNoFlags = (generatedSource.match(/^void REGPARAM2 op_[0-9a-f]+_0_comp_nf[^\n]*\/\* SUB \*\//gm) || []).length;
const generatedSubSourceLocks = (generatedSource.match(/int __subsrclock=jit_value_lock\(src\);/g) || []).length;
const generatedSubSourceUnlocks = (generatedSource.match(/jit_value_unlock\(__subsrclock\);/g) || []).length;
const generatedSubEaLocks = (generatedSource.match(/int __subdstealock=jit_value_lock\(dsta\);/g) || []).length;
const generatedSubEaUnlocks = (generatedSource.match(/jit_value_unlock\(__subdstealock\);/g) || []).length;
if (generatedSubFunctions !== 208 || generatedSubFlagLive !== 104 || generatedSubNoFlags !== 104 ||
    generatedSubSourceLocks !== 0 || generatedSubSourceUnlocks !== 0 ||
    generatedSubEaLocks !== 126 || generatedSubEaUnlocks !== 126) {
  fail(`generated SUB ownership: functions=${generatedSubFunctions} split=${generatedSubFlagLive}/${generatedSubNoFlags} source=${generatedSubSourceLocks}/${generatedSubSourceUnlocks} ea=${generatedSubEaLocks}/${generatedSubEaUnlocks}`);
}
for (const [variant, width] of [
  ["jnf", "b"], ["jnf", "w"], ["jnf", "l"],
  ["jff", "b"], ["jff", "w"], ["jff", "l"],
] as const) {
  const body = functionBody(
    midfunc2Source,
    `MIDFUNC(2,${variant}_SUB_${width},`,
    `MENDFUNC(2,${variant}_SUB_${width},`,
    `${variant}_SUB_${width} operand/flags lifecycle`,
  );
  requireText(body, `COMPCALL(${variant}_SUB_${width}_imm)`, `${variant}_SUB_${width} constant source route`);
  requireText(body, `INIT_REGS_${width}(d, s);`, `${variant}_SUB_${width} operand acquisition`);
  requireText(body, "EXIT_REGS(d, s);", `${variant}_SUB_${width} operand release`);
  requireBefore(body, `INIT_REGS_${width}(d, s);`, "EXIT_REGS(d, s);", `${variant}_SUB_${width} operand lifecycle`);
  if (width === "b" || width === "w") {
    const bits = width === "b" ? 8 : 16;
    requireText(body, variant === "jff" ? `BFXIL_xxii(d, REG_WORK1, ${32 - bits}, ${bits});` : `BFI_wwii(d, REG_WORK1, 0, ${bits});`, `${variant}_SUB_${width} upper-lane preservation`);
  } else {
    requireText(body, variant === "jff" ? "SUBS_www(d, d, s);" : "SUB_www(d, d, s);", `${variant}_SUB_l full-width result`);
  }
  if (variant === "jff") {
    requireText(body, "SUBS_", `${variant}_SUB_${width} flag-producing arithmetic`);
    requireText(body, "flags_carry_inverted = true;", `${variant}_SUB_${width} borrow polarity`);
    requireText(body, "DUPLICACTE_CARRY", `${variant}_SUB_${width} X publication`);
  } else if (body.includes("SUBS_") || body.includes("DUPLICACTE_CARRY") || body.includes("flags_carry_inverted")) {
    fail(`${variant}_SUB_${width} no-flags path publishes NZVCX metadata`);
  }
}
for (const [variant, width] of [
  ["jnf", "b"], ["jnf", "w"], ["jnf", "l"],
  ["jff", "b"], ["jff", "w"], ["jff", "l"],
] as const) {
  const body = functionBody(
    midfunc2Source,
    `MIDFUNC(2,${variant}_SUB_${width}_imm,`,
    `MENDFUNC(2,${variant}_SUB_${width}_imm,`,
    `${variant}_SUB_${width}_imm immediate/flags lifecycle`,
  );
  requireText(body, variant === "jff" ? "SUBS_" : "SUB_", `${variant}_SUB_${width}_imm arithmetic`);
  if (variant === "jff") {
    requireText(body, "flags_carry_inverted = true;", `${variant}_SUB_${width}_imm borrow polarity`);
    requireText(body, "DUPLICACTE_CARRY", `${variant}_SUB_${width}_imm X publication`);
  } else {
    requireText(body, "if (isconst(d))", `${variant}_SUB_${width}_imm constant fold`);
    if (body.includes("SUBS_") || body.includes("DUPLICACTE_CARRY") || body.includes("flags_carry_inverted"))
      fail(`${variant}_SUB_${width}_imm no-flags path publishes NZVCX metadata`);
  }
}
for (const contract of [
  "sub_b_postinc_source_dreg_collision", "[sub_b_postinc_source_dreg_collision]=21",
  "[sub_b_postinc_source_dreg_collision]=0", "[sub_b_postinc_source_dreg_collision]=1",
  "sub_b_postinc_x_ea_collision", "[sub_b_postinc_x_ea_collision]=20",
  "[sub_b_postinc_x_ea_collision]=17", "[sub_b_postinc_x_ea_collision]=1",
]) requireText(regallocPressureSource, contract, "SUB source/EA/X allocator pressure");
const subExactVectors = [
  "sub_core_b_reg_zero_native", "sub_core_w_reg_overflow_native", "sub_core_l_reg_borrow_native",
  "sub_core_b_self_alias_native", "sub_core_w_self_alias_native", "sub_core_l_self_alias_native",
  "sub_core_b_imm_overflow_native", "sub_core_w_imm_borrow_native",
  "sub_core_l_imm_large_native", "sub_core_l_imm_negative_native",
  "sub_core_b_reg_noflags_native", "sub_core_w_reg_noflags_native", "sub_core_l_reg_noflags_native",
  "sub_core_b_imm_noflags_native", "sub_core_w_imm_noflags_native", "sub_core_l_imm_noflags_native",
  "sub_core_b_aind_source_special_native", "sub_core_w_postinc_source_native",
  "sub_core_l_predec_source_native", "sub_core_b_d16_source_native",
  "sub_core_w_index_source_special_native", "sub_core_l_absw_source_native",
  "sub_core_b_absl_source_special_native", "sub_core_w_pc16_source_native",
  "sub_core_l_pcindex_source_native", "sub_core_b_aind_dest_special_native",
  "sub_core_w_postinc_dest_native", "sub_core_l_predec_dest_native",
  "sub_core_b_d16_dest_native", "sub_core_w_index_dest_special_native",
  "sub_core_l_absw_dest_native", "sub_core_b_absl_dest_special_native",
  "sub_core_b_a7_postinc_dest_native", "sub_core_b_a7_predec_dest_native",
  "sub_core_b_subi_postinc_dest_native", "sub_core_b_postinc_dest_native",
  "sub_core_b_postinc_dest_noflags_native",
];
for (const fragment of [
  "declare -a SUB_NATIVE_MATRIX_NAMES=(",
  'TEST_ORDER+=("${SUB_NATIVE_MATRIX_NAMES[@]}")',
  'for _sub_name in "${SUB_NATIVE_MATRIX_NAMES[@]}"; do\n    NATIVE_REPLAY_TESTS["$_sub_name"]=1\n    NATIVE_REPLAY_PC["$_sub_name"]=0x1000\n    NATIVE_REPLAY_COUNT["$_sub_name"]=2',
  'for _sub_name in "${SUB_NATIVE_MATRIX_NAMES[@]}"; do\n    RISKY_TESTS["$_sub_name"]=1',
]) requireText(harnessSource, fragment, "SUB exact-native matrix/replay contract");
for (const name of subExactVectors) {
  for (const fragment of [`TESTS[${name}]=`, `EXPECTED_REG_FIELDS[${name}]=`, `INIT_REGS[${name}]=`])
    requireText(harnessSource, fragment, `SUB exact-native vector ${name}`);
  requireText(activeRiskySource, name, `SUB active mismatch-first vector ${name}`);
}
const subMemoryVectors = [
  "sub_core_b_aind_source_special_native", "sub_core_w_postinc_source_native",
  "sub_core_l_predec_source_native", "sub_core_b_d16_source_native",
  "sub_core_w_index_source_special_native", "sub_core_l_absw_source_native",
  "sub_core_b_absl_source_special_native", "sub_core_w_pc16_source_native",
  "sub_core_l_pcindex_source_native", "sub_core_b_aind_dest_special_native",
  "sub_core_w_postinc_dest_native", "sub_core_l_predec_dest_native",
  "sub_core_b_d16_dest_native", "sub_core_w_index_dest_special_native",
  "sub_core_l_absw_dest_native", "sub_core_b_absl_dest_special_native",
  "sub_core_b_a7_postinc_dest_native", "sub_core_b_a7_predec_dest_native",
  "sub_core_b_subi_postinc_dest_native", "sub_core_b_postinc_dest_native",
  "sub_core_b_postinc_dest_noflags_native",
];
for (const name of subMemoryVectors) {
  requireText(harnessSource, `TEST_MEMORY_BYTES[${name}]=`, `SUB memory bytes ${name}`);
  requireText(harnessSource, `NATIVE_REPLAY_BYTES[${name}]=`, `SUB native memory replay ${name}`);
}
for (const name of [
  "sub_core_b_aind_source_special_native", "sub_core_w_index_source_special_native",
  "sub_core_b_absl_source_special_native", "sub_core_b_aind_dest_special_native",
  "sub_core_w_index_dest_special_native", "sub_core_b_absl_dest_special_native",
]) requireText(harnessSource, `SPECIAL_MEMORY_TESTS[${name}]=1`, `SUB special-memory route ${name}`);
for (const name of [
  "sub_core_b_reg_noflags_native", "sub_core_w_reg_noflags_native", "sub_core_l_reg_noflags_native",
  "sub_core_b_imm_noflags_native", "sub_core_w_imm_noflags_native", "sub_core_l_imm_noflags_native",
  "sub_core_b_postinc_dest_noflags_native",
]) requireText(harnessSource, `TESTS[${name}]=`, `SUB no-flags vector ${name}`);
requireText(harnessSource, 'TESTS[sub_core_b_postinc_dest_native]="9118 40C2 1028 FFFF"', "SUB.B D0,(A0)+ exact-native regression");

/* AND shares generator routing with OR/EOR but has an independently accepted
 * semantic lifecycle. Writable logical destinations own the original EA from
 * fetch through the ordered store; register MIDFUNCs acquire source before RMW
 * destination, preserve narrow upper lanes and X, and split flag-live from
 * no-flags lowering without inference from adjacent logical families. */
const logicalGenerator = functionBody(
  gencompSource,
  "     case i_OR:",
  "     case i_ORSR:",
  "OR/AND/EOR shared generator",
);
for (const contract of [
  'genamode (curi->smode, "srcreg", curi->size, "src", GENA_GETV_FETCH, GENA_MOVEM_DO_INC);',
  'genamode (curi->dmode, "dstreg", curi->size, "dst", GENA_GETV_FETCH, GENA_MOVEM_DO_INC);',
  'comprintf("\\tint __logicdstealock=jit_value_lock(dsta);\\n");',
  'case i_OR: genflags (flag_or, curi->size, "", "src", "dst"); break;',
  'case i_AND: genflags (flag_and, curi->size, "", "src", "dst"); break;',
  'genastore ("dst", curi->dmode, "dstreg", curi->size, "dst");',
  'comprintf("\\tjit_value_unlock(__logicdstealock);\\n");',
]) requireText(logicalGenerator, contract, "logical destination EA lifecycle");
requireBefore(logicalGenerator, "jit_value_lock(dsta)", "case i_OR: genflags", "OR EA before logic");
requireBefore(logicalGenerator, "jit_value_lock(dsta)", "case i_AND: genflags", "AND EA before logic");
requireBefore(logicalGenerator, 'genastore ("dst"', "jit_value_unlock(__logicdstealock)", "logical EA through store");
if (logicalGenerator.includes("__logicsrclock"))
  fail("logical generator reintroduced a redundant source lock outside MIDFUNC ownership");
const generatedLogicalBodies = [...generatedSource.matchAll(
  /void REGPARAM2 op_[0-9a-f]+_0_comp_(?:ff|nf)[^{]*\/\* (AND|OR|EOR) \*\/[\s\S]*?\n}\n/g,
)];
const logicalGeneratedCounts = new Map<string, { functions: number; locks: number; unlocks: number }>();
for (const match of generatedLogicalBodies) {
  const family = match[1];
  const body = match[0];
  const locks = (body.match(/int __logicdstealock=jit_value_lock\(dsta\);/g) || []).length;
  const unlocks = (body.match(/jit_value_unlock\(__logicdstealock\);/g) || []).length;
  if (locks !== unlocks || locks > 1)
    fail(`generated ${family} handler has unbalanced/duplicate logical EA ownership: ${locks}/${unlocks}`);
  if (locks === 1) {
    const operationName = family === "EOR" ? "xor" : family.toLowerCase();
    const operation = body.search(new RegExp(`\\b${operationName}_[bwl]\\(`));
    const store = body.search(/\bwrite(?:byte|word|long)\(dsta,/);
    const lock = body.indexOf("int __logicdstealock=jit_value_lock(dsta);");
    const unlock = body.indexOf("jit_value_unlock(__logicdstealock);");
    if (operation < 0 || store < 0 || lock < 0 || lock >= operation || store <= operation || unlock <= store)
      fail(`generated ${family} handler does not retain logical EA through its MIDFUNC operation and ordered store`);
  }
  if (family === "OR" || family === "EOR") {
    const operationName = family === "EOR" ? "xor" : "or";
    const routes = body.match(new RegExp(`\\b${operationName}_[bwl]\\(`, "g")) ?? [];
    const noFlagsNarrow = body.includes("_comp_nf") &&
      (body.includes(`${operationName}_b(`) || body.includes(`${operationName}_w(`));
    const expectedRoutes = noFlagsNarrow ? 2 : 1;
    if (routes.length !== expectedRoutes || (noFlagsNarrow && !body.includes(`${operationName}_l(`)))
      fail(`generated ${family} handler route split: expected=${expectedRoutes} actual=${routes.length}`);
  }
  const item = logicalGeneratedCounts.get(family) ?? { functions: 0, locks: 0, unlocks: 0 };
  item.functions++;
  item.locks += locks;
  item.unlocks += unlocks;
  logicalGeneratedCounts.set(family, item);
}
for (const [family, functions, locks] of [
  ["OR", 156, 84], ["AND", 156, 84], ["EOR", 96, 84],
] as const) {
  const found = logicalGeneratedCounts.get(family);
  if (!found || found.functions !== functions || found.locks !== locks || found.unlocks !== locks) {
    fail(`generated ${family} ownership: functions=${found?.functions ?? 0} locks=${found?.locks ?? 0}/${found?.unlocks ?? 0}`);
  }
}
const generatedOrFlagLive = (generatedSource.match(/^void REGPARAM2 op_[0-9a-f]+_0_comp_ff[^\n]*\/\* OR \*\//gm) ?? []).length;
const generatedOrNoFlags = (generatedSource.match(/^void REGPARAM2 op_[0-9a-f]+_0_comp_nf[^\n]*\/\* OR \*\//gm) ?? []).length;
if (generatedOrFlagLive !== 78 || generatedOrNoFlags !== 78)
  fail(`generated OR flag split: ff=${generatedOrFlagLive} nf=${generatedOrNoFlags}`);
const generatedEorFlagLive = (generatedSource.match(/^void REGPARAM2 op_[0-9a-f]+_0_comp_ff[^\n]*\/\* EOR \*\//gm) ?? []).length;
const generatedEorNoFlags = (generatedSource.match(/^void REGPARAM2 op_[0-9a-f]+_0_comp_nf[^\n]*\/\* EOR \*\//gm) ?? []).length;
if (generatedEorFlagLive !== 48 || generatedEorNoFlags !== 48)
  fail(`generated EOR flag split: ff=${generatedEorFlagLive} nf=${generatedEorNoFlags}`);

for (const [variant, width] of [
  ["jnf", "b"], ["jnf", "w"], ["jnf", "l"],
  ["jff", "b"], ["jff", "w"], ["jff", "l"],
] as const) {
  const body = functionBody(
    midfunc2Source,
    `MIDFUNC(2,${variant}_AND_${width},`,
    `MENDFUNC(2,${variant}_AND_${width},`,
    `${variant}_AND_${width} operand/flags lifecycle`,
  );
  requireText(body, `COMPCALL(${variant}_AND_${width}_imm)`, `${variant}_AND_${width} constant source route`);
  requireText(body, `INIT_REGS_${width}(d, s);`, `${variant}_AND_${width} operand acquisition`);
  requireText(body, "EXIT_REGS(d, s);", `${variant}_AND_${width} operand release`);
  requireBefore(body, `INIT_REGS_${width}(d, s);`, "EXIT_REGS(d, s);", `${variant}_AND_${width} operand lifecycle`);
  requireText(body, variant === "jff" ? "ANDS_www(" : "AND_www(", `${variant}_AND_${width} flag selection`);
  if (width === "b" || width === "w") {
    const bits = width === "b" ? 8 : 16;
    if (variant === "jff") {
      requireText(body, `SIGNED${bits}_REG_2_REG(REG_WORK1, d);`, `${variant}_AND_${width} signed destination`);
      requireText(body, `SIGNED${bits}_REG_2_REG(REG_WORK2, s);`, `${variant}_AND_${width} signed source`);
    } else {
      requireText(body, "AND_www(REG_WORK1, d, s);", `${variant}_AND_${width} narrow result staging`);
    }
    requireText(body, `BFI_wwii(d, REG_WORK1, 0, ${bits});`, `${variant}_AND_${width} upper-lane preservation`);
  } else {
    requireText(body, `${variant === "jff" ? "ANDS" : "AND"}_www(d, d, s);`, `${variant}_AND_l full-width result`);
  }
  if (/\b(?:FLAGX|DUPLICACTE_CARRY)\b/.test(body)) fail(`${variant}_AND_${width} modifies X`);
  if (variant === "jff") requireText(body, "flags_carry_inverted = false;", `${variant}_AND_${width} carry state`);
  else if (body.includes("flags_carry_inverted")) fail(`${variant}_AND_${width} no-flags path changes carry metadata`);
}
for (const [variant, width] of [
  ["jnf", "b"], ["jnf", "w"], ["jnf", "l"],
  ["jff", "b"], ["jff", "w"], ["jff", "l"],
] as const) {
  const body = functionBody(
    midfunc2Source,
    `MIDFUNC(2,${variant}_AND_${width}_imm,`,
    `MENDFUNC(2,${variant}_AND_${width}_imm,`,
    `${variant}_AND_${width}_imm immediate/flags lifecycle`,
  );
  requireText(body, variant === "jff" ? "ANDS_www(" : "AND_www(", `${variant}_AND_${width}_imm flag selection`);
  if (width === "b" || width === "w") {
    const bits = width === "b" ? 8 : 16;
    if (variant === "jff") {
      requireText(body, `SIGNED${bits}_REG_2_REG(REG_WORK1, d);`, `${variant}_AND_${width}_imm signed destination`);
      requireText(body, `SIGNED${bits}_IMM_2_REG(REG_WORK2, v);`, `${variant}_AND_${width}_imm signed immediate`);
      requireText(body, `BFI_wwii(d, REG_WORK1, 0, ${bits});`, `${variant}_AND_${width}_imm upper-lane preservation`);
    } else {
      const mask = width === "b"
        ? "(live.state[d].val & 0xffffff00) | ((live.state[d].val & v) & 0x000000ff)"
        : "(live.state[d].val & 0xffff0000) | ((live.state[d].val & v) & 0x0000ffff)";
      requireText(body, mask, `${variant}_AND_${width}_imm constant upper-lane preservation`);
      requireText(body, "MOVN_xi(REG_WORK1", `${variant}_AND_${width}_imm runtime immediate materialisation`);
    }
  } else {
    requireText(body, "LOAD_U32(REG_WORK1, v);", `${variant}_AND_l_imm full immediate materialisation`);
    if (variant === "jnf")
      requireText(body, "live.state[d].val = live.state[d].val & v;", `${variant}_AND_l_imm constant fold`);
  }
  if (/\b(?:FLAGX|DUPLICACTE_CARRY)\b/.test(body)) fail(`${variant}_AND_${width}_imm modifies X`);
  if (variant === "jff") requireText(body, "flags_carry_inverted = false;", `${variant}_AND_${width}_imm carry state`);
  else if (body.includes("flags_carry_inverted")) fail(`${variant}_AND_${width}_imm no-flags path changes carry metadata`);
}

const andExactVectors = [
  "and_core_b_reg_zero_native", "and_core_w_reg_negative_native", "and_core_l_reg_positive_native",
  "and_core_b_self_alias_native", "and_core_w_self_alias_native", "and_core_l_self_alias_native",
  "and_core_b_imm_zero_native", "and_core_w_imm_negative_native",
  "and_core_l_imm_pattern_native", "and_core_l_imm_negative_native",
  "and_core_b_reg_noflags_native", "and_core_w_reg_noflags_native", "and_core_l_reg_noflags_native",
  "and_core_b_aind_source_special_native", "and_core_w_postinc_source_native",
  "and_core_l_predec_source_native", "and_core_b_d16_source_native",
  "and_core_w_index_source_special_native", "and_core_l_absw_source_native",
  "and_core_b_absl_source_special_native", "and_core_w_pc16_source_native",
  "and_core_l_pcindex_source_native", "and_core_b_aind_dest_special_native",
  "and_core_w_postinc_dest_native", "and_core_l_predec_dest_native",
  "and_core_b_d16_dest_native", "and_core_w_index_dest_special_native",
  "and_core_l_absw_dest_native", "and_core_b_absl_dest_special_native",
  "and_core_b_a7_postinc_dest_native", "and_core_b_a7_predec_dest_native",
  "and_core_b_andi_postinc_dest_native", "and_core_b_postinc_dest_native",
  "and_core_b_postinc_dest_noflags_native",
];
for (const fragment of [
  "declare -a AND_NATIVE_MATRIX_NAMES=(",
  'TEST_ORDER+=("${AND_NATIVE_MATRIX_NAMES[@]}")',
  'for _and_name in "${AND_NATIVE_MATRIX_NAMES[@]}"; do\n    NATIVE_REPLAY_TESTS["$_and_name"]=1\n    NATIVE_REPLAY_PC["$_and_name"]=0x1000\n    NATIVE_REPLAY_COUNT["$_and_name"]=2',
  'for _and_name in "${AND_NATIVE_MATRIX_NAMES[@]}"; do\n    RISKY_TESTS["$_and_name"]=1',
]) requireText(harnessSource, fragment, "AND exact-native matrix/replay contract");
for (const name of andExactVectors) {
  for (const fragment of [`TESTS[${name}]=`, `EXPECTED_REG_FIELDS[${name}]=`, `INIT_REGS[${name}]=`])
    requireText(harnessSource, fragment, `AND exact-native vector ${name}`);
}
const andMemoryVectors = [
  "and_core_b_aind_source_special_native", "and_core_w_postinc_source_native",
  "and_core_l_predec_source_native", "and_core_b_d16_source_native",
  "and_core_w_index_source_special_native", "and_core_l_absw_source_native",
  "and_core_b_absl_source_special_native", "and_core_w_pc16_source_native",
  "and_core_l_pcindex_source_native", "and_core_b_aind_dest_special_native",
  "and_core_w_postinc_dest_native", "and_core_l_predec_dest_native",
  "and_core_b_d16_dest_native", "and_core_w_index_dest_special_native",
  "and_core_l_absw_dest_native", "and_core_b_absl_dest_special_native",
  "and_core_b_a7_postinc_dest_native", "and_core_b_a7_predec_dest_native",
  "and_core_b_andi_postinc_dest_native", "and_core_b_postinc_dest_native",
  "and_core_b_postinc_dest_noflags_native",
];
for (const name of andMemoryVectors) {
  requireText(harnessSource, `TEST_MEMORY_BYTES[${name}]=`, `AND memory bytes ${name}`);
  requireText(harnessSource, `NATIVE_REPLAY_BYTES[${name}]=`, `AND native memory replay ${name}`);
}
for (const name of [
  "and_core_b_aind_source_special_native", "and_core_w_index_source_special_native",
  "and_core_b_absl_source_special_native", "and_core_b_aind_dest_special_native",
  "and_core_w_index_dest_special_native", "and_core_b_absl_dest_special_native",
]) requireText(harnessSource, `SPECIAL_MEMORY_TESTS[${name}]=1`, `AND special-memory route ${name}`);
for (const name of [
  "and_core_b_reg_noflags_native", "and_core_w_reg_noflags_native",
  "and_core_l_reg_noflags_native", "and_core_b_postinc_dest_noflags_native",
]) requireText(harnessSource, `TESTS[${name}]=`, `AND no-flags vector ${name}`);
for (const contract of [
  "and_b_postinc_source_dreg_collision", "[and_b_postinc_source_dreg_collision]=21",
  "[and_b_postinc_source_dreg_collision]=0", "[and_b_postinc_source_dreg_collision]=1",
  "and_b_postinc_ea_source_collision", "[and_b_postinc_ea_source_collision]=20",
  "[and_b_postinc_ea_source_collision]=21", "[and_b_postinc_ea_source_collision]=1",
]) requireText(regallocPressureSource, contract, "AND source/EA allocator pressure");
requireText(harnessSource, 'TESTS[and_core_b_postinc_dest_native]="C118 40C2 1028 FFFF"', "AND.B D0,(A0)+ exact-native regression");
requireText(activeRiskySource, "and_core_b_postinc_dest_native", "AND.B D0,(A0)+ active mismatch-first regression");
/* EOR shares the generator's writable-EA repair but has an independently
 * closed semantic lifecycle. The source is Dn/immediate only; all seven legal
 * writable memory EAs and all twelve flag-live/no-flags MIDFUNC routes remain
 * explicit so adjacent AND/OR evidence cannot silently promote this family. */
for (const [variant, width] of [
  ["jnf", "b"], ["jnf", "w"], ["jnf", "l"],
  ["jff", "b"], ["jff", "w"], ["jff", "l"],
] as const) {
  const body = functionBody(
    midfunc2Source,
    `MIDFUNC(2,${variant}_EOR_${width},`,
    `MENDFUNC(2,${variant}_EOR_${width},`,
    `${variant}_EOR_${width} operand/flags lifecycle`,
  );
  requireText(body, `COMPCALL(${variant}_EOR_${width}_imm)`, `${variant}_EOR_${width} constant source route`);
  requireText(body, `INIT_REGS_${width}(d, s);`, `${variant}_EOR_${width} operand acquisition`);
  requireText(body, "EXIT_REGS(d, s);", `${variant}_EOR_${width} operand release`);
  requireBefore(body, `INIT_REGS_${width}(d, s);`, "EXIT_REGS(d, s);", `${variant}_EOR_${width} operand lifecycle`);
  requireText(body, "EOR_www(", `${variant}_EOR_${width} result lowering`);
  if (width === "b" || width === "w") {
    const bits = width === "b" ? 8 : 16;
    requireText(body, `BFI_wwii(d, REG_WORK1, 0, ${bits});`, `${variant}_EOR_${width} upper-lane preservation`);
    if (variant === "jff") {
      requireText(body, `SIGNED${bits}_REG_2_REG(REG_WORK1, d);`, `${variant}_EOR_${width} signed destination`);
      requireText(body, `SIGNED${bits}_REG_2_REG(REG_WORK2, s);`, `${variant}_EOR_${width} signed source`);
    }
  } else {
    requireText(body, "EOR_www(d, d, s);", `${variant}_EOR_l full-width result`);
  }
  if (variant === "jff") {
    requireText(body, "TST_ww(", `${variant}_EOR_${width} N/Z and V/C publication`);
    requireText(body, "flags_carry_inverted = false;", `${variant}_EOR_${width} carry metadata`);
  } else if (body.includes("TST_ww(") || body.includes("flags_carry_inverted")) {
    fail(`${variant}_EOR_${width} no-flags path publishes flags or carry metadata`);
  }
  if (/\b(?:FLAGX|DUPLICACTE_CARRY)\b/.test(body)) fail(`${variant}_EOR_${width} modifies X`);
}
for (const [variant, width] of [
  ["jnf", "b"], ["jnf", "w"], ["jnf", "l"],
  ["jff", "b"], ["jff", "w"], ["jff", "l"],
] as const) {
  const body = functionBody(
    midfunc2Source,
    `MIDFUNC(2,${variant}_EOR_${width}_imm,`,
    `MENDFUNC(2,${variant}_EOR_${width}_imm,`,
    `${variant}_EOR_${width}_imm immediate/flags lifecycle`,
  );
  requireText(body, "EOR_www(", `${variant}_EOR_${width}_imm result lowering`);
  if (width === "b" || width === "w") {
    const bits = width === "b" ? 8 : 16;
    if (variant === "jff") {
      requireText(body, `SIGNED${bits}_REG_2_REG(REG_WORK1, d);`, `${variant}_EOR_${width}_imm signed destination`);
      requireText(body, `SIGNED${bits}_IMM_2_REG(REG_WORK2, v);`, `${variant}_EOR_${width}_imm signed immediate`);
      requireText(body, `BFI_wwii(d, REG_WORK1, 0, ${bits});`, `${variant}_EOR_${width}_imm upper-lane preservation`);
    } else {
      requireText(body, "MOV_xi(REG_WORK1", `${variant}_EOR_${width}_imm bounded immediate materialisation`);
    }
  } else {
    requireText(body, "LOAD_U32(REG_WORK1, v);", `${variant}_EOR_l_imm full immediate materialisation`);
    if (variant === "jnf")
      requireText(body, "live.state[d].val = live.state[d].val ^ v;", `${variant}_EOR_l_imm constant fold`);
  }
  if (variant === "jff") {
    requireText(body, "TST_ww(", `${variant}_EOR_${width}_imm N/Z and V/C publication`);
    requireText(body, "flags_carry_inverted = false;", `${variant}_EOR_${width}_imm carry metadata`);
  } else if (body.includes("TST_ww(") || body.includes("flags_carry_inverted")) {
    fail(`${variant}_EOR_${width}_imm no-flags path publishes flags or carry metadata`);
  }
  if (/\b(?:FLAGX|DUPLICACTE_CARRY)\b/.test(body)) fail(`${variant}_EOR_${width}_imm modifies X`);
}
const eorExactVectors = [
  "eor_core_b_reg_zero_native", "eor_core_w_reg_negative_native", "eor_core_l_reg_positive_native",
  "eor_core_b_self_alias_native", "eor_core_w_self_alias_native", "eor_core_l_self_alias_native",
  "eor_core_b_imm_zero_native", "eor_core_w_imm_negative_native",
  "eor_core_l_imm_pattern_native", "eor_core_l_imm_negative_native",
  "eor_core_b_reg_noflags_native", "eor_core_w_reg_noflags_native", "eor_core_l_reg_noflags_native",
  "eor_core_b_imm_noflags_native", "eor_core_w_imm_noflags_native", "eor_core_l_imm_noflags_native",
  "eor_core_b_aind_dest_special_native", "eor_core_w_postinc_dest_native",
  "eor_core_l_predec_dest_native", "eor_core_b_d16_dest_native",
  "eor_core_w_index_dest_special_native", "eor_core_l_absw_dest_native",
  "eor_core_b_absl_dest_special_native", "eor_core_b_a7_postinc_dest_native",
  "eor_core_b_a7_predec_dest_native", "eor_core_b_eori_postinc_dest_native",
  "eor_core_b_postinc_dest_native", "eor_core_b_postinc_dest_noflags_native",
];
for (const fragment of [
  "declare -a EOR_NATIVE_MATRIX_NAMES=(",
  'TEST_ORDER+=("${EOR_NATIVE_MATRIX_NAMES[@]}")',
  'for _eor_name in "${EOR_NATIVE_MATRIX_NAMES[@]}"; do\n    NATIVE_REPLAY_TESTS["$_eor_name"]=1\n    NATIVE_REPLAY_PC["$_eor_name"]=0x1000\n    NATIVE_REPLAY_COUNT["$_eor_name"]=2',
  'for _eor_name in "${EOR_NATIVE_MATRIX_NAMES[@]}"; do\n    RISKY_TESTS["$_eor_name"]=1',
]) requireText(harnessSource, fragment, "EOR exact-native matrix/replay contract");
for (const name of eorExactVectors) {
  for (const fragment of [`TESTS[${name}]=`, `EXPECTED_REG_FIELDS[${name}]=`, `INIT_REGS[${name}]=`])
    requireText(harnessSource, fragment, `EOR exact-native vector ${name}`);
  requireText(activeRiskySource, name, `EOR active mismatch-first vector ${name}`);
}
const eorMemoryVectors = [
  "eor_core_b_aind_dest_special_native", "eor_core_w_postinc_dest_native",
  "eor_core_l_predec_dest_native", "eor_core_b_d16_dest_native",
  "eor_core_w_index_dest_special_native", "eor_core_l_absw_dest_native",
  "eor_core_b_absl_dest_special_native", "eor_core_b_a7_postinc_dest_native",
  "eor_core_b_a7_predec_dest_native", "eor_core_b_eori_postinc_dest_native",
  "eor_core_b_postinc_dest_native", "eor_core_b_postinc_dest_noflags_native",
];
for (const name of eorMemoryVectors) {
  requireText(harnessSource, `TEST_MEMORY_BYTES[${name}]=`, `EOR memory bytes ${name}`);
  requireText(harnessSource, `NATIVE_REPLAY_BYTES[${name}]=`, `EOR native memory replay ${name}`);
}
for (const name of [
  "eor_core_b_aind_dest_special_native", "eor_core_w_index_dest_special_native",
  "eor_core_b_absl_dest_special_native",
]) requireText(harnessSource, `SPECIAL_MEMORY_TESTS[${name}]=1`, `EOR special-memory route ${name}`);
for (const name of [
  "eor_core_b_reg_noflags_native", "eor_core_w_reg_noflags_native", "eor_core_l_reg_noflags_native",
  "eor_core_b_imm_noflags_native", "eor_core_w_imm_noflags_native", "eor_core_l_imm_noflags_native",
  "eor_core_b_postinc_dest_noflags_native",
]) requireText(harnessSource, `TESTS[${name}]=`, `EOR no-flags vector ${name}`);
for (const contract of [
  "eor_b_postinc_source_dest_collision", "[eor_b_postinc_source_dest_collision]=6",
  "[eor_b_postinc_source_dest_collision]=21", "[eor_b_postinc_source_dest_collision]=1",
  "eor_b_postinc_ea_dest_collision", "[eor_b_postinc_ea_dest_collision]=20",
  "[eor_b_postinc_ea_dest_collision]=21", "[eor_b_postinc_ea_dest_collision]=1",
]) requireText(regallocPressureSource, contract, "EOR source/EA allocator pressure");
requireText(harnessSource, 'TESTS[eor_core_b_postinc_dest_native]="B118 40C2 1028 FFFF"', "EOR.B D0,(A0)+ exact-native regression");

/* OR is the complete two-direction logical family: readable-memory, Dn and
 * immediate sources feed register or writable-memory destinations. Prove its
 * lifecycle independently of the shared AND/EOR generator repair. */
for (const [variant, width] of [
  ["jnf", "b"], ["jnf", "w"], ["jnf", "l"],
  ["jff", "b"], ["jff", "w"], ["jff", "l"],
] as const) {
  const body = functionBody(
    midfunc2Source,
    `MIDFUNC(2,${variant}_OR_${width},`,
    `MENDFUNC(2,${variant}_OR_${width},`,
    `${variant}_OR_${width} operand/flags lifecycle`,
  );
  requireText(body, `COMPCALL(${variant}_OR_${width}_imm)`, `${variant}_OR_${width} constant source route`);
  requireText(body, `INIT_REGS_${width}(d, s);`, `${variant}_OR_${width} operand acquisition`);
  requireText(body, "EXIT_REGS(d, s);", `${variant}_OR_${width} operand release`);
  requireBefore(body, `INIT_REGS_${width}(d, s);`, "EXIT_REGS(d, s);", `${variant}_OR_${width} operand lifecycle`);
  requireText(body, "ORR_www(", `${variant}_OR_${width} result lowering`);
  if (width === "b" || width === "w") {
    const bits = width === "b" ? 8 : 16;
    requireText(body, `BFI_wwii(d, REG_WORK1, 0, ${bits});`, `${variant}_OR_${width} upper-lane preservation`);
    if (variant === "jff") {
      requireText(body, `SIGNED${bits}_REG_2_REG(REG_WORK1, d);`, `${variant}_OR_${width} signed destination`);
      requireText(body, `SIGNED${bits}_REG_2_REG(REG_WORK2, s);`, `${variant}_OR_${width} signed source`);
    }
  } else {
    requireText(body, "ORR_www(d, d, s);", `${variant}_OR_l full-width result`);
  }
  if (variant === "jff") {
    requireText(body, "TST_ww(", `${variant}_OR_${width} N/Z and V/C publication`);
    requireText(body, "flags_carry_inverted = false;", `${variant}_OR_${width} carry metadata`);
  } else if (body.includes("TST_ww(") || body.includes("flags_carry_inverted")) {
    fail(`${variant}_OR_${width} no-flags path publishes flags or carry metadata`);
  }
  if (/\b(?:FLAGX|DUPLICACTE_CARRY)\b/.test(body)) fail(`${variant}_OR_${width} modifies X`);
}
for (const [variant, width] of [
  ["jnf", "b"], ["jnf", "w"], ["jnf", "l"],
  ["jff", "b"], ["jff", "w"], ["jff", "l"],
] as const) {
  const body = functionBody(
    midfunc2Source,
    `MIDFUNC(2,${variant}_OR_${width}_imm,`,
    `MENDFUNC(2,${variant}_OR_${width}_imm,`,
    `${variant}_OR_${width}_imm immediate/flags lifecycle`,
  );
  requireText(body, "ORR_www(", `${variant}_OR_${width}_imm result lowering`);
  if (width === "b" || width === "w") {
    const bits = width === "b" ? 8 : 16;
    if (variant === "jff") {
      requireText(body, `SIGNED${bits}_REG_2_REG(REG_WORK1, d);`, `${variant}_OR_${width}_imm signed destination`);
      requireText(body, `SIGNED${bits}_IMM_2_REG(REG_WORK2, v);`, `${variant}_OR_${width}_imm signed immediate`);
      requireText(body, `BFI_wwii(d, REG_WORK1, 0, ${bits});`, `${variant}_OR_${width}_imm upper-lane preservation`);
    } else {
      const mask = width === "b"
        ? "(live.state[d].val & 0xffffff00) | ((live.state[d].val | v) & 0x000000ff)"
        : "(live.state[d].val & 0xffff0000) | ((live.state[d].val | v) & 0x0000ffff)";
      requireText(body, mask, `${variant}_OR_${width}_imm constant upper-lane preservation`);
      requireText(body, width === "b" ? "MOV_xi(REG_WORK2" : "MOV_xi(REG_WORK1", `${variant}_OR_${width}_imm runtime immediate materialisation`);
    }
  } else {
    requireText(body, "LOAD_U32(REG_WORK1, v);", `${variant}_OR_l_imm full immediate materialisation`);
    if (variant === "jnf")
      requireText(body, "live.state[d].val = live.state[d].val | v;", `${variant}_OR_l_imm constant fold`);
  }
  if (variant === "jff") {
    requireText(body, "TST_ww(", `${variant}_OR_${width}_imm N/Z and V/C publication`);
    requireText(body, "flags_carry_inverted = false;", `${variant}_OR_${width}_imm carry metadata`);
  } else if (body.includes("TST_ww(") || body.includes("flags_carry_inverted")) {
    fail(`${variant}_OR_${width}_imm no-flags path publishes flags or carry metadata`);
  }
  if (/\b(?:FLAGX|DUPLICACTE_CARRY)\b/.test(body)) fail(`${variant}_OR_${width}_imm modifies X`);
}
const orExactVectors = [
  "or_core_b_reg_zero_native", "or_core_w_reg_negative_native", "or_core_l_reg_positive_native",
  "or_core_b_self_alias_native", "or_core_w_self_alias_native", "or_core_l_self_alias_native",
  "or_core_b_imm_zero_native", "or_core_w_imm_negative_native",
  "or_core_l_imm_pattern_native", "or_core_l_imm_negative_native",
  "or_core_b_reg_noflags_native", "or_core_w_reg_noflags_native", "or_core_l_reg_noflags_native",
  "or_core_b_imm_noflags_native", "or_core_w_imm_noflags_native", "or_core_l_imm_noflags_native",
  "or_core_b_aind_source_special_native", "or_core_w_postinc_source_native",
  "or_core_l_predec_source_native", "or_core_b_d16_source_native",
  "or_core_w_index_source_special_native", "or_core_l_absw_source_native",
  "or_core_b_absl_source_special_native", "or_core_w_pc16_source_native",
  "or_core_l_pcindex_source_native", "or_core_b_aind_dest_special_native",
  "or_core_w_postinc_dest_native", "or_core_l_predec_dest_native",
  "or_core_b_d16_dest_native", "or_core_w_index_dest_special_native",
  "or_core_l_absw_dest_native", "or_core_b_absl_dest_special_native",
  "or_core_b_a7_postinc_dest_native", "or_core_b_a7_predec_dest_native",
  "or_core_b_ori_postinc_dest_native", "or_core_b_postinc_dest_native",
  "or_core_b_postinc_dest_noflags_native",
];
for (const fragment of [
  "declare -a OR_NATIVE_MATRIX_NAMES=(",
  'TEST_ORDER+=("${OR_NATIVE_MATRIX_NAMES[@]}")',
  'for _or_name in "${OR_NATIVE_MATRIX_NAMES[@]}"; do\n    NATIVE_REPLAY_TESTS["$_or_name"]=1\n    NATIVE_REPLAY_PC["$_or_name"]=0x1000\n    NATIVE_REPLAY_COUNT["$_or_name"]=2',
  'for _or_name in "${OR_NATIVE_MATRIX_NAMES[@]}"; do\n    RISKY_TESTS["$_or_name"]=1',
]) requireText(harnessSource, fragment, "OR exact-native matrix/replay contract");
for (const name of orExactVectors) {
  for (const fragment of [`TESTS[${name}]=`, `EXPECTED_REG_FIELDS[${name}]=`, `INIT_REGS[${name}]=`])
    requireText(harnessSource, fragment, `OR exact-native vector ${name}`);
  requireText(activeRiskySource, name, `OR active mismatch-first vector ${name}`);
}
const orMemoryVectors = [
  "or_core_b_aind_source_special_native", "or_core_w_postinc_source_native",
  "or_core_l_predec_source_native", "or_core_b_d16_source_native",
  "or_core_w_index_source_special_native", "or_core_l_absw_source_native",
  "or_core_b_absl_source_special_native", "or_core_w_pc16_source_native",
  "or_core_l_pcindex_source_native", "or_core_b_aind_dest_special_native",
  "or_core_w_postinc_dest_native", "or_core_l_predec_dest_native",
  "or_core_b_d16_dest_native", "or_core_w_index_dest_special_native",
  "or_core_l_absw_dest_native", "or_core_b_absl_dest_special_native",
  "or_core_b_a7_postinc_dest_native", "or_core_b_a7_predec_dest_native",
  "or_core_b_ori_postinc_dest_native", "or_core_b_postinc_dest_native",
  "or_core_b_postinc_dest_noflags_native",
];
for (const name of orMemoryVectors) {
  requireText(harnessSource, `TEST_MEMORY_BYTES[${name}]=`, `OR memory bytes ${name}`);
  requireText(harnessSource, `NATIVE_REPLAY_BYTES[${name}]=`, `OR native memory replay ${name}`);
}
for (const name of [
  "or_core_b_aind_source_special_native", "or_core_w_index_source_special_native",
  "or_core_b_absl_source_special_native", "or_core_b_aind_dest_special_native",
  "or_core_w_index_dest_special_native", "or_core_b_absl_dest_special_native",
]) requireText(harnessSource, `SPECIAL_MEMORY_TESTS[${name}]=1`, `OR special-memory route ${name}`);
for (const name of [
  "or_core_b_reg_noflags_native", "or_core_w_reg_noflags_native", "or_core_l_reg_noflags_native",
  "or_core_b_imm_noflags_native", "or_core_w_imm_noflags_native", "or_core_l_imm_noflags_native",
  "or_core_b_postinc_dest_noflags_native",
]) requireText(harnessSource, `TESTS[${name}]=`, `OR no-flags vector ${name}`);
for (const contract of [
  "or_b_postinc_source_dreg_collision", "[or_b_postinc_source_dreg_collision]=21",
  "[or_b_postinc_source_dreg_collision]=0", "[or_b_postinc_source_dreg_collision]=1",
  "or_b_postinc_ea_source_collision", "[or_b_postinc_ea_source_collision]=20",
  "[or_b_postinc_ea_source_collision]=21", "[or_b_postinc_ea_source_collision]=1",
]) requireText(regallocPressureSource, contract, "OR source/EA allocator pressure");
requireText(harnessSource, 'TESTS[or_core_b_postinc_dest_native]="8118 40C2 1028 FFFF"', "OR.B D0,(A0)+ exact-native regression");

/* NEG is generated as zero-source through the shared SUB lifecycle.  Memory
 * destinations additionally own the pre-write EA from fetch through result
 * allocation, flags and ordered storage.  Directly prove the separately live
 * generic NEG_ww encoder rather than treating M68K execution as encoder proof. */
const negGenerator = functionBody(
  gencompSource,
  "     case i_NEG:",
  "     case i_NEGX:",
  "NEG generator",
);
for (const contract of [
  'genamode (curi->smode, "srcreg", curi->size, "src", GENA_GETV_FETCH, GENA_MOVEM_DO_INC);',
  'if (curi->smode != Dreg)',
  'comprintf("\\tint __negealock=jit_value_lock(srca);\\n");',
  'comprintf("\\tint dst=scratchie++;\\n");',
  'comprintf("\\tmov_l_ri(dst,0);\\n");',
  'genflags (flag_sub, curi->size, "", "src", "dst");',
  'genastore ("dst", curi->smode, "srcreg", curi->size, "src");',
  'comprintf("\\tjit_value_unlock(__negealock);\\n");',
]) {
  requireText(negGenerator, contract, "NEG semantic/EA lifecycle");
}
requireBefore(negGenerator, 'jit_value_lock(srca)', 'genflags (flag_sub', "NEG EA ownership");
requireBefore(negGenerator, 'genastore ("dst"', 'jit_value_unlock(__negealock)', "NEG EA ownership");
const generatedNegLocks = (generatedSource.match(/int __negealock=jit_value_lock\(srca\);/g) || []).length;
const generatedNegUnlocks = (generatedSource.match(/jit_value_unlock\(__negealock\);/g) || []).length;
if (generatedNegLocks !== 42 || generatedNegUnlocks !== 42) {
  fail(`generated NEG EA ownership: locks=${generatedNegLocks} unlocks=${generatedNegUnlocks}`);
}
for (const [opcode, nextOpcode, width, move] of [
  ["4400", "4410", "b", "mov_b_rr"],
  ["4440", "4450", "w", "mov_w_rr"],
  ["4480", "4490", "l", "mov_l_rr"],
] as const) {
  const liveBody = functionBody(
    generatedSource,
    `void REGPARAM2 op_${opcode}_0_comp_ff`,
    `void REGPARAM2 op_${nextOpcode}_0_comp_ff`,
    `generated NEG.${width} flag-live`,
  );
  for (const contract of [
    "mov_l_ri(dst,0)", `sub_${width}(dst,src)`, "duplicate_carry()", `${move}(srcreg, dst)`,
  ]) requireText(liveBody, contract, `generated NEG.${width} flag-live`);
  const deadBody = functionBody(
    generatedSource,
    `void REGPARAM2 op_${opcode}_0_comp_nf`,
    `void REGPARAM2 op_${nextOpcode}_0_comp_nf`,
    `generated NEG.${width} no-flags`,
  );
  for (const contract of ["mov_l_ri(dst,0)", "dont_care_flags()", `sub_${width}(dst,src)`, `${move}(srcreg, dst)`]) {
    requireText(deadBody, contract, `generated NEG.${width} no-flags`);
  }
  if (deadBody.includes("start_needflags()") || deadBody.includes("duplicate_carry()")) {
    fail(`generated NEG.${width} no-flags path still publishes dead flags`);
  }
}
const negExactVectors = [
  "neg_b_zero_native", "neg_w_zero_native", "neg_l_zero_native",
  "neg_b_one_native", "neg_w_one_native", "neg_l_one_native",
  "neg_b_min_overflow_native", "neg_w_min_overflow_native", "neg_l_min_overflow_native",
  "neg_b_minus_one_native", "neg_w_minus_one_native", "neg_l_minus_one_native",
  "neg_b_min_nf_native", "neg_w_min_nf_native", "neg_l_min_nf_native",
  "neg_b_aind_special_native", "neg_w_postinc_native", "neg_l_predec_native",
  "neg_b_d16_native", "neg_w_indexed_special_native", "neg_l_absw_native",
  "neg_b_absl_special_native", "neg_b_a7_postinc_native", "neg_b_a7_predec_native",
];
for (const name of negExactVectors) requireText(harnessSource, name, `NEG exact-native vector ${name}`);
for (const contract of [
  'for _neg_name in "${NEG_NATIVE_MATRIX_NAMES[@]}"',
  'NATIVE_REPLAY_TESTS["$_neg_name"]=1',
  'NATIVE_REPLAY_PC["$_neg_name"]=0x1000',
  'NATIVE_REPLAY_COUNT["$_neg_name"]=2',
  "SPECIAL_MEMORY_TESTS[neg_b_aind_special_native]=1",
  "SPECIAL_MEMORY_TESTS[neg_w_indexed_special_native]=1",
  "SPECIAL_MEMORY_TESTS[neg_b_absl_special_native]=1",
]) requireText(harnessSource, contract, "NEG exact-native/memory gate");
requireText(activeRiskySource, "neg_l_min_overflow_native", "NEG active-risky sentinel");
for (const contract of [
  "neg_b_postinc_result_ea_collision", "[neg_b_postinc_result_ea_collision]=22",
  "[neg_b_postinc_result_ea_collision]=20", "[neg_b_postinc_result_ea_collision]=1",
]) requireText(regallocPressureSource, contract, "NEG forced result/EA collision");
requireText(codegenHeaderSource, "#define NEG_ww(Wd,Wm)", "reachable NEG_ww emitter declaration");
const negEmitterCallsites = (shiftSource.match(/\bNEG_ww\(/g) || []).length;
if (negEmitterCallsites !== 6) fail(`reachable NEG_ww emitter callers=${negEmitterCallsites} expected=6`);
for (const contract of ["NEG_ww(d, m)", "neg_ww_word(10, 9)", "0x4b0903eau", "emitter_neg_native_vectors", "vectors == 7"]) {
  requireText(negEmitterProbeSource, contract, "NEG_ww direct emitter probe");
}
for (const contract of ["-std=c++17", "-Wall -Wextra -Werror", "emitter-neg-conformance.cpp"]) {
  requireText(negEmitterHarnessSource, contract, "NEG_ww emitter harness");
}
requireText(harnessSource, 'emitter-neg-conformance.sh', "NEG_ww mandatory harness gate");

for (const contract of [
  "#define B_i(i)", "#define BR_x(Xn)", "#define CC_B_i(cc,i)",
  "#define CBNZ_wi(Wt,i)", "#define CBNZ_xi(Xt,i)",
  "#define CBZ_wi(Wt,i)", "#define CBZ_xi(Xt,i)",
  "#define TBNZ_xii(Xt,bit,i)", "#define TBNZ_wii(Wt,bit,i)",
  "#define TBZ_xii(Xt,bit,i)", "#define TBZ_wii(Wt,bit,i)",
  "((i) & 0x3fff) << 5", "((bit) & 0x20u) << 26",
]) requireText(codegenHeaderSource, contract, "generic branch emitter encoding");
if (codegenHeaderSource.includes("% 0x3fff"))
  fail("generic branch emitter encoding: modulo cannot encode signed imm14 displacement");
for (const contract of [
  "byte_offset % 4 != 0", "ARM64_BRANCH_PATCH_UNALIGNED",
  "(instruction & 0xfc000000) == 0x14000000",
  "off > 0x1ffffff || off < -0x2000000", "ARM64_BRANCH_PATCH_B_RANGE",
  "(instruction & 0x7e000000) == 0x36000000",
  "off > 0x1fff || off < -0x2000", "ARM64_BRANCH_PATCH_TB_RANGE",
  "instruction & 0xfff8001f",
  "(instruction & 0x7e000000) == 0x34000000", "ARM64_BRANCH_PATCH_CB_RANGE",
  "off > 0x3ffff || off < -0x40000",
  "(instruction & 0xff000010) == 0x54000000", "ARM64_BRANCH_PATCH_BCOND_RANGE",
  "ARM64_BRANCH_PATCH_UNSUPPORTED", "ARM64_BRANCH_PATCH_OK",
]) requireText(branchPatchSource, contract, "branch patch width/range contract");
const patchBranch = midfuncSource.slice(
  requireText(midfuncSource, "STATIC_INLINE void write_jmp_target", "branch patch boundary"),
  requireText(midfuncSource, "static inline void emit_jmp_target", "branch patch boundary"),
);
for (const contract of [
  "arm64_patch_branch_instruction", "switch (status)",
  "ARM64_BRANCH_PATCH_B_RANGE", "ARM64_BRANCH_PATCH_TB_RANGE",
  "ARM64_BRANCH_PATCH_CB_RANGE", "ARM64_BRANCH_PATCH_BCOND_RANGE",
  "unsupported branch patch instruction", "jit_abort(",
]) requireText(patchBranch, contract, "branch patch fail-closed boundary");
requireBefore(patchBranch, "arm64_patch_branch_instruction", "jit_begin_write_window", "validate branch before write window");
if (patchBranch.includes("write_log("))
  fail("branch patch width/range contract must fail closed instead of truncating after a warning");
for (const contract of [
  "expected_b(int immediate)", "expected_cc(unsigned condition, int immediate)",
  "expected_cb(CompareBranch kind", "expected_tb(TestBranch kind",
  "tb_word(TestBranch kind, unsigned reg, int bit, int immediate)",
  "check_patch_word(", "check_patch_rejection(", "check_patch_native(",
  "BNE_i negative displacement", "B.cond taken/not-taken",
  "CBZ/CBNZ width and route", "TBZ/TBNZ bit, width, and route",
  "emitter_branch_exact_words", "emitter_branch_native_vectors",
  "emitter_branch_patch_exact_words", "emitter_branch_patch_rejections",
  "patch_exact_words == 8 && patch_rejections == 10 && patch_native_vectors == 4",
]) requireText(branchEmitterProbeSource, contract, "generic branch direct emitter probe");
for (const contract of [
  "-std=c++17", "-Wall -Wextra -Werror", "-fsanitize=undefined",
  "-fno-sanitize-recover=all", "emitter-branch-conformance.cpp",
]) requireText(branchEmitterHarnessSource, contract, "generic branch emitter harness");
requireText(harnessSource, 'emitter-branch-conformance.sh', "generic branch mandatory harness gate");

/* NEGX does not call the similarly named jff_/jnf_NEGX_* legacy MIDFUNCs.
 * Its live generator creates zero - source - X through flag_subx and the
 * shared sbb_b/w/l compatibility layer. Lock both generated flag lifecycles,
 * narrow-lane publication, exact-native coverage, memory RMW geometry, and
 * forced source/destination allocator ownership to that executable path. */
const negxGenerator = functionBody(
  gencompSource,
  "     case i_NEGX:",
  "     case i_NBCD:",
  "NEGX generator",
);
for (const contract of [
  "isaddx;",
  'genamode (curi->smode, "srcreg", curi->size, "src", GENA_GETV_FETCH, GENA_MOVEM_DO_INC);',
  'comprintf("\\tint __negxealock=jit_value_lock(srca);\\n");',
  'comprintf("\\tint dst=scratchie++;\\n");',
  'comprintf("\\tmov_l_ri(dst,0);\\n");',
  'genflags (flag_subx, curi->size, "", "src", "dst");',
  'genastore ("dst", curi->smode, "srcreg", curi->size, "src");',
  'comprintf("\\tjit_value_unlock(__negxealock);\\n");',
]) {
  requireText(negxGenerator, contract, "NEGX shared SUBX lowering");
}
requireBefore(negxGenerator, 'jit_value_lock(srca)', 'genflags (flag_subx', "NEGX EA ownership");
requireBefore(negxGenerator, 'genastore ("dst"', 'jit_value_unlock(__negxealock)', "NEGX EA ownership");
const generatedNegxLocks = (generatedSource.match(/int __negxealock=jit_value_lock\(srca\);/g) || []).length;
const generatedNegxUnlocks = (generatedSource.match(/jit_value_unlock\(__negxealock\);/g) || []).length;
if (generatedNegxLocks !== 42 || generatedNegxUnlocks !== 42) {
  fail(`generated NEGX EA ownership: locks=${generatedNegxLocks} unlocks=${generatedNegxUnlocks}`);
}
for (const [opcode, nextOpcode, width, move] of [
  ["4000", "4010", "b", "mov_b_rr"],
  ["4040", "4050", "w", "mov_w_rr"],
  ["4080", "4090", "l", "mov_l_rr"],
] as const) {
  const liveBody = functionBody(
    generatedSource,
    `void REGPARAM2 op_${opcode}_0_comp_ff`,
    `void REGPARAM2 op_${nextOpcode}_0_comp_ff`,
    `generated NEGX.${width} flag-live`,
  );
  for (const contract of [
    "mov_l_ri(dst,0)",
    "restore_carry()",
    `sbb_${width}(dst,src)`,
    "set_zero(zero, one)",
    "duplicate_carry()",
    `${move}(srcreg, dst)`,
  ]) {
    requireText(liveBody, contract, `generated NEGX.${width} flag-live`);
  }
  const deadBody = functionBody(
    generatedSource,
    `void REGPARAM2 op_${opcode}_0_comp_nf`,
    `void REGPARAM2 op_${nextOpcode}_0_comp_nf`,
    `generated NEGX.${width} no-flags`,
  );
  for (const contract of [
    "mov_l_ri(dst,0)",
    "dont_care_flags()",
    "restore_carry()",
    `sbb_${width}(dst,src)`,
    `${move}(srcreg, dst)`,
  ]) {
    requireText(deadBody, contract, `generated NEGX.${width} no-flags`);
  }
  if (deadBody.includes("set_zero(") || deadBody.includes("duplicate_carry()")) {
    fail(`generated NEGX.${width} no-flags path still publishes dead flags`);
  }
}
const legacySbbLBody = functionBody(compatSource, "void sbb_l(", "static inline void legacy_load_rr4_to_work", "legacy SBB.L");
for (const [body, width, shift, insert] of [
  [legacySbbBBody, 8, 24, "BFXIL_xxii(d, REG_WORK1, 24, 8)"],
  [legacySbbWBody, 16, 16, "BFXIL_xxii(d, REG_WORK1, 16, 16)"],
] as const) {
  for (const contract of [
    "legacy_invert_carry_in_pstate()",
    `LSL_wwi(REG_WORK1, d, ${shift})`,
    `LSL_wwi(REG_WORK3, s, ${shift})`,
    "SBCS_www(REG_WORK1, REG_WORK1, REG_WORK3)",
    insert,
    `legacy_set_z_from_narrow_result(d, ${width})`,
    "flags_carry_inverted = true",
  ]) {
    requireText(body, contract, `NEGX/SUBX ${width}-bit lane lifecycle`);
  }
}
for (const contract of [
  "legacy_invert_carry_in_pstate()",
  "SBCS_www(d, d, s)",
  "flags_carry_inverted = true",
]) {
  requireText(legacySbbLBody, contract, "NEGX/SUBX 32-bit lifecycle");
}
const negxExactVectors = [
  "negx_b_zero_x0_z1_native", "negx_w_zero_x0_z1_native", "negx_l_zero_x0_z1_native",
  "negx_b_zero_x0_z0_native", "negx_w_zero_x0_z0_native", "negx_l_zero_x0_z0_native",
  "negx_b_zero_x1_z1_native", "negx_w_zero_x1_z1_native", "negx_l_zero_x1_z1_native",
  "negx_b_min_x0_overflow_native", "negx_w_min_x0_overflow_native", "negx_l_min_x0_overflow_native",
  "negx_b_min_x1_native", "negx_w_min_x1_native", "negx_l_min_x1_native",
  "negx_b_min_x1_nf_native", "negx_w_min_x1_nf_native", "negx_l_min_x1_nf_native",
  "negx_b_aind_special_native", "negx_w_postinc_native", "negx_l_predec_native",
  "negx_b_d16_native", "negx_w_indexed_special_native", "negx_l_absw_native",
  "negx_b_absl_special_native", "negx_b_a7_postinc_native", "negx_b_a7_predec_native",
];
for (const name of negxExactVectors) {
  requireText(harnessSource, name, `NEGX exact-native vector ${name}`);
}
for (const contract of [
  'for _negx_name in "${NEGX_NATIVE_MATRIX_NAMES[@]}"',
  'NATIVE_REPLAY_TESTS["$_negx_name"]=1',
  'NATIVE_REPLAY_PC["$_negx_name"]=0x1000',
  'NATIVE_REPLAY_COUNT["$_negx_name"]=2',
  "SPECIAL_MEMORY_TESTS[negx_b_aind_special_native]=1",
  "SPECIAL_MEMORY_TESTS[negx_w_indexed_special_native]=1",
  "SPECIAL_MEMORY_TESTS[negx_b_absl_special_native]=1",
]) {
  requireText(harnessSource, contract, "NEGX exact-native/memory gate");
}
requireText(activeRiskySource, "negx_l_min_x0_overflow_native", "NEGX active-risky sentinel");
for (const width of ["b", "w", "l"]) {
  const name = `negx_${width}_source_dst_collision`;
  for (const contract of [name, `[${name}]=20`, `[${name}]=1`]) {
    requireText(regallocPressureSource, contract, `NEGX.${width} forced source/destination collision`);
  }
}
for (const contract of [
  "negx_b_postinc_result_ea_collision", "[negx_b_postinc_result_ea_collision]=22",
  "[negx_b_postinc_result_ea_collision]=20", "[negx_b_postinc_result_ea_collision]=1",
]) requireText(regallocPressureSource, contract, "NEGX forced result/EA collision");
for (const contract of [
  "Constant-backed scratch RMW values (NEGX)",
  "historical_const_scratch = r >= S1 && isconst(r)",
  "REGPRESSURE_PIN_SKIP scratch_vreg=%d pin_vreg=%d",
]) {
  requireText(allocatorSource, contract, "NEGX constant-backed RMW pressure hook");
}

/* TAS is always architecturally flag-live.  Its only reachable MIDFUNC must
 * sample the original signed byte before setting bit 7, clear V/C through TST,
 * preserve X outside NZCV, and keep every memory EA live through read/RMW/write.
 * The no-flags namesake and legacy runtime helper are unreachable. */
const tasGenerator = functionBody(
  gencompSource,
  "\t case i_TAS:",
  "     case i_FPP:",
  "TAS generator",
);
for (const contract of [
  'genamode (curi->smode, "srcreg", curi->size, "src", GENA_GETV_FETCH, GENA_MOVEM_DO_INC);',
  'comprintf("\\tint __tasealock=jit_value_lock(srca);\\n");',
  'comprintf("\\tstart_needflags();\\n");',
  'comprintf("\\tjff_TAS(src);\\n");',
  'comprintf("\\tlive_flags();\\n");',
  'comprintf("\\tend_needflags();\\n");',
  'genastore ("src", curi->smode, "srcreg", curi->size, "src");',
  'comprintf("\\tjit_value_unlock(__tasealock);\\n");',
]) {
  requireText(tasGenerator, contract, "TAS mandatory flag-live routing");
}
if (tasGenerator.includes("jnf_TAS")) {
  fail("TAS mandatory flag-live routing: no-flags handler became reachable");
}
const tasMidfunc = functionBody(
  midfunc2Source,
  "MIDFUNC(1,jff_TAS,(RW1 d))",
  "MENDFUNC(1,jff_TAS,(RW1 d))",
  "TAS original-byte flag lifecycle",
);
for (const contract of [
  "d = rmw(d);",
  "SIGNED8_REG_2_REG(REG_WORK1, d);",
  "TST_ww(REG_WORK1, REG_WORK1);",
  "MOV_wi(REG_WORK2, 0x80);",
  "ORR_www(d, d, REG_WORK2);",
  "flags_carry_inverted = false;",
  "unlock2(d);",
]) {
  requireText(tasMidfunc, contract, "TAS original-byte flag lifecycle");
}
requireBefore(tasMidfunc, "SIGNED8_REG_2_REG(REG_WORK1, d);", "TST_ww(REG_WORK1, REG_WORK1);", "TAS signed-byte N/Z sampling");
requireBefore(tasMidfunc, "TST_ww(REG_WORK1, REG_WORK1);", "ORR_www(d, d, REG_WORK2);", "TAS flags before bit set");
requireBefore(tasMidfunc, "ORR_www(d, d, REG_WORK2);", "flags_carry_inverted = false;", "TAS carry publication");
if ((generatedSource.match(/\bjff_TAS\(src\);/g) || []).length !== 16) {
  fail("generated TAS family: expected eight flag-live and eight nominal no-flags handlers");
}
const generatedTasLocks = (generatedSource.match(/int __tasealock=jit_value_lock\(srca\);/g) || []).length;
const generatedTasUnlocks = (generatedSource.match(/jit_value_unlock\(__tasealock\);/g) || []).length;
if (generatedTasLocks !== 14 || generatedTasUnlocks !== 14)
  fail(`generated TAS EA ownership: locks=${generatedTasLocks} unlocks=${generatedTasUnlocks}`);
if (generatedSource.includes("jnf_TAS(src)") || gencompSource.includes("jnf_TAS(src)")) {
  fail("generated TAS family: unreachable no-flags handler has a caller");
}
const tasRegisterLive = functionBody(generatedSource, "void REGPARAM2 op_4ac0_0_comp_ff", "void REGPARAM2 op_4ad0_0_comp_ff", "generated TAS register flag-live");
const tasRegisterNominalNf = functionBody(generatedSource, "void REGPARAM2 op_4ac0_0_comp_nf", "void REGPARAM2 op_4ad0_0_comp_nf", "generated TAS register nominal no-flags");
for (const body of [tasRegisterLive, tasRegisterNominalNf]) {
  requireBefore(body, "jff_TAS(src);", "mov_b_rr(srcreg, src);", "generated TAS Dn upper-lane writeback");
}
for (const [opcode, nextOpcode] of [
  ["4ad0", "4ad8"], ["4ad8", "4ae0"], ["4ae0", "4ae8"], ["4ae8", "4af0"],
  ["4af0", "4af8"], ["4af8", "4af9"], ["4af9", "4c00"],
] as const) {
  for (const suffix of ["ff", "nf"] as const) {
    const body = functionBody(
      generatedSource,
      `void REGPARAM2 op_${opcode}_0_comp_${suffix}`,
      `void REGPARAM2 op_${nextOpcode}_0_comp_${suffix}`,
      `generated TAS memory ${opcode}/${suffix}`,
    );
    requireBefore(body, "readbyte(srca, src, scratchie);", "jit_value_lock(srca)", `TAS ${opcode}/${suffix} read-before-EA-lock`);
    requireBefore(body, "jit_value_lock(srca)", "jff_TAS(src);", `TAS ${opcode}/${suffix} EA-lock-before-RMW`);
    requireBefore(body, "jff_TAS(src);", "writebyte(srca, src, scratchie);", `TAS ${opcode}/${suffix} RMW-before-write`);
    requireBefore(body, "writebyte(srca, src, scratchie);", "jit_value_unlock(__tasealock)", `TAS ${opcode}/${suffix} unlock-after-write`);
  }
}
for (const contract of [
  "lea_l_brr(srcreg + 8,srcreg + 8, areg_byteinc[srcreg]);",
  "lea_l_brr(srcreg + 8, srcreg + 8, (uae_s32)-areg_byteinc[srcreg]);",
]) {
  requireText(generatedSource, contract, "TAS A7 byte geometry");
}
const tasExactVectors = [
  "tas_b_d0_zero_x0_native", "tas_b_d0_zero_x1_native",
  "tas_b_d0_positive_x1_native", "tas_b_d0_negative_x0_native",
  "tas_b_aind_special_native", "tas_b_postinc_native", "tas_b_predec_native",
  "tas_b_d16_native", "tas_b_indexed_special_native", "tas_b_absw_native",
  "tas_b_absl_special_native", "tas_b_a7_postinc_native", "tas_b_a7_predec_native",
];
for (const name of tasExactVectors) requireText(harnessSource, name, `TAS exact-native vector ${name}`);
for (const contract of [
  'for _tas_name in "${TAS_NATIVE_MATRIX_NAMES[@]}"',
  'NATIVE_REPLAY_TESTS["$_tas_name"]=1',
  'NATIVE_REPLAY_PC["$_tas_name"]=0x1000',
  'NATIVE_REPLAY_COUNT["$_tas_name"]=2',
  "SPECIAL_MEMORY_TESTS[tas_b_aind_special_native]=1",
  "SPECIAL_MEMORY_TESTS[tas_b_indexed_special_native]=1",
  "SPECIAL_MEMORY_TESTS[tas_b_absl_special_native]=1",
]) {
  requireText(harnessSource, contract, "TAS exact-native/memory gate");
}
requireText(activeRiskySource, "tas_b_absw_native", "TAS active-risky sentinel");
for (const contract of [
  "tas_b_ea_value_collision",
  "[tas_b_ea_value_collision]=8",
  "[tas_b_ea_value_collision]=20",
  "[tas_b_ea_value_collision]=1",
  '[tas_b_ea_value_collision]="A000 00"',
]) {
  requireText(regallocPressureSource, contract, "TAS EA/value allocator ownership");
}

/* MOVE, MOVEA and MOVE16 form the transfer/ownership cluster, but retain three
 * distinct architectural contracts. MOVE owns one fetched value until flags
 * and storage consume it; MOVEA sign-extends word sources without touching CCR;
 * MOVE16 masks transfer addresses, copies four ordered longwords, and publishes
 * only the architecturally selected postincrements. */
const moveGenerator = functionBody(
  gencompSource,
  "     case i_MOVE:",
  "     case i_MOVEA:",
  "MOVE source ownership generator",
);
for (const contract of [
  'genamode (curi->smode, "srcreg", curi->size, "src", GENA_GETV_FETCH, GENA_MOVEM_DO_INC);',
  'comprintf("\\tint __srclk=jit_value_lock(src);\\n");',
  'genflags (flag_mov, curi->size, "", "src", "dst");',
  'genflags (flag_logical, curi->size, "src", "", "");',
  'genastore ("dst", curi->dmode, "dstreg", curi->size, "dst");',
  'genastore ("src", curi->dmode, "dstreg", curi->size, "dst");',
  'comprintf("\\tjit_value_unlock(__srclk);\\n");',
]) {
  requireText(moveGenerator, contract, "MOVE complete source ownership");
}
requireBefore(moveGenerator, 'genamode (curi->smode', "jit_value_lock(src)", "MOVE fetch-before-lock");
requireBefore(moveGenerator, "jit_value_lock(src)", "switch(curi->dmode)", "MOVE lock-before-destination");
requireBefore(moveGenerator, "switch(curi->dmode)", "jit_value_unlock(__srclk)", "MOVE unlock-after-destination");
const generatedMoveFunctions = (generatedSource.match(/void REGPARAM2 op_[0-9a-f]+_0_comp_(?:ff|nf)[^{]*\/\* MOVE \*\//g) || []).length;
const generatedMoveLocks = (generatedSource.match(/int __srclk=jit_value_lock\(src\);/g) || []).length;
const generatedMoveUnlocks = (generatedSource.match(/jit_value_unlock\(__srclk\);/g) || []).length;
if (generatedMoveFunctions !== 562 || generatedMoveLocks !== generatedMoveFunctions || generatedMoveUnlocks !== generatedMoveFunctions) {
  fail(`generated MOVE ownership: functions=${generatedMoveFunctions} locks=${generatedMoveLocks} unlocks=${generatedMoveUnlocks}`);
}

const moveJnfByte = functionBody(midfunc2Source, "MIDFUNC(2,jnf_MOVE_b,(W1 d, RR1 s))", "MENDFUNC(2,jnf_MOVE_b,(W1 d, RR1 s))", "MOVE.B no-flags MIDFUNC");
const moveJnfWord = functionBody(midfunc2Source, "MIDFUNC(2,jnf_MOVE_w,(W2 d, RR2 s))", "MENDFUNC(2,jnf_MOVE_w,(W2 d, RR2 s))", "MOVE.W no-flags MIDFUNC");
const moveJffByte = functionBody(midfunc2Source, "MIDFUNC(2,jff_MOVE_b,(W1 d, RR1 s))", "MENDFUNC(2,jff_MOVE_b,(W1 d, RR1 s))", "MOVE.B flag-live MIDFUNC");
const moveJffWord = functionBody(midfunc2Source, "MIDFUNC(2,jff_MOVE_w,(W2 d, RR2 s))", "MENDFUNC(2,jff_MOVE_w,(W2 d, RR2 s))", "MOVE.W flag-live MIDFUNC");
for (const [body, width] of [[moveJnfByte, 8], [moveJnfWord, 16]] as const) {
  requireText(body, "if(s == d)", `MOVE.${width} no-flags self alias`);
  requireText(body, `BFI_wwii(d, s, 0, ${width});`, `MOVE.${width} no-flags lane preservation`);
}
for (const [body, signed, width] of [
  [moveJffByte, "SIGNED8_REG_2_REG(REG_WORK1, s);", 8],
  [moveJffWord, "SIGNED16_REG_2_REG(REG_WORK1, s);", 16],
] as const) {
  requireBefore(body, "s = readreg(s);", "d = rmw(d);", `MOVE.${width} source-before-destination ownership`);
  requireBefore(body, signed, "TST_ww(REG_WORK1, REG_WORK1);", `MOVE.${width} signed NZ sampling`);
  requireBefore(body, "TST_ww(REG_WORK1, REG_WORK1);", `BFI_wwii(d, REG_WORK1, 0, ${width});`, `MOVE.${width} flags-before-write`);
  requireText(body, "flags_carry_inverted = false;", `MOVE.${width} carry lifecycle`);
}
for (const wrapper of [
  "void mov_b_rr(W1 d, RR1 s) { if (legacy_needflags_enabled()) jff_MOVE_b(d, s); else jnf_MOVE_b(d, s); }",
  "void mov_w_rr(W2 d, RR2 s) { if (legacy_needflags_enabled()) jff_MOVE_w(d, s); else jnf_MOVE_w(d, s); }",
  "void mov_w_ri(W2 d, uae_s32 i) { if (legacy_needflags_enabled()) jff_MOVE_w_imm(d, i); else jnf_MOVE_w_imm(d, i); }",
]) {
  requireText(compatSource, wrapper, "MOVE flag-liveness wrapper");
}
for (const forbidden of ["jff_MOVE_l(", "jnf_MOVE_l(", "jnf_MOVE16(", "jnf_MOVEA_w(", "jnf_MOVEA_l("]) {
  if (generatedSource.includes(forbidden)) fail(`generated transfer path calls unreachable MIDFUNC ${forbidden}`);
}

const moveaGenerator = functionBody(gencompSource, "     case i_MOVEA:", "     case i_MVSR2:", "MOVEA direct generator");
for (const contract of [
  'genamode (curi->smode, "srcreg", curi->size, "src", GENA_GETV_FETCH, GENA_MOVEM_DO_INC);',
  'case sz_word: comprintf("\\tsign_extend_16_rr(dstreg + 8,src);\\n");',
  'case sz_long: comprintf("\\tmov_l_rr(dstreg + 8,src);\\n");',
  'comprintf("\\tforget_about(src);\\n");',
]) {
  requireText(moveaGenerator, contract, "MOVEA extension/no-flags routing");
}
if (moveaGenerator.includes("genflags") || moveaGenerator.includes("jff_MOVEA") || moveaGenerator.includes("jnf_MOVEA")) {
  fail("MOVEA direct generator: legacy MIDFUNC or flag publication became reachable");
}

const move16Generator = functionBody(gencompSource, "static void genmov16", "static void\ngenmovemel", "MOVE16 direct generator");
for (const contract of [
  'if ((opcode & 0xfff8) == 0xf620)',
  'comprintf("\\tand_l_ri(src,~15);\\n");',
  'comprintf("\\tand_l_ri(dst,~15);\\n");',
  'comprintf("\\tif (srcreg != dstreg)\\n");',
  'comprintf("\\tadd_l_ri(srcreg+8,16);\\n");',
  'comprintf("\\tadd_l_ri(dstreg+8,16);\\n");',
  'comprintf("\\tif (special_mem) {\\n");',
  "readlong(src,tmp,scratchie);",
  "writelong_clobber(dst,tmp,scratchie);",
  "get_n_addr(src,src,scratchie);",
  "get_n_addr(dst,dst,scratchie);",
  "mov_l_rR(tmp,src,12);",
  "mov_l_Rr(dst,tmp,12);",
]) {
  requireText(move16Generator, contract, "MOVE16 aligned ordered transfer");
}
if ((move16Generator.match(/readlong\(src,tmp,scratchie\);/g) || []).length !== 4 ||
    (move16Generator.match(/writelong_clobber\(dst,tmp,scratchie\);/g) || []).length !== 4 ||
    (move16Generator.match(/mov_l_rR\(tmp,src,/g) || []).length !== 4 ||
    (move16Generator.match(/mov_l_Rr\(dst,tmp,/g) || []).length !== 4) {
  fail("MOVE16 ordered transfer: expected four helper and four direct longword pairs");
}

for (const [prefix, count] of [["move_core_", 31], ["movea_core_", 10], ["move16_core_", 7]] as const) {
  const found = (harnessSource.match(new RegExp(`^TESTS\\[${prefix}`, "gm")) || []).length;
  if (found !== count) fail(`${prefix} exact-native matrix: expected ${count}, found ${found}`);
}
for (const contract of [
  'for _move_name in "${MOVE_NATIVE_MATRIX_NAMES[@]}"',
  'for _movea_name in "${MOVEA_NATIVE_MATRIX_NAMES[@]}"',
  'for _move16_name in "${MOVE16_NATIVE_MATRIX_NAMES[@]}"',
  "SPECIAL_MEMORY_TESTS[move_core_b_aind_to_dn_special_native]=1",
  "SPECIAL_MEMORY_TESTS[movea_core_w_aind_special_native]=1",
  "SPECIAL_MEMORY_TESTS[move16_core_postpost_special_native]=1",
  'env_vars+=(B2_TEST_MEMORY_BYTES="$memory_bytes")',
]) {
  requireText(harnessSource, contract, "MOVE cluster exact-native/memory gate");
}
for (const active of [
  "move_core_b_aind_to_dn_special_native",
  "movea_core_w_postinc_alias_native",
  "move16_core_postpost_special_native",
]) requireText(activeRiskySource, active, `MOVE cluster active-risky ${active}`);
for (const contract of [
  'restore_test_bytes_glue("B2_TEST_MEMORY_BYTES")',
  'replay && *replay',
  '? "B2_TEST_REPLAY_BYTES" : "B2_TEST_MEMORY_BYTES"',
]) requireText(basiliskGlueSource, contract, "initial/exact-replay memory fixture");
for (const contract of [
  "v >= 0 && v < VREGS",
  "force_target >= 0 && r == force_target",
  "move_b_mem_source_dst_collision",
  "[move_b_mem_source_dst_collision]=20",
  "[move_b_mem_source_dst_collision]=0",
  "[move_b_mem_source_dst_collision]=1",
]) {
  const body = contract.startsWith("move_") || contract.startsWith("[") ? regallocPressureSource : allocatorSource;
  requireText(body, contract, "MOVE inverse source/destination pressure contract");
}

/* DBcc/Scc share condition consumption and CCR preservation, but their write
 * lifecycles differ: DBcc owns a low-word counter plus a dynamic block edge;
 * Scc owns a Boolean byte plus a Dn lane or complete writable EA. */
const dbccGenerator = functionBody(gencompSource, "     case i_DBcc:", "     case i_Scc:", "DBcc generator lifecycle");
for (const contract of [
  'genamode (curi->smode, "srcreg", curi->size, "src", GENA_GETV_FETCH, GENA_MOVEM_DO_INC);',
  'genamode (curi->dmode, "dstreg", curi->size, "offs", GENA_GETV_FETCH, GENA_MOVEM_DO_INC);',
  'comprintf("\\tm68k_pc_offset=0;\\n");',
  'comprintf("\\tint nsrc=scratchie++;\\n");',
  'comprintf("\\tmov_l_rr(nsrc,src);\\n");',
  'comprintf("\\tpreserve_flags_before_nzcv_clobber();\\n");',
  'comprintf("\\tdbf_dec_test_ne_w(src);\\n");',
  'register_branch(v1,v2,%d);',
  'comprintf("\\tdbcc_cond_move_ne_w(PC_P, offs, nsrc);\\n");',
  'comprintf("\\tdbcc_dec_w(src);\\n");',
  'comprintf("\\tcmov_l_rr(offs,PC_P,%d);\\n",',
  'comprintf("\\tcmov_l_rr(src,nsrc,%d);\\n",',
  'comprintf("\\tsave_and_discard_flags_in_nzcv();\\n");',
  'genastore ("src", curi->smode, "srcreg", curi->size, "src");',
  'comprintf("\\tdiscard_flags_in_nzcv();\\n");',
  'gen_update_next_handler();',
]) requireText(dbccGenerator, contract, "DBcc counter/edge/CCR lifecycle");
requireBefore(dbccGenerator, "mov_l_rr(nsrc,src)", "dbf_dec_test_ne_w(src)", "DBF copy-before-decrement");
requireBefore(dbccGenerator, "dbcc_dec_w(src)", "cmov_l_rr(offs,PC_P", "DBcc decrement-before-condition restore");
if (dbccGenerator.lastIndexOf("cmov_l_rr(src,nsrc") >= dbccGenerator.lastIndexOf("dbcc_cond_move_ne_w")) {
  fail("DBcc condition-before-terminal test: conditional restore must precede the terminal selection");
}
requireBefore(dbccGenerator, "dbcc_cond_move_ne_w", "save_and_discard_flags_in_nzcv", "DBcc terminal-before-CCR save");
if (dbccGenerator.lastIndexOf('genastore ("src"') >= dbccGenerator.lastIndexOf("discard_flags_in_nzcv")) {
  fail("DBcc writeback-before-final flag discard: final discard must follow counter storage");
}
const dbccBoundaryStart = allocatorSource.indexOf("/* DBcc loop back-edge:");
const dbccBoundaryEnd = allocatorSource.indexOf("freescratch();", dbccBoundaryStart);
if (dbccBoundaryStart < 0 || dbccBoundaryEnd < 0) fail("missing DBcc dynamic runtime-PC boundary");
const dbccBoundary = allocatorSource.slice(dbccBoundaryStart, dbccBoundaryEnd);
for (const contract of [
  "((dop & 0xF0F8) == 0x50C8)",
  "(((dop >> 8) & 0xf) >= 1)",
  "live.flags_are_important = 1;",
  "flush(1);",
  "compemu_raw_mov_l_rm(REG_PC_TMP, (uintptr)&regs.pc_p);",
  "compemu_raw_endblock_pc_inreg(REG_PC_TMP, retired_cycles);",
  "forced_interpreter_barrier = true;",
]) requireText(dbccBoundary, contract, "DBcc dynamic runtime-PC boundary");

const dbccCmov = functionBody(compatSource, "void cmov_l_rr(", "/* jit_value_lock / jit_value_unlock", "DBcc conditional move helper");
for (const contract of [
  "FIX_INVERTED_CARRY",
  "if (cc == 7)",
  "CSEL_xxxc(REG_WORK3, src, REG_WORK2, NATIVE_CC_CC);",
  "CSEL_xxxc(d, REG_WORK2, REG_WORK3, NATIVE_CC_EQ);",
  "else if (cc == 6)",
  "CSEL_xxxc(REG_WORK3, src, REG_WORK2, NATIVE_CC_CS);",
  "CSEL_xxxc(d, src, REG_WORK3, NATIVE_CC_EQ);",
  "unlock2(src);",
]) requireText(dbccCmov, contract, "DBcc M68K HI/LS composite conditions");
if (dbccCmov.includes("unlock2(s);")) {
  fail("DBcc conditional move released a virtual source ID instead of its physical host register");
}

const sccGenerator = functionBody(gencompSource, "     case i_Scc:", "\t case i_DIVU:", "Scc generator lifecycle");
for (const contract of [
  'genamode (curi->smode, "srcreg", curi->size, "src", GENA_GETV_FETCH_ALIGN, GENA_MOVEM_DO_INC);',
  'comprintf("\\tint __sccealock=jit_value_lock(srca);\\n");',
  'comprintf("\\tmake_flags_live();\\n");',
  'comprintf("\\tjnf_SCC(val,%d);\\n", curi->cc);',
  'genastore ("val", curi->smode, "srcreg", curi->size, "src");',
  'comprintf("\\tjit_value_unlock(__sccealock);\\n");',
]) requireText(sccGenerator, contract, "Scc condition/value/EA lifecycle");
if (sccGenerator.includes("setcc(") || sccGenerator.includes("sub_b_ri(")) {
  fail("Scc direct condition lifecycle regressed to legacy setcc/subtract lowering");
}
requireBefore(sccGenerator, "jit_value_lock(srca)", "jnf_SCC(val", "Scc EA lock before condition result");
requireBefore(sccGenerator, "jnf_SCC(val", 'genastore ("val"', "Scc condition before store");
requireBefore(sccGenerator, 'genastore ("val"', "jit_value_unlock(__sccealock)", "Scc unlock after store");

const sccMidfunc = functionBody(midfunc2Source, "MIDFUNC(2,jnf_SCC,(W1 d, IM8 cc))", "MENDFUNC(2,jnf_SCC,(W1 d, IM8 cc))", "direct Scc MIDFUNC");
for (const contract of [
  "FIX_INVERTED_CARRY", "case 0:", "case 1:",
  "case 2: /* HI = !C && !Z;", "NATIVE_CC_CC", "NATIVE_CC_NE", "AND_www",
  "case 3: /* LS = C || Z;", "NATIVE_CC_CS", "NATIVE_CC_EQ", "ORR_www",
  "case 4: native_cc = NATIVE_CC_CC;", "case 5: native_cc = NATIVE_CC_CS;",
  "case 6: native_cc = NATIVE_CC_NE;", "case 7: native_cc = NATIVE_CC_EQ;",
  "case 8: native_cc = NATIVE_CC_VC;", "case 9: native_cc = NATIVE_CC_VS;",
  "case 10: native_cc = NATIVE_CC_PL;", "case 11: native_cc = NATIVE_CC_MI;",
  "case 12: native_cc = NATIVE_CC_GE;", "case 13: native_cc = NATIVE_CC_LT;",
  "case 14: native_cc = NATIVE_CC_GT;", "case 15: native_cc = NATIVE_CC_LE;",
  "CSETM_wc(REG_WORK1, native_cc);", "BFI_wwii(d, REG_WORK1, 0, 8);",
]) requireText(sccMidfunc, contract, "complete direct Scc condition map");

const generatedSccCalls = (generatedSource.match(/\bjnf_SCC\(val,/g) || []).length;
const generatedSccLocks = (generatedSource.match(/int __sccealock=jit_value_lock\(srca\);/g) || []).length;
const generatedSccUnlocks = (generatedSource.match(/jit_value_unlock\(__sccealock\);/g) || []).length;
if (generatedSccCalls !== 256 || generatedSccLocks !== 224 || generatedSccUnlocks !== 224) {
  fail(`generated Scc lifecycle: calls=${generatedSccCalls} locks=${generatedSccLocks} unlocks=${generatedSccUnlocks}`);
}
for (const [token, count] of [
  ["dbf_dec_test_ne_w(src);", 2],
  ["cmov_l_rr(offs,PC_P", 28],
  ["dbcc_cond_move_ne_w(PC_P", 30],
] as const) {
  const found = generatedSource.split(token).length - 1;
  if (found !== count) fail(`generated DBcc lifecycle ${token}: expected ${count}, found ${found}`);
}
for (const [prefix, count] of [["scc_core_", 17], ["dbcc_core_", 18]] as const) {
  const found = (harnessSource.match(new RegExp(`^TESTS\\[${prefix}`, "gm")) || []).length;
  if (found !== count) fail(`${prefix} exact-native matrix: expected ${count}, found ${found}`);
}
for (const contract of [
  'for _scc_name in "${SCC_NATIVE_MATRIX_NAMES[@]}"',
  'for _dbcc_name in "${DBCC_NATIVE_MATRIX_NAMES[@]}"',
  "SPECIAL_MEMORY_TESTS[scc_core_aind_hi_special_native]=1",
  "SPECIAL_MEMORY_TESTS[scc_core_index_vs_special_native]=1",
  "SPECIAL_MEMORY_TESTS[scc_core_absl_gt_special_native]=1",
]) requireText(harnessSource, contract, "DBcc/Scc exact-native gate");
for (const contract of [
  "scc_b_ea_value_collision", "dbcc_w_counter_copy_collision",
  "[scc_b_ea_value_collision]=20", "[scc_b_ea_value_collision]=21",
  "[dbcc_w_counter_copy_collision]=0", "[dbcc_w_counter_copy_collision]=21",
]) requireText(regallocPressureSource, contract, "DBcc/Scc allocator pressure");
for (const active of ["scc_core_aind_hi_special_native", "dbcc_core_hi_true_native"]) {
  requireText(activeRiskySource, active, `DBcc/Scc active-risky ${active}`);
}

/* Classic bit operations share count reduction and original-bit Z semantics,
 * but only BCHG/BCLR/BSET own a writable destination. Audit the complete
 * dynamic/immediate, byte-memory/long-Dn lifecycle as one family. */
const bitopGenerator = functionBody(gencompSource, "     case i_BCHG:", "     case i_CMPM:", "classic bit-operation generator");
for (const contract of [
  "case i_BCHG:", "case i_BCLR:", "case i_BSET:", "case i_BTST:",
  'genamode (curi->smode, "srcreg", curi->size, "src", GENA_GETV_FETCH, GENA_MOVEM_DO_INC);',
  'genamode (curi->dmode, "dstreg", curi->size, "dst", GENA_GETV_FETCH, GENA_MOVEM_DO_INC);',
  "curi->mnemo != i_BTST && curi->dmode != Dreg",
  'comprintf("\\tint __bitdstealock=jit_value_lock(dsta);\\n");',
  '"\\tjff_BTST_%c(dst, src);\\n"',
  '"\\tjff_%s_%c(dst, src);\\n"',
  'comprintf("\\tjnf_%s_%c(dst, src);\\n"',
  'genastore ("dst", curi->dmode, "dstreg", curi->size, "dst");',
  'comprintf("\\tjit_value_unlock(__bitdstealock);\\n");',
]) requireText(bitopGenerator, contract, "classic bit-operation generator lifecycle");
requireBefore(bitopGenerator, "jit_value_lock(dsta)", "jff_%s_%c", "bit-op EA lock before flag-producing RMW");
requireBefore(bitopGenerator, "jit_value_lock(dsta)", "jnf_%s_%c", "bit-op EA lock before no-flags RMW");
requireBefore(bitopGenerator, 'genastore ("dst"', "jit_value_unlock(__bitdstealock)", "bit-op EA unlock after store");

const bitopBody = (name: string, args: string) => functionBody(
  midfunc2Source, `MIDFUNC(2,${name},(${args}))`, `MENDFUNC(2,${name},(${args}))`, name,
);
const modifyingFamilies = ["BCHG", "BCLR", "BSET"] as const;
for (const family of modifyingFamilies) {
  for (const [width, rw] of [["b", "RW1"], ["l", "RW4"]] as const) {
    const immNoFlags = bitopBody(`jnf_${family}_${width}_imm`, `${rw} d, IM8 s`);
    const dynNoFlags = bitopBody(`jnf_${family}_${width}`, `${rw} d, RR4 s`);
    for (const body of [immNoFlags, dynNoFlags]) {
      for (const forbidden of ["MRS_NZCV", "MSR_NZCV", "TST_ww", "CSET_xc"])
        if (body.includes(forbidden)) fail(`no-flags ${family}.${width} clobbers or publishes NZCV via ${forbidden}`);
    }
    requireText(immNoFlags, width === "b" ? "s & 0x7" : "s & 0x1f", `${family}.${width} immediate modulo count`);
    requireText(dynNoFlags, width === "b" ? "UBFIZ_xxii(REG_WORK1, s, 0, 3)" : "UBFIZ_xxii(REG_WORK1, s, 0, 5)", `${family}.${width} dynamic modulo count`);

    const immFlags = bitopBody(`jff_${family}_${width}_imm`, `${rw} d, IM8 s`);
    const dynFlags = bitopBody(`jff_${family}_${width}`, `${rw} d, RR4 s`);
    for (const body of [immFlags, dynFlags]) {
      requireText(body, "MRS_NZCV_x(REG_WORK1);", `${family}.${width} preserve incoming NZVC`);
      requireText(body, "MSR_NZCV_x(REG_WORK1);", `${family}.${width} restore incoming NZVC with architectural Z`);
    }
    requireText(dynFlags, "CSET_xc(REG_WORK3, NATIVE_CC_EQ);", `${family}.${width} dynamic original-bit Z`);
    requireText(dynFlags, "BFI_xxii(REG_WORK1, REG_WORK3, 30, 1);", `${family}.${width} dynamic Z-only publication`);
  }
}
for (const [width, rr] of [["b", "RR1"], ["l", "RR4"]] as const) {
  const imm = bitopBody(`jff_BTST_${width}_imm`, `${rr} d, IM8 s`);
  const dyn = bitopBody(`jff_BTST_${width}`, `${rr} d, RR4 s`);
  for (const body of [imm, dyn]) {
    requireText(body, "MRS_NZCV_x(REG_WORK1);", `BTST.${width} preserve incoming NZVC`);
    requireText(body, "MSR_NZCV_x(REG_WORK1);", `BTST.${width} restore incoming NZVC with architectural Z`);
    for (const forbidden of ["EOR_", "BIC_", "ORR_", "SET_xxbit", "CLEAR_xxbit"])
      if (body.includes(forbidden)) fail(`read-only BTST.${width} mutates its destination via ${forbidden}`);
  }
}
const bchgImmLong = bitopBody("jff_BCHG_l_imm", "RW4 d, IM8 s");
requireBefore(bchgImmLong, "EOR_xxbit", "UBFX_xxii", "BCHG immediate derives Z from toggled/original inverse bit");
const bchgDynLong = bitopBody("jff_BCHG_l", "RW4 d, RR4 s");
requireBefore(bchgDynLong, "TST_ww", "EOR_www", "BCHG dynamic samples original bit before toggle");
requireText(
  bitopBody("jnf_BCLR_l_imm", "RW4 d, IM8 s"),
  "uae_u32(1) << (s & 0x1f)",
  "BCLR.L unsigned bit-31 constant folding",
);

const generatedBitopLocks = (generatedSource.match(/int __bitdstealock=jit_value_lock\(dsta\);/g) || []).length;
const generatedBitopUnlocks = (generatedSource.match(/jit_value_unlock\(__bitdstealock\);/g) || []).length;
if (generatedBitopLocks !== 108 || generatedBitopUnlocks !== 108)
  fail(`generated modifying bit-op EA lifecycle: locks=${generatedBitopLocks} unlocks=${generatedBitopUnlocks}`);
for (const [token, expected] of [
  ["jff_BCHG_b(dst, src);", 18], ["jnf_BCHG_b(dst, src);", 18],
  ["jff_BCLR_b(dst, src);", 18], ["jnf_BCLR_b(dst, src);", 18],
  ["jff_BSET_b(dst, src);", 18], ["jnf_BSET_b(dst, src);", 18],
  ["jff_BTST_b(dst, src);", 20], ["jff_BTST_l(dst, src);", 2],
] as const) {
  const found = generatedSource.split(token).length - 1;
  if (found !== expected) fail(`generated bit-op route ${token}: expected ${expected}, found ${found}`);
}
const focusedBitopCount = (harnessSource.match(/^TESTS\[bitop_core_/gm) || []).length;
if (focusedBitopCount !== 29) fail(`classic bit-op exact-native matrix: expected 29, found ${focusedBitopCount}`);
for (const contract of [
  'for _bitop_name in "${BITOP_NATIVE_MATRIX_NAMES[@]}"',
  "bitop_core_bchg_imm_aind_zero_special_native",
  "bitop_core_bset_dyn_index_one_special_native",
  "bitop_core_bclr_imm_absl_one_special_native",
  "bitop_core_btst_dyn_aind_set_special_native",
]) requireText(harnessSource, contract, "classic bit-op exact-native gate");
for (const contract of [
  "bitop_b_ea_value_collision", "[bitop_b_ea_value_collision]=20", "[bitop_b_ea_value_collision]=21",
]) requireText(regallocPressureSource, contract, "classic bit-op allocator pressure");
for (const active of ["bitop_core_bchg_dyn_l_alias_native", "bitop_core_bset_dyn_index_one_special_native"])
  requireText(activeRiskySource, active, `classic bit-op active-risky ${active}`);
requireText(allocatorSource, "const bool explicit_target = force_target >= 0 && r == force_target;", "private RMW pressure targeting");

/* CMP, CMPM, and CMPA share the live jff_CMP_{b,w,l} lowering. CMPA widens
 * its source in generated code; the namesake jff_CMPA MIDFUNCs are dead. */
const compareGenerator = functionBody(gencompSource, "     case i_CMPM:", "     case i_MVPRM:", "compare generator family");
const cmpGenerator = functionBody(compareGenerator, "case i_CMPM:", "case i_CMPA:", "CMP/CMPM generator");
const cmpaGenerator = functionBody(gencompSource, "     case i_CMPA:", "     case i_MVPRM:", "CMPA generator");
for (const contract of [
  "case i_CMPM:", "case i_CMP:", "case i_CMPA:",
  'comprintf("\\tint __cmpsrclock=jit_value_lock(src);\\n");',
  'genflags (flag_cmp, curi->size, "", "src", "dst");',
  'comprintf("\\tjit_value_unlock(__cmpsrclock);\\n");',
  'comprintf("\\tint __cmpasrclock=jit_value_lock(src);\\n");',
  'case sz_word: comprintf("\\tsign_extend_16_rr(tmps,src);\\n"); break;',
  'case sz_long: comprintf("tmps=src;\\n"); break;',
  'genflags (flag_cmp, sz_long, "", "tmps", "dst");',
  'comprintf("\\tjit_value_unlock(__cmpasrclock);\\n");',
]) requireText(compareGenerator, contract, "compare generator lifecycle");
requireBefore(cmpGenerator, "jit_value_lock(src)", 'genamode (curi->dmode', "CMP/CMPM source lock before destination acquisition");
requireBefore(cmpGenerator, 'genflags (flag_cmp, curi->size', "jit_value_unlock(__cmpsrclock)", "CMP/CMPM unlock after flags");
requireBefore(cmpaGenerator, "jit_value_lock(src)", "sign_extend_16_rr(tmps,src)", "CMPA source lock before widening");
requireBefore(cmpaGenerator, 'genflags (flag_cmp, sz_long', "jit_value_unlock(__cmpasrclock)", "CMPA unlock after flags");

const generatedCmpLocks = (generatedSource.match(/int __cmpsrclock=jit_value_lock\(src\);/g) || []).length;
const generatedCmpUnlocks = (generatedSource.match(/jit_value_unlock\(__cmpsrclock\);/g) || []).length;
const generatedCmpaLocks = (generatedSource.match(/int __cmpasrclock=jit_value_lock\(src\);/g) || []).length;
const generatedCmpaUnlocks = (generatedSource.match(/jit_value_unlock\(__cmpasrclock\);/g) || []).length;
if (generatedCmpLocks !== 136 || generatedCmpUnlocks !== 136)
  fail(`generated CMP/CMPM source ownership: locks=${generatedCmpLocks} unlocks=${generatedCmpUnlocks}`);
if (generatedCmpaLocks !== 48 || generatedCmpaUnlocks !== 48)
  fail(`generated CMPA source ownership: locks=${generatedCmpaLocks} unlocks=${generatedCmpaUnlocks}`);
for (const [token, expected] of [["cmp_b(dst,src);", 22], ["cmp_w(dst,src);", 23], ["cmp_l(dst,src);", 23]] as const) {
  const found = generatedSource.split(token).length - 1;
  if (found !== expected) fail(`generated compare route ${token}: expected ${expected}, found ${found}`);
}
if (generatedSource.includes("jff_CMPA_") || generatedSource.includes("jnf_CMPA_"))
  fail("generated compare family unexpectedly calls dead namesake CMPA MIDFUNCs");

const compareBody = (name: string, args: string) => functionBody(
  midfunc2Source, `MIDFUNC(2,${name},(${args}))`, `MENDFUNC(2,${name},(${args}))`, name,
);
for (const [width, rr, imm, shift] of [
  ["b", "RR1", "IM8", "24"], ["w", "RR2", "IM16", "16"], ["l", "RR4", "IM32", ""],
] as const) {
  const dynamicBody = compareBody(`jff_CMP_${width}`, `${rr} d, ${rr} s`);
  const immediateBody = compareBody(`jff_CMP_${width}_imm`, `${rr} d, ${imm} v`);
  for (const body of [dynamicBody, immediateBody]) {
    for (const contract of [
      "MRS_NZCV_x(REG_WORK3);", "EOR_xxCflag(REG_WORK3, REG_WORK3);",
      "MSR_NZCV_x(REG_WORK3);", "flags_carry_inverted = false;",
    ]) requireText(body, contract, `CMP.${width} borrow-polarity publication`);
    for (const forbidden of ["FLAGX", "rmw(", "writereg(", "set_const("])
      if (body.includes(forbidden)) fail(`CMP.${width} mutates data/X via ${forbidden}`);
  }
  if (shift) {
    requireText(dynamicBody, `CMP_wwLSLi(REG_WORK1, s, ${shift});`, `CMP.${width} dynamic width isolation`);
    requireText(immediateBody, `CMP_wwLSLi(REG_WORK1, REG_WORK2, ${shift});`, `CMP.${width} immediate width isolation`);
  } else {
    requireText(dynamicBody, "CMP_ww(d, s);", "CMP.L dynamic 32-bit subtract");
    requireText(immediateBody, "uae_u32 newv", "CMP.L constant-folded subtraction");
    requireText(immediateBody, "if(((uae_u32)v) > ((uae_u32)live.state[d].val))", "CMP.L constant borrow");
  }
}
for (const [start, end, label] of [
  ["void REGPARAM2 op_b108_0_comp_nf", "void REGPARAM2 op_b110_0_comp_nf", "CMPM.B no-flags"],
  ["void REGPARAM2 op_b1d8_0_comp_nf", "void REGPARAM2 op_b1e0_0_comp_nf", "CMPA.L postincrement no-flags"],
] as const) {
  const body = functionBody(generatedSource, start, end, label);
  requireText(body, "jit_value_lock(src)", `${label} source ownership`);
  if (body.includes("start_needflags()") || /\bcmp_[bwl]\(/.test(body))
    fail(`${label} emits a flag-producing compare`);
}
const cmpmNf = functionBody(generatedSource, "void REGPARAM2 op_b108_0_comp_nf", "void REGPARAM2 op_b110_0_comp_nf", "CMPM.B no-flags dual read");
if ((cmpmNf.match(/readbyte\(/g) || []).length !== 2)
  fail("CMPM.B no-flags must retain both ordered reads");
if ((cmpmNf.match(/lea_l_brr\(/g) || []).length !== 2)
  fail("CMPM.B no-flags must retain both postincrements");

const focusedCompareCount = (harnessSource.match(/^TESTS\[(?:cmp|cmpm|cmpa)_core_/gm) || []).length;
if (focusedCompareCount !== 31) fail(`compare exact-native matrix: expected 31, found ${focusedCompareCount}`);
for (const contract of [
  'for _cmp_name in "${CMP_NATIVE_MATRIX_NAMES[@]}"',
  "cmp_core_b_aind_special_native", "cmp_core_w_index_special_native",
  "cmpm_core_w_special_native", "cmpa_core_l_aind_special_native",
]) requireText(harnessSource, contract, "compare exact-native gate");
for (const contract of [
  "cmpm_b_source_dst_collision", "cmpa_w_postinc_source_dst_collision",
  "[cmpm_b_source_dst_collision]=21", "[cmpm_b_source_dst_collision]=23",
  "[cmpa_w_postinc_source_dst_collision]=21", "[cmpa_w_postinc_source_dst_collision]=22",
]) requireText(regallocPressureSource, contract, "compare allocator pressure");
for (const active of ["cmpm_core_b_distinct_native", "cmpa_core_w_postinc_alias_native"])
  requireText(activeRiskySource, active, `compare active-risky ${active}`);

/* The generic CMP encoders are a separate cross-caller layer. Prove their
 * exact A64 aliases, every configured caller, and direct native NZCV behavior. */
for (const contract of [
  "#define _W(c) emit_long((uae_u32)(c))",
  "#define CMP_wi(Wn,i12)            _W((0b0111000100 << 22) | (((i12) & 0xfff) << 10) | ((Wn) << 5) | (0b11111))",
  "#define CMP_xi(Xn,i12)            _W((0b1111000100 << 22) | (((i12) & 0xfff) << 10) | ((Xn) << 5) | (0b11111))",
  "#define CMP_ww(Wn,Wm)             _W((0b01101011000 << 21) | ((Wm) << 16) | (0 << 10) | ((Wn) << 5) | (0b11111))",
  "#define CMP_xx(Xn,Xm)             _W((0b11101011000 << 21) | ((Xm) << 16) | (0 << 10) | ((Xn) << 5) | (0b11111))",
  "#define CMP_wwLSLi(Wn,Wm,i)       _W((0b01101011000 << 21) | ((Wm) << 16) | (((i) & 0x1f) << 10) | ((Wn) << 5) | (0b11111))",
]) requireText(codegenHeaderSource, contract, "generic CMP emitter encoding");

const compareEmitterCallers = `${midfunc2Source}\n${compatSource}\n${source}`;
for (const [name, expected] of [
  ["CMP_wi", 49], ["CMP_xi", 3], ["CMP_ww", 25], ["CMP_xx", 6], ["CMP_wwLSLi", 6],
] as const) {
  const found = (compareEmitterCallers.match(new RegExp(`\\b${name}\\(`, "g")) || []).length;
  if (found !== expected) fail(`generic ${name} caller census: expected ${expected}, found ${found}`);
}
const cmpWiArgs = [...compareEmitterCallers.matchAll(/\bCMP_wi\([^,]+,\s*([^)]+)\)/g)].map((match) => match[1].trim());
if (cmpWiArgs.filter((arg) => arg === "i").length !== 3)
  fail("CMP_wi dynamic immediate caller census changed");
for (const arg of cmpWiArgs) {
  if (arg === "i") continue;
  const value = Number(arg);
  if (!Number.isInteger(value) || value < 0 || value > 0xfff)
    fail(`CMP_wi caller exceeds imm12 contract: ${arg}`);
}
if ((midfunc2Source.match(/COMPCALL\(jff_ASL_[bwl]_imm\)\(d, live\.state\[i\]\.val & 0x3f\)/g) || []).length !== 3)
  fail("CMP_wi dynamic immediate is not bounded by the six-bit ASL contract");
const cmpXiArgs = [...compareEmitterCallers.matchAll(/\bCMP_xi\([^,]+,\s*([^)]+)\)/g)].map((match) => Number(match[1].trim()));
if (cmpXiArgs.length !== 3 || cmpXiArgs.some((value) => !Number.isInteger(value) || value < 0 || value > 0xfff))
  fail(`CMP_xi caller exceeds imm12 contract: ${cmpXiArgs.join(",")}`);
const cmpShiftArgs = [...compareEmitterCallers.matchAll(/\bCMP_wwLSLi\([^,]+,[^,]+,\s*([^)]+)\)/g)].map((match) => Number(match[1].trim()));
if (cmpShiftArgs.length !== 6 || cmpShiftArgs.some((value) => ![16, 24].includes(value)))
  fail(`CMP_wwLSLi configured shift contract changed: ${cmpShiftArgs.join(",")}`);
for (const contract of [
  "0x7100013fu", "0xf13ffd7fu", "0x6b0a013fu", "0xeb0c017fu", "0x6b0a7d3fu",
  "CMP_wi imm12-max", "CMP_xi width64", "CMP_ww overflow", "CMP_xx width64",
  "CMP_wwLSLi shift0", "CMP_wwLSLi shift31", "PROT_READ | PROT_WRITE",
  "mprotect(page, static_cast<std::size_t>(page_size), PROT_READ | PROT_EXEC)",
  "__builtin___clear_cache", "return vectors == 20 ? 0 : 1;",
]) requireText(compareEmitterProbeSource, contract, "generic CMP native conformance");
for (const contract of ["-Wall -Wextra -Werror", "emitter-compare-conformance.cpp"])
  requireText(compareEmitterHarnessSource, contract, "generic CMP conformance build");
requireText(harnessSource, 'timeout -k 5s 60s "$SCRIPT_DIR/emitter-compare-conformance.sh"', "generic CMP bounded acceptance gate");

/* The generic ADD encoders are a separate seven-API cross-caller layer. Audit
 * every raw source spelling, legal immediate/extension/shift fields, exact A64
 * words, native width behavior, and the non-flag-setting contract. */
for (const contract of [
  "#define ADD_wwwEX(Wd,Wn,Wm,ex)    _W((0b00001011001 << 21) | ((Wm) << 16) | ((ex) << 13) | (0 << 10) | ((Wn) << 5) | (Wd))",
  "#define ADD_xxwEX(Xd,Xn,Wm,ex)    _W((0b10001011001 << 21) | ((Wm) << 16) | ((ex) << 13) | (0 << 10) | ((Xn) << 5) | (Xd))",
  "#define ADD_wwi(Wd,Wn,i12)        _W((0b0001000100 << 22) | (((i12) & 0xfff) << 10) | ((Wn) << 5) | (Wd))",
  "#define ADD_xxi(Xd,Xn,i12)        _W((0b1001000100 << 22) | (((i12) & 0xfff) << 10) | ((Xn) << 5) | (Xd))",
  "#define ADD_www(Wd,Wn,Wm)         _W((0b00001011000 << 21) | ((Wm) << 16) | (0 << 10) | ((Wn) << 5) | (Wd))",
  "#define ADD_xxx(Xd,Xn,Xm)         _W((0b10001011000 << 21) | ((Xm) << 16) | (0 << 10) | ((Xn) << 5) | (Xd))",
  "#define ADD_wwwLSLi(Wd,Wn,Wm,i)   _W((0b00001011000 << 21) | ((Wm) << 16) | (((i) & 0x1f) << 10) | ((Wn) << 5) | (Wd))",
]) requireText(codegenHeaderSource, contract, "generic ADD emitter encoding");

const addEmitterCallers = `${midfuncSource}\n${midfunc2Source}\n${compatSource}\n${codegenSource}`;
for (const [name, expected] of [
  ["ADD_wwi", 17], ["ADD_xxi", 7], ["ADD_wwwEX", 1], ["ADD_xxwEX", 9],
  ["ADD_www", 27], ["ADD_xxx", 3], ["ADD_wwwLSLi", 8],
] as const) {
  const found = (addEmitterCallers.match(new RegExp(`\\b${name}\\(`, "g")) || []).length;
  if (found !== expected) fail(`generic ${name} raw caller census: expected ${expected}, found ${found}`);
}
const lastArgs = (pattern: RegExp) => [...addEmitterCallers.matchAll(pattern)].map((match) => match[1].trim());
const expectArgs = (label: string, found: string[], expected: string[]) => {
  if (JSON.stringify(found) !== JSON.stringify(expected))
    fail(`${label} caller arguments changed: ${found.join(",")}`);
};
expectArgs("ADD_wwi imm12", lastArgs(/\bADD_wwi\([^,\n]+,[^,\n]+,\s*([^\)]+)\)/g), [
  "offset", "offset", "i32", "i", "v & 0xff", "v & 0xff", "v & 0xff",
  "v", "v", "v", "tmp", "v", "live.state[s].val", "6", "0x60", "1", "1",
]);
expectArgs("ADD_xxi imm12", lastArgs(/\bADD_xxi\([^,\n]+,[^,\n]+,\s*([^\)]+)\)/g), [
  "offset", "offset", "i", "offset", "JIT_OBSERVER_SAVE_SIZE", "4", "4",
]);
expectArgs("ADD_wwwEX extension", lastArgs(/\bADD_wwwEX\([^,\n]+,[^,\n]+,[^,\n]+,\s*([^\)]+)\)/g), ["EX_SXTH"]);
expectArgs("ADD_xxwEX extension", lastArgs(/\bADD_xxwEX\([^,\n]+,[^,\n]+,[^,\n]+,\s*([^\)]+)\)/g), [
  "6", "EX_SXTW", "EX_UXTW", "EX_UXTW", "EX_UXTW", "EX_UXTW", "EX_UXTW", "EX_UXTW", "EX_UXTW",
]);
expectArgs("ADD_wwwLSLi shift", lastArgs(/\bADD_wwwLSLi\([^,\n]+,[^,\n]+,[^,\n]+,\s*([^\)]+)\)/g), [
  "shift & 0x1f", "shift & 0x1f", "shft", "shft", "2", "1", "1", "1",
]);
for (const contract of [
  "if(offset >= 0 && offset <= 0xfff) {\n\t\t\tADD_xxi(d, s, offset);",
  "if(offset >= 0 && offset <= 0xfff) {\n\t\tADD_wwi(d, s, offset);",
  "if (offset > 0 && offset <= 0xfff) {\n\t\tADD_xxi(d, d, offset);",
  "if (i32 <= 0xfff) {\n\t\tADD_wwi(d, d, i32);",
  "MIDFUNC(2,arm_ADD_l_ri8,(RW4 d, IM8 i))",
]) requireText(midfuncSource, contract, "generic ADD immediate caller bound");
for (const contract of [
  "if(v >= 0 && v <= 0xfff)", "if(tmp >= 0 && tmp <= 0xfff)",
  "live.state[s].val >= 0 && live.state[s].val <= 0xfff",
]) requireText(midfunc2Source, contract, "generic ADD immediate caller bound");
requireText(codegenSource, "static constexpr int JIT_OBSERVER_SAVE_SIZE = 240;", "generic ADD observer-stack immediate bound");
requireText(compatSource, "if (offset > 0 && offset <= 4095) {\n\t\tADD_xxi(tmp, base, offset);", "generic ADD compatibility immediate bound");
if ((midfuncSource.match(/case 1: shft=0; break;\n\t\tcase 2: shft=1; break;\n\t\tcase 4: shft=2; break;\n\t\tcase 8: shft=3; break;/g) || []).length !== 2)
  fail("generic ADD indexed-EA shift bounds changed");
for (const contract of [
  "0x11000149u", "0x113ffd49u", "0x9100018bu", "0x913ffd8bu",
  "0x0b2f01cdu", "0x0b2fc1cdu", "0x8b324230u", "0x8b32c230u",
  "0x0b150293u", "0x8b1802f6u", "0x0b1b0359u", "0x0b1b7f59u",
  "ADD_wwi preserves NZCV", "ADD_xxi preserves NZCV", "ADD_wwwEX preserves NZCV",
  "ADD_xxwEX preserves NZCV", "ADD_www preserves NZCV", "ADD_xxx preserves NZCV",
  "ADD_wwwLSLi preserves NZCV", "PROT_READ | PROT_WRITE",
  "mprotect(page, static_cast<std::size_t>(page_size), PROT_READ | PROT_EXEC)",
  "__builtin___clear_cache", "exact_words == 12 && result_vectors == 39 && flag_vectors == 7",
]) requireText(addEmitterProbeSource, contract, "generic ADD native conformance");
for (const contract of ["-Wall -Wextra -Werror", "emitter-add-conformance.cpp"])
  requireText(addEmitterHarnessSource, contract, "generic ADD conformance build");
requireText(harnessSource, 'timeout -k 5s 60s "$SCRIPT_DIR/emitter-add-conformance.sh"', "generic ADD bounded acceptance gate");

/* The generic SUB/SUBS encoders are a separate seven-API cross-caller layer.
 * Audit every raw source spelling and legal immediate/shift field, then prove
 * exact W/X encodings, aliases, S=0 preservation, and S=1 native NZCV. */
for (const contract of [
  "#define SUB_wwi(Wd,Wn,i12)        _W((0b0101000100 << 22) | (((i12) & 0xfff) << 10) | ((Wn) << 5) | (Wd))",
  "#define SUB_xxi(Xd,Xn,i12)        _W((0b1101000100 << 22) | (((i12) & 0xfff) << 10) | ((Xn) << 5) | (Xd))",
  "#define SUB_www(Wd,Wn,Wm)         _W((0b01001011000 << 21) | ((Wm) << 16) | (0 << 10) | ((Wn) << 5) | (Wd))",
  "#define SUB_xxx(Xd,Xn,Xm)         _W((0b11001011000 << 21) | ((Xm) << 16) | (0 << 10) | ((Xn) << 5) | (Xd))",
  "#define SUBS_wwi(Wd,Wn,i12)       _W((0b0111000100 << 22) | (((i12) & 0xfff) << 10) | ((Wn) << 5) | (Wd))",
  "#define SUBS_www(Wd,Wn,Wm)        _W((0b01101011000 << 21) | ((Wm) << 16) | (0 << 10) | ((Wn) << 5) | (Wd))",
  "#define SUBS_wwwLSLi(Wd,Wn,Wm,i)  _W((0b01101011000 << 21) | ((Wm) << 16) | (((i) & 0x1f) << 10) | ((Wn) << 5) | (Wd))",
]) requireText(codegenHeaderSource, contract, "generic SUB emitter encoding");

const subEmitterCallers = `${midfuncSource}\n${midfunc2Source}\n${compatSource}\n${codegenSource}`;
for (const [name, expected] of [
  ["SUB_wwi", 54], ["SUB_xxi", 6], ["SUB_www", 36], ["SUB_xxx", 3],
  ["SUBS_wwi", 6], ["SUBS_www", 3], ["SUBS_wwwLSLi", 3],
] as const) {
  const found = (subEmitterCallers.match(new RegExp(`\\b${name}\\(`, "g")) || []).length;
  if (found !== expected) fail(`generic ${name} raw caller census: expected ${expected}, found ${found}`);
}
expectArgs("SUB_wwi imm12", [...subEmitterCallers.matchAll(/\bSUB_wwi\([^,\n]+,[^,\n]+,\s*([^\)]+)\)/g)].map((match) => match[1].trim()), [
  "-offset", "-offset", "i", "i", "1", "-tmp", "-v", "1", "1", "1", "1", "1", "1",
  "36", "18", "9", "34", "17", "33", "36", "18", "9", "34", "17", "33", "1", "36", "18",
  "9", "34", "17", "33", "36", "18", "9", "1", "34", "17", "1", "33", "1", "v & 0xff",
  "v & 0xff", "v", "v", "v", "6", "0x60", "6", "0x60", "cycles", "cycles", "cycles", "cycles",
]);
expectArgs("SUB_xxi imm12", [...subEmitterCallers.matchAll(/\bSUB_xxi\([^,\n]+,[^,\n]+,\s*([^\)]+)\)/g)].map((match) => match[1].trim()), [
  "-offset", "i", "-offset", "i", "-offset", "JIT_OBSERVER_SAVE_SIZE",
]);
expectArgs("SUBS_wwi imm12", [...subEmitterCallers.matchAll(/\bSUBS_wwi\([^,\n]+,[^,\n]+,\s*([^\)]+)\)/g)].map((match) => match[1].trim()), [
  "1", "1", "1", "v", "1", "1",
]);
expectArgs("SUBS_wwwLSLi shift", [...subEmitterCallers.matchAll(/\bSUBS_wwwLSLi\([^,\n]+,[^,\n]+,[^,\n]+,\s*([^\)]+)\)/g)].map((match) => match[1].trim()), [
  "24", "16", "16",
]);
for (const contract of [
  "else if(offset >= -0xfff && offset < 0) {\n\t\t\tSUB_xxi(d, s, -offset);",
  "else if(offset >= -0xfff && offset < 0) {\n\t\tSUB_wwi(d, s, -offset);",
  "else if (offset < 0 && offset >= -0xfff) {\n\t\tSUB_xxi(d, d, -offset);",
  "MIDFUNC(5,lea_l_brr_indexed,(W4 d, RR4 s, RR4 index, IM8 factor, IM8 offset))",
  "MIDFUNC(2,sub_l_ri,(RW4 d, IM8 i))",
  "MIDFUNC(2,arm_SUB_l_ri8,(RW4 d, IM8 i))",
]) requireText(midfuncSource, contract, "generic SUB immediate caller bound");
for (const contract of [
  "else if (tmp >= -0xfff && tmp < 0) {\n\t\tSUB_wwi(d, d, -tmp);",
  "else if (v >= -0xfff && v < 0) {\n\t\tSUB_wwi(d, d, -v);",
  "if(v >= 0 && v < 4096) {\n\t\tSUBS_wwi(d, d, v);",
]) requireText(midfunc2Source, contract, "generic SUB immediate caller bound");
if ((midfunc2Source.match(/if\(v >= 0 && v < 4096\) \{\n\t\tSUB_wwi\(d, d, v\);/g) || []).length !== 3)
  fail("generic SUB_wwi guarded positive imm12 caller count changed");
if ((codegenSource.match(/if\(cycles >= 0 && cycles <= 0xfff\) \{\n\t\tSUB_wwi\([^\n]+, cycles\);/g) || []).length !== 4)
  fail("generic SUB_wwi guarded cycle imm12 caller count changed");
requireText(codegenSource, "static constexpr int JIT_OBSERVER_SAVE_SIZE = 240;", "generic SUB observer immediate bound");
requireText(compatSource, "if (offset < 0 && offset >= -4095) {\n\t\tSUB_xxi(tmp, base, -offset);", "generic SUB compatibility immediate bound");
for (const contract of [
  "0x51000149u", "0x513fffffu", "0xd100018bu", "0xd13fffffu",
  "0x4b1f03ffu", "0xcb1f03ffu", "0x71000149u", "0x713fffffu",
  "0x6b1f03ffu", "0x6b1b0359u", "0x6b1f7fffu",
  "SUB_www destination-rhs alias", "SUB_xxx destination-rhs alias",
  "SUBS_www destination-rhs alias", "SUBS_wwwLSLi destination-rhs alias",
  "SUB_wwi preserves NZCV", "SUB_xxi preserves NZCV", "SUB_www preserves NZCV", "SUB_xxx preserves NZCV",
  "expected_subs_w_nzcv", "PROT_READ | PROT_WRITE",
  "mprotect(page, static_cast<std::size_t>(page_size), PROT_READ | PROT_EXEC)",
  "__builtin___clear_cache", "exact_words == 11 && result_vectors == 42 && preserve_vectors == 4 && flag_vectors == 24",
]) requireText(subEmitterProbeSource, contract, "generic SUB native conformance");
for (const contract of ["-Wall -Wextra -Werror", "emitter-sub-conformance.cpp"])
  requireText(subEmitterHarnessSource, contract, "generic SUB conformance build");
requireText(harnessSource, 'timeout -k 5s 60s "$SCRIPT_DIR/emitter-sub-conformance.sh"', "generic SUB bounded acceptance gate");

/* The mechanically selected reachable generic AND cluster consists only of the
 * 32-bit #0x3f logical-immediate form and the W/X register forms. Keep its raw
 * caller census and call shapes fail-closed, then prove exact words, W/X width,
 * source/destination aliases, and S=0 NZCV preservation directly on AArch64. */
for (const contract of [
  "#define AND_ww3f(Wd,Wn)           _W((0b000100100 << 23) | immEncode(0,0b000000,0b000101) | ((Wn) << 5) | (Wd))",
  "#define AND_www(Wd,Wn,Wm)         _W((0b00001010000 << 21) | ((Wm) << 16) | (0 << 10) | ((Wn) << 5) | (Wd))",
  "#define AND_xxx(Xd,Xn,Xm)         _W((0b10001010000 << 21) | ((Xm) << 16) | (0 << 10) | ((Xn) << 5) | (Xd))",
]) requireText(codegenHeaderSource, contract, "generic AND emitter encoding");

const andEmitterCallers = `${midfuncSource}\n${midfunc2Source}\n${compatSource}\n${codegenSource}`;
for (const [name, expected] of [
  ["AND_ww3f", 31], ["AND_www", 20], ["AND_xxx", 32],
] as const) {
  const found = (andEmitterCallers.match(new RegExp(`\\b${name}\\(`, "g")) || []).length;
  if (found !== expected) fail(`generic ${name} raw caller census: expected ${expected}, found ${found}`);
}
const expectAndCallShape = (name: string, pattern: RegExp, expected: number) => {
  const found = (andEmitterCallers.match(pattern) || []).length;
  if (found !== expected) fail(`generic ${name} caller shape: expected ${expected}, found ${found}`);
};
expectAndCallShape("AND_ww3f REG_WORK1,i", /\bAND_ww3f\(REG_WORK1, i\)/g, 23);
expectAndCallShape("AND_ww3f REG_WORK2,i", /\bAND_ww3f\(REG_WORK2, i\)/g, 8);
for (const [shape, expected] of [
  ["d, d, REG_WORK1", 3], ["d, d, s", 3], ["REG_WORK1, adr, REG_WORK1", 4],
  ["REG_WORK1, d, s", 2], ["REG_WORK1, REG_WORK1, imm_reg", 1],
  ["REG_WORK1, REG_WORK1, REG_WORK2", 2], ["REG_WORK3, adr, REG_WORK3", 1],
  ["REG_WORK3, REG_WORK1, REG_WORK3", 1], ["REG_WORK4, REG_WORK4, REG_WORK2", 3],
] as const) expectAndCallShape(`AND_www ${shape}`, new RegExp(`\\bAND_www\\(${shape.replaceAll(" ", "\\s*")}\\)`, "g"), expected);
for (const [shape, expected] of [
  ["d2, d2, REG_WORK2", 6], ["d, d, REG_WORK1", 1], ["d, d, REG_WORK2", 6],
  ["REG_WORK1, REG_WORK1, REG_WORK2", 19],
] as const) expectAndCallShape(`AND_xxx ${shape}`, new RegExp(`\\bAND_xxx\\(${shape.replaceAll(" ", "\\s*")}\\)`, "g"), expected);
for (const contract of [
  "#define N_REGS 18   /* really 32", "#define REG_WORK1 R2_INDEX",
  "#define REG_WORK2 R3_INDEX", "#define REG_WORK3 R4_INDEX", "#define REG_WORK4 R5_INDEX",
]) requireText(`${compemuArmHeaderSource}\n${codegenSource}`, contract, "generic AND register field bound");
for (const contract of [
  "0x12001549u", "0x120017beu", "0x120017ffu",
  "0x0a0b0149u", "0x0a1c03beu", "0x0a1f03ffu",
  "0x8a0e01acu", "0x8a1a037cu", "0x8a1f03ffu", "AND_ww3f preserves NZCV",
  "AND_www preserves NZCV", "AND_xxx preserves NZCV", "AND_www native d=m alias",
  "AND_xxx native all alias", "PROT_READ | PROT_WRITE",
  "mprotect(page, static_cast<std::size_t>(page_size), PROT_READ | PROT_EXEC)",
  "__builtin___clear_cache", "exact_words == 9 && result_vectors == 24 && flag_vectors == 3",
]) requireText(andEmitterProbeSource, contract, "generic AND native conformance");
for (const contract of ["-Wall -Wextra -Werror", "emitter-and-conformance.cpp"])
  requireText(andEmitterHarnessSource, contract, "generic AND conformance build");
requireText(harnessSource, 'timeout -k 5s 60s "$SCRIPT_DIR/emitter-and-conformance.sh"', "generic AND bounded acceptance gate");

/* The reachable generic EOR surface combines two W register encoders with the
 * 64-bit single-bit/C-bit logical-immediate helpers and their shared immediate
 * base. Keep both the 53 configured references and the stronger 64 raw source
 * compositions fail-closed; prove exact words, shift/bit boundaries, aliases,
 * W/X width, and S=0 NZCV preservation directly on AArch64. */
for (const contract of [
  "#define EOR_www(Wd,Wn,Wm)         _W((0b01001010000 << 21) | ((Wm) << 16) | (0 << 10) | ((Wn) << 5) | (Wd))",
  "#define EOR_wwwLSLi(Wd,Wn,Wm,i)   _W((0b01001010000 << 21) | ((Wm) << 16) | (((i) & 0x1f) << 10) | ((Wn) << 5) | (Wd))",
  "#define immOP_EOR                 (0b110100100 << 23)",
  "#define EOR_xxCflag(Xd,Xn)        _W(immCflag | immOP_EOR | ((Xn) << 5) | (Xd))",
  "#define EOR_xxbit(Xd,Xn,bit)      _W(immOP_EOR | immEncode(1, ((-(bit)) & 0x3f), 0b000000) | ((Xn) << 5) | (Xd))",
]) requireText(codegenHeaderSource, contract, "generic EOR emitter encoding");

const eorEmitterCallers = `${midfuncSource}\n${midfunc2Source}\n${compatSource}\n${codegenSource}\n${allocatorSource}`;
for (const [name, expected] of [
  ["EOR_www", 25], ["EOR_wwwLSLi", 1], ["EOR_xxCflag", 31], ["EOR_xxbit", 5],
] as const) {
  const found = (eorEmitterCallers.match(new RegExp(`\\b${name}\\(`, "g")) || []).length;
  if (found !== expected) fail(`generic ${name} raw caller census: expected ${expected}, found ${found}`);
}
if ((codegenHeaderSource.match(/\bimmOP_EOR\b/g) ?? []).length !== 3)
  fail("generic immOP_EOR composition census changed");
const expectEorCallShape = (name: string, pattern: RegExp, expected: number) => {
  const found = (eorEmitterCallers.match(pattern) || []).length;
  if (found !== expected) fail(`generic ${name} caller shape: expected ${expected}, found ${found}`);
};
for (const [shape, expected] of [
  ["REG_WORK1, REG_WORK1, REG_WORK2", 5], ["REG_WORK1, REG_WORK1, imm_reg", 1],
  ["REG_WORK1, d, s", 2], ["REG_WORK3, REG_WORK2, d", 2],
  ["d, REG_WORK1, REG_WORK2", 4], ["d, d, REG_WORK1", 4],
  ["d, d, REG_WORK2", 4], ["d, d, s", 3],
] as const) expectEorCallShape(`EOR_www ${shape}`, new RegExp(`\\bEOR_www\\(${shape.replaceAll(" ", "\\s*")}\\)`, "g"), expected);
expectEorCallShape("EOR_wwwLSLi fixed shift", /\bEOR_wwwLSLi\(REG_WORK1, d, d, 1\)/g, 1);
for (const [shape, expected] of [
  ["REG_WORK1, REG_WORK1", 10], ["REG_WORK2, REG_WORK2", 5],
  ["REG_WORK3, REG_WORK3", 10], ["REG_WORK4, REG_WORK4", 5], ["r, r", 1],
] as const) expectEorCallShape(`EOR_xxCflag ${shape}`, new RegExp(`\\bEOR_xxCflag\\(${shape.replaceAll(" ", "\\s*")}\\)`, "g"), expected);
expectEorCallShape("EOR_xxbit byte mask", /\bEOR_xxbit\(d, d, s & 0x7\)/g, 2);
expectEorCallShape("EOR_xxbit long mask", /\bEOR_xxbit\(d, d, s & 0x1f\)/g, 2);
expectEorCallShape("EOR_xxbit X toggle", /\bEOR_xxbit\(f, f, 0\)/g, 1);
for (const contract of [
  "#define N_REGS 18   /* really 32", "#define REG_WORK1 R2_INDEX",
  "#define REG_WORK2 R3_INDEX", "#define REG_WORK3 R4_INDEX", "#define REG_WORK4 R5_INDEX",
]) requireText(`${compemuArmHeaderSource}\n${codegenSource}`, contract, "generic EOR register field bound");
for (const contract of [
  "0x4a0b0149u", "0x4a1c03beu", "0x4a1f03ffu",
  "0x4a0b1d49u", "0x4a1c7fbeu", "EOR_wwwLSLi masked shift",
  "0xd2630149u", "0xd26303beu", "0xd26303ffu",
  "0xd2400149u", "0xd26301acu", "0xd24103beu", "0xd24103ffu",
  "immOP_EOR exact base", "EOR_www native d=m alias", "EOR_wwwLSLi native all alias",
  "EOR_xxCflag native distinct", "EOR_xxbit native bit 63 clear",
  "EOR_www preserves NZCV", "EOR_wwwLSLi preserves NZCV",
  "EOR_xxCflag preserves NZCV", "EOR_xxbit preserves NZCV",
  "PROT_READ | PROT_WRITE", "mprotect(page, static_cast<std::size_t>(page_size), PROT_READ | PROT_EXEC)",
  "__builtin___clear_cache", "exact_words == 13 && constant_checks == 1 && result_vectors == 18 && flag_vectors == 4",
]) requireText(eorEmitterProbeSource, contract, "generic EOR native conformance");
for (const contract of ["-Wall -Wextra -Werror", "emitter-eor-conformance.cpp"])
  requireText(eorEmitterHarnessSource, contract, "generic EOR conformance build");
requireText(harnessSource, 'timeout -k 5s 60s "$SCRIPT_DIR/emitter-eor-conformance.sh"', "generic EOR bounded acceptance gate");

/* FMOV_dd/raw_fmov_rr/fmov_rr form one binary64 bit-copy primitive stack.
   Architectural 80-bit register FMOVE is serviced before reaching it; pin the
   remaining fixed-home ownership and complete D-register encoding contract. */
requireText(codegenHeaderSource, "#define FMOV_dd(Dd,Dn)", "FMOV_dd emitter declaration");
const rawFmovStart = codegenSource.indexOf("LOWFUNC(NONE,NONE,2,raw_fmov_rr,(FW d, FR s))");
const rawFmovEnd = codegenSource.indexOf("LENDFUNC(NONE,NONE,2,raw_fmov_rr", rawFmovStart);
if (rawFmovStart < 0 || rawFmovEnd < 0) fail("missing raw_fmov_rr boundary");
const rawFmovBody = codegenSource.slice(rawFmovStart, rawFmovEnd);
requireText(rawFmovBody, "FMOV_dd(d, s);", "raw_fmov_rr exact wrapper");
if ((rawFmovBody.match(/FMOV_dd\(/g) || []).length !== 1)
  fail("raw_fmov_rr must emit exactly one FMOV_dd");
const midFmovStart = midfuncSource.indexOf("MIDFUNC(2,fmov_rr,(FW d, FR s))");
const midFmovEnd = midfuncSource.indexOf("MENDFUNC(2,fmov_rr", midFmovStart);
if (midFmovStart < 0 || midFmovEnd < 0) fail("missing fmov_rr MIDFUNC");
const midFmovBody = midfuncSource.slice(midFmovStart, midFmovEnd);
for (const contract of [
  "if (d == s)", "s = f_readreg(s);", "d = f_writereg(d);",
  "raw_fmov_rr(d, s);", "f_unlock(s);", "f_unlock(d);",
]) requireText(midFmovBody, contract, "fmov_rr ownership contract");
requireBefore(midFmovBody, "s = f_readreg(s);", "d = f_writereg(d);", "fmov_rr source preservation");
requireBefore(midFmovBody, "d = f_writereg(d);", "raw_fmov_rr(d, s);", "fmov_rr destination publication");
for (const contract of [
  "if (r < 8)\n        bestreg = r + 8", "else if (r == FP_RESULT)\n        bestreg = 6",
  "else // FS1\n        bestreg = 7", "static void f_unlock(int r)\n{\n}",
  "f_mark_runtime_dirty(r);", "live.fate[r].status = DIRTY;",
]) requireText(allocatorSource, contract, "fmov_rr fixed-home allocator contract");
const authoritativeFmovSpellings = (fppCompilerSource.match(/\bfmov_rr\(/g) || []).length;
if (authoritativeFmovSpellings !== 7)
  fail(`fmov_rr authoritative caller spellings=${authoritativeFmovSpellings} expected=7`);
for (const contract of [
  "#define MAKE_FPSR(r) do { fmov_rr(FP_RESULT,r); } while (0)",
  "fmov_rr(dest_reg, val);", "fmov_rr(reg, src);",
  "fcompare_result_rr(FP_RESULT, reg, src);", "fmov_rr(FS1, src);",
  "fmov_rr(FP_RESULT, FS1);", "fmov_rr(FP_RESULT, src);",
]) requireText(fppCompilerSource, contract, "fmov_rr configured caller roles");
for (const contract of [
  "for (unsigned d = 0; d < 32; ++d)", "for (unsigned s = 0; s < 32; ++s)",
  "0x1e604000u | (s << 5) | d", "signalling NaN payload", "negative quiet NaN payload",
  "MSR_NZCV_x(3)", "MSR_FPCR_x(4)", "MSR_FPSR_x(5)",
  "PROT_READ | PROT_WRITE", "mprotect(page, static_cast<std::size_t>(page_size), PROT_READ | PROT_EXEC)",
  "__builtin___clear_cache", "exact_words == 1024 && native_vectors == 10240",
]) requireText(fmovEmitterProbeSource, contract, "FMOV primitive native conformance");
for (const contract of ["-Wall -Wextra -Werror", "emitter-fmov-conformance.cpp"])
  requireText(fmovEmitterHarnessSource, contract, "FMOV primitive conformance build");
requireText(harnessSource, 'timeout -k 5s 90s "$SCRIPT_DIR/emitter-fmov-conformance.sh"', "FMOV primitive bounded acceptance gate");
console.log("METRIC structural_fmov_primitive_exact_words=1024");
console.log("METRIC structural_fmov_primitive_native_vectors=10240");
console.log("METRIC structural_fmov_primitive_caller_spellings=7");

/* FCMP_dd and FCMP_d0 are shared by the live FPP classifier, conversions, and
   status publication. Pin the whole generic API rather than inferring it from
   the guest-level FCMP matrix alone. */
const fcmpDdCallers = (codegenSource.match(/\bFCMP_dd\(/g) || []).length;
const fcmpD0Callers = (codegenSource.match(/\bFCMP_d0\(/g) || []).length;
if (fcmpDdCallers !== 5 || fcmpD0Callers !== 3)
  fail(`FCMP emitter callers dd=${fcmpDdCallers} d0=${fcmpD0Callers}, expected 5/3`);
for (const contract of [
  "FCMP_dd(SCRATCH_F64_1, SCRATCH_F64_2);", "FCMP_dd(s, SCRATCH_F64_1);",
  "FCMP_dd(d, s);", "FCMP_d0(d);", "FCMP_d0(s);", "FCMP_d0(r);",
]) requireText(codegenSource, contract, "generic FCMP configured callers");
for (const contract of [
  "#define FCMP_dd(Dn,Dm)", "#define FCMP_d0(Dn)",
]) requireText(codegenHeaderSource, contract, "generic FCMP emitter declaration");
for (const contract of [
  "for (unsigned n = 0; n < 32; ++n)", "for (unsigned m = 0; m < 32; ++m)",
  "0x1e602000u | (m << 16) | (n << 5)", "0x1e602008u | (n << 5)",
  "FCMP preserves lhs", "FCMP preserves rhs", "FCMP preserves FPCR",
  "fcmp_invoke_checked", "FCMP preserves caller D8-D15",
  "FCMP restores caller FPCR", "FCMP restores caller FPSR",
  "FCMP FPSR invalid contract", "FCMP lhs qNaN", "FCMP rhs qNaN",
  "FCMP lhs sNaN", "FCMP rhs sNaN", "FCMP_d0 sNaN",
  "PROT_READ | PROT_WRITE", "mprotect(page, static_cast<std::size_t>(page_size), PROT_READ | PROT_EXEC)",
  "__builtin___clear_cache", "exact_words == 1056 && dd_vectors == 40 && d0_vectors == 32",
]) requireText(fcmpEmitterProbeSource, contract, "generic FCMP native conformance");
for (const contract of ["-Wall -Wextra -Werror", "emitter-fcmp-conformance.cpp"])
  requireText(fcmpEmitterHarnessSource, contract, "generic FCMP conformance build");
requireText(harnessSource, 'timeout -k 5s 120s "$SCRIPT_DIR/emitter-fcmp-conformance.sh"', "generic FCMP bounded acceptance gate");
console.log("METRIC structural_fcmp_emitter_exact_words=1056");
console.log("METRIC structural_fcmp_emitter_native_vectors=72");
console.log("METRIC structural_fcmp_emitter_callers=8");

/* FCVTAS_wd is a single-caller generic API inside FRINTI-based guest integer
   conversion. Audit its own nearest-away/exception contract separately from
   the caller's guest-FPCR rounding and Motorola saturation lifecycle. */
const fcvtasCallers = (codegenSource.match(/\bFCVTAS_wd\(/g) || []).length;
if (fcvtasCallers !== 1) fail(`FCVTAS_wd emitter callers=${fcvtasCallers} expected=1`);
const fmovToIntStart = codegenSource.indexOf("STATIC_INLINE void fmov_to_int_emit(W4 d, FR s, int width)");
const fmovToIntEnd = codegenSource.indexOf("LOWFUNC(NONE,NONE,2,raw_fmov_to_l_rr", fmovToIntStart);
if (fmovToIntStart < 0 || fmovToIntEnd < 0) fail("missing fmov_to_int_emit caller boundary");
const fmovToIntBody = codegenSource.slice(fmovToIntStart, fmovToIntEnd);
requireBefore(fmovToIntBody, "FRINTI_dd(SCRATCH_F64_1, s);", "FCVTAS_wd(REG_WORK1, SCRATCH_F64_1);", "FCVTAS_wd guest rounding composition");
requireText(codegenHeaderSource, "#define FCVTAS_wd(Wd,Dn)", "FCVTAS_wd emitter declaration");
for (const contract of [
  "for (unsigned w = 0; w < 32; ++w)", "for (unsigned d = 0; d < 32; ++d)",
  "0x1e640000u | (d << 5) | w", "positive half", "negative half",
  "positive overflow", "negative overflow", "quiet NaN", "signalling NaN",
  "FCVTAS preserves source", "FCVTAS preserves NZCV", "FCVTAS preserves FPCR",
  "FCVTAS preserves caller D8-D15", "FCVTAS restores caller FPCR", "FCVTAS restores caller FPSR",
  "PROT_READ | PROT_WRITE", "mprotect(page, static_cast<std::size_t>(page_size), PROT_READ | PROT_EXEC)",
  "__builtin___clear_cache", "exact_words == 1024 && native_vectors == 256",
]) requireText(fcvtasEmitterProbeSource, contract, "generic FCVTAS native conformance");
for (const contract of [
  'process.env.GROUP === "integer"', 'new Set([0, 4, 6])',
  '(Number.parseInt(item.extra, 16) >> 10) & 7',
  'process.env.GROUP === "integer" ? 36 : 45',
]) requireText(fppFmoveDestinationBasicMatrix, contract, "FCVTAS guest integer composition subset");
for (const contract of ["-Wall -Wextra -Werror", "emitter-fcvtas-conformance.cpp"])
  requireText(fcvtasEmitterHarnessSource, contract, "generic FCVTAS conformance build");
requireText(harnessSource, 'timeout -k 5s 120s "$SCRIPT_DIR/emitter-fcvtas-conformance.sh"', "generic FCVTAS bounded acceptance gate");
console.log("METRIC structural_fcvtas_emitter_exact_words=1024");
console.log("METRIC structural_fcvtas_emitter_native_vectors=256");
console.log("METRIC structural_fcvtas_emitter_callers=1");

/* FCVT_sd/FCVT_ds are the shared bidirectional binary64/binary32 conversion
   pair. Close only their generic format/field/state contract; compound callers
   retain separate memory/arithmetic/Motorola exception ownership. */
const fcvtSdCallers = (codegenSource.match(/\bFCVT_sd\(/g) || []).length;
const fcvtDsCallers = (codegenSource.match(/\bFCVT_ds\(/g) || []).length;
if (fcvtSdCallers !== 7 || fcvtDsCallers !== 6)
  fail(`FCVT emitter callers sd=${fcvtSdCallers} ds=${fcvtDsCallers}, expected 7/6`);
for (const contract of [
  "FCVT_ds(d, SCRATCH_F64_1);", "FCVT_sd(SCRATCH_F64_1, s);",
  "FCVT_ds(r, r);", "FCVT_sd(SCRATCH_F64_1, d);",
  "FCVT_sd(SCRATCH_F64_2, s);", "FCVT_ds(d, SCRATCH_F64_1);",
]) requireText(codegenSource, contract, "generic FCVT configured source sites");
const getFpSingleMemoryCall = getFpValueBody.indexOf("fmov_s_rr(FS1, S2);");
const getFpSingleMemoryStart = getFpValueBody.lastIndexOf("case 1: /* single precision */", getFpSingleMemoryCall);
const getFpSingleMemoryEnd = getFpValueBody.indexOf("case 2: /* extended precision */", getFpSingleMemoryCall);
if (getFpSingleMemoryStart < 0 || getFpSingleMemoryEnd < 0)
  fail("FCVT configured single-memory import boundary is incomplete");
const getFpSingleMemory = getFpValueBody.slice(getFpSingleMemoryStart, getFpSingleMemoryEnd);
for (const contract of [
  "readlong(ad, S2, S3);", "#if defined(CPU_aarch64) || defined(CPU_AARCH64)",
  "fmov_s_rr(FS1, S2);", "#else", "fmovs_rm(FS1, (uintptr) temp_fp);",
]) requireText(getFpSingleMemory, contract, "FCVT configured single-memory import routing");
requireBefore(getFpSingleMemory, "readlong(ad, S2, S3);", "fmov_s_rr(FS1, S2);", "FCVT configured single-memory load order");
const fmovSingleRegisterMidfunc = functionBody(
  midfuncSource, "MIDFUNC(2,fmov_s_rr,(FW d, RR4 s))", "MENDFUNC(2,fmov_s_rr,(FW d, RR4 s))",
  "FCVT configured fmov_s_rr route",
);
requireText(fmovSingleRegisterMidfunc, "raw_fmov_s_rr(d, s);", "FCVT configured fmov_s_rr route");
const rawFmovSingleRegister = functionBody(
  codegenSource, "LOWFUNC(NONE,NONE,2,raw_fmov_s_rr,(FW d, RR4 s))",
  "LENDFUNC(NONE,NONE,2,raw_fmov_s_rr,(FW d, RR4 s))", "FCVT configured raw_fmov_s_rr route",
);
requireBefore(rawFmovSingleRegister, "FMOV_sw(SCRATCH_F64_1, s);", "FCVT_ds(d, SCRATCH_F64_1);", "FCVT configured raw_fmov_s_rr order");
for (const contract of ["#define FCVT_sd(Sd,Dn)", "#define FCVT_ds(Dd,Sn)"])
  requireText(codegenHeaderSource, contract, "generic FCVT emitter declaration");
for (const contract of [
  "0x1e624000u|(b<<5)|a", "0x1e22c000u|(b<<5)|a",
  "inexact_normal", "half_min_subnormal", "negative_half_min_subnormal",
  "positive_overflow", "negative_overflow", "signalling_nan", "single_snan",
  "FCVT preserves source", "FCVT preserves NZCV", "FCVT preserves FPCR",
  "FCVT preserves caller D8-D15", "FCVT restores caller FPCR", "FCVT restores caller FPSR",
  "PROT_READ|PROT_WRITE", "mprotect(p,ps,PROT_READ|PROT_EXEC)",
  "__builtin___clear_cache", "exact==2048&&nv==144&&wv==112&&av==64",
]) requireText(fcvtEmitterProbeSource, contract, "generic FCVT native conformance");
for (const contract of ["-Wall -Wextra -Werror", "emitter-fcvt-conformance.cpp"])
  requireText(fcvtEmitterHarnessSource, contract, "generic FCVT conformance build");
for (const contract of [
  'process.env.GROUP === "single"',
  'item.anchor === 0x1000 && ((extra >> 10) & 7) === 1',
  'process.env.GROUP === "single" ? 8 : process.env.GROUP === "integer" ? 18 : 29',
]) requireText(fppFmoveSourceMatrix, contract, "FCVT single register/immediate source composition subset");
for (const contract of [
  'process.env.GROUP === "single"',
  '((Number.parseInt(item.extra, 16) >> 10) & 7) === 1',
  'process.env.GROUP === "single" ? 3 : 18',
]) requireText(fppFmoveMemoryBasicMatrix, contract, "FCVT single memory-source composition subset");
requireText(harnessSource, 'timeout -k 5s 120s "$SCRIPT_DIR/emitter-fcvt-conformance.sh"', "generic FCVT bounded acceptance gate");
console.log("METRIC structural_fcvt_emitter_exact_words=2048");
console.log("METRIC structural_fcvt_emitter_native_vectors=256");
console.log("METRIC structural_fcvt_emitter_callers=13");

/* FMOV_sw/FMOV_ws are reciprocal 32-bit bit-transfer encoders. Close only
   their format/field/lane/state contract; their raw and MIDFUNC compositions
   retain separate conversion, rounding, memory, and Motorola-status ownership. */
const fmovSwCallers = (codegenSource.match(/\bFMOV_sw\(/g) || []).length;
const fmovWsCallers = (codegenSource.match(/\bFMOV_ws\(/g) || []).length;
if (fmovSwCallers !== 1 || fmovWsCallers !== 1)
  fail(`FMOV W/S emitter callers sw=${fmovSwCallers} ws=${fmovWsCallers}, expected 1/1`);
for (const contract of ["#define FMOV_sw(Sd,Wn)", "#define FMOV_ws(Wd,Sn)"])
  requireText(codegenHeaderSource, contract, "generic FMOV W/S emitter declaration");
requireBefore(rawFmovSingleRegister, "FMOV_sw(SCRATCH_F64_1, s);", "FCVT_ds(d, SCRATCH_F64_1);", "FMOV_sw configured composition");
const rawFmovToSingleStart = codegenSource.indexOf("LOWFUNC(NONE,NONE,2,raw_fmov_to_s_rr");
const rawFmovToSingleEnd = codegenSource.indexOf("LENDFUNC(NONE,NONE,2,raw_fmov_to_s_rr", rawFmovToSingleStart);
if (rawFmovToSingleStart < 0 || rawFmovToSingleEnd < 0)
  fail("FMOV_ws configured composition boundary is incomplete");
const rawFmovToSingle = codegenSource.slice(rawFmovToSingleStart, rawFmovToSingleEnd);
requireBefore(rawFmovToSingle, "FCVT_sd(SCRATCH_F64_1, s);", "FMOV_ws(d, SCRATCH_F64_1);", "FMOV_ws configured composition");
for (const contract of [
  "0x1e270000u | (b << 5) | a", "0x1e260000u | (b << 5) | a",
  "for (unsigned destination = 0; destination < 32; ++destination)",
  "for (unsigned source = 0; source < 32; ++source)",
  "FMOV_sw low word and upper-lane zero", "FMOV_ws W result or WZR discard",
  "FMOV_sw preserves W source", "FMOV_ws preserves S source lane",
  "FMOV preserves NZCV", "FMOV preserves FPCR", "FMOV preserves FPSR",
  "FMOV preserves caller D8-D15", "FMOV restores caller FPCR", "FMOV restores caller FPSR",
  "for (unsigned reg = 19; reg <= 30; ++reg)",
  "PROT_READ | PROT_WRITE", "PROT_READ | PROT_EXEC", "__builtin___clear_cache",
  "exact_words == 2048 && native_routes == 2048 && same_number_routes == 64",
]) requireText(fmovSwWsEmitterProbeSource, contract, "generic FMOV W/S native conformance");
for (const contract of ["-Wall -Wextra -Werror", "emitter-fmov-sw-ws-conformance.cpp"])
  requireText(fmovSwWsEmitterHarnessSource, contract, "generic FMOV W/S conformance build");
requireText(harnessSource, 'timeout -k 5s 180s "$SCRIPT_DIR/emitter-fmov-sw-ws-conformance.sh"', "generic FMOV W/S bounded acceptance gate");
console.log("METRIC structural_fmov_sw_ws_emitter_exact_words=2048");
console.log("METRIC structural_fmov_sw_ws_emitter_native_routes=2048");
console.log("METRIC structural_fmov_sw_ws_emitter_callers=2");

/* FMOV_dx/FMOV_xd are reciprocal 64-bit bit-transfer encoders. Close only
   their format/field/state contract; raw and MIDFUNC compositions retain
   separate pair-splitting, compare, extended-memory, and status ownership. */
const fmovDxCallers = (codegenSource.match(/\bFMOV_dx\(/g) || []).length;
const fmovXdCallers = (codegenSource.match(/\bFMOV_xd\(/g) || []).length;
if (fmovDxCallers !== 6 || fmovXdCallers !== 4)
  fail(`FMOV X/D emitter callers dx=${fmovDxCallers} xd=${fmovXdCallers}, expected 6/4`);
for (const contract of ["#define FMOV_dx(Dd,Xn)", "#define FMOV_xd(Xd,Dn)"])
  requireText(codegenHeaderSource, contract, "generic FMOV X/D emitter declaration");
for (const contract of [
  "FMOV_dx(d, s1);", "FMOV_xd(REG_WORK3, s);", "FMOV_xd(d1, s);",
  "FMOV_dx(result, REG_WORK1);", "FMOV_xd(REG_WORK1, d);",
  "FMOV_xd(REG_WORK1, s);", "FMOV_dx(d, REG_WORK1);",
]) requireText(codegenSource, contract, "generic FMOV X/D configured source sites");
for (const contract of [
  "0x9e670000u | (b << 5) | a", "0x9e660000u | (b << 5) | a",
  "for (unsigned destination = 0; destination < 32; ++destination)",
  "for (unsigned source = 0; source < 32; ++source)",
  "FMOV_dx exact 64-bit transfer", "FMOV_xd X result or XZR discard",
  "FMOV_dx preserves X source", "FMOV_xd preserves D source lane",
  "FMOV preserves NZCV", "FMOV preserves FPCR", "FMOV preserves FPSR",
  "FMOV preserves caller D8-D15", "FMOV restores caller FPCR", "FMOV restores caller FPSR",
  "for (unsigned reg = 19; reg <= 30; ++reg)",
  "PROT_READ | PROT_WRITE", "PROT_READ | PROT_EXEC", "__builtin___clear_cache",
  "exact_words == 2048 && native_routes == 2048 && same_number_routes == 64",
]) requireText(fmovDxXdEmitterProbeSource, contract, "generic FMOV X/D native conformance");
for (const contract of ["-Wall -Wextra -Werror", "emitter-fmov-dx-xd-conformance.cpp"])
  requireText(fmovDxXdEmitterHarnessSource, contract, "generic FMOV X/D conformance build");
requireText(harnessSource, 'timeout -k 5s 180s "$SCRIPT_DIR/emitter-fmov-dx-xd-conformance.sh"', "generic FMOV X/D bounded acceptance gate");
console.log("METRIC structural_fmov_dx_xd_emitter_exact_words=2048");
console.log("METRIC structural_fmov_dx_xd_emitter_native_routes=2048");
console.log("METRIC structural_fmov_dx_xd_emitter_callers=10");

/* SCVTF_dw converts signed int32 to binary64 exactly. Close only its generic
   encoding/field/value/state contract; compound source-width, pair-splitting,
   memory, and Motorola-status ownership remains with raw/MIDFUNC callers. */
const scvtfDwCallers = (codegenSource.match(/\bSCVTF_dw\(/g) || []).length;
if (scvtfDwCallers !== 6)
  fail(`SCVTF_dw emitter callers=${scvtfDwCallers}, expected 6`);
requireText(codegenHeaderSource, "#define SCVTF_dw(Dd,Wn)", "generic SCVTF emitter declaration");
for (const contract of [
  "SCVTF_dw(d, s);", "SCVTF_dw(d, REG_WORK1);",
  "SCVTF_dw(SCRATCH_F64_2, REG_WORK1);", "SCVTF_dw(r, REG_WORK1);",
]) requireText(codegenSource, contract, "generic SCVTF configured source sites");
for (const contract of [
  "0x1e620000u | (source << 5) | destination",
  "for (unsigned destination = 0; destination < 32; ++destination)",
  "for (unsigned source = 0; source < 32; ++source)",
  "for (unsigned mode = 0; mode < 4; ++mode)",
  "static_cast<std::int32_t>(bits)", "double_bits(static_cast<double>(input))",
  "SCVTF exact signed int32 conversion", "SCVTF preserves X source and upper half",
  "SCVTF preserves NZCV", "SCVTF preserves FPCR", "SCVTF preserves FPSR without exceptions",
  "SCVTF preserves caller D8-D15", "SCVTF restores caller FPCR", "SCVTF restores caller FPSR",
  "for (unsigned reg = 19; reg <= 30; ++reg)",
  "PROT_READ | PROT_WRITE", "PROT_READ | PROT_EXEC", "__builtin___clear_cache",
  "exact_words == 1024 && native_routes == 4096 && same_number_routes == 128",
]) requireText(scvtfEmitterProbeSource, contract, "generic SCVTF native conformance");
for (const contract of ["-Wall -Wextra -Werror", "emitter-scvtf-conformance.cpp"])
  requireText(scvtfEmitterHarnessSource, contract, "generic SCVTF conformance build");
requireText(harnessSource, 'timeout -k 5s 300s "$SCRIPT_DIR/emitter-scvtf-conformance.sh"', "generic SCVTF bounded acceptance gate");
console.log("METRIC structural_scvtf_emitter_exact_words=1024");
console.log("METRIC structural_scvtf_emitter_native_routes=4096");
console.log("METRIC structural_scvtf_emitter_callers=6");

/* FRINTA/FRINTI/FRINTZ are one scalar-binary64 rounding cluster with distinct
   fixed-away, FPCR-current, and fixed-zero direction contracts. */
const frintACallers = (codegenSource.match(/\bFRINTA_dd\(/g) || []).length;
const frintICallers = (codegenSource.match(/\bFRINTI_dd\(/g) || []).length;
const frintZCallers = (codegenSource.match(/\bFRINTZ_dd\(/g) || []).length;
if (frintACallers !== 1 || frintICallers !== 2 || frintZCallers !== 2)
  fail(`FRINT emitter callers A/I/Z=${frintACallers}/${frintICallers}/${frintZCallers}, expected 1/2/2`);
for (const contract of ["#define FRINTA_dd(Dd,Dn)", "#define FRINTI_dd(Dd,Dn)", "#define FRINTZ_dd(Dd,Dn)"])
  requireText(codegenHeaderSource, contract, "generic FRINT emitter declaration");
for (const contract of [
  "FRINTI_dd(SCRATCH_F64_1, s);", "FRINTI_dd(d, s);", "FRINTZ_dd(d, s);",
  "FRINTZ_dd(SCRATCH_F64_1, SCRATCH_F64_1);", "FRINTA_dd(SCRATCH_F64_2, SCRATCH_F64_2);",
]) requireText(codegenSource, contract, "generic FRINT configured source sites");
for (const contract of [
  "0x1e664000u", "0x1e67c000u", "0x1e65c000u",
  "for (unsigned kind = 0; kind < 3; ++kind)",
  "for (unsigned destination = 0; destination < 32; ++destination)",
  "for (unsigned source = 0; source < 32; ++source)",
  "for (unsigned mode = 0; mode < 4; ++mode)",
  "positive_half", "negative_half", "positive_two_half", "negative_two_half",
  "positive_subnormal", "negative_subnormal", "negative_zero", "large_integral",
  "quiet_nan", "signalling_nan", "FRINT source/alias semantics",
  "FRINT preserves NZCV", "FRINT preserves FPCR", "FRINT FPSR IOC without IXC",
  "FRINT preserves caller D8-D15", "FRINT restores caller FPCR", "FRINT restores caller FPSR",
  "for (unsigned reg = 19; reg <= 30; ++reg)",
  "PROT_READ | PROT_WRITE", "PROT_READ | PROT_EXEC", "__builtin___clear_cache",
  "exact_words==3072 && native_routes==12288 && alias_routes==384",
]) requireText(frintEmitterProbeSource, contract, "generic FRINT native conformance");
for (const contract of ["-Wall -Wextra -Werror", "emitter-frint-conformance.cpp"])
  requireText(frintEmitterHarnessSource, contract, "generic FRINT conformance build");
requireText(harnessSource, 'timeout -k 5s 600s "$SCRIPT_DIR/emitter-frint-conformance.sh"', "generic FRINT bounded acceptance gate");
console.log("METRIC structural_frint_emitter_exact_words=3072");
console.log("METRIC structural_frint_emitter_native_routes=12288");
console.log("METRIC structural_frint_emitter_callers=5");

/* FMOV_di is the complete scalar-binary64 architectural imm8 expansion API.
   Close only encoding/value/state; constant wrappers retain separate roles. */
const fmovDiCallers = (codegenSource.match(/\bFMOV_di\(/g) || []).length;
if (fmovDiCallers !== 5) fail(`FMOV_di emitter callers=${fmovDiCallers}, expected 5`);
requireText(codegenHeaderSource, "#define FMOV_di(Dd,i)", "generic FMOV immediate declaration");
for (const contract of [
  "FMOV_di(r, 0b01110000);", "FMOV_di(r, 0b00100100);",
  "FMOV_di(result, 0b01110000);", "FMOV_di(0, 0b00000000);", "FMOV_di(0, 0b00100100);",
]) requireText(codegenSource, contract, "generic FMOV immediate configured sites");
for (const contract of [
  "0x1e601000u|(immediate<<13)|destination",
  "for(unsigned destination=0;destination<32;++destination)",
  "for(unsigned immediate=0;immediate<256;++immediate)",
  "for(unsigned mode=0;mode<4;++mode)",
  "static std::uint64_t expand_imm8", "(immediate >> 7) & 1", "(immediate >> 6) & 1",
  "FMOV_di VFPExpandImm", "FMOV_di preserves NZCV", "FMOV_di preserves FPCR", "FMOV_di preserves FPSR",
  "FMOV_di preserves caller D8-D15", "FMOV_di restores caller FPCR", "FMOV_di restores caller FPSR",
  "PROT_READ|PROT_WRITE", "PROT_READ|PROT_EXEC", "__builtin___clear_cache",
  "exact_words==8192&&native_routes==32768",
]) requireText(fmovDiEmitterProbeSource, contract, "generic FMOV immediate native conformance");
for (const contract of ["-Wall -Wextra -Werror", "emitter-fmov-di-conformance.cpp"])
  requireText(fmovDiEmitterHarnessSource, contract, "generic FMOV immediate conformance build");
requireText(harnessSource, 'timeout -k 5s 900s "$SCRIPT_DIR/emitter-fmov-di-conformance.sh"', "generic FMOV immediate bounded acceptance gate");
console.log("METRIC structural_fmov_di_emitter_exact_words=8192");
console.log("METRIC structural_fmov_di_emitter_native_routes=32768");
console.log("METRIC structural_fmov_di_emitter_callers=5");

/* FSQRT_dd is the sole configured scalar-binary64 square-root encoder. Close
   only its generic encoding/value/exception/state contract. */
const fsqrtCallers = (codegenSource.match(/\bFSQRT_dd\(/g) || []).length;
if (fsqrtCallers !== 1) fail(`FSQRT emitter callers=${fsqrtCallers}, expected 1`);
requireText(codegenHeaderSource, "#define FSQRT_dd(Dd,Dn)", "generic FSQRT declaration");
const rawFsqrt = functionBody(codegenSource,
  "LOWFUNC(NONE,NONE,2,raw_fsqrt_rr,(FW d, FR s))",
  "LENDFUNC(NONE,NONE,2,raw_fsqrt_rr,(FW d, FR s))", "generic FSQRT configured composition");
requireText(rawFsqrt, "FSQRT_dd(d, s);", "generic FSQRT configured composition");
for (const contract of [
  "0x1e61c000u|(s<<5)|d", "for(unsigned d=0;d<32;d++)", "for(unsigned s=0;s<32;s++)",
  "for(unsigned mode=0;mode<4;mode++)", "sqrt_two", "minimum_subnormal", "negative_zero",
  "negative_one", "negative_infinity", "quiet_nan", "signalling_nan",
  "FSQRT source/alias semantics", "FSQRT preserves NZCV", "FSQRT preserves FPCR", "FSQRT FPSR",
  "FSQRT preserves caller D8-D15", "FSQRT restores caller FPCR", "FSQRT restores caller FPSR",
  "PROT_READ|PROT_WRITE", "PROT_READ|PROT_EXEC", "__builtin___clear_cache",
  "exact==1024&&routes==4096&&aliases==128",
]) requireText(fsqrtEmitterProbeSource, contract, "generic FSQRT native conformance");
for (const contract of ["-Wall -Wextra -Werror", "emitter-fsqrt-conformance.cpp"])
  requireText(fsqrtEmitterHarnessSource, contract, "generic FSQRT conformance build");
requireText(harnessSource, 'timeout -k 5s 300s "$SCRIPT_DIR/emitter-fsqrt-conformance.sh"', "generic FSQRT bounded acceptance gate");
console.log("METRIC structural_fsqrt_emitter_exact_words=1024");
console.log("METRIC structural_fsqrt_emitter_native_routes=4096");
console.log("METRIC structural_fsqrt_emitter_callers=1");

/* FSUB_ddd is the sole configured scalar-binary64 subtract encoder. Close its
   generic encoding/value/alias/exception/state contract only. */
const fsubEmitterCallers = (codegenSource.match(/\bFSUB_ddd\(/g) || []).length;
if (fsubEmitterCallers !== 1) fail(`FSUB emitter callers=${fsubEmitterCallers}, expected 1`);
requireText(codegenHeaderSource, "#define FSUB_ddd(Dd,Dn,Dm)", "generic FSUB declaration");
const rawFsub = functionBody(codegenSource,
  "LOWFUNC(NONE,NONE,2,raw_fsub_rr,(FRW d, FR s))",
  "LENDFUNC(NONE,NONE,2,raw_fsub_rr,(FRW d, FR s))", "generic FSUB configured composition");
requireText(rawFsub, "FSUB_ddd(d, d, s);", "generic FSUB configured composition");
for (const contract of [
  "0x1e603800u|(m<<16)|(n<<5)|d", "for(unsigned d=0;d<32;d++)",
  "for(unsigned n=0;n<32;n++)", "for(unsigned m=0;m<32;m++)",
  "positive_midpoint", "negative_midpoint", "positive_overflow", "negative_overflow",
  "exact_cancel", "negative_zero_minus_positive_zero", "infinity_minus_infinity",
  "left_quiet_nan", "right_quiet_nan", "left_signalling_nan", "right_signalling_nan", "finite_equal_sources",
  "FSUB N source/alias semantics", "FSUB M source/alias semantics",
  "FSUB preserves NZCV", "FSUB preserves FPCR", "FSUB FPSR",
  "FSUB preserves caller D8-D15", "FSUB restores caller FPCR", "FSUB restores caller FPSR",
  "PROT_READ|PROT_WRITE", "PROT_READ|PROT_EXEC", "__builtin___clear_cache",
  "exact==32768&&native==576&&aliases==256",
]) requireText(fsubEmitterProbeSource, contract, "generic FSUB native conformance");
for (const contract of ["-Wall -Wextra -Werror", "emitter-fsub-conformance.cpp"])
  requireText(fsubEmitterHarnessSource, contract, "generic FSUB conformance build");
requireText(harnessSource, 'timeout -k 5s 300s "$SCRIPT_DIR/emitter-fsub-conformance.sh"', "generic FSUB bounded acceptance gate");
console.log("METRIC structural_fsub_emitter_exact_words=32768");
console.log("METRIC structural_fsub_emitter_native_routes=576");
console.log("METRIC structural_fsub_emitter_callers=1");

/* FMUL_ddd is the sole configured scalar-binary64 multiply encoder. */
const fmulEmitterCallers = (codegenSource.match(/\bFMUL_ddd\(/g) || []).length;
if (fmulEmitterCallers !== 1) fail(`FMUL emitter callers=${fmulEmitterCallers}, expected 1`);
requireText(codegenHeaderSource, "#define FMUL_ddd(Dd,Dn,Dm)", "generic FMUL declaration");
const rawFmul = functionBody(codegenSource,
  "LOWFUNC(NONE,NONE,2,raw_fmul_rr,(FRW d, FR s))",
  "LENDFUNC(NONE,NONE,2,raw_fmul_rr,(FRW d, FR s))", "generic FMUL configured composition");
requireText(rawFmul, "FMUL_ddd(d, d, s);", "generic FMUL configured composition");
for (const contract of [
  "0x1e600800u|(m<<16)|(n<<5)|d", "positive_midpoint_product", "negative_midpoint_product",
  "positive_overflow", "negative_overflow", "positive_half_min_subnormal", "negative_half_min_subnormal",
  "zero_times_infinity", "infinity_times_zero", "left_quiet_nan", "right_quiet_nan",
  "left_signalling_nan", "right_signalling_nan", "finite_equal_source_square",
  "FMUL N source/alias semantics", "FMUL M source/alias semantics",
  "FMUL preserves NZCV", "FMUL preserves FPCR", "FMUL FPSR",
  "FMUL preserves caller D8-D15", "FMUL restores caller FPCR", "FMUL restores caller FPSR",
  "PROT_READ|PROT_WRITE", "PROT_READ|PROT_EXEC", "__builtin___clear_cache",
  "exact==32768&&native==604&&aliases==272",
]) requireText(fmulEmitterProbeSource, contract, "generic FMUL native conformance");
for (const contract of ["-Wall -Wextra -Werror", "emitter-fmul-conformance.cpp"])
  requireText(fmulEmitterHarnessSource, contract, "generic FMUL conformance build");
requireText(harnessSource, 'timeout -k 5s 300s "$SCRIPT_DIR/emitter-fmul-conformance.sh"', "generic FMUL bounded acceptance gate");
console.log("METRIC structural_fmul_emitter_exact_words=32768");
console.log("METRIC structural_fmul_emitter_native_routes=604");
console.log("METRIC structural_fmul_emitter_callers=1");

/* FMUL_sss is the sole configured scalar-binary32 multiply encoder. */
const fmulSingleCallers = (codegenSource.match(/\bFMUL_sss\(/g) || []).length;
if (fmulSingleCallers !== 1) fail(`FMUL_sss emitter callers=${fmulSingleCallers}, expected 1`);
requireText(codegenHeaderSource, "#define FMUL_sss(Sd,Sn,Sm)", "generic FMUL single declaration");
const rawFsglmul = functionBody(codegenSource,
  "LOWFUNC(NONE,NONE,2,raw_fsglmul_rr,(FRW d, FR s))",
  "LENDFUNC(NONE,NONE,2,raw_fsglmul_rr,(FRW d, FR s))", "generic FMUL single composition");
for (const contract of [
  "FCVT_sd(SCRATCH_F64_1, d);", "FCVT_sd(SCRATCH_F64_2, s);",
  "FMUL_sss(SCRATCH_F64_1, SCRATCH_F64_1, SCRATCH_F64_2);", "FCVT_ds(d, SCRATCH_F64_1);",
]) requireText(rawFsglmul, contract, "generic FMUL single composition");
for (const contract of [
  "0x1e200800u|(m<<16)|(n<<5)|d", "0x3f800200ull", "0x3f802000ull",
  "positive_midpoint_product", "negative_midpoint_product", "positive_half_min_subnormal",
  "negative_half_min_subnormal", "zero_times_infinity", "infinity_times_zero",
  "left_quiet_nan", "right_quiet_nan", "left_signalling_nan", "right_signalling_nan",
  "FMOV_sw(r.n,1);", "FMOV_xd(12,r.d);", "finite_equal_source_square",
  "distinct n==m second-load square", "distinct n==m second-load image",
  "FMUL N source/alias semantics", "FMUL M source/alias semantics",
  "exact==32768&&native==608&&aliases==276",
]) requireText(fmulSingleEmitterProbeSource, contract, "generic FMUL single native conformance");
for (const contract of ["-Wall -Wextra -Werror", "emitter-fmul-s-conformance.cpp"])
  requireText(fmulSingleEmitterHarnessSource, contract, "generic FMUL single conformance build");
requireText(harnessSource, 'timeout -k 5s 300s "$SCRIPT_DIR/emitter-fmul-s-conformance.sh"', "generic FMUL single bounded gate");
console.log("METRIC structural_fmul_single_emitter_exact_words=32768");
console.log("METRIC structural_fmul_single_emitter_native_routes=608");
console.log("METRIC structural_fmul_single_emitter_callers=1");

/* FDIV_ddd/FDIV_sss are one scalar division encoding cluster. */
const fdivDoubleCallers = (codegenSource.match(/\bFDIV_ddd\(/g) || []).length;
const fdivSingleCallers = (codegenSource.match(/\bFDIV_sss\(/g) || []).length;
if (fdivDoubleCallers !== 3 || fdivSingleCallers !== 1)
  fail(`FDIV emitter callers d/s=${fdivDoubleCallers}/${fdivSingleCallers}, expected 3/1`);
for (const contract of ["#define FDIV_ddd(Dd,Dn,Dm)", "#define FDIV_sss(Sd,Sn,Sm)"])
  requireText(codegenHeaderSource, contract, "generic FDIV declarations");
for (const contract of [
  "FDIV_ddd(d, d, s);", "FDIV_ddd(SCRATCH_F64_1, d, s);",
  "FDIV_ddd(SCRATCH_F64_2, d, s);", "FDIV_sss(SCRATCH_F64_1, SCRATCH_F64_1, SCRATCH_F64_2);",
]) requireText(codegenSource, contract, "generic FDIV configured sites");
for (const [probe, base, context] of [
  [fdivDoubleEmitterProbeSource, "0x1e601800u|(m<<16)|(n<<5)|d", "generic FDIV binary64 conformance"],
  [fdivSingleEmitterProbeSource, "0x1e201800u|(m<<16)|(n<<5)|d", "generic FDIV binary32 conformance"],
] as const) for (const contract of [
  base, "positive_one_third", "negative_one_third", "positive_divide_by_zero",
  "negative_divide_by_zero", "zero_divide_zero", "finite_divide_infinity",
  "infinity_divide_infinity", "left_quiet_nan", "right_quiet_nan",
  "left_signalling_nan", "right_signalling_nan", "distinct n==m second-load divide",
  "distinct n==m second-load image", "FDIV N source/alias semantics", "FDIV M source/alias semantics",
  "exact==32768&&native==636&&aliases==292",
]) requireText(probe, contract, context);
for (const [harness, file, context] of [
  [fdivDoubleEmitterHarnessSource, "emitter-fdiv-d-conformance.cpp", "generic FDIV binary64 build"],
  [fdivSingleEmitterHarnessSource, "emitter-fdiv-s-conformance.cpp", "generic FDIV binary32 build"],
] as const) for (const contract of ["-Wall -Wextra -Werror", file]) requireText(harness, contract, context);
for (const gate of [
  'timeout -k 5s 300s "$SCRIPT_DIR/emitter-fdiv-d-conformance.sh"',
  'timeout -k 5s 300s "$SCRIPT_DIR/emitter-fdiv-s-conformance.sh"',
]) requireText(harnessSource, gate, "generic FDIV bounded gates");
console.log("METRIC structural_fdiv_emitter_exact_words=65536");
console.log("METRIC structural_fdiv_emitter_native_routes=1272");
console.log("METRIC structural_fdiv_emitter_callers=4");

/* FMSUB_dddd is the four-field fused Da-(Dn*Dm) encoder used by both
   remainder quotient paths. */
const fmsubCallers = (codegenSource.match(/\bFMSUB_dddd\(/g) || []).length;
if (fmsubCallers !== 2) fail(`FMSUB emitter callers=${fmsubCallers}, expected 2`);
requireText(codegenHeaderSource, "#define FMSUB_dddd(Dd,Dn,Dm,Da)", "generic FMSUB declaration");
for (const contract of [
  "FMSUB_dddd(d, SCRATCH_F64_1, s, d);", "FMSUB_dddd(d, SCRATCH_F64_2, s, d);",
]) requireText(codegenSource, contract, "generic FMSUB configured sites");
for (const contract of [
  "0x1f408000u|(m<<16)|(a<<10)|(n<<5)|d", "for(unsigned a=0;a<32;a++)",
  "fused_cancellation", "0x3970000000000000ull", "positive_midpoint", "negative_midpoint",
  "positive_overflow", "negative_overflow", "positive_half_min_subnormal", "negative_half_min_subnormal",
  "zero_times_infinity", "infinity_cancellation", "n_quiet_nan", "m_quiet_nan", "a_quiet_nan",
  "n_signalling_nan", "m_signalling_nan", "a_signalling_nan",
  "FMSUB N source/alias semantics", "FMSUB M source/alias semantics", "FMSUB A source/alias semantics",
  "FMSUB source-alias load order", "FMSUB preserves NZCV", "FMSUB preserves FPCR", "FMSUB FPSR",
  "exact==1048576&&native==400&&aliases==208",
]) requireText(fmsubEmitterProbeSource, contract, "generic FMSUB native conformance");
for (const contract of ["-Wall -Wextra -Werror", "emitter-fmsub-conformance.cpp"])
  requireText(fmsubEmitterHarnessSource, contract, "generic FMSUB conformance build");
requireText(harnessSource, 'timeout -k 5s 600s "$SCRIPT_DIR/emitter-fmsub-conformance.sh"', "generic FMSUB bounded gate");
console.log("METRIC structural_fmsub_emitter_exact_words=1048576");
console.log("METRIC structural_fmsub_emitter_native_routes=400");
console.log("METRIC structural_fmsub_emitter_callers=2");

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

/* MULL is one generator/MIDFUNC/allocator lifecycle. Dl must be pinned while
 * the source EA is fetched; selected-64 handlers own explicit Dl/Dh/source
 * operands; selected-32 flags describe the full mathematical product. */
const mullGenerator = functionBody(
  gencompSource,
  "     case i_MULL:",
  "     case i_BFTST:",
  "MULL generator family",
);
for (const contract of [
  "int dl = (extra >> 12) & 7;",
  "int dh = extra & 7;",
  "int mull_dl_lock = jit_value_lock(dl);",
  "jit_value_unlock(mull_dl_lock);",
  "jnf_MULS64(dl, dh, src);",
  "jff_MULS64(dl, dh, src);",
  "jnf_MULU64(dl, dh, src);",
  "jff_MULU64(dl, dh, src);",
]) {
  requireText(mullGenerator, contract, "MULL generator ownership");
  requireText(generatedSource, contract, "generated MULL ownership");
}
requireBefore(mullGenerator, "jit_value_lock(dl)", "GENA_GETV_FETCH", "MULL Dl/source ordering");
requireBefore(mullGenerator, "GENA_GETV_FETCH", "jit_value_unlock(mull_dl_lock)", "MULL Dl/source ordering");
for (const forbidden of [
  "jnf_MULS64(dl, src)", "jff_MULS64(dl, src)",
  "jnf_MULU64(dl, src)", "jff_MULU64(dl, src)",
  "src now has high 32 bits", "mov_l_rr(dh, src)",
]) {
  if (mullGenerator.includes(forbidden) || generatedSource.includes(forbidden)) {
    fail(`MULL generator ownership: obsolete source-write contract remains: ${forbidden}`);
  }
}

const mullSigned32 = functionBody(
  midfunc2Source,
  "MIDFUNC(2,jff_MULS32,",
  "MIDFUNC(3,jnf_MULS64,",
  "signed selected-32 MULL flags",
);
const mullUnsigned32 = functionBody(
  midfunc2Source,
  "MIDFUNC(2,jff_MULU32,",
  "MIDFUNC(3,jnf_MULU64,",
  "unsigned selected-32 MULL flags",
);
for (const [body, signed] of [[mullSigned32, true], [mullUnsigned32, false]] as const) {
  const label = signed ? "signed" : "unsigned";
  requireText(body, "TST_xx(d, d)", `${label} selected-32 full-product N/Z`);
  requireText(body, "MRS_NZCV_x(REG_WORK4)", `${label} selected-32 flag preservation`);
  requireText(body, "CSET_xc(REG_WORK2, NATIVE_CC_NE)", `${label} selected-32 branchless overflow`);
  requireText(body, "ORR_xxxLSLi(REG_WORK4, REG_WORK4, REG_WORK2, 28)", `${label} selected-32 V publication`);
  if (/\b(?:CBZ|CBNZ|B)_\w+i\s*\(/.test(body)) {
    fail(`${label} selected-32 MULL reintroduced fixed-displacement flag branching`);
  }
}
requireText(mullSigned32, "SXTW_xw(REG_WORK1, d)", "signed selected-32 fit comparison");
requireText(mullSigned32, "CMP_xx(d, REG_WORK1)", "signed selected-32 fit comparison");
requireText(mullUnsigned32, "LSR_xxi(REG_WORK1, d, 32)", "unsigned selected-32 high-half overflow");

for (const signature of [
  "MIDFUNC(3,jnf_MULS64,(W4 dl, W4 dh, RR4 s))",
  "MIDFUNC(3,jff_MULS64,(W4 dl, W4 dh, RR4 s))",
  "MIDFUNC(3,jnf_MULU64,(W4 dl, W4 dh, RR4 s))",
  "MIDFUNC(3,jff_MULU64,(W4 dl, W4 dh, RR4 s))",
]) {
  requireText(midfunc2Source, signature, "selected-64 MULL three-operand API");
}
for (const contract of [
  "STAGE_MULL32_OPERAND(dl, REG_WORK1)",
  "STAGE_MULL32_OPERAND(s, REG_WORK2)",
  "PUBLISH_MULL64_RESULT(dl, dh)",
]) {
  const occurrences = midfunc2Source.split(contract).length - 1;
  const expected = contract.startsWith("PUBLISH_") ? 5 : 4; // macro definition plus four calls
  if (occurrences !== expected) fail(`selected-64 MULL contract ${contract}: expected ${expected}, got ${occurrences}`);
}
const mullPublishStart = requireText(midfunc2Source, "#define PUBLISH_MULL64_RESULT(dl, dh)", "selected-64 MULL publication");
const mullPublishEnd = requireText(midfunc2Source.slice(mullPublishStart), "MIDFUNC(3,jnf_MULS64,", "selected-64 MULL publication") + mullPublishStart;
const mullPublish = midfunc2Source.slice(mullPublishStart, mullPublishEnd);
requireBefore(mullPublish, "writereg(dh)", "writereg(dl)", "selected-64 MULL high-before-low publication");
for (const contract of [
  "DECLARE_MIDFUNC(jnf_MULU64(W4 dl, W4 dh, RR4 s));",
  "DECLARE_MIDFUNC(jnf_MULS64(W4 dl, W4 dh, RR4 s));",
  "DECLARE_MIDFUNC(jff_MULU64(W4 dl, W4 dh, RR4 s));",
  "DECLARE_MIDFUNC(jff_MULS64(W4 dl, W4 dh, RR4 s));",
]) {
  for (const [header, label] of [
    [midfuncArmHeaderSource, "primary"],
    [midfuncArm2HeaderSource, "JIT2"],
  ] as const) {
    const normalizedHeader = header.replaceAll("DECLARE_MIDFUNC (", "DECLARE_MIDFUNC(");
    requireText(normalizedHeader, contract, `selected-64 MULL ${label} AArch64 declarations`);
  }
}
for (const contract of [
  "jff_MULS64(d, s, s)", "jnf_MULS64(d, s, s)",
  "jff_MULU64(d, s, s)", "jnf_MULU64(d, s, s)",
]) {
  requireText(compatSource, contract, "legacy MULL two-operand bridge");
}

const mullNativeReplaySection = harnessSource.slice(
  requireText(harnessSource, "declare -A NATIVE_REPLAY_TESTS=(", "MULL native replay inventory"),
  requireText(harnessSource, "declare -A NATIVE_REPLAY_PC=(", "MULL native replay inventory"),
);
const mullExactVectors = [
  "mulls32_negative_fit_v_native",
  "mullu64_source_preserve_v_native",
  "mullu64_source_low_alias_native",
  "mullu64_same_result_alias_native",
  "mullu32_low_sign_full_flags_native",
  "mullu32_overflow_low_zero_flags_native",
  "mulls32_negative_overflow_low_zero_native",
  "mulls32_positive_overflow_low_sign_native",
  "mulls64_negative_flags_native",
  "mullu64_zero_flags_native",
  "mullu64_source_high_alias_native",
  "mullu64_all_alias_native",
  "mullu32_immediate_nf_native",
  "mullu64_memory_nf_native",
] as const;
for (const name of mullExactVectors) {
  requireText(harnessSource, `TESTS[${name}]=`, `${name} MULL vector`);
  requireText(mullNativeReplaySection, `[${name}]=1`, `${name} exact-native replay inventory`);
  requireText(harnessSource, `INIT_REGS[${name}]=`, `${name} exact entry state`);
  requireText(harnessSource, `SENTINEL_A6[${name}]=`, `${name} register sentinel`);
  if (!activeRiskyNames.has(name)) fail(`${name}: missing from active risky corpus`);
}
requireText(harnessSource, '[mullu64_memory_nf_native]="A000 00 A001 00 A002 00 A003 02"', "MULL deterministic memory replay");
for (const contract of [
  "mullu64_mem_source_locked_dl",
  "[mullu64_mem_source_locked_dl]=0x00001012",
  "[mullu64_mem_source_locked_dl]=20",
  "REGPRESSURE_PIN_SKIP",
]) {
  requireText(regallocPressureSource, contract, "MULL allocator-pressure witness");
}

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
if (gencompSource.split(arm64OverflowCases).length - 1 !== 2) {
  fail("ARM64 overflow condition codegen: Bcc/DBcc must handle VC/VS natively");
}
for (const contract of [
  "case 8: native_cc = NATIVE_CC_VC; break;",
  "case 9: native_cc = NATIVE_CC_VS; break;",
]) {
  requireText(shiftSource, contract, "direct AArch64 Scc overflow condition mapping");
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
console.log("METRIC structural_harness_fail_closed_status=1");
console.log("METRIC structural_bcd_flag_lifecycle=1");
console.log("METRIC structural_add_shared_midfunc_routes=6");
console.log(`METRIC structural_add_exact_native_vectors=${addExactVectors.length}`);
console.log("METRIC structural_add_readable_ea_classes=9");
console.log("METRIC structural_add_writable_ea_classes=7");
console.log(`METRIC structural_add_memory_vectors=${addMemoryVectors.length}`);
console.log("METRIC structural_add_midfunc_operand_routes=6");
console.log(`METRIC structural_add_redundant_generator_source_locks=${generatedAddSourceLocks}`);
console.log(`METRIC structural_add_generated_ea_locks=${generatedAddEaLocks}`);
console.log("METRIC structural_add_noflags_vectors=4");
console.log("METRIC structural_add_allocator_pressure=2");
console.log("METRIC structural_adda_midfunc_routes=4");
console.log(`METRIC structural_adda_exact_native_vectors=${addaExactVectors.length}`);
console.log(`METRIC structural_adda_equivalence_vectors=${addaVectors.length - addaExactVectors.length}`);
console.log("METRIC structural_adda_readable_ea_classes=9");
console.log(`METRIC structural_adda_memory_vectors=${addaMemoryVectors.length}`);
console.log("METRIC structural_adda_special_memory_routes=2");
console.log("METRIC structural_adda_noflags_vectors=2");
console.log(`METRIC structural_adda_generated_functions=${generatedAddaFunctions}`);
console.log(`METRIC structural_adda_generated_flag_live=${generatedAddaFlagLive}`);
console.log(`METRIC structural_adda_generated_noflags=${generatedAddaNoFlags}`);
console.log(`METRIC structural_adda_generated_source_locks=${generatedAddaSourceLocks}`);
console.log(`METRIC structural_adda_generated_writeback_locks=${generatedAddaWritebackLocks}`);
console.log("METRIC structural_adda_allocator_pressure=2");
console.log(`METRIC structural_bcc_exact_native_vectors=${bccVectors.length}`);
console.log(`METRIC structural_bcc_generated_functions=${generatedBccBodies.length}`);
console.log(`METRIC structural_bcc_generated_flag_live=${generatedBccFlagLive}`);
console.log(`METRIC structural_bcc_generated_noflags=${generatedBccNoFlags}`);
console.log("METRIC structural_bcc_reachable_conditions=15");
console.log("METRIC structural_bcc_conditional_outcomes=28");
console.log("METRIC structural_bcc_displacement_widths=3");
console.log("METRIC structural_bcc_signed_backward_widths=3");
console.log("METRIC structural_bcc_dynamic_allocator_values=0");
console.log("METRIC structural_bcc_condition_translation_boundaries=2");
console.log(`METRIC structural_clr_exact_native_vectors=${clrVectors.length}`);
console.log(`METRIC structural_clr_generated_functions=${generatedClrBodies.length}`);
console.log(`METRIC structural_clr_generated_flag_live=${generatedClrFlagLive}`);
console.log(`METRIC structural_clr_generated_noflags=${generatedClrNoFlags}`);
console.log("METRIC structural_clr_writable_ea_classes=8");
console.log(`METRIC structural_clr_memory_vectors=${clrMemoryVectors.length}`);
console.log("METRIC structural_clr_special_memory_routes=3");
console.log("METRIC structural_clr_noflags_vectors=2");
console.log("METRIC structural_clr_allocator_pressure=1");
console.log("METRIC structural_clr_unreachable_namesake_midfuncs=6");
console.log(`METRIC structural_exg_exact_native_vectors=${exgVectors.length}`);
console.log(`METRIC structural_exg_generated_functions=${generatedExgBodies.length}`);
console.log(`METRIC structural_exg_generated_flag_live=${generatedExgFlagLive}`);
console.log(`METRIC structural_exg_generated_noflags=${generatedExgNoFlags}`);
console.log("METRIC structural_exg_encoding_classes=3");
console.log("METRIC structural_exg_self_alias_classes=2");
console.log("METRIC structural_exg_roundtrip_classes=3");
console.log("METRIC structural_exg_noflags_vectors=1");
console.log("METRIC structural_exg_allocator_pressure=1");
console.log(`METRIC structural_ext_exact_native_vectors=${extVectors.length}`);
console.log(`METRIC structural_ext_generated_functions=${generatedExtBodies.length}`);
console.log(`METRIC structural_ext_generated_flag_live=${generatedExtFlagLive}`);
console.log(`METRIC structural_ext_generated_noflags=${generatedExtNoFlags}`);
console.log("METRIC structural_ext_encoding_forms=3");
console.log("METRIC structural_ext_result_classes=3");
console.log("METRIC structural_ext_noflags_vectors=3");
console.log("METRIC structural_ext_allocator_pressure=1");
console.log("METRIC structural_fbcc_exact_native_vectors=160");
console.log("METRIC structural_fbcc_conditions=16");
console.log("METRIC structural_fbcc_fp_classes=5");
console.log("METRIC structural_fbcc_displacement_widths=2");
console.log("METRIC structural_fbcc_integer_ccr_preservation=1");
console.log("METRIC structural_fbcc_fpu_boundary_sync=1");
console.log("METRIC structural_sub_shared_midfunc_routes=6");
console.log("METRIC structural_sub_immediate_routes=6");
console.log(`METRIC structural_sub_exact_native_vectors=${subExactVectors.length}`);
console.log("METRIC structural_sub_readable_ea_classes=9");
console.log("METRIC structural_sub_writable_ea_classes=7");
console.log(`METRIC structural_sub_memory_vectors=${subMemoryVectors.length}`);
console.log("METRIC structural_sub_special_memory_routes=6");
console.log("METRIC structural_sub_noflags_vectors=7");
console.log(`METRIC structural_sub_generated_functions=${generatedSubFunctions}`);
console.log(`METRIC structural_sub_generated_flag_live=${generatedSubFlagLive}`);
console.log(`METRIC structural_sub_generated_noflags=${generatedSubNoFlags}`);
console.log(`METRIC structural_sub_redundant_generator_source_locks=${generatedSubSourceLocks}`);
console.log(`METRIC structural_sub_generated_ea_locks=${generatedSubEaLocks}`);
console.log("METRIC structural_sub_allocator_pressure=2");
console.log("METRIC structural_and_shared_midfunc_routes=6");
console.log("METRIC structural_and_immediate_routes=6");
console.log(`METRIC structural_and_exact_native_vectors=${andExactVectors.length}`);
console.log("METRIC structural_and_readable_ea_classes=9");
console.log("METRIC structural_and_writable_ea_classes=7");
console.log(`METRIC structural_and_memory_vectors=${andMemoryVectors.length}`);
console.log("METRIC structural_and_special_memory_routes=6");
console.log("METRIC structural_and_noflags_vectors=4");
console.log("METRIC structural_and_generated_functions=156");
console.log("METRIC structural_and_generated_ea_locks=84");
console.log("METRIC structural_logical_generated_ea_locks=252");
console.log("METRIC structural_and_allocator_pressure=2");
console.log("METRIC structural_eor_shared_midfunc_routes=6");
console.log("METRIC structural_eor_immediate_routes=6");
console.log(`METRIC structural_eor_exact_native_vectors=${eorExactVectors.length}`);
console.log("METRIC structural_eor_writable_ea_classes=7");
console.log(`METRIC structural_eor_memory_vectors=${eorMemoryVectors.length}`);
console.log("METRIC structural_eor_special_memory_routes=3");
console.log("METRIC structural_eor_noflags_vectors=7");
console.log("METRIC structural_eor_generated_functions=96");
console.log(`METRIC structural_eor_generated_flag_live=${generatedEorFlagLive}`);
console.log(`METRIC structural_eor_generated_noflags=${generatedEorNoFlags}`);
console.log("METRIC structural_eor_generated_ea_locks=84");
console.log("METRIC structural_eor_allocator_pressure=2");
console.log("METRIC structural_or_shared_midfunc_routes=6");
console.log("METRIC structural_or_immediate_routes=6");
console.log(`METRIC structural_or_exact_native_vectors=${orExactVectors.length}`);
console.log("METRIC structural_or_readable_ea_classes=9");
console.log("METRIC structural_or_writable_ea_classes=7");
console.log(`METRIC structural_or_memory_vectors=${orMemoryVectors.length}`);
console.log("METRIC structural_or_special_memory_routes=6");
console.log("METRIC structural_or_noflags_vectors=7");
console.log("METRIC structural_or_generated_functions=156");
console.log(`METRIC structural_or_generated_flag_live=${generatedOrFlagLive}`);
console.log(`METRIC structural_or_generated_noflags=${generatedOrNoFlags}`);
console.log("METRIC structural_or_generated_ea_locks=84");
console.log("METRIC structural_or_allocator_pressure=2");
console.log("METRIC structural_neg_shared_sub_lowering=1");
console.log(`METRIC structural_neg_exact_native_vectors=${negExactVectors.length}`);
console.log("METRIC structural_neg_memory_ea_classes=9");
console.log(`METRIC structural_neg_generated_ea_locks=${generatedNegLocks}`);
console.log("METRIC structural_neg_allocator_pressure=1");
console.log("METRIC structural_neg_emitter_apis=1");
console.log(`METRIC structural_neg_emitter_callsites=${negEmitterCallsites}`);
console.log("METRIC structural_neg_emitter_native_vectors=7");
console.log("METRIC structural_negx_shared_subx_lowering=1");
console.log("METRIC structural_negx_narrow_lane_flags=1");
console.log("METRIC structural_negx_no_flags_lifecycle=1");
console.log(`METRIC structural_negx_exact_native_vectors=${negxExactVectors.length}`);
console.log("METRIC structural_negx_memory_ea_classes=9");
console.log(`METRIC structural_negx_generated_ea_locks=${generatedNegxLocks}`);
console.log("METRIC structural_negx_allocator_pressure_cells=4");
console.log("METRIC structural_tas_mandatory_flag_live=1");
console.log("METRIC structural_tas_original_byte_flags=1");
console.log(`METRIC structural_tas_exact_native_vectors=${tasExactVectors.length}`);
console.log("METRIC structural_tas_memory_ea_classes=9");
console.log("METRIC structural_tas_allocator_pressure=1");
console.log("METRIC structural_bcd_patched_branch_joins=7");
console.log("METRIC structural_bcd_a7_predecrement_geometry=1");
console.log("METRIC structural_bcd_exact_pc_memory_replay=1");
console.log("METRIC structural_division_patched_branch_joins=28");
console.log("METRIC structural_division_overflow_flags=1");
console.log("METRIC structural_mull_full_product_flags=1");
console.log("METRIC structural_mull_three_operand_ownership=1");
console.log("METRIC structural_mull_dl_source_lock=1");
console.log(`METRIC structural_mull_exact_native_vectors=${mullExactVectors.length}`);
console.log("METRIC structural_mull_allocator_pressure=1");
console.log("METRIC structural_movem_private_cursor_ownership=1");
console.log("METRIC structural_movem_base_alias_writeback=1");
console.log("METRIC structural_movem_mask_ea_extension_order=1");
console.log(`METRIC structural_movem_exact_native_vectors=${movemExactVectors.length}`);
console.log("METRIC structural_movem_generated_load_handlers=32");
console.log("METRIC structural_movem_generated_store_handlers=24");
console.log("METRIC structural_movem_allocator_pressure=1");
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
console.log("METRIC structural_move_complete_source_ownership=1");
console.log("METRIC structural_move_exact_native_vectors=31");
console.log("METRIC structural_movea_exact_native_vectors=10");
console.log("METRIC structural_move16_exact_native_vectors=7");
console.log("METRIC structural_move_inverse_allocator_pressure=1");
console.log("METRIC structural_scc_direct_condition_map=16");
console.log("METRIC structural_scc_exact_native_vectors=17");
console.log("METRIC structural_dbcc_dynamic_edge_lifecycle=1");
console.log("METRIC structural_dbcc_exact_native_vectors=18");
console.log("METRIC structural_dbcc_scc_allocator_pressure=2");
console.log("METRIC structural_bitop_midfunc_routes=28");
console.log("METRIC structural_bitop_exact_native_vectors=29");
console.log("METRIC structural_bitop_memory_ea_locks=108");
console.log("METRIC structural_bitop_unsigned_constant_fold=1");
console.log("METRIC structural_bitop_allocator_pressure=1");
console.log("METRIC structural_compare_shared_midfunc_routes=6");
console.log("METRIC structural_compare_exact_native_vectors=31");
console.log("METRIC structural_cmp_cmpm_source_locks=136");
console.log("METRIC structural_cmpa_source_locks=48");
console.log("METRIC structural_compare_allocator_pressure=2");
console.log("METRIC structural_compare_emitter_apis=5");
console.log("METRIC structural_compare_emitter_callsites=86");
console.log("METRIC structural_compare_emitter_native_vectors=20");
console.log("METRIC structural_add_emitter_apis=7");
console.log("METRIC structural_add_emitter_raw_callsites=72");
console.log("METRIC structural_add_emitter_exact_words=12");
console.log("METRIC structural_add_emitter_native_vectors=46");
console.log("METRIC structural_eor_emitter_apis=5");
console.log("METRIC structural_eor_emitter_configured_callsites=53");
console.log("METRIC structural_eor_emitter_raw_compositions=64");
console.log("METRIC structural_eor_emitter_exact_words=13");
console.log("METRIC structural_eor_emitter_base_constants=1");
console.log("METRIC structural_eor_emitter_native_vectors=22");
console.log("METRIC structural_branch_emitter_apis=21");
console.log("METRIC structural_branch_emitter_exact_words=56");
console.log("METRIC structural_branch_emitter_native_vectors=251");
console.log("METRIC structural_branch_patch_exact_words=8");
console.log("METRIC structural_branch_patch_rejections=10");
console.log("METRIC structural_branch_patch_native_vectors=4");
console.log("METRIC structural_branch_emitter_signed_range_edges=8");
console.log("METRIC structural_runtime_helper_logical_opcode=1");
