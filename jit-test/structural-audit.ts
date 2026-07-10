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
  "$(UAE_PATH)/registers.h $(UAE_PATH)/fpu/types.h",
  "JIT_SUPPORT_DEPS = $(UAE_PATH)/compiler/compemu_support_arm.cpp",
  "$(UAE_PATH)/compiler/compemu_legacy_arm64_compat.cpp",
  "$(UAE_PATH)/compiler/codegen_arm64.cpp",
  "$(UAE_PATH)/compiler/compemu_midfunc_arm64.cpp",
  "$(JIT_LAYOUT_OBJECTS): $(JIT_LAYOUT_DEPS)",
  "$(OBJ_DIR)/compemu_support.o: $(JIT_SUPPORT_DEPS)",
]) {
  requireText(makefileTemplate, layoutDependency, "JIT object layout epoch");
}
const harnessSource = await Bun.file(new URL("./run.sh", import.meta.url)).text();
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
]) {
  requireText(observerBody, preserved, "diagnostic observer preservation");
}

const midfuncPath = new URL(
  "../BasiliskII/src/uae_cpu_2026/compiler/compemu_midfunc_arm64.cpp",
  import.meta.url,
);
const midfuncSource = await Bun.file(midfuncPath).text();
if (midfuncSource.includes("compemu_raw_call((uintptr)jit_trace_setpc_value)")) {
  fail("diagnostic observer preservation: raw trace call remains in allocator midfunc");
}
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
const gencompSource = await Bun.file(new URL(
  "../BasiliskII/src/uae_cpu_2026/compiler/gencomp.c",
  import.meta.url,
)).text();
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
if (allocatorSource.includes("(prop[cft_map(opcode)].cflow & fl_end_block) != 0 && i + 1 < blocklen")) {
  fail("fallback control-flow runtime successor: terminal fallback remains position-gated");
}
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

const resetListsStart = allocatorSource.indexOf("static inline void reset_lists(void)");
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
  "bi->direct_handler = bi->direct_pen",
  "set_dhtu(bi, bi->direct_pen)",
  "zero-source dependency containment",
);

const blockBuilderPath = new URL(
  "../BasiliskII/src/uae_cpu_2026/compiler/compemu_legacy_arm64_compat.cpp",
  import.meta.url,
);
const blockBuilder = await Bun.file(blockBuilderPath).text();
requireText(blockBuilder, "case 0: return NATIVE_CC_VS;", "complete legacy condition mapping");
requireText(blockBuilder, "case 1: return NATIVE_CC_VC;", "complete legacy condition mapping");
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

console.log("METRIC structural_jit_object_layout_epoch=1");
console.log("METRIC structural_fullsr_ea_mode_decode=1");
console.log("METRIC structural_complete_mvsr2_helper_family=1");
console.log("METRIC structural_complete_legacy_condition_mapping=1");
console.log("METRIC structural_arm64_overflow_condition_codegen=1");
console.log("METRIC structural_shape_safe_handler_propagation=1");
console.log("METRIC structural_explicit_handler_propagation=1");
console.log("METRIC structural_fallback_architectural_cflow=1");
console.log("METRIC structural_fallback_controlflow_runtime_pc=1");
console.log("METRIC structural_helper_call_abi=1");
console.log("METRIC structural_diagnostic_observer_abi=1");
console.log("METRIC structural_helper_allocator_barrier=1");
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
console.log("METRIC structural_endblock_successor_pc=1");
console.log("METRIC structural_basic_block_control_boundary=1");
