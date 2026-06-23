/*
 *  ppc-jit.cpp — PPC → AArch64 direct codegen JIT
 *
 *  Compiles PPC basic blocks to native ARM64 instructions.
 *  Generated code is called as: void block(powerpc_registers *regs)
 *  with x0 = regs pointer. Block reads/writes GPR/CR/LR/CTR/PC via
 *  LDR/STR at known offsets from x0 (moved to callee-saved x20).
 */

#ifdef __aarch64__

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include "ppc-jit.h"
#include "ppc-codegen-aarch64.h"
#include "jit-target-cache.hpp"

extern "C" void sheepshaver_jit_execute_sheep(void *regs, uint32_t opcode, uint32_t pc);
extern "C" void sheepshaver_jit_emul_return(void *regs);
extern "C" void sheepshaver_jit_exec_return(void *regs);
extern "C" void sheepshaver_jit_execute_emul_op(void *regs, uint32_t emul_op, uint32_t next_pc);
extern "C" void sheepshaver_jit_execute_native_op(void *regs, uint32_t selector, uint32_t next_pc);
extern "C" uint32_t sheepshaver_jit_safe_lwz(uint32_t ea, uint32_t old_value);
extern "C" void sheepshaver_jit_safe_stw(uint32_t ea, uint32_t value);
extern "C" uint32_t sheepshaver_jit_safe_load(uint32_t ea, uint32_t old_value, uint32_t load_kind);
extern "C" void sheepshaver_jit_safe_store(uint32_t ea, uint32_t value, uint32_t store_kind);
extern "C" uint32_t sheepshaver_jit_safe_load_reversed(uint32_t ea, uint32_t old_value, uint32_t access_size);
extern "C" void sheepshaver_jit_safe_store_reversed(uint32_t ea, uint32_t value, uint32_t access_size);
extern "C" void sheepshaver_jit_fp_load(void *regs, uint32_t ea, uint32_t fpr, uint32_t is_double);
extern "C" void sheepshaver_jit_fp_store(void *regs, uint32_t ea, uint32_t fpr, uint32_t is_double);
extern "C" uint32_t sheepshaver_jit_lwarx(void *regs, uint32_t ea);
extern "C" uint32_t sheepshaver_jit_stwcx(void *regs, uint32_t ea, uint32_t value);
extern "C" uint64_t sheepshaver_jit_get_tb_ticks(void);
extern "C" void sheepshaver_jit_dcbz(uint32_t ea);
/* icbi targeted-invalidate helper: only full-flush the JIT cache when a compiled
 * block actually overlaps the icbi'd 32-byte line (most icbi targets are code being
 * written, not executed, so nothing is compiled there). Defined below near the flush. */
extern "C" void ppc_jit_aarch64_icbi(uint32_t ea);
/* Frame buffer base/size helpers (sheepshaver_glue.cpp) for the D-form load/store
 * valid-check: the framebuffer is 1:1-mapped guest memory (VMBaseDiff==0) like RAM/ROM. */
extern "C" uint32_t sheepshaver_jit_fb_base(void);
extern "C" uint32_t sheepshaver_jit_fb_size(void);

/* ---- Code cache ---- */
static uint8_t  *jit_cache_base = NULL;
static size_t    jit_cache_size = 0;
static uint32_t *jit_cache_wp   = NULL;
static uint32_t *jit_cache_end  = NULL;

/* ---- Block address cache (PC → compiled code) ----
 *
 * CONTRACT (see SheepShaver/docs/AARCH64_JIT_RUNTIME_CONTRACT.md):
 *   Compiled blocks are stored here by PPC entry PC so they are not
 *   recompiled on every execution.  Hash table with chaining:
 *   bucket = (pc >> 2) & JIT_BC_MASK.  Entries within a bucket are
 *   linked via .next.  An entry is valid when .code != NULL.
 *
 *   Flush discipline: the entire cache must be invalidated whenever
 *   Mac OS invalidates any region of PPC code (icbi/isync) or when
 *   the JIT code-cache write-pointer is reset (ppc_jit_aarch64_flush).
 */
#define JIT_BC_BUCKETS  8192                /* must be power of 2 */
#define JIT_BC_MASK     (JIT_BC_BUCKETS - 1)
#define JIT_BC_POOL     16384               /* max total entries across all chains */

/* ---- Chain patch-site pool -----------------------------------------------
 * When emit_epilogue_with_pc() cannot chain at compile time (target not yet
 * in JIT cache), it records the location of the first LDP instruction in the
 * standard epilogue.  When the target block is later inserted, all matching
 * sites are back-patched: the LDP is overwritten with a direct B <chain_code>.
 * The remaining LDP+RET instructions become unreachable dead code.
 * On full cache flush, all sites are discarded (blocks are recompiled). */
#define JIT_CHAIN_SITE_POOL 4096
struct jit_chain_site {
	uint32_t  target_pc; /* PPC PC this site wants to chain to */
	uint32_t *patch_loc; /* ARM64 addr of first LDP in std epilogue; NULL=consumed */
	int       next;      /* next site in same bucket, -1=end */
};
static struct jit_chain_site chain_site_pool[JIT_CHAIN_SITE_POOL];
static int chain_site_heads[JIT_BC_BUCKETS]; /* -1=empty; initialised by jit_bc_flush() before first use */
static int chain_site_pool_next = 0;

struct jit_bc_entry {
	uint32_t  pc;         /* PPC address this block was compiled from */
	uint32_t *code;       /* normal ABI entry point (with prologue) */
	uint32_t *chain_code; /* chain entry point (after prologue, for direct chaining) */
	int       n_insns;    /* number of compiled PPC instructions */
	bool      complete;   /* true iff every instruction in block is native */
	int       next;       /* index of next entry in chain, -1 = end */
};

static struct jit_bc_entry jit_bc_pool[JIT_BC_POOL];
static int jit_bc_heads[JIT_BC_BUCKETS];  /* -1=empty; initialised by jit_bc_flush() before first use */
static int jit_bc_pool_next = 0;          /* next free pool entry */
/* Conservative [min,max) span of all compiled-block guest PCs. Used by the icbi
 * handler to skip the full pool scan when the icbi'd line lies outside any
 * compiled code. Only ever widened (invalidated slots are not subtracted), so it
 * is always a superset of live block ranges -> never skips a real overlap. */
static uint64_t jit_bc_span_min = UINT64_MAX;
static uint64_t jit_bc_span_max = 0;

static inline void jit_bc_span_add(uint32_t pc, int n_insns) {
	uint64_t start = (uint64_t)pc;
	uint64_t end = start + (uint64_t)(n_insns > 0 ? n_insns : 1) * 4u;
	if (start < jit_bc_span_min) jit_bc_span_min = start;
	if (end > jit_bc_span_max) jit_bc_span_max = end;
}

static void jit_bc_flush(void) {
	for (int i = 0; i < JIT_BC_BUCKETS; i++) jit_bc_heads[i] = -1;
	jit_bc_pool_next = 0;
	jit_bc_span_min = UINT64_MAX;
	jit_bc_span_max = 0;
	/* Also clear chain patch sites — all recorded epilogues are now invalid */
	for (int i = 0; i < JIT_BC_BUCKETS; i++) chain_site_heads[i] = -1;
	chain_site_pool_next = 0;
}

/* Record a chain patch site: when the target block at next_pc is compiled,
 * patch_loc (pointing to the first LDP of the standard epilogue) will be
 * overwritten with B <chain_code_of_next_pc>. */
static bool jit_chain_enabled(void) {
	static int enabled = -1;
	if (enabled < 0) {
		const char *disable = getenv("SS_DISABLE_JIT_CHAIN");
		enabled = !(disable && disable[0] && disable[0] != '0');
	}
	return enabled != 0;
}

static void record_chain_site(uint32_t next_pc, uint32_t *patch_loc) {
	if (!jit_chain_enabled()) return;
	if (chain_site_pool_next >= JIT_CHAIN_SITE_POOL) return; /* pool full, skip */
	int bucket = (next_pc >> 2) & JIT_BC_MASK;
	int idx = chain_site_pool_next++;
	chain_site_pool[idx].target_pc = next_pc;
	chain_site_pool[idx].patch_loc = patch_loc;
	chain_site_pool[idx].next      = chain_site_heads[bucket];
	chain_site_heads[bucket]       = idx;
}

/* When a new block is inserted at pc with chain_code, back-patch all
 * standard epilogues that were waiting to chain to this PC. */
static void patch_chain_sites(uint32_t pc, uint32_t *chain_code) {
	if (!jit_chain_enabled()) return;
	if (!chain_code) return;
	int bucket = (pc >> 2) & JIT_BC_MASK;
	int idx = chain_site_heads[bucket];
	while (idx >= 0) {
		struct jit_chain_site *site = &chain_site_pool[idx];
		if (site->target_pc == pc && site->patch_loc) {
			uint8_t *cc = (uint8_t *)chain_code;
			uint8_t *pl = (uint8_t *)site->patch_loc;
			int32_t off = (int32_t)(cc - pl);
			/* Both the patch site and the chain target must be in-cache (see
			 * emit_epilogue_with_pc): never back-patch a stale/out-of-cache target. */
			if (cc >= jit_cache_base && cc < jit_cache_base + jit_cache_size &&
			    pl >= jit_cache_base && pl < jit_cache_base + jit_cache_size &&
			    off >= -(1 << 25) && off < (1 << 25)) {
				*site->patch_loc = 0x14000000 | ((off >> 2) & 0x3FFFFFF); /* B offset */
				/* Flush ARM64 I-cache for the patched word */
				jit_cache_flush(site->patch_loc, sizeof(uint32_t));
			}
			site->patch_loc = NULL; /* mark consumed */
		}
		idx = site->next;
	}
}

static void jit_bc_invalidate_pc(uint32_t pc) {
	int bucket = (pc >> 2) & JIT_BC_MASK;
	int prev = -1;
	int idx = jit_bc_heads[bucket];
	while (idx >= 0) {
		if (jit_bc_pool[idx].pc == pc) {
			/* Unlink from chain */
			if (prev >= 0)
				jit_bc_pool[prev].next = jit_bc_pool[idx].next;
			else
				jit_bc_heads[bucket] = jit_bc_pool[idx].next;
			jit_bc_pool[idx].code = NULL;
			return;
		}
		prev = idx;
		idx = jit_bc_pool[idx].next;
	}
}

static const struct jit_bc_entry *jit_bc_lookup(uint32_t pc) {
	int idx = jit_bc_heads[(pc >> 2) & JIT_BC_MASK];
	while (idx >= 0) {
		if (jit_bc_pool[idx].pc == pc && jit_bc_pool[idx].code)
			return &jit_bc_pool[idx];
		idx = jit_bc_pool[idx].next;
	}
	return NULL;
}

static void jit_bc_insert(uint32_t pc, uint32_t *code, uint32_t *chain_code, bool complete, int n_insns = 0) {
	/* Check if already exists */
	int bucket = (pc >> 2) & JIT_BC_MASK;
	int idx = jit_bc_heads[bucket];
	while (idx >= 0) {
		if (jit_bc_pool[idx].pc == pc) {
			jit_bc_pool[idx].code       = code;
			jit_bc_pool[idx].chain_code = chain_code;
			jit_bc_pool[idx].complete   = complete;
			jit_bc_pool[idx].n_insns    = n_insns;
			jit_bc_span_add(pc, n_insns);
			/* Existing entries can be refreshed after invalidation/recompile; satisfy
			 * any epilogues that were recorded while the target was unavailable. */
			patch_chain_sites(pc, chain_code);
			return;
		}
		idx = jit_bc_pool[idx].next;
	}
	/* New entry — allocate from pool */
	if (jit_bc_pool_next >= JIT_BC_POOL) {
		/* Pool exhausted — flush metadata AND generated code. Metadata-only flush is
		 * unsafe with direct chaining: old code can still branch to old code, but the
		 * block table/span no longer knows those guest PC ranges for icbi invalidation. */
		jit_cache_wp = (uint32_t *)jit_cache_base;
		jit_bc_flush();
	}
	idx = jit_bc_pool_next++;
	jit_bc_pool[idx].pc         = pc;
	jit_bc_pool[idx].code       = code;
	jit_bc_pool[idx].chain_code = chain_code;
	jit_bc_pool[idx].complete   = complete;
	jit_bc_pool[idx].n_insns    = n_insns;
	jit_bc_span_add(pc, n_insns);
	jit_bc_pool[idx].next       = jit_bc_heads[bucket];
	jit_bc_heads[bucket]        = idx;
	/* Back-patch any standard epilogues in older blocks that were waiting
	 * to chain to this PC but couldn't at their compile time. */
	patch_chain_sites(pc, chain_code);
}

/* ---- Register offsets in powerpc_registers ----
   Determined from compiled struct layout on aarch64. */
#define PPCR_GPR(n) ((uint32_t)((n) * 4))
#define PPCR_GPR_HI(n) ((uint32_t)(128 + (n) * 4))  /* upper 32 bits for 64-bit G5 mode */
#define PPCR_CR     1024
#define PPCR_XER    1028
/* XER is a struct {uint8 so, ov, ca, byte_count} — use byte offsets */
#define PPCR_XER_SO   1028
#define PPCR_XER_OV   1029
#define PPCR_XER_CA   1030
#define PPCR_XER_CNT  1031
#define PPCR_VRSAVE 1036
#define PPCR_FPSCR  1040
#define PPCR_LR     1044
#define PPCR_CTR    1048
#define PPCR_PC     1052



/* Host register assignments */
#define RCR0    19   /* x19 = pending CR0 result (callee-saved) */
#define RSTATE  20   /* x20 = regs pointer (callee-saved) */
#define RTMP0    0
#define RTMP1    1
#define RTMP2    2
#define RTMP3    3
#define RTMP4    4

/* FPR offsets: FPR[n] at offset 128 + n*8 (each is a 64-bit double) */
#define PPCR_FPR(n) ((uint32_t)(256 + (n) * 8))

/* ARM64 FP register helpers */
/* LDR Dt, [Xn, #imm] (64-bit FP load, unsigned offset scaled by 8) */
static void emit_load_fpr(int fd, int fpr_num) {
	/* LDR Dt, [RSTATE, #offset] */
	uint32_t off = PPCR_FPR(fpr_num);
	emit32(0xFD400000 | ((off / 8) << 10) | (RSTATE << 5) | fd);
}

/* STR Dt, [Xn, #imm] */
static void emit_store_fpr(int fs, int fpr_num) {
	uint32_t off = PPCR_FPR(fpr_num);
	emit32(0xFD000000 | ((off / 8) << 10) | (RSTATE << 5) | fs);
}

/* ---- PPC instruction field extraction ---- */
static inline uint32_t PPC_OPC(uint32_t op)  { return op >> 26; }
static inline uint32_t PPC_RD(uint32_t op)   { return (op >> 21) & 0x1F; }
static inline uint32_t PPC_RS(uint32_t op)   { return (op >> 21) & 0x1F; }
static inline uint32_t PPC_RA(uint32_t op)   { return (op >> 16) & 0x1F; }
static inline uint32_t PPC_RB(uint32_t op)   { return (op >> 11) & 0x1F; }
static inline int16_t  PPC_SIMM(uint32_t op) { return (int16_t)(op & 0xFFFF); }
static inline uint16_t PPC_UIMM(uint32_t op) { return (uint16_t)(op & 0xFFFF); }
static inline uint32_t PPC_XO(uint32_t op)   { return (op >> 1) & 0x3FF; }

/* ---- Emit helpers ---- */

/* ---- Register allocator ----
 * Maps PPC GPRs to ARM64 callee-saved registers x21–x28 (8 slots).
 * Eliminates redundant LDR/STR when the same GPR is used across
 * consecutive instructions within a block.
 */
#define RA_NUM_REGS  8
#define RA_FIRST_REG 21  /* x21 */

static int  ra_ppc_to_host[32];   /* PPC GPR → ARM64 reg, -1 = not cached */
static int  ra_host_to_ppc[RA_NUM_REGS]; /* ARM64 slot → PPC GPR, -1 = free */
static bool ra_dirty[RA_NUM_REGS];       /* true = cached value modified, needs writeback */
static int  ra_lru[RA_NUM_REGS];         /* access counter for LRU eviction */
static int  ra_clock = 0;                /* monotonic access counter */
static bool ra_enabled = false;          /* enabled only for straight-line blocks */

static void ra_reset(void) {
	for (int i = 0; i < 32; i++) ra_ppc_to_host[i] = -1;
	for (int i = 0; i < RA_NUM_REGS; i++) {
		ra_host_to_ppc[i] = -1;
		ra_dirty[i] = false;
		ra_lru[i] = 0;
	}
	ra_clock = 0;
}

/* Evict one slot: write back if dirty, mark free */
static void ra_evict(int slot) {
	int ppc = ra_host_to_ppc[slot];
	if (ppc >= 0) {
		if (ra_dirty[slot])
			a64_str_w_imm(RA_FIRST_REG + slot, RSTATE, PPCR_GPR(ppc));
		ra_ppc_to_host[ppc] = -1;
	}
	ra_host_to_ppc[slot] = -1;
	ra_dirty[slot] = false;
}

/* Find LRU slot to evict */
static int ra_find_lru(void) {
	int best = 0;
	for (int i = 1; i < RA_NUM_REGS; i++)
		if (ra_lru[i] < ra_lru[best]) best = i;
	return best;
}

/* Get ARM64 reg for reading PPC GPR n (loads from struct if not cached) */
static int ra_load(int n) {
	int host = ra_ppc_to_host[n];
	if (host >= 0) {
		ra_lru[host - RA_FIRST_REG] = ++ra_clock;
		return host;
	}
	/* Not cached — load from struct and cache it */
	int slot = -1;
	for (int i = 0; i < RA_NUM_REGS; i++) {
		if (ra_host_to_ppc[i] < 0) { slot = i; break; }
	}
	if (slot < 0) {
		slot = ra_find_lru();
		ra_evict(slot);
	}
	host = RA_FIRST_REG + slot;
	a64_ldr_w_imm(host, RSTATE, PPCR_GPR(n));
	ra_ppc_to_host[n] = host;
	ra_host_to_ppc[slot] = n;
	ra_dirty[slot] = false;
	ra_lru[slot] = ++ra_clock;
	return host;
}

/* Get ARM64 reg for writing PPC GPR n (marks dirty, allocates if needed) */
static int ra_store(int n) {
	int host = ra_ppc_to_host[n];
	if (host >= 0) {
		int slot = host - RA_FIRST_REG;
		ra_dirty[slot] = true;
		ra_lru[slot] = ++ra_clock;
		return host;
	}
	/* Allocate — same as load but don't bother loading old value */
	int slot = -1;
	for (int i = 0; i < RA_NUM_REGS; i++) {
		if (ra_host_to_ppc[i] < 0) { slot = i; break; }
	}
	if (slot < 0) {
		slot = ra_find_lru();
		ra_evict(slot);
	}
	host = RA_FIRST_REG + slot;
	ra_ppc_to_host[n] = host;
	ra_host_to_ppc[slot] = n;
	ra_dirty[slot] = true;
	ra_lru[slot] = ++ra_clock;
	return host;
}

/* Flush all dirty cached regs back to struct (call at block exit) */
static void ra_flush_all(void) {
	for (int i = 0; i < RA_NUM_REGS; i++) {
		if (ra_host_to_ppc[i] >= 0 && ra_dirty[i])
			a64_str_w_imm(RA_FIRST_REG + i, RSTATE, PPCR_GPR(ra_host_to_ppc[i]));
	}
}

static void emit_load_gpr(int rd, int n) {
	if (ra_enabled) {
		int host = ra_load(n);
		if (rd != host) a64_mov_w_reg(rd, host);
		return;
	}
	a64_ldr_w_imm(rd, RSTATE, PPCR_GPR(n));
}

static void emit_store_gpr(int rs, int n) {
	if (ra_enabled) {
		int host = ra_store(n);
		if (rs != host) a64_mov_w_reg(host, rs);
		return;
	}
	a64_str_w_imm(rs, RSTATE, PPCR_GPR(n));
}

/* Direct-host GPR accessors that avoid the RTMP<->host round-trip moves emitted by
 * emit_load_gpr/emit_store_gpr when register allocation is enabled. A handler reads
 * its sources with gpr_in() and writes its result into the register returned by
 * gpr_out(), then calls gpr_out_commit(). With RA on this operates directly on the
 * x21-x28 cache (no moves); with RA off it falls back to the scratch register + an
 * explicit struct LDR/STR, exactly matching emit_load_gpr/emit_store_gpr.
 * Smaller emitted blocks => the 8MB code cache holds more before filling (fewer
 * cache-full flushes / recompiles) plus lower icache/issue pressure. */
static int gpr_in(int n, int scratch) {
	if (ra_enabled) return ra_load(n);
	a64_ldr_w_imm(scratch, RSTATE, PPCR_GPR(n));
	return scratch;
}
static int gpr_out(int n, int scratch) {
	return ra_enabled ? ra_store(n) : scratch;
}
static void gpr_out_commit(int n, int reg) {
	if (!ra_enabled) a64_str_w_imm(reg, RSTATE, PPCR_GPR(n));
}

/* 64-bit GPR access for G5/PPC64 instructions.
   Uses gpr[n] (low 32) + gpr_hi[n] (high 32) as a split 64-bit register.
   On little-endian ARM64: load low word, load high word, combine. */
static void emit_load_gpr64_tmp(int xd, int n, int tmp) {
	/* Load low 32 bits (RA-aware), zero-extended to Xd */
	emit_load_gpr(xd, n);
	/* LDR Wtmp, [RSTATE, #gpr_hi] — high 32 bits, zero-extends to Xtmp */
	a64_ldr_w_imm(tmp, RSTATE, PPCR_GPR_HI(n));
	/* Combine into 64-bit Xd: Xd = (hi << 32) | lo
	 * ORR Xd, Xd, Xtmp, LSL #32: imm6=32 at bits 15-10 of the ORR shifted-reg form */
	emit32(0xAA000000 | (tmp << 16) | (0x20 << 10) | (xd << 5) | xd);
	/* NOTE: the ORR above is the correct and complete 64-bit combine.
	 * No BFI needed here. */
}

static void emit_load_gpr64(int xd, int n) {
	int tmp = (xd == RTMP0) ? RTMP1 : RTMP0;
	emit_load_gpr64_tmp(xd, n, tmp);
}

static void emit_store_gpr64(int xs, int n) {
	/* Store low 32 (RA-aware) */
	emit_store_gpr(xs, n);
	/* Store high 32: LSR Xtmp, Xs, #32; STR Wtmp, [RSTATE, #gpr_hi]
	 * LSR Xd,Xn,#32 = UBFM Xd,Xn,#immr=32,#imms=63 = 0xD360FC00|(Xn<<5)|Xd */
	int tmp = (xs == RTMP0) ? RTMP1 : RTMP0;
	emit32(0xD360FC00 | (xs << 5) | tmp); /* LSR Xtmp, Xs, #32 */
	a64_str_w_imm(tmp, RSTATE, PPCR_GPR_HI(n));
}

/* Emit LSL Xd,Xn,#imm (64-bit logical shift left, 1 <= imm <= 63) */
static void emit_lsl64_imm(int rd, int rn, int imm) {
	if (imm <= 0 || imm >= 64) return;
	int immr = (64 - imm) & 63;
	int imms = 63 - imm;
	emit32(0xD3400000 | (immr << 16) | (imms << 10) | (rn << 5) | rd);
}

/* Emit LSR Xd,Xn,#imm (64-bit logical shift right, 1 <= imm <= 63) */
static void emit_lsr64_imm(int rd, int rn, int imm) {
	if (imm <= 0 || imm >= 64) return;
	emit32(0xD3400000 | (imm << 16) | (63 << 10) | (rn << 5) | rd);
}

/* Load a 64-bit immediate into a 64-bit register (MOVZ + up to 3 MOVK) */
static void emit_load_imm64(int rd, uint64_t imm) {
	uint16_t p[4];
	for (int i = 0; i < 4; i++) p[i] = (imm >> (i * 16)) & 0xFFFF;
	int first = 0;
	for (int i = 0; i < 4; i++) { if (p[i]) { first = i; break; } }
	a64_movz(rd, p[first], first);
	for (int i = 0; i < 4; i++)
		if (i != first && p[i]) a64_movk(rd, p[i], i);
}

static void emit_load_imm32(int rd, int32_t imm) {
	uint32_t u = (uint32_t)imm;
	uint16_t lo = u & 0xFFFF;
	uint16_t hi = (u >> 16) & 0xFFFF;
	if (imm >= 0 && imm < 65536) {
		a64_movz(rd, lo, 0);
	} else if (imm < 0 && imm >= -65536) {
		emit32(0x12800000 | ((uint32_t)(uint16_t)(~u) << 5) | rd); /* MOVN Wd, #~u */
	} else {
		a64_movz(rd, lo, 0);
		if (hi) a64_movk(rd, hi, 1);
	}
}

/* Update CR0 based on a 32-bit result in ARM64 register 'rd'.
   CR0: bit31=LT(negative), bit30=GT(positive nonzero), bit29=EQ(zero), bit28=SO(from XER) */
/* Read XER[SO] (byte at offset PPCR_XER_SO) into register rd as 0 or 1 */
static void emit_read_xer_so(int rd) {
	emit32(0x39400000 | (PPCR_XER_SO << 10) | (RSTATE << 5) | rd); /* LDRB Wt, [Xn, #off] */
}

/* Merge XER[SO] into a CR field nibble in reg (at bit 0 position) */
static void emit_or_xer_so_into_cr_nibble(int reg) {
	int tmp = (reg == RTMP0) ? RTMP1 : RTMP0;
	emit_read_xer_so(tmp);
	emit32(0x2A000000 | (tmp << 16) | (reg << 5) | reg); /* ORR Wd, Wreg, Wtmp */
}

static void emit_update_cr0(int result_reg) {
	/* Simple approach: compute CR0 nibble with conditional instructions */
	/* Compare result with 0 */
	emit32(0x7100001F | (result_reg << 5)); /* CMP Wn, #0 */
	/* CR0 = 0 by default */
	a64_movz(RTMP2, 0, 0);
	/* MOV W(RTMP0), #8; MOV W(RTMP1), #4; MOV W(RTMP2), #2 */
	/* CSEL based on condition */
	/* Simplest: use three conditional moves */
	a64_movz(RTMP2, 0, 0);
	emit_load_imm32(RTMP0, 8); /* LT value */
	emit_load_imm32(RTMP1, 4); /* GT value */
	/* CSEL RTMP2, RTMP0, RTMP2, LT (if signed less than) */
	emit32(0x1A800000 | (RTMP2 << 16) | (0xB << 12) | (RTMP0 << 5) | RTMP2); /* CSEL Wd,Wn,Wm,LT */
	/* CSEL RTMP2, RTMP1, RTMP2, GT (if signed greater than) */
	emit32(0x1A800000 | (RTMP2 << 16) | (0xC << 12) | (RTMP1 << 5) | RTMP2); /* CSEL Wd,Wn,Wm,GT */
	/* If EQ, set to 2 */
	emit_load_imm32(RTMP0, 2);
	emit32(0x1A800000 | (RTMP2 << 16) | (0x0 << 12) | (RTMP0 << 5) | RTMP2); /* CSEL Wd,Wn,Wm,EQ */
	/* OR in XER[SO] as bit 0 */
	emit_or_xer_so_into_cr_nibble(RTMP2);
	/* Shift nibble into CR0 position (bits 31:28) */
	emit_load_imm32(RTMP0, 28);
	emit32(0x1AC02000 | (RTMP0 << 16) | (RTMP2 << 5) | RTMP2); /* LSL Wd,Wn,Wm */
	/* Load CR, clear CR0 field, OR in new value */
	a64_ldr_w_imm(RTMP0, RSTATE, PPCR_CR);
	emit_load_imm32(RTMP1, 0x0FFFFFFF);
	emit32(0x0A000000 | (RTMP1 << 16) | (RTMP0 << 5) | RTMP0); /* AND */
	emit32(0x2A000000 | (RTMP2 << 16) | (RTMP0 << 5) | RTMP0); /* ORR */
	a64_str_w_imm(RTMP0, RSTATE, PPCR_CR);
}


/* Read XER.CA byte into ARM64 register rd (0 or 1) */
static void emit_read_xer_ca(int rd) {
	emit32(0x39400000 | (PPCR_XER_CA << 10) | (RSTATE << 5) | rd); /* LDRB Wt, [Xn, #off] */
}

/* Write ARM64 carry flag (from last ADDS/SUBS) into XER.CA byte */
static void emit_write_xer_ca_from_carry(void) {
	/* CSET Wd, CS (carry set) — Wd = 1 if C=1, else 0 */
	emit32(0x1A9F37E0 | RTMP2); /* CSET W(RTMP2), CS = CSINC WZR, WZR, CC */
	emit32(0x39000000 | (PPCR_XER_CA << 10) | (RSTATE << 5) | RTMP2); /* STRB */
}

/* Write ARM64 signed overflow flag (from last ADDS/SUBS/ADCS/SBCS) into
 * XER.OV and accumulate it into XER.SO. */
static void emit_write_xer_ov_so_from_overflow(void) {
	emit32(0x1A9F77E0 | RTMP2); /* CSET W(RTMP2), VS */
	emit32(0x39000000 | (PPCR_XER_OV << 10) | (RSTATE << 5) | RTMP2); /* STRB OV */
	emit32(0x39400000 | (PPCR_XER_SO << 10) | (RSTATE << 5) | RTMP1); /* LDRB SO */
	emit32(0x2A000000 | (RTMP2 << 16) | (RTMP1 << 5) | RTMP1); /* ORR SO,SO,OV */
	emit32(0x39000000 | (PPCR_XER_SO << 10) | (RSTATE << 5) | RTMP1); /* STRB SO */
}

static void emit_write_xer_ov_so_from_reg(int reg) {
	emit32(0x39000000 | (PPCR_XER_OV << 10) | (RSTATE << 5) | reg); /* STRB OV */
	emit32(0x39400000 | (PPCR_XER_SO << 10) | (RSTATE << 5) | RTMP1); /* LDRB SO */
	emit32(0x2A000000 | (reg << 16) | (RTMP1 << 5) | RTMP1); /* ORR SO,SO,OV */
	emit32(0x39000000 | (PPCR_XER_SO << 10) | (RSTATE << 5) | RTMP1); /* STRB SO */
}

/* Set XER.CA byte to a specific value (0 or 1) */
static void emit_set_xer_ca(int val) {
	if (val) {
		emit_load_imm32(RTMP0, 1);
	} else {
		a64_movz(RTMP0, 0, 0);
	}
	emit32(0x39000000 | (PPCR_XER_CA << 10) | (RSTATE << 5) | RTMP0); /* STRB */
}

/* Sync PPC FPSCR rounding mode (bits 30-31) to ARM64 FPCR (bits 22-23).
   PPC RN: 0=nearest, 1=toward zero, 2=+inf, 3=-inf
   ARM64 RMode: 0=nearest, 3=toward zero, 1=+inf, 2=-inf
   Called after any FPSCR write that might change the RN field. */
static void emit_sync_fpscr_rounding(void) {
	a64_ldr_w_imm(RTMP0, RSTATE, PPCR_FPSCR);
	/* Extract PPC RN field: bits 30-31 (least significant 2 bits of FPSCR) */
	emit32(0x12000400 | (RTMP0 << 5) | RTMP0); /* AND Wd, Wn, #3 */
	/* Map PPC RN to ARM64 RMode via conditional moves */
	a64_mov_reg(RTMP1, RTMP0); /* save PPC RN */
	a64_movz(RTMP0, 0, 0); /* default: ARM nearest (PPC 0 → ARM 0) */
	emit_load_imm32(RTMP2, 3);
	emit32(0x7100043F | (RTMP1 << 5)); /* CMP Wn, #1 */
	emit32(0x1A800000 | (RTMP0 << 16) | (0x0 << 12) | (RTMP2 << 5) | RTMP0); /* CSEL 3 if EQ (PPC zero→ARM 3) */
	emit_load_imm32(RTMP2, 1);
	emit32(0x7100083F | (RTMP1 << 5)); /* CMP Wn, #2 */
	emit32(0x1A800000 | (RTMP0 << 16) | (0x0 << 12) | (RTMP2 << 5) | RTMP0); /* CSEL 1 if EQ (PPC +inf→ARM 1) */
	emit_load_imm32(RTMP2, 2);
	emit32(0x71000C3F | (RTMP1 << 5)); /* CMP Wn, #3 */
	emit32(0x1A800000 | (RTMP0 << 16) | (0x0 << 12) | (RTMP2 << 5) | RTMP0); /* CSEL 2 if EQ (PPC -inf→ARM 2) */
	/* Shift to FPCR RMode position (bits 22-23) */
	emit_load_imm32(RTMP1, 22);
	emit32(0x1AC02000 | (RTMP1 << 16) | (RTMP0 << 5) | RTMP0); /* LSL */
	/* Read FPCR, clear RMode bits, set new value */
	emit32(0xD53B4400 | RTMP1); /* MRS Xt, FPCR */
	emit_load_imm32(RTMP2, ~(3 << 22));
	emit32(0x0A000000 | (RTMP2 << 16) | (RTMP1 << 5) | RTMP1); /* AND: clear RMode */
	emit32(0x2A000000 | (RTMP0 << 16) | (RTMP1 << 5) | RTMP1); /* ORR: set new RMode */
	emit32(0xD51B4400 | RTMP1); /* MSR FPCR, Xt */
}


/* Load effective address: if rA==0, use 0; otherwise load GPR[rA].
   Always puts result in RTMP0. */
static void emit_load_ea_base(int ra_num) {
	if (ra_num == 0) {
		a64_movz(RTMP0, 0, 0);
	} else {
		emit_load_gpr(RTMP0, ra_num);
	}
}

static void patch_bcond(uint32_t *loc, uint8_t cond, uint32_t *target) {
	int32_t off = (int32_t)((uint8_t *)target - (uint8_t *)loc);
	*loc = 0x54000000 | (((off >> 2) & 0x7FFFF) << 5) | (cond & 0xF);
}

static void emit_cmp_w_imm(int rn, uint32_t imm) {
	emit32(0x7100001F | ((imm & 0xFFF) << 10) | (rn << 5)); /* CMP Wn,#imm */
}

static void emit_add_w_imm(int rd, int rn, uint32_t imm) {
	emit32(0x11000000 | ((imm & 0xFFF) << 10) | (rn << 5) | rd); /* ADD Wd,Wn,#imm */
}

extern uint32_t RAMBase;
extern uint32_t RAMSize;
extern uint32_t ROMBase;
class SheepMem {
public:
	static uintptr_t base;
	static uintptr_t data;
	static uintptr_t zero_page;
	static uint32_t page_size;
};

static void patch_cond_to_here(uint32_t *loc, uint8_t cond) {
	patch_bcond(loc, cond, jit_code_ptr);
}

static void emit_branch_if_ea_in_range_size(int ea_reg, uint32_t start, uint32_t size, uint32_t **valid_locs, int *valid_count) {
	if (size == 0)
		return;
	/* Unsigned range membership in a single compare:
	 *     (ea - start) <u size   <=>   ea in [start, start+size)
	 * If ea < start the subtraction wraps to a large unsigned value >= size, so the
	 * branch is not taken (correctly out of range). This replaces the previous
	 * two-compare/two-branch form (CMP ea,start / B.LO skip / CMP ea,end / B.LO valid),
	 * shrinking every guarded load/store's valid-check by ~2 insns and one branch per
	 * range with identical semantics. RTMP3/RTMP4 are free scratch here (callers pass
	 * ea in RTMP0 and the loaded/stored value in RTMP1). */
	int cmp_reg;
	if (start != 0) {
		emit_load_imm32(RTMP3, (int32_t)start);
		emit32(0x4B000000 | (RTMP3 << 16) | (ea_reg << 5) | RTMP3); /* SUB W3,Wea,W3 = ea-start */
		cmp_reg = RTMP3;
	} else {
		cmp_reg = ea_reg; /* ea - 0 == ea */
	}
	emit_load_imm32(RTMP4, (int32_t)size);
	emit32(0x6B000000 | (RTMP4 << 16) | (cmp_reg << 5) | 31); /* CMP Wcmp,Wsize */
	valid_locs[(*valid_count)++] = jit_code_ptr; emit32(0); /* B.LO valid */
}

static void emit_branch_if_ea_in_range(int ea_reg, uint32_t start, uint32_t end_exclusive, uint32_t **valid_locs, int *valid_count) {
	if (end_exclusive <= start)
		return;
	emit_branch_if_ea_in_range_size(ea_reg, start, end_exclusive - start, valid_locs, valid_count);
}

static void emit_direct_access_valid_check(int ea_reg, uint32_t access_size, bool allow_rom, bool store, uint32_t **valid_locs, int *valid_count) {
	/* RAM is by far the most frequently accessed region, so test it FIRST: the hot
	 * path then matches on the first comparison. Region order does not affect the
	 * valid/invalid outcome (membership is the union of all ranges), only how many
	 * comparisons execute before a hit, so this reordering is purely a speed win. */
	const uint32_t ram_start = RAMBase;
	if (RAMSize >= access_size)
		emit_branch_if_ea_in_range_size(ea_reg, ram_start, RAMSize - access_size + 1, valid_locs, valid_count);

	const uint32_t lowmem_end = 0x3000U >= access_size ? (0x3000U - access_size + 1) : 0;
	if (lowmem_end)
		emit_branch_if_ea_in_range(ea_reg, 0, lowmem_end, valid_locs, valid_count);

	if (allow_rom) {
		const uint32_t rom_start = ROMBase;
		const uint32_t rom_size = 0x500000U;
		if (rom_size >= access_size)
			emit_branch_if_ea_in_range_size(ea_reg, rom_start, rom_size - access_size + 1, valid_locs, valid_count);
		}

	const uint32_t sheep_base = (uint32_t)SheepMem::base;
	const uint32_t sheep_end = (uint32_t)SheepMem::data;
	if (sheep_end > sheep_base && sheep_end >= access_size) {
		if (store) {
			const uint32_t zp_start = (uint32_t)SheepMem::zero_page;
			const uint32_t zp_end = zp_start + SheepMem::page_size;
			if (zp_start > sheep_base && zp_start >= access_size)
				emit_branch_if_ea_in_range(ea_reg, sheep_base, zp_start - access_size + 1, valid_locs, valid_count);
			if (zp_end < sheep_end)
				emit_branch_if_ea_in_range(ea_reg, zp_end, sheep_end - access_size + 1, valid_locs, valid_count);
		} else {
			emit_branch_if_ea_in_range(ea_reg, sheep_base, sheep_end - access_size + 1, valid_locs, valid_count);
		}
	}

	/* KERNEL_DATA areas: KERNEL_DATA_BASE=0x68ffe000 and its alias
	 * KERNEL_DATA2_BASE=0x5fffe000, KERNEL_AREA_SIZE=0x2000 each.  These are
	 * shm-mapped 1:1 into the host address space (VMBaseDiff==0), exactly like
	 * RAM/ROM/SheepMem, so the inline LDR/STR using the guest EA as a host
	 * pointer is valid here too.  The nanokernel performs heavy D-form
	 * stw/lwz into this region during early kernel-data init (e.g.
	 * stw r13,1668(r1) at 0x18310278 with r1=0x68ffe000).  Without these
	 * ranges those stores were silently dropped (no-op) and the matching
	 * loads returned 0, so kernel-data-ready was never latched and boot
	 * stalled.  Indexed forms (stwx/lwzx) already went through the safe
	 * helper and handled this correctly; the D-form fast path did not. */
	{
		const uint32_t kd1_start = 0x68ffe000U;
		const uint32_t kd1_end   = 0x68ffe000U + 0x2000U;
		const uint32_t kd2_start = 0x5fffe000U;
		const uint32_t kd2_end   = 0x5fffe000U + 0x2000U;
		if (kd1_end >= access_size)
			emit_branch_if_ea_in_range(ea_reg, kd1_start, kd1_end - access_size + 1, valid_locs, valid_count);
		if (kd2_end >= access_size)
			emit_branch_if_ea_in_range(ea_reg, kd2_start, kd2_end - access_size + 1, valid_locs, valid_count);
	}

	/* Framebuffer accesses intentionally do NOT use an inline direct-valid range.
	 * screen_base/cur_mode/rowBytes can change during video mode switches, while compiled
	 * blocks bake valid-check constants permanently. Let framebuffer D-form accesses take
	 * the safe_load/safe_store slow path instead; the helper consults the current framebuffer
	 * extent at runtime and still uses direct Read/WriteMacInt for genuinely mapped video RAM. */

	const uint32_t highmem_valid_starts = (0x10000U >= access_size) ? (0x10000U - access_size + 1) : 0;
	if (highmem_valid_starts)
		emit_branch_if_ea_in_range_size(ea_reg, 0xFFFF0000U, highmem_valid_starts, valid_locs, valid_count);
}

static void emit_guarded_load_zero_invalid(int ea_reg, int dst_reg, int load_kind, int ppc_dst_reg) {
	uint32_t *valid_locs[12] = {0};
	int valid_count = 0;
	uint32_t *done = NULL;
	uint32_t access_size = (load_kind == 1) ? 1 : (load_kind == 4 ? 4 : 2);
	emit_direct_access_valid_check(ea_reg, access_size, true, false, valid_locs, &valid_count);
	/* INVALID fast-path branch: EA is outside the statically-enumerated 1:1 regions.
	 * The stale destination value is arg1 (old_value) for the helper, but it is ONLY
	 * needed on this cold path: on the valid path the inline LDR below overwrites dst,
	 * so loading it up-front was dead work on the hot path. Load it here instead.
	 * Instead of silently leaving the stale destination (which skipped real loads of
	 * dynamically-mapped CFM arenas -> FATAL-0x39 stale-CTR bctrl), call the safe helper:
	 * it reads genuinely-mapped guest memory like the interpreter (mincore-probed) and
	 * leaves the old value only for truly-unmapped MMIO. RA-enabled memory blocks emit a
	 * flush+reset barrier before every guest-memory instruction, so the register struct is
	 * authoritative across this helper call; x21-x28 are callee-saved by the AArch64 ABI. */
	emit_load_gpr(dst_reg, ppc_dst_reg);                     /* x1 = old_value (helper arg1) */
	emit_load_imm32(RTMP2, (int32_t)load_kind);              /* x2 = load_kind */
	emit_load_imm64(RTMP4, (uint64_t)(uintptr_t)sheepshaver_jit_safe_load);
	emit32(0xD63F0000 | (RTMP4 << 5));                       /* BLR x4 (ea=x0, old=x1, kind=x2) */
	if (dst_reg != RTMP0) a64_mov_reg(dst_reg, RTMP0);       /* result -> dst */
	done = jit_code_ptr; emit32(0); /* B done (skip the inline LDR) */
	for (int i = 0; i < valid_count; i++)
		patch_cond_to_here(valid_locs[i], 3);
	switch (load_kind) {
	case 1: emit32(0x39400000 | (ea_reg << 5) | dst_reg); break; /* LDRB */
	case 2: emit32(0x79400000 | (ea_reg << 5) | dst_reg); emit32(0x5AC00400 | (dst_reg << 5) | dst_reg); break; /* LDRH+REV16 */
	case 3: emit32(0x79400000 | (ea_reg << 5) | dst_reg); emit32(0x5AC00400 | (dst_reg << 5) | dst_reg); emit32(0x13003C00 | (dst_reg << 5) | dst_reg); break; /* LHA */
	case 4: emit32(0xB9400000 | (ea_reg << 5) | dst_reg); emit32(0x5AC00800 | (dst_reg << 5) | dst_reg); break; /* LDR+REV */
	}
	patch_bcond(done, 14, jit_code_ptr); /* AL */
}

static void emit_guarded_store_noop_invalid(int ea_reg, int val_reg, int store_kind) {
	uint32_t *valid_locs[12] = {0};
	int valid_count = 0;
	uint32_t *done = NULL;
	uint32_t access_size = (store_kind == 1) ? 1 : (store_kind == 4 ? 4 : 2);
	emit_direct_access_valid_check(ea_reg, access_size, false, true, valid_locs, &valid_count);
	/* INVALID fast-path branch: route to the safe helper (see load above) so stores into
	 * dynamically-mapped guest arenas are committed like the interpreter; truly-unmapped
	 * MMIO is still dropped. ea=x0(ea_reg), value=x1(val_reg), kind=x2. */
	emit_load_imm32(RTMP2, (int32_t)store_kind);            /* x2 = store_kind */
	emit_load_imm64(RTMP4, (uint64_t)(uintptr_t)sheepshaver_jit_safe_store);
	emit32(0xD63F0000 | (RTMP4 << 5));                      /* BLR x4 */
	done = jit_code_ptr; emit32(0); /* B done (skip the inline STR) */
	for (int i = 0; i < valid_count; i++)
		patch_cond_to_here(valid_locs[i], 3);
	switch (store_kind) {
	case 1: emit32(0x39000000 | (ea_reg << 5) | val_reg); break; /* STRB */
	case 2: emit32(0x79000000 | (ea_reg << 5) | val_reg); break; /* STRH */
	case 4: emit32(0xB9000000 | (ea_reg << 5) | val_reg); break; /* STR */
	}
	patch_bcond(done, 14, jit_code_ptr);
}

static void emit_call_fp_load_helper(int ea_reg, uint32_t fpr, bool is_double) {
	if (ea_reg != RTMP1) a64_mov_reg(RTMP1, ea_reg); /* x1 = EA */
	a64_mov_reg(RTMP0, RSTATE);                      /* x0 = regs */
	emit_load_imm32(RTMP2, (int32_t)fpr);             /* x2 = FPR index */
	emit_load_imm32(RTMP3, is_double ? 1 : 0);        /* x3 = is_double */
	emit_load_imm64(RTMP4, (uint64_t)(uintptr_t)sheepshaver_jit_fp_load);
	emit32(0xD63F0000 | (RTMP4 << 5));
}

static void emit_call_fp_store_helper(int ea_reg, uint32_t fpr, bool is_double) {
	if (ea_reg != RTMP1) a64_mov_reg(RTMP1, ea_reg); /* x1 = EA */
	a64_mov_reg(RTMP0, RSTATE);                      /* x0 = regs */
	emit_load_imm32(RTMP2, (int32_t)fpr);             /* x2 = FPR index */
	emit_load_imm32(RTMP3, is_double ? 1 : 0);        /* x3 = is_double */
	emit_load_imm64(RTMP4, (uint64_t)(uintptr_t)sheepshaver_jit_fp_store);
	emit32(0xD63F0000 | (RTMP4 << 5));
}

static void emit_lsl_w_imm(int rd, int rn, uint32_t sh) {
	if (sh == 0) { a64_mov_w_reg(rd, rn); return; }
	emit_load_imm32(RTMP4, sh);
	emit32(0x1AC02000 | (RTMP4 << 16) | (rn << 5) | rd); /* LSL Wd,Wn,Wm */
}

static void emit_lsr_w_imm(int rd, int rn, uint32_t sh) {
	if (sh == 0) { a64_mov_w_reg(rd, rn); return; }
	emit_load_imm32(RTMP4, sh);
	emit32(0x1AC02400 | (RTMP4 << 16) | (rn << 5) | rd); /* LSR Wd,Wn,Wm */
}

static void emit_string_count_guard(uint32_t **guards, int *guard_count, uint32_t byte_index) {
	emit_cmp_w_imm(RTMP3, byte_index + 1);
	guards[(*guard_count)++] = jit_code_ptr;
	emit32(0); /* B.LO done: patched after unrolled transfer */
}

static void emit_lswx_runtime_count(uint32_t rd) {
	uint32_t *guards[127];
	int guard_count = 0;
	emit32(0x39400000 | (PPCR_XER_CNT << 10) | (RSTATE << 5) | RTMP3); /* LDRB count */
	for (uint32_t i = 0; i < 127; i++) {
		emit_string_count_guard(guards, &guard_count, i);
		uint32_t r = (rd + (i >> 2)) & 31;
		uint32_t b = i & 3;
		uint32_t sh = (3 - b) * 8;
		emit32(0x39400000 | (RTMP0 << 5) | RTMP1); /* LDRB byte,[EA] */
		emit_lsl_w_imm(RTMP1, RTMP1, sh);
		if (b == 0) {
			a64_str_w_imm(RTMP1, RSTATE, PPCR_GPR(r));
		} else {
			a64_ldr_w_imm(RTMP2, RSTATE, PPCR_GPR(r));
			emit_load_imm32(RTMP4, (int32_t)~(0xFFu << sh));
			emit32(0x0A000000 | (RTMP4 << 16) | (RTMP2 << 5) | RTMP2); /* clear byte */
			emit32(0x2A000000 | (RTMP1 << 16) | (RTMP2 << 5) | RTMP2); /* merge */
			a64_str_w_imm(RTMP2, RSTATE, PPCR_GPR(r));
		}
		emit_add_w_imm(RTMP0, RTMP0, 1);
	}
	uint32_t *done = jit_code_ptr;
	for (int i = 0; i < guard_count; i++) patch_bcond(guards[i], 3, done); /* LO/CC */
}

static void emit_stswx_runtime_count(uint32_t rs) {
	uint32_t *guards[127];
	int guard_count = 0;
	emit32(0x39400000 | (PPCR_XER_CNT << 10) | (RSTATE << 5) | RTMP3); /* LDRB count */
	for (uint32_t i = 0; i < 127; i++) {
		emit_string_count_guard(guards, &guard_count, i);
		uint32_t r = (rs + (i >> 2)) & 31;
		uint32_t b = i & 3;
		uint32_t sh = (3 - b) * 8;
		a64_ldr_w_imm(RTMP1, RSTATE, PPCR_GPR(r));
		emit_lsr_w_imm(RTMP1, RTMP1, sh);
		emit32(0x39000000 | (RTMP0 << 5) | RTMP1); /* STRB byte,[EA] */
		emit_add_w_imm(RTMP0, RTMP0, 1);
	}
	uint32_t *done = jit_code_ptr;
	for (int i = 0; i < guard_count; i++) patch_bcond(guards[i], 3, done); /* LO/CC */
}

/* ---- AltiVec Vector Register helpers ---- */
/* VR[n] at offset 384 + n*16, each 128-bit (16 bytes) */
#define PPCR_VR(n) ((uint32_t)(512 + (n) * 16))

/* Load 128-bit vector register into ARM64 Q register (NEON) */
static void emit_load_vr(int qd, int vr_num) {
	uint32_t off = PPCR_VR(vr_num);
	/* LDR Qt, [Xn, #imm] — 128-bit vector load, unsigned offset scaled by 16 */
	emit32(0x3DC00000 | ((off / 16) << 10) | (RSTATE << 5) | qd);
}

/* Store ARM64 Q register into VR[n] */
static void emit_store_vr(int qs, int vr_num) {
	uint32_t off = PPCR_VR(vr_num);
	emit32(0x3D800000 | ((off / 16) << 10) | (RSTATE << 5) | qs);
}

/* AltiVec field extraction */
static inline uint32_t VR_VD(uint32_t op) { return (op >> 21) & 0x1F; }
static inline uint32_t VR_VA(uint32_t op) { return (op >> 16) & 0x1F; }
static inline uint32_t VR_VB(uint32_t op) { return (op >> 11) & 0x1F; }
static inline uint32_t VR_VC(uint32_t op) { return (op >> 6) & 0x1F; }

/* Emit: store next_pc to regs->pc, epilogue, ret */
static void emit_return_to_dispatch(void) {
	a64_ldp_post(27, 28, A64_SP, 16);
	a64_ldp_post(25, 26, A64_SP, 16);
	a64_ldp_post(23, 24, A64_SP, 16);
	a64_ldp_post(21, 22, A64_SP, 16);
	a64_ldp_post(19, RSTATE, A64_SP, 16);
	a64_ldp_post(A64_FP, A64_LR, A64_SP, 16);
	a64_ret();
}

static uint32_t jit_compiling_block_pc = 0; /* set at block compile start */

static void emit_epilogue_with_pc(uint32_t next_pc) {
	/* Flush register allocator: write all dirty cached GPRs back to struct */
	ra_flush_all();
	emit_load_imm32(RTMP0, (int32_t)next_pc);
	a64_str_w_imm(RTMP0, RSTATE, PPCR_PC);
	/* NEVER chain backward branches (next_pc <= block start).  Tight polling
	 * loops like the nanokernel idle loop (lwz/addi/stw/b .-) must return
	 * to the dispatch loop so check_spcflags() can observe timer interrupts.
	 * Without this, chained backward branches spin in native code forever. */
	bool allow_chain = (next_pc > jit_compiling_block_pc);
	/* Compile-time chaining: if the target PC is already in the JIT block
	 * cache and has a chain entry, branch directly to it instead of
	 * restoring callee-saved registers and returning to the dispatch loop.
	 * The callee-saved registers (x19–x28) remain valid on the stack from
	 * the current block's prologue — the chained block re-uses that frame. */
	const struct jit_bc_entry *chain_target = (allow_chain && jit_chain_enabled()) ? jit_bc_lookup(next_pc) : NULL;
	if (chain_target && chain_target->chain_code) {
		/* The chain target MUST point inside the code cache. Under heavy icbi/isync
		 * flushing a bc entry's chain_code was observed stale/corrupt (pointing into
		 * a mapped library), and emitting a direct B to it produced a wild branch ->
		 * SIGILL (executing a library ELF header). Enforce the in-cache invariant;
		 * if violated, fall back to the dispatch-return epilogue (always safe). */
		uint8_t *cc = (uint8_t *)chain_target->chain_code;
		if (cc >= jit_cache_base && cc < jit_cache_base + jit_cache_size) {
			int32_t off = (int32_t)((uint8_t *)chain_target->chain_code - (uint8_t *)jit_code_ptr);
			if (off >= -(1 << 25) && off < (1 << 25)) {
				emit32(0x14000000 | ((off >> 2) & 0x3FFFFFF)); /* B <offset> */
				return; /* no LDP+RET: caller re-uses current stack frame */
			}
		}
		/* else: chain target outside the code cache (stale/corrupt) -> never chain;
		 * fall through to the dispatch-return epilogue below. */
	}
	/* Runtime back-patching: record this epilogue location so that when
	 * next_pc is compiled later, the first LDP can be patched to B chain_code.
	 * patch_loc = address of the first LDP instruction we are about to emit. */
	if (allow_chain)
		record_chain_site(next_pc, jit_code_ptr);
	/* Standard epilogue: restore callee-saved regs and return to dispatch */
	a64_ldp_post(27, 28, A64_SP, 16);
	a64_ldp_post(25, 26, A64_SP, 16);
	a64_ldp_post(23, 24, A64_SP, 16);
	a64_ldp_post(21, 22, A64_SP, 16);
	a64_ldp_post(19, RSTATE, A64_SP, 16);
	a64_ldp_post(A64_FP, A64_LR, A64_SP, 16);
	a64_ret();
}

/* Emit: if lk=1, save pc+4 to PPCR_LR (bcl / bctrl / blrl semantics) */
static void emit_save_lr_if_link(uint32_t cur_pc, bool lk) {
	if (!lk) return;
	emit_load_imm32(RTMP0, (int32_t)(cur_pc + 4));
	a64_str_w_imm(RTMP0, RSTATE, PPCR_LR);
}

/* PPC indirect branch targets use the target address with the low two bits
 * ignored. Masking here keeps bclr/bcctr/blr in ISA-defined 4-byte alignment
 * without relying on any ROM- or address-specific rejection. */
static void emit_clear_branch_target_low_bits(int reg) {
	emit_load_imm32(RTMP3, (int32_t)~3u);
	emit32(0x0A000000 | (RTMP3 << 16) | (reg << 5) | reg); /* AND Wreg,Wreg,Wmask */
}

/* ---- Instruction offset map for intra-block branches ---- */
static uint32_t *insn_code_offset[512];  /* ARM64 code ptr at start of each PPC insn */
static uint32_t  insn_ppc_pc[512];       /* PPC PC of each compiled instruction */
static int       insn_count = 0;

/* ---- Lazy CR0 flags ----
 * Instead of materializing CR0 on every Rc=1 instruction (~15 ARM64 insns),
 * we defer the computation until CR0 is actually read (branch, mfcr) or
 * the block exits. The last Rc=1 result is kept as a CMP against zero in
 * the ARM64 NZCV flags register — we just remember that NZCV is valid.
 *
 * lazy_cr0_valid: true if ARM64 NZCV currently reflects the last Rc=1 result
 * lazy_cr0_reg: the ARM64 register that was CMP'd (needed for re-CMP after
 *               any instruction that clobbers NZCV)
 */
static bool lazy_cr0_valid = false;
static int  lazy_cr0_reg = -1;  /* ARM64 reg holding last Rc=1 result, -1 = none */

/* Materialize CR0 from current NZCV state (call only when lazy_cr0_valid) */
static void emit_materialize_cr0(void) {
	if (!lazy_cr0_valid) return;
	/* Re-CMP if needed — NZCV may have been clobbered by intervening insns.
	 * For safety, always re-CMP the saved register. */
	if (lazy_cr0_reg >= 0)
		emit32(0x7100001F | (lazy_cr0_reg << 5)); /* CMP Wn, #0 */

	/* Build CR0 nibble from ARM64 condition codes:
	 * CR0.LT = N, CR0.GT = !N && !Z, CR0.EQ = Z, CR0.SO = XER.SO */
	a64_movz(RTMP2, 0, 0);
	emit_load_imm32(RTMP0, 8); /* LT */
	emit_load_imm32(RTMP1, 4); /* GT */
	emit32(0x1A800000 | (RTMP2 << 16) | (0xB << 12) | (RTMP0 << 5) | RTMP2); /* CSEL RTMP2,RTMP0,RTMP2,LT */
	emit32(0x1A800000 | (RTMP2 << 16) | (0xC << 12) | (RTMP1 << 5) | RTMP2); /* CSEL RTMP2,RTMP1,RTMP2,GT */
	emit_load_imm32(RTMP0, 2); /* EQ */
	emit32(0x1A800000 | (RTMP2 << 16) | (0x0 << 12) | (RTMP0 << 5) | RTMP2); /* CSEL RTMP2,RTMP0,RTMP2,EQ */
	emit_or_xer_so_into_cr_nibble(RTMP2);
	emit_load_imm32(RTMP0, 28);
	emit32(0x1AC02000 | (RTMP0 << 16) | (RTMP2 << 5) | RTMP2); /* LSL */
	a64_ldr_w_imm(RTMP0, RSTATE, PPCR_CR);
	emit_load_imm32(RTMP1, 0x0FFFFFFF);
	emit32(0x0A000000 | (RTMP1 << 16) | (RTMP0 << 5) | RTMP0); /* AND clear CR0 */
	emit32(0x2A000000 | (RTMP2 << 16) | (RTMP0 << 5) | RTMP0); /* ORR merge */
	a64_str_w_imm(RTMP0, RSTATE, PPCR_CR);
	lazy_cr0_valid = false;
	lazy_cr0_reg = -1;
}

/* Mark CR0 as pending — keep a stable copy in x19 so later scratch use cannot clobber it. */
static void lazy_update_cr0(int result_reg) {
	a64_mov_reg(RCR0, result_reg);
	lazy_cr0_reg = RCR0;
	lazy_cr0_valid = true;
}

/* Ensure CR0 is materialized — call before branches testing CR0, mfcr, block exits */
static void lazy_flush_cr0(void) {
	if (lazy_cr0_valid)
		emit_materialize_cr0();
}

/* Get ARM64 reg for writing PPC GPR n (marks dirty, allocates if needed) */

/* Find the ARM64 code offset for a PPC PC within the current block */
static uint32_t *find_code_for_pc(uint32_t target_pc) {
	for (int i = 0; i < insn_count; i++) {
		if (insn_ppc_pc[i] == target_pc)
			return insn_code_offset[i];
	}
	return NULL;
}


/* ---- Opcode miss tracking ---- */
static uint32_t jit_miss_count[64] = {0};  /* primary opcode histogram */
static uint32_t jit_xo_miss[1024] = {0};   /* XO opcode histogram for opc=31 */
static uint32_t jit_total_miss = 0;
static uint32_t jit_total_hit = 0;
static uint32_t jit_blocks_attempted = 0;
static uint32_t jit_blocks_complete = 0;
static uint32_t jit_last_fail_op = 0;
static uint32_t jit_cum_fail_opc[64] = {0};
static uint32_t jit_cum_fail_xo31[1024] = {0};
static uint32_t jit_cum_fail_total = 0;

static void jit_report_misses(void) {
	if (jit_total_miss == 0 && jit_total_hit == 0) return;
	fprintf(stderr, "PPC-JIT-A64: blocks=%u complete=%u (%.1f%%)\n",
		jit_blocks_attempted, jit_blocks_complete,
		jit_blocks_attempted ? jit_blocks_complete * 100.0 / jit_blocks_attempted : 0.0);
	fprintf(stderr, "PPC-JIT-A64: hit=%u miss=%u (%.1f%% coverage)\n",
		jit_total_hit, jit_total_miss,
		jit_total_hit * 100.0 / (jit_total_hit + jit_total_miss));
	fprintf(stderr, "PPC-JIT-A64: top missed primary opcodes:\n");
	/* Sort and print top 10 */
	for (int pass = 0; pass < 10; pass++) {
		uint32_t max_v = 0; int max_i = -1;
		for (int i = 0; i < 64; i++) {
			if (jit_miss_count[i] > max_v) { max_v = jit_miss_count[i]; max_i = i; }
		}
		if (max_i < 0 || max_v == 0) break;
		fprintf(stderr, "  opc=%d: %u misses\n", max_i, max_v);
		jit_miss_count[max_i] = 0; /* clear for next pass */
	}
	fprintf(stderr, "PPC-JIT-A64: top missed XO opcodes (opc=31):\n");
	for (int pass = 0; pass < 10; pass++) {
		uint32_t max_v = 0; int max_i = -1;
		for (int i = 0; i < 1024; i++) {
			if (jit_xo_miss[i] > max_v) { max_v = jit_xo_miss[i]; max_i = i; }
		}
		if (max_i < 0 || max_v == 0) break;
		fprintf(stderr, "  XO=%d: %u misses\n", max_i, max_v);
		jit_xo_miss[max_i] = 0;
	}
}

/* ---- Compile one PPC instruction ---- */
static bool compile_one(uint32_t op, uint32_t pc) {
	uint32_t opc = PPC_OPC(op);
	uint32_t rd, ra, rb;
	int16_t simm;
	uint16_t uimm;

	switch (opc) {

	case 14: /* addi / li */
	{
		rd = PPC_RD(op); ra = PPC_RA(op); simm = PPC_SIMM(op);
		if (ra == 0) {
			int d = gpr_out(rd, RTMP0);
			emit_load_imm32(d, (int32_t)simm);          /* li: immediate straight into dest */
			gpr_out_commit(rd, d);
		} else {
			int s = gpr_in(ra, RTMP0);
			emit_load_imm32(RTMP1, (int32_t)simm);
			int d = gpr_out(rd, RTMP0);
			emit32(0x0B000000 | (RTMP1 << 16) | (s << 5) | d); /* ADD Wd,Wn,Wm */
			gpr_out_commit(rd, d);
		}
		return true;
	}

	case 15: /* addis / lis */
	{
		rd = PPC_RD(op); ra = PPC_RA(op); simm = PPC_SIMM(op);
		int32_t shifted_simm = (int32_t)((uint32_t)(uint16_t)simm << 16);
		if (ra == 0) {
			int d = gpr_out(rd, RTMP0);
			emit_load_imm32(d, shifted_simm);
			gpr_out_commit(rd, d);
		} else {
			int s = gpr_in(ra, RTMP0);
			emit_load_imm32(RTMP1, shifted_simm);
			int d = gpr_out(rd, RTMP0);
			emit32(0x0B000000 | (RTMP1 << 16) | (s << 5) | d);
			gpr_out_commit(rd, d);
		}
		return true;
	}

	case 23: /* rlwnm rA,rS,rB,MB,ME (rotate left word then AND mask) */
	{
		uint32_t rs = PPC_RS(op);
		ra = PPC_RA(op);
		rb = (op >> 11) & 0x1F;
		uint32_t mb = (op >> 6) & 0x1F;
		uint32_t me = (op >> 1) & 0x1F;
		int s = gpr_in(rs, RTMP0);
		int shc = gpr_in(rb, RTMP1);
		int d = gpr_out(ra, RTMP0);
		/* Rotate left by rB: NEG the count into SCRATCH (never the cached rB), then ROR */
		emit32(0x4B0003E0 | (shc << 16) | RTMP1); /* NEG RTMP1, shc (32-count) */
		emit32(0x1AC02C00 | (RTMP1 << 16) | (s << 5) | d); /* ROR d, s, RTMP1 */
		uint32_t mask = 0;
		if (mb <= me) { for (uint32_t i = mb; i <= me; i++) mask |= (0x80000000U >> i); }
		else { for (uint32_t i = 0; i <= me; i++) mask |= (0x80000000U >> i);
		       for (uint32_t i = mb; i <= 31; i++) mask |= (0x80000000U >> i); }
		if (mask != 0xFFFFFFFF) {
			emit_load_imm32(RTMP1, (int32_t)mask);
			emit32(0x0A000000 | (RTMP1 << 16) | (d << 5) | d); /* AND d, d, mask */
		}
		gpr_out_commit(ra, d);
		if (op & 1) lazy_update_cr0(d);
		return true;
	}

	case 24: /* ori (and NOP = ori 0,0,0) */
	{
		ra = PPC_RA(op); rd = PPC_RS(op); uimm = PPC_UIMM(op);
		if (rd == 0 && ra == 0 && uimm == 0) return true; /* NOP */
		int s = gpr_in(rd, RTMP0);
		int d = gpr_out(ra, RTMP0);
		if (uimm) {
			emit_load_imm32(RTMP1, (int32_t)(uint32_t)uimm);
			emit32(0x2A000000 | (RTMP1 << 16) | (s << 5) | d); /* ORR */
		} else if (d != s) {
			emit32(0x2A0003E0 | (s << 16) | d); /* MOV d, s */
		}
		gpr_out_commit(ra, d);
		return true;
	}

	case 25: /* oris */
	{
		ra = PPC_RA(op); rd = PPC_RS(op); uimm = PPC_UIMM(op);
		int s = gpr_in(rd, RTMP0);
		int d = gpr_out(ra, RTMP0);
		if (uimm) {
			emit_load_imm32(RTMP1, (int32_t)((uint32_t)uimm << 16));
			emit32(0x2A000000 | (RTMP1 << 16) | (s << 5) | d);
		} else if (d != s) {
			emit32(0x2A0003E0 | (s << 16) | d); /* MOV d, s */
		}
		gpr_out_commit(ra, d);
		return true;
	}

	case 26: /* xori rA,rS,UIMM */
	{
		ra = PPC_RA(op); rd = PPC_RS(op); uimm = PPC_UIMM(op);
		int s = gpr_in(rd, RTMP0);
		int d = gpr_out(ra, RTMP0);
		if (uimm) {
			emit_load_imm32(RTMP1, (int32_t)(uint32_t)uimm);
			emit32(0x4A000000 | (RTMP1 << 16) | (s << 5) | d); /* EOR */
		} else if (d != s) {
			emit32(0x2A0003E0 | (s << 16) | d); /* MOV d, s */
		}
		gpr_out_commit(ra, d);
		return true;
	}

	case 27: /* xoris rA,rS,UIMM */
	{
		ra = PPC_RA(op); rd = PPC_RS(op); uimm = PPC_UIMM(op);
		int s = gpr_in(rd, RTMP0);
		int d = gpr_out(ra, RTMP0);
		if (uimm) {
			emit_load_imm32(RTMP1, (int32_t)((uint32_t)uimm << 16));
			emit32(0x4A000000 | (RTMP1 << 16) | (s << 5) | d);
		} else if (d != s) {
			emit32(0x2A0003E0 | (s << 16) | d); /* MOV d, s */
		}
		gpr_out_commit(ra, d);
		return true;
	}

	case 28: /* andi. */
	{
		ra = PPC_RA(op); rd = PPC_RS(op); uimm = PPC_UIMM(op);
		int s = gpr_in(rd, RTMP0);
		int d = gpr_out(ra, RTMP0);
		emit_load_imm32(RTMP1, (int32_t)(uint32_t)uimm);
		emit32(0x0A000000 | (RTMP1 << 16) | (s << 5) | d); /* AND */
		gpr_out_commit(ra, d);
		lazy_update_cr0(d); /* andi. always updates CR0 */
		return true;
	}

	case 29: /* andis. — rA = rS & (UIMM << 16), always updates CR0 */
	{
		ra = PPC_RA(op); rd = PPC_RS(op); uimm = PPC_UIMM(op);
		int s = gpr_in(rd, RTMP0);
		int d = gpr_out(ra, RTMP0);
		emit_load_imm32(RTMP1, (int32_t)((uint32_t)uimm << 16));
		emit32(0x0A000000 | (RTMP1 << 16) | (s << 5) | d); /* AND */
		gpr_out_commit(ra, d);
		lazy_update_cr0(d);
		return true;
	}

	case 31: { /* XO-form extended opcodes */
		uint32_t xo = PPC_XO(op);
		rd = PPC_RD(op); ra = PPC_RA(op); rb = PPC_RB(op);
		switch (xo) {
		case 0: /* cmp (cmpw crD,rA,rB) — signed compare */
		{
			uint32_t crd = (op >> 23) & 0x7;
			lazy_flush_cr0();
			int s1 = gpr_in(ra, RTMP0);
			int s2 = gpr_in(rb, RTMP1);
			emit32(0x6B000000 | (s2 << 16) | (s1 << 5) | 0x1F); /* SUBS WZR,Wn,Wm */
			/* Build CR field with CSEL: signed LT/GT/EQ */
			a64_movz(RTMP0, 0, 0);
			emit_load_imm32(RTMP1, 8); /* LT */
			emit32(0x1A800000 | (RTMP0 << 16) | (0xB << 12) | (RTMP1 << 5) | RTMP0); /* CSEL LT */
			emit_load_imm32(RTMP1, 4); /* GT */
			emit32(0x1A800000 | (RTMP0 << 16) | (0xC << 12) | (RTMP1 << 5) | RTMP0); /* CSEL GT */
			emit_load_imm32(RTMP1, 2); /* EQ */
			emit32(0x1A800000 | (RTMP0 << 16) | (0x0 << 12) | (RTMP1 << 5) | RTMP0); /* CSEL EQ */
			emit_or_xer_so_into_cr_nibble(RTMP0);
			uint32_t shift = (7 - crd) * 4;
			if (shift) { emit_load_imm32(RTMP1, shift); emit32(0x1AC02000 | (RTMP1 << 16) | (RTMP0 << 5) | RTMP0); }
			lazy_flush_cr0();
			a64_ldr_w_imm(RTMP1, RSTATE, PPCR_CR);
			emit_load_imm32(RTMP2, ~(0xF << shift));
			emit32(0x0A000000 | (RTMP2 << 16) | (RTMP1 << 5) | RTMP1);
			emit32(0x2A000000 | (RTMP0 << 16) | (RTMP1 << 5) | RTMP1);
			a64_str_w_imm(RTMP1, RSTATE, PPCR_CR);
			return true;
		}
		case 266: /* add / add. */
		case 778: /* addo / addo. */
		{
			int s1 = gpr_in(ra, RTMP0);
			int s2 = gpr_in(rb, RTMP1);
			int d  = gpr_out(rd, RTMP0);
			if (xo == 778) {
				emit32(0x2B000000 | (s2 << 16) | (s1 << 5) | d); /* ADDS */
				gpr_out_commit(rd, d);
				emit_write_xer_ov_so_from_overflow();
			} else {
				emit32(0x0B000000 | (s2 << 16) | (s1 << 5) | d); /* ADD */
				gpr_out_commit(rd, d);
			}
			if (op & 1) lazy_update_cr0(d);
			return true;
		}
		case 40: /* subf (rD = rB - rA) */
		case 552: /* subfo / subfo. */
		{
			int s1 = gpr_in(rb, RTMP0); /* minuend */
			int s2 = gpr_in(ra, RTMP1); /* subtrahend */
			int d  = gpr_out(rd, RTMP0);
			if (xo == 552) {
				emit32(0x6B000000 | (s2 << 16) | (s1 << 5) | d); /* SUBS */
				gpr_out_commit(rd, d);
				emit_write_xer_ov_so_from_overflow();
			} else {
				emit32(0x4B000000 | (s2 << 16) | (s1 << 5) | d); /* SUB */
				gpr_out_commit(rd, d);
			}
			if (op & 1) lazy_update_cr0(d);
			return true;
		}
		case 28: /* and */
		{
			int s1 = gpr_in(PPC_RS(op), RTMP0);
			int s2 = gpr_in(rb, RTMP1);
			int d  = gpr_out(ra, RTMP0);
			emit32(0x0A000000 | (s2 << 16) | (s1 << 5) | d); /* AND */
			gpr_out_commit(ra, d);
			if (op & 1) lazy_update_cr0(d);
			return true;
		}
		case 444: /* or / or. (also mr) */
		{
			int s1 = gpr_in(PPC_RS(op), RTMP0);
			int s2 = gpr_in(rb, RTMP1);
			int d  = gpr_out(ra, RTMP0);
			emit32(0x2A000000 | (s2 << 16) | (s1 << 5) | d); /* ORR */
			gpr_out_commit(ra, d);
			if (op & 1) lazy_update_cr0(d);
			return true;
		}
		case 316: /* xor */
		{
			int s1 = gpr_in(PPC_RS(op), RTMP0);
			int s2 = gpr_in(rb, RTMP1);
			int d  = gpr_out(ra, RTMP0);
			emit32(0x4A000000 | (s2 << 16) | (s1 << 5) | d); /* EOR */
			gpr_out_commit(ra, d);
			if (op & 1) lazy_update_cr0(d);
			return true;
		}
		case 104: /* neg / neg. */
		{
			int s = gpr_in(ra, RTMP0);
			int d = gpr_out(rd, RTMP0);
			emit32(0x4B0003E0 | (s << 16) | d); /* NEG d, s = SUB d, WZR, s */
			gpr_out_commit(rd, d);
			if (op & 1) lazy_update_cr0(d);
			return true;
		}
		case 26: /* cntlzw */
		{
			int s = gpr_in(PPC_RS(op), RTMP0);
			int d = gpr_out(ra, RTMP0);
			emit32(0x5AC01000 | (s << 5) | d); /* CLZ Wd, Wn */
			gpr_out_commit(ra, d);
			if (op & 1) lazy_update_cr0(d);
			return true;
		}
		case 922: /* extsh */
		{
			int s = gpr_in(PPC_RS(op), RTMP0);
			int d = gpr_out(ra, RTMP0);
			emit32(0x13003C00 | (s << 5) | d); /* SXTH Wd, Wn */
			gpr_out_commit(ra, d);
			if (op & 1) lazy_update_cr0(d);
			return true;
		}
		case 954: /* extsb */
		{
			int s = gpr_in(PPC_RS(op), RTMP0);
			int d = gpr_out(ra, RTMP0);
			emit32(0x13001C00 | (s << 5) | d); /* SXTB Wd, Wn */
			gpr_out_commit(ra, d);
			if (op & 1) lazy_update_cr0(d);
			return true;
		}
		case 747: /* mullwo / mullwo. (OE bit set) */
			emit_load_gpr(RTMP0, ra);
			emit_load_gpr(RTMP1, rb);
			/* SMULL Xprod,Wra,Wrb; overflow if sign_extend(low32) != product. */
			emit32(0x9B200000 | (RTMP1 << 16) | (31 << 10) | (RTMP0 << 5) | RTMP3); /* SMULL */
			emit_store_gpr(RTMP3, rd);
			emit32(0x93407C00 | (RTMP3 << 5) | RTMP4); /* SXTW Xtmp,Wprod */
			emit32(0xEB00001F | (RTMP3 << 16) | (RTMP4 << 5)); /* CMP Xtmp,Xprod */
			emit32(0x1A9F07E0 | RTMP2); /* CSET Wov,NE */
			emit_write_xer_ov_so_from_reg(RTMP2);
			if (op & 1) lazy_update_cr0(RTMP3);
			return true;
		case 235: /* mullw */
			emit_load_gpr(RTMP0, ra);
			emit_load_gpr(RTMP1, rb);
			emit32(0x1B007C00 | (RTMP1 << 16) | (RTMP0 << 5) | RTMP0); /* MUL Wd,Wn,Wm */
			emit_store_gpr(RTMP0, rd);
			if (op & 1) lazy_update_cr0(RTMP0);
			return true;
		case 491: /* divw */
			/* Match the interpreter on the architecturally-undefined cases
			 * (divisor==0, or dividend==INT_MIN && divisor==-1): a real PPC fills the
			 * result with the dividend's sign bit (dividend>>31). Plain AArch64 SDIV
			 * instead yields 0 / INT_MIN there, so select the sign-fill explicitly.
			 * Same predicate/result as divwo below, without the OV write. */
			emit_load_gpr(RTMP0, ra);
			emit_load_gpr(RTMP1, rb);
			emit_cmp_w_imm(RTMP1, 0);
			emit32(0x1A9F17E0 | RTMP2); /* CSET RTMP2, EQ (divisor==0) */
			emit_load_imm32(RTMP3, (int32_t)0x80000000u);
			emit32(0x6B000000 | (RTMP3 << 16) | (RTMP0 << 5) | 31); /* CMP dividend, INT_MIN */
			emit32(0x1A9F17E0 | RTMP3); /* CSET RTMP3, EQ */
			emit_load_imm32(RTMP4, -1);
			emit32(0x6B000000 | (RTMP4 << 16) | (RTMP1 << 5) | 31); /* CMP divisor, -1 */
			emit32(0x1A9F17E0 | RTMP4); /* CSET RTMP4, EQ */
			emit32(0x0A000000 | (RTMP4 << 16) | (RTMP3 << 5) | RTMP3); /* AND (INT_MIN && -1) */
			emit32(0x2A000000 | (RTMP3 << 16) | (RTMP2 << 5) | RTMP2); /* OR -> special predicate RTMP2 */
			emit32(0x1AC00C00 | (RTMP1 << 16) | (RTMP0 << 5) | RTMP3); /* SDIV RTMP3 = a/b */
			emit_load_gpr(RTMP4, ra);
			emit32(0x131F7C00 | (RTMP4 << 5) | RTMP4); /* RTMP4 = (int32)dividend >> 31 (ASR #31) */
			emit_cmp_w_imm(RTMP2, 0);
			emit32(0x1A800000 | (RTMP3 << 16) | (0x1 << 12) | (RTMP4 << 5) | RTMP0); /* CSEL RTMP0 = NE ? signfill : sdiv */
			emit_store_gpr(RTMP0, rd);
			if (op & 1) lazy_update_cr0(RTMP0);
			return true;
		case 1003: /* divwo / divwo. */
			emit_load_gpr(RTMP0, ra); /* dividend */
			emit_load_gpr(RTMP1, rb); /* divisor */
			/* overflow = divisor==0 || (dividend==INT_MIN && divisor==-1) */
			emit_cmp_w_imm(RTMP1, 0);
			emit32(0x1A9F17E0 | RTMP2); /* CSET RTMP2, EQ */
			emit_load_imm32(RTMP3, (int32_t)0x80000000u);
			emit32(0x6B000000 | (RTMP3 << 16) | (RTMP0 << 5) | 31); /* CMP dividend,INT_MIN */
			emit32(0x1A9F17E0 | RTMP3); /* CSET RTMP3, EQ */
			emit_load_imm32(RTMP4, -1);
			emit32(0x6B000000 | (RTMP4 << 16) | (RTMP1 << 5) | 31); /* CMP divisor,-1 */
			emit32(0x1A9F17E0 | RTMP4); /* CSET RTMP4, EQ */
			emit32(0x0A000000 | (RTMP4 << 16) | (RTMP3 << 5) | RTMP3); /* AND min && -1 */
			emit32(0x2A000000 | (RTMP3 << 16) | (RTMP2 << 5) | RTMP2); /* OR overflow */
			emit32(0x1AC00C00 | (RTMP1 << 16) | (RTMP0 << 5) | RTMP3); /* normal SDIV */
			emit_load_gpr(RTMP4, ra);
			emit32(0x131F7C00 | (RTMP4 << 5) | RTMP4); /* special result = dividend >> 31 */
			emit_cmp_w_imm(RTMP2, 0);
			emit32(0x1A800000 | (RTMP3 << 16) | (0x1 << 12) | (RTMP4 << 5) | RTMP0); /* CSEL special:normal, NE */
			emit_store_gpr(RTMP0, rd);
			emit_write_xer_ov_so_from_reg(RTMP2);
			if (op & 1) lazy_update_cr0(RTMP0);
			return true;
		case 19: /* mfcr rD */
			lazy_flush_cr0();
			a64_ldr_w_imm(RTMP0, RSTATE, PPCR_CR);
			emit_store_gpr(RTMP0, rd);
			return true;
		case 144: /* mtcrf CRM,rS */
		{
			uint32_t crm = (op >> 12) & 0xFF;
			lazy_flush_cr0();
			emit_load_gpr(RTMP0, PPC_RS(op));
			if (crm == 0xFF) {
				/* Move entire CR */
				a64_str_w_imm(RTMP0, RSTATE, PPCR_CR);
			} else {
				/* Selective CR field update */
				uint32_t mask = 0;
				for (int i = 0; i < 8; i++)
					if (crm & (0x80 >> i)) mask |= (0xF0000000U >> (i * 4));
				lazy_flush_cr0();
				a64_ldr_w_imm(RTMP1, RSTATE, PPCR_CR);
				emit_load_imm32(RTMP2, (int32_t)~mask);
				emit32(0x0A000000 | (RTMP2 << 16) | (RTMP1 << 5) | RTMP1); /* AND clear */
				emit_load_imm32(RTMP2, (int32_t)mask);
				emit32(0x0A000000 | (RTMP2 << 16) | (RTMP0 << 5) | RTMP0); /* AND source */
				emit32(0x2A000000 | (RTMP0 << 16) | (RTMP1 << 5) | RTMP1); /* ORR */
				a64_str_w_imm(RTMP1, RSTATE, PPCR_CR);
			}
			return true;
		}
		case 339: /* mfspr */
		{
			uint32_t spr = ((op >> 16) & 0x1F) | ((op >> 6) & 0x3E0);
			if (spr == 8) { /* LR */
				a64_ldr_w_imm(RTMP0, RSTATE, PPCR_LR);
				emit_store_gpr(RTMP0, rd);
				return true;
			}
			if (spr == 9) { /* CTR */
				a64_ldr_w_imm(RTMP0, RSTATE, PPCR_CTR);
				emit_store_gpr(RTMP0, rd);
				return true;
			}
			if (spr == 1) { /* XER — pack {so,ov,ca,byte_count} into PPC format */
				emit32(0x39400000 | (PPCR_XER_SO << 10) | (RSTATE << 5) | RTMP0); /* LDRB so */
				emit_load_imm32(RTMP1, 31);
				emit32(0x1AC02000 | (RTMP1 << 16) | (RTMP0 << 5) | RTMP0); /* LSL #31 */
				emit32(0x39400000 | (PPCR_XER_OV << 10) | (RSTATE << 5) | RTMP1); /* LDRB ov */
				emit32(0x2A01781E | (RTMP1 << 16) | (RTMP0 << 5) | RTMP0); /* ORR Wd, Wd, Wm LSL #30... */
				/* Actually: build it step by step */
				a64_movz(RTMP0, 0, 0);
				emit32(0x39400000 | (PPCR_XER_SO << 10) | (RSTATE << 5) | RTMP1);
				emit_load_imm32(RTMP2, 31); emit32(0x1AC02000 | (RTMP2 << 16) | (RTMP1 << 5) | RTMP1);
				emit32(0x2A000000 | (RTMP1 << 16) | (RTMP0 << 5) | RTMP0);
				emit32(0x39400000 | (PPCR_XER_OV << 10) | (RSTATE << 5) | RTMP1);
				emit_load_imm32(RTMP2, 30); emit32(0x1AC02000 | (RTMP2 << 16) | (RTMP1 << 5) | RTMP1);
				emit32(0x2A000000 | (RTMP1 << 16) | (RTMP0 << 5) | RTMP0);
				emit32(0x39400000 | (PPCR_XER_CA << 10) | (RSTATE << 5) | RTMP1);
				emit_load_imm32(RTMP2, 29); emit32(0x1AC02000 | (RTMP2 << 16) | (RTMP1 << 5) | RTMP1);
				emit32(0x2A000000 | (RTMP1 << 16) | (RTMP0 << 5) | RTMP0);
				emit32(0x39400000 | (PPCR_XER_CNT << 10) | (RSTATE << 5) | RTMP1);
				emit32(0x2A000000 | (RTMP1 << 16) | (RTMP0 << 5) | RTMP0);
				emit_store_gpr(RTMP0, rd);
				return true;
			}
			if (spr == 25) { /* SDR1 — SheepShaver interpreter returns a sentinel */
				emit_load_imm32(RTMP0, (int32_t)0xdead001fU);
				emit_store_gpr(RTMP0, rd);
				return true;
			}
			if (spr == 256) { /* VRSAVE */
				a64_ldr_w_imm(RTMP0, RSTATE, PPCR_VRSAVE);
				emit_store_gpr(RTMP0, rd);
				return true;
			}
			if (spr == 287) { /* PVR — must match interpreter's PVR value */
				extern uint32_t PVR;
				emit_load_imm32(RTMP0, (int32_t)PVR);
				emit_store_gpr(RTMP0, rd);
				return true;
			}
			/* SheepShaver interpreter returns zero for unsupported SPR reads. */
			a64_movz(RTMP0, 0, 0);
			emit_store_gpr(RTMP0, rd);
			return true;
		}
		case 467: /* mtspr */
		{
			uint32_t spr = ((op >> 16) & 0x1F) | ((op >> 6) & 0x3E0);
			if (spr == 8) { /* LR */
				emit_load_gpr(RTMP0, PPC_RS(op));
				a64_str_w_imm(RTMP0, RSTATE, PPCR_LR);
				return true;
			}
			if (spr == 9) { /* CTR */
				emit_load_gpr(RTMP0, PPC_RS(op));
				a64_str_w_imm(RTMP0, RSTATE, PPCR_CTR);
				return true;
			}
			if (spr == 256) { /* VRSAVE */
				emit_load_gpr(RTMP0, PPC_RS(op));
				a64_str_w_imm(RTMP0, RSTATE, PPCR_VRSAVE);
				return true;
			}
			if (spr == 1) { /* XER — unpack PPC format into {so,ov,ca,byte_count} */
				emit_load_gpr(RTMP0, PPC_RS(op));
				/* SO = bit 31 */
				a64_mov_reg(RTMP1, RTMP0);
				emit_load_imm32(RTMP2, 31); emit32(0x1AC02400 | (RTMP2 << 16) | (RTMP1 << 5) | RTMP1);
				emit32(0x39000000 | (PPCR_XER_SO << 10) | (RSTATE << 5) | RTMP1);
				/* OV = bit 30 */
				a64_mov_reg(RTMP1, RTMP0);
				emit_load_imm32(RTMP2, 30); emit32(0x1AC02400 | (RTMP2 << 16) | (RTMP1 << 5) | RTMP1);
				emit32(0x12000000 | (RTMP1 << 5) | RTMP1); /* AND #1 */
				emit32(0x39000000 | (PPCR_XER_OV << 10) | (RSTATE << 5) | RTMP1);
				/* CA = bit 29 */
				a64_mov_reg(RTMP1, RTMP0);
				emit_load_imm32(RTMP2, 29); emit32(0x1AC02400 | (RTMP2 << 16) | (RTMP1 << 5) | RTMP1);
				emit32(0x12000000 | (RTMP1 << 5) | RTMP1); /* AND #1 */
				emit32(0x39000000 | (PPCR_XER_CA << 10) | (RSTATE << 5) | RTMP1);
				/* byte_count = bits 6:0 */
				a64_mov_reg(RTMP1, RTMP0);
				emit_load_imm32(RTMP2, 0x7F); emit32(0x0A000000 | (RTMP2 << 16) | (RTMP1 << 5) | RTMP1);
				emit32(0x39000000 | (PPCR_XER_CNT << 10) | (RSTATE << 5) | RTMP1);
				return true;
			}
			/* SheepShaver interpreter ignores unsupported SPR writes. */
			return true;
		}
		case 824: /* srawi rA,rS,SH (arithmetic shift right immediate, set CA) */
		{
			uint32_t sh = (op >> 11) & 0x1F;
			uint32_t rs = PPC_RS(op);
			emit_load_gpr(RTMP0, rs);
			if (sh == 0) {
				emit_store_gpr(RTMP0, ra);
				emit_set_xer_ca(0);
			} else {
				/* CA = (rS < 0) && ((rS & ((1<<sh)-1)) != 0) */
				/* Save original for CA computation */
				a64_mov_reg(RTMP1, RTMP0); /* RTMP1 = original rS */
				/* ASR Wd, Wn, #sh = SBFM Wd,Wn,#sh,#31 */
				emit32(0x13000000 | (sh << 16) | (0x1F << 10) | (RTMP0 << 5) | RTMP0);
				emit_store_gpr(RTMP0, ra);
				/* Compute CA: test if source negative AND shifted-out bits nonzero */
				/* RTMP1 = original rS. Mask = (1<<sh)-1 */
				uint32_t mask = (1u << sh) - 1;
				emit_load_imm32(RTMP2, (int32_t)mask);
				emit32(0x6A000000 | (RTMP2 << 16) | (RTMP1 << 5) | 0x1F); /* TST Wn, mask (= ANDS WZR) */
				/* If Z=0 (bits nonzero) and rS < 0: CA=1 */
				/* Use: shifted_out_nonzero = (TST result != 0) = !Z */
				/* negative = (rS >> 31) */
				/* CA = shifted_out_nonzero & negative */
				a64_movz(RTMP0, 0, 0);
				emit_load_imm32(RTMP2, 1);
				/* CSEL RTMP0, 1, 0, NE (if shifted-out bits nonzero) */
				emit32(0x1A800000 | (RTMP0 << 16) | (0x1 << 12) | (RTMP2 << 5) | RTMP0);
				/* AND with sign bit of original */
				emit32(0x13010000 | (31 << 10) | (RTMP1 << 5) | RTMP1 | (31 << 16)); /* UBFX Wd, Wn, #31, #1 */
				emit32(0x0A000000 | (RTMP1 << 16) | (RTMP0 << 5) | RTMP0); /* AND */
				/* RTMP0 = CA value (0 or 1). Write to XER.CA byte */
				emit32(0x39000000 | (PPCR_XER_CA << 10) | (RSTATE << 5) | RTMP0); /* STRB */
			}
			if (op & 1) { emit_load_gpr(RTMP0, ra); lazy_update_cr0(RTMP0); }
			return true;
		}
		case 24: /* slw rA,rS,rB (shift left word) */
		{
			emit_load_gpr(RTMP0, PPC_RS(op));
			emit_load_gpr(RTMP1, rb);
			/* PPC slw uses a 6-bit shift amount (rB&0x3f); shift>=32 yields 0. ARM 32-bit
			 * LSL masks to 5 bits (wrong for 32..63). Use a 64-bit shift of the zero-
			 * extended operand: shifts of 32..63 push all bits out of the low word -> 0. */
			emit32(0x9AC02000 | (RTMP1 << 16) | (RTMP0 << 5) | RTMP0); /* LSLV Xd,Xn,Xm (64-bit) */
			emit_store_gpr(RTMP0, ra);
			if (op & 1) lazy_update_cr0(RTMP0); /* slw. updates CR0 (32-bit result; materialize uses CMP Wn) */
			return true;
		}
		case 536: /* srw rA,rS,rB (shift right word) */
		{
			emit_load_gpr(RTMP0, PPC_RS(op));
			emit_load_gpr(RTMP1, rb);
			/* PPC srw: 6-bit shift amount; shift>=32 yields 0. emit_load_gpr zero-extends
			 * rS into the full X reg, so a 64-bit LSR of 32..63 produces 0 in the low word. */
			emit32(0x9AC02400 | (RTMP1 << 16) | (RTMP0 << 5) | RTMP0); /* LSRV Xd,Xn,Xm (64-bit) */
			emit_store_gpr(RTMP0, ra);
			if (op & 1) lazy_update_cr0(RTMP0); /* srw. updates CR0 */
			return true;
		}
		case 792: /* sraw rA,rS,rB (arithmetic shift right, set CA) */
		{
			uint32_t rs = PPC_RS(op);
			emit_load_gpr(RTMP0, rs);
			emit_load_gpr(RTMP1, rb);
			/* PPC sraw uses a 6-bit shift (rB&0x3f); shift>=32 -> result = full sign-extend.
			 * 32-bit ARM ASR masks the amount to 5 bits (wrong for 32..63, e.g. returning
			 * 0xFFFFFFFF mis-shifted). Sign-extend rS to 64-bit and arithmetic-shift in 64-bit:
			 * 32..63 then naturally yields all-sign in the low word. */
			emit32(0x93407C00 | (RTMP0 << 5) | RTMP0); /* SXTW Xd,Wn: sign-extend rS to 64-bit */
			a64_mov_reg(RTMP2, RTMP0); /* RTMP2 = sign-extended rS (for CA) */
			emit32(0x9AC02800 | (RTMP1 << 16) | (RTMP0 << 5) | RTMP0); /* ASRV Xd,Xn,Xm (64-bit) */
			emit_store_gpr(RTMP0, ra); /* low 32 bits = result */
			/* CA = (rS<0) && (any 1-bit shifted out) = sign(rS) && ((result<<sh) != sext(rS)),
			 * reconstructed+compared in 64-bit so shift>=32 is handled correctly. */
			emit32(0x9AC02000 | (RTMP1 << 16) | (RTMP0 << 5) | RTMP0); /* LSLV Xd,result,sh (64-bit) */
			emit32(0xEB000000 | (RTMP2 << 16) | (RTMP0 << 5) | 0x1F); /* CMP Xn(recon),Xm(sext rS) (64-bit) */
			a64_movz(RTMP0, 0, 0);
			emit_load_imm32(RTMP1, 1);
			emit32(0x1A800000 | (RTMP0 << 16) | (0x1 << 12) | (RTMP1 << 5) | RTMP0); /* CSEL RTMP0 = NE ? 1 : 0 */
			emit32(0x53010000 | (RTMP2 << 5) | RTMP2 | (31 << 10) | (31 << 16)); /* UBFX RTMP2,RTMP2,#31,#1 (sign bit) */
			emit32(0x0A000000 | (RTMP2 << 16) | (RTMP0 << 5) | RTMP0); /* AND: CA &= sign(rS) */
			emit32(0x39000000 | (PPCR_XER_CA << 10) | (RSTATE << 5) | RTMP0); /* STRB CA */
			if (op & 1) { emit_load_gpr(RTMP0, ra); lazy_update_cr0(RTMP0); }
			return true;
		}

		case 32: /* cmpl (cmplw crD,rA,rB) */
		{
			uint32_t crd = (op >> 23) & 0x7;
			lazy_flush_cr0();
			int s1 = gpr_in(ra, RTMP0);
			int s2 = gpr_in(rb, RTMP1);
			emit32(0x6B000000 | (s2 << 16) | (s1 << 5) | 0x1F);
			a64_movz(RTMP2, 0, 0);
			emit_load_imm32(RTMP0, 8);
			emit32(0x1A800000 | (RTMP2 << 16) | (0x3 << 12) | (RTMP0 << 5) | RTMP2); /* CC=LT */
			emit_load_imm32(RTMP0, 4);
			emit32(0x1A800000 | (RTMP2 << 16) | (0x8 << 12) | (RTMP0 << 5) | RTMP2); /* HI=GT */
			emit_load_imm32(RTMP0, 2);
			emit32(0x1A800000 | (RTMP2 << 16) | (0x0 << 12) | (RTMP0 << 5) | RTMP2); /* EQ */
			/* OR in XER[SO] as bit 0 */
			emit_or_xer_so_into_cr_nibble(RTMP2);
			uint32_t shift = (7 - crd) * 4;
			if (shift) { emit_load_imm32(RTMP0, shift); emit32(0x1AC02000 | (RTMP0 << 16) | (RTMP2 << 5) | RTMP2); }
			lazy_flush_cr0();
			a64_ldr_w_imm(RTMP0, RSTATE, PPCR_CR);
			emit_load_imm32(RTMP1, ~(0xF << shift));
			emit32(0x0A000000 | (RTMP1 << 16) | (RTMP0 << 5) | RTMP0);
			emit32(0x2A000000 | (RTMP2 << 16) | (RTMP0 << 5) | RTMP0);
			a64_str_w_imm(RTMP0, RSTATE, PPCR_CR);
			return true;
		}

		case 23: /* lwzx rD,rA,rB */
			/* Materialize any pending CR0 FIRST: emit_materialize_cr0 clobbers
			 * RTMP0/1/2, so flushing after building the EA in RTMP0 would corrupt
			 * it (a prior addic. leaves CR0=GT -> 0x40000000, the bad EA seen). */
			lazy_flush_cr0();
			emit_load_gpr(RTMP0, ra == 0 ? rb : ra);
			if (ra != 0) {
				emit_load_gpr(RTMP1, rb);
				emit32(0x0B000000 | (RTMP1 << 16) | (RTMP0 << 5) | RTMP0);
			}
			ra_flush_all();
			emit_load_gpr(RTMP1, rd);
			emit_load_imm64(RTMP4, (uint64_t)(uintptr_t)sheepshaver_jit_safe_lwz);
			emit32(0xD63F0000 | (RTMP4 << 5));
			ra_reset();
			emit_store_gpr(RTMP0, rd);
			return true;

		case 151: /* stwx rS,rA,rB */
			/* CR0 first: emit_materialize_cr0 clobbers RTMP0/1/2 (see lwzx). */
			lazy_flush_cr0();
			emit_load_gpr(RTMP1, PPC_RS(op));
			emit_load_gpr(RTMP0, ra == 0 ? rb : ra);
			if (ra != 0) {
				emit_load_gpr(RTMP2, rb);
				emit32(0x0B000000 | (RTMP2 << 16) | (RTMP0 << 5) | RTMP0);
			}
			ra_flush_all();
			emit_load_imm64(RTMP4, (uint64_t)(uintptr_t)sheepshaver_jit_safe_stw);
			emit32(0xD63F0000 | (RTMP4 << 5));
			ra_reset();
			return true;

		case 8: /* subfc rD,rA,rB (rD = rB - rA, set CA) */
		case 520: /* subfco / subfco. */
			emit_load_gpr(RTMP0, rb);
			emit_load_gpr(RTMP1, ra);
			emit32(0x6B000000 | (RTMP1 << 16) | (RTMP0 << 5) | RTMP0); /* SUBS */
			emit_store_gpr(RTMP0, rd);
			emit_write_xer_ca_from_carry();
			if (xo == 520) emit_write_xer_ov_so_from_overflow();
			if (op & 1) lazy_update_cr0(RTMP0);
			return true;
		case 136: /* subfe rD,rA,rB (rD = ~rA + rB + CA) */
		case 648: /* subfeo / subfeo. */
			emit_load_gpr(RTMP0, ra);
			emit32(0x2A2003E0 | (RTMP0 << 16) | RTMP0); /* MVN (NOT rA) */
			emit_load_gpr(RTMP1, rb);
			emit_read_xer_ca(RTMP2);
			emit32(0x7100001F | (1 << 10) | (RTMP2 << 5)); /* CMP Wca,#1: ARM C = XER.CA */
			emit32(0x3A000000 | (RTMP1 << 16) | (RTMP0 << 5) | RTMP0); /* ADCS ~rA+rB+CA */
			emit_store_gpr(RTMP0, rd);
			emit_write_xer_ca_from_carry();
			if (xo == 648) emit_write_xer_ov_so_from_overflow();
			if (op & 1) lazy_update_cr0(RTMP0);
			return true;
		case 10: /* addc rD,rA,rB (set CA) */
		case 522: /* addco / addco. */
			emit_load_gpr(RTMP0, ra);
			emit_load_gpr(RTMP1, rb);
			emit32(0x2B000000 | (RTMP1 << 16) | (RTMP0 << 5) | RTMP0); /* ADDS */
			emit_store_gpr(RTMP0, rd);
			emit_write_xer_ca_from_carry();
			if (xo == 522) emit_write_xer_ov_so_from_overflow();
			if (op & 1) lazy_update_cr0(RTMP0);
			return true;
		case 138: /* adde rD,rA,rB (rD = rA + rB + CA) */
		case 650: /* addeo / addeo. */
			emit_load_gpr(RTMP0, ra);
			emit_load_gpr(RTMP1, rb);
			emit_read_xer_ca(RTMP2);
			emit32(0x7100001F | (1 << 10) | (RTMP2 << 5)); /* CMP Wca,#1: ARM C = XER.CA */
			emit32(0x3A000000 | (RTMP1 << 16) | (RTMP0 << 5) | RTMP0); /* ADCS rA+rB+CA */
			emit_store_gpr(RTMP0, rd);
			emit_write_xer_ca_from_carry();
			if (xo == 650) emit_write_xer_ov_so_from_overflow();
			if (op & 1) lazy_update_cr0(RTMP0);
			return true;
		case 234: /* addme rD,rA (rD = rA + CA - 1, set CA) */
		{
			/* rA + 0xFFFFFFFF + CA. Mirror adde: preset ARM C = XER.CA, then a SINGLE
			 * ADCS so the carry is counted exactly once (the old ADDS+ADCS chain
			 * double-counted the first add's carry -> wrong result and wrong CA). */
			emit_load_gpr(RTMP0, ra);
			emit_load_imm32(RTMP1, -1); /* 0xFFFFFFFF */
			emit_read_xer_ca(RTMP2);
			emit32(0x7100001F | (1 << 10) | (RTMP2 << 5)); /* CMP Wca,#1: ARM C = XER.CA */
			emit32(0x3A000000 | (RTMP1 << 16) | (RTMP0 << 5) | RTMP0); /* ADCS Wd = rA + 0xFFFFFFFF + CA */
			emit_store_gpr(RTMP0, rd);
			emit_write_xer_ca_from_carry();
			if (op & 1) lazy_update_cr0(RTMP0);
			return true;
		}
		case 202: /* addze rD,rA (rD = rA + CA, set CA) */
		{
			emit_load_gpr(RTMP0, ra);
			emit_read_xer_ca(RTMP1); /* RTMP1 = CA (0 or 1) */
			emit32(0x2B000000 | (RTMP1 << 16) | (RTMP0 << 5) | RTMP0); /* ADDS Wd, rA, CA */
			emit_store_gpr(RTMP0, rd);
			emit_write_xer_ca_from_carry();
			if (op & 1) lazy_update_cr0(RTMP0);
			return true;
		}
		case 232: /* subfme rD,rA (rD = ~rA + CA - 1, set CA) */
		{
			/* ~rA + 0xFFFFFFFF + CA. Same single-ADCS pattern as addme. */
			emit_load_gpr(RTMP0, ra);
			emit32(0x2A2003E0 | (RTMP0 << 16) | RTMP0); /* MVN Wd, Wn = ~rA */
			emit_load_imm32(RTMP1, -1); /* 0xFFFFFFFF */
			emit_read_xer_ca(RTMP2);
			emit32(0x7100001F | (1 << 10) | (RTMP2 << 5)); /* CMP Wca,#1: ARM C = XER.CA */
			emit32(0x3A000000 | (RTMP1 << 16) | (RTMP0 << 5) | RTMP0); /* ADCS Wd = ~rA + 0xFFFFFFFF + CA */
			emit_store_gpr(RTMP0, rd);
			emit_write_xer_ca_from_carry();
			if (op & 1) lazy_update_cr0(RTMP0);
			return true;
		}
		case 200: /* subfze rD,rA (rD = ~rA + CA, set CA) */
		{
			emit_load_gpr(RTMP0, ra);
			emit32(0x2A2003E0 | (RTMP0 << 16) | RTMP0); /* MVN = ~rA */
			emit_read_xer_ca(RTMP1);
			emit32(0x2B000000 | (RTMP1 << 16) | (RTMP0 << 5) | RTMP0); /* ADDS Wd, ~rA, CA */
			emit_store_gpr(RTMP0, rd);
			emit_write_xer_ca_from_carry();
			if (op & 1) lazy_update_cr0(RTMP0);
			return true;
		}
		case 476: /* nand rA,rS,rB  (rA = ~(rS & rB)) */
		{
			int s1 = gpr_in(PPC_RS(op), RTMP0);
			int s2 = gpr_in(rb, RTMP1);
			int d  = gpr_out(ra, RTMP0);
			emit32(0x0A000000 | (s2 << 16) | (s1 << 5) | d); /* AND d = rS & rB */
			emit32(0x2A2003E0 | (d << 16) | d); /* MVN d = ~(rS & rB) */
			gpr_out_commit(ra, d);
			if (op & 1) lazy_update_cr0(d);
			return true;
		}
		case 124: /* nor rA,rS,rB */
		{
			int s1 = gpr_in(PPC_RS(op), RTMP0);
			int s2 = gpr_in(rb, RTMP1);
			int d  = gpr_out(ra, RTMP0);
			emit32(0x2A000000 | (s2 << 16) | (s1 << 5) | d); /* ORR */
			emit32(0x2A2003E0 | (d << 16) | d); /* MVN */
			gpr_out_commit(ra, d);
			if (op & 1) lazy_update_cr0(d);
			return true;
		}
		case 284: /* eqv rA,rS,rB (XNOR) */
		{
			int s1 = gpr_in(PPC_RS(op), RTMP0);
			int s2 = gpr_in(rb, RTMP1);
			int d  = gpr_out(ra, RTMP0);
			emit32(0x4A000000 | (s2 << 16) | (s1 << 5) | d); /* EOR */
			emit32(0x2A2003E0 | (d << 16) | d); /* MVN */
			gpr_out_commit(ra, d);
			if (op & 1) lazy_update_cr0(d);
			return true;
		}
		case 60: /* andc rA,rS,rB */
		{
			int s1 = gpr_in(PPC_RS(op), RTMP0);
			int s2 = gpr_in(rb, RTMP1);
			int d  = gpr_out(ra, RTMP0);
			emit32(0x0A200000 | (s2 << 16) | (s1 << 5) | d); /* BIC d = rS & ~rB */
			gpr_out_commit(ra, d);
			if (op & 1) lazy_update_cr0(d);
			return true;
		}
		case 412: /* orc rA,rS,rB */
		{
			int s1 = gpr_in(PPC_RS(op), RTMP0);
			int s2 = gpr_in(rb, RTMP1);
			int d  = gpr_out(ra, RTMP0);
			emit32(0x2A200000 | (s2 << 16) | (s1 << 5) | d); /* ORN d = rS | ~rB */
			gpr_out_commit(ra, d);
			if (op & 1) lazy_update_cr0(d);
			return true;
		}
		case 459: /* divwu rD,rA,rB (unsigned divide) */
		case 971: /* divwuo / divwuo. */
			emit_load_gpr(RTMP0, ra);
			emit_load_gpr(RTMP1, rb);
			/* The ARM64 UDIV result for divisor zero is architecturally zero; PPC
			 * leaves the result undefined for divide overflow, so only XER.OV/SO
			 * need to be made architecturally visible for the OE form. */
			emit_cmp_w_imm(RTMP1, 0);
			emit32(0x1A9F17E0 | RTMP2); /* CSET RTMP2, EQ (divisor zero) */
			emit32(0x1AC00800 | (RTMP1 << 16) | (RTMP0 << 5) | RTMP0); /* UDIV Wd,Wn,Wm */
			emit_store_gpr(RTMP0, rd);
			if (xo == 971) emit_write_xer_ov_so_from_reg(RTMP2);
			if (op & 1) lazy_update_cr0(RTMP0);
			return true;
		case 75: /* mulhw rD,rA,rB (high word of signed multiply) */
			emit_load_gpr(RTMP0, ra);
			emit_load_gpr(RTMP1, rb);
			/* SMULL Xd, Wn, Wm then LSR Xd, Xd, #32 (sign already encoded in 64-bit product) */
			emit32(0x9B207C00 | (RTMP1 << 16) | (RTMP0 << 5) | RTMP0); /* SMULL */
			emit32(0xD360FC00 | (RTMP0 << 5) | RTMP0); /* LSR Xd, Xn, #32 */
			emit_store_gpr(RTMP0, rd);
			if (op & 1) lazy_update_cr0(RTMP0);
			return true;
		case 11: /* mulhwu rD,rA,rB (high word of unsigned multiply) */
			emit_load_gpr(RTMP0, ra);
			emit_load_gpr(RTMP1, rb);
			emit32(0x9BA07C00 | (RTMP1 << 16) | (RTMP0 << 5) | RTMP0); /* UMULL */
			emit32(0xD360FC00 | (RTMP0 << 5) | RTMP0); /* LSR Xd, Xn, #32 */
			emit_store_gpr(RTMP0, rd);
			if (op & 1) lazy_update_cr0(RTMP0);
			return true;
		case 87: /* lbzx rD,rA,rB */
			emit_load_gpr(RTMP0, ra == 0 ? rb : ra);
			if (ra != 0) { emit_load_gpr(RTMP1, rb); emit32(0x0B000000 | (RTMP1 << 16) | (RTMP0 << 5) | RTMP0); }
			emit_guarded_load_zero_invalid(RTMP0, RTMP1, 1, rd);
			emit_store_gpr(RTMP1, rd);
			return true;
		case 215: /* stbx rS,rA,rB */
			emit_load_gpr(RTMP1, PPC_RS(op));
			emit_load_gpr(RTMP0, ra == 0 ? rb : ra);
			if (ra != 0) { emit_load_gpr(RTMP2, rb); emit32(0x0B000000 | (RTMP2 << 16) | (RTMP0 << 5) | RTMP0); }
			emit_guarded_store_noop_invalid(RTMP0, RTMP1, 1);
			return true;
		case 279: /* lhzx rD,rA,rB */
			emit_load_gpr(RTMP0, ra == 0 ? rb : ra);
			if (ra != 0) { emit_load_gpr(RTMP1, rb); emit32(0x0B000000 | (RTMP1 << 16) | (RTMP0 << 5) | RTMP0); }
			emit_guarded_load_zero_invalid(RTMP0, RTMP1, 2, rd);
			emit_store_gpr(RTMP1, rd);
			return true;
		case 407: /* sthx rS,rA,rB */
			emit_load_gpr(RTMP1, PPC_RS(op));
			emit32(0x5AC00400 | (RTMP1 << 5) | RTMP1); /* REV16 */
			emit_load_gpr(RTMP0, ra == 0 ? rb : ra);
			if (ra != 0) { emit_load_gpr(RTMP2, rb); emit32(0x0B000000 | (RTMP2 << 16) | (RTMP0 << 5) | RTMP0); }
			emit_guarded_store_noop_invalid(RTMP0, RTMP1, 2);
			return true;
		case 343: /* lhax rD,rA,rB (load halfword algebraic indexed) */
			emit_load_gpr(RTMP0, ra == 0 ? rb : ra);
			if (ra != 0) { emit_load_gpr(RTMP1, rb); emit32(0x0B000000 | (RTMP1 << 16) | (RTMP0 << 5) | RTMP0); }
			emit_guarded_load_zero_invalid(RTMP0, RTMP1, 3, rd);
			emit_store_gpr(RTMP1, rd);
			return true;
		case 371: /* mftb/mftbu rD — move from time base */
		{
			uint32_t tbr = ((op >> 16) & 0x1F) | ((op >> 6) & 0x3E0);
			if (tbr != 268 && tbr != 269) return false;
			/* Match interpreter get_tb_ticks(): GetTicks_usec() scaled by TimebaseSpeed.
			 * Raw CNTVCT_EL0 has host-specific frequency/epoch and diverges from the
			 * emulated PPC timebase. TBR 268 is TBL (low 32), TBR 269 is TBU (high 32). */
			emit_load_imm64(RTMP4, (uint64_t)(uintptr_t)sheepshaver_jit_get_tb_ticks);
			emit32(0xD63F0000 | (RTMP4 << 5)); /* BLR x4 -> X0 ticks */
			if (tbr == 269)
				emit32(0xD360FC00 | (RTMP0 << 5) | RTMP0); /* LSR Xd,Xn,#32 */
			emit_store_gpr(RTMP0, rd);
			return true;
		}

		case 119: /* lbzux rD,rA,rB */
			/* ra==0: use 0 as base; ra==rd: update gets overwritten by load (PPC undefined but harmless) */
			emit_load_gpr(RTMP0, ra); emit_load_gpr(RTMP1, rb);
			emit32(0x0B000000 | (RTMP1 << 16) | (RTMP0 << 5) | RTMP0);
			a64_mov_reg(A64_FP, RTMP0); /* preserve EA across helper; x29 is callee-saved */
			emit_guarded_load_zero_invalid(RTMP0, RTMP1, 1, rd);
			emit_store_gpr(A64_FP, ra); /* update rA after memory access */
			emit_store_gpr(RTMP1, rd);
			return true;
		case 247: /* stbux rS,rA,rB */
			emit_load_gpr(RTMP1, PPC_RS(op));
			emit_load_gpr(RTMP0, ra); emit_load_gpr(RTMP2, rb);
			emit32(0x0B000000 | (RTMP2 << 16) | (RTMP0 << 5) | RTMP0);
			a64_mov_reg(A64_FP, RTMP0);
			emit_guarded_store_noop_invalid(RTMP0, RTMP1, 1);
			emit_store_gpr(A64_FP, ra); /* update rA after memory access */
			return true;
		case 311: /* lhzux rD,rA,rB */
			/* ra==0: use 0 as base; ra==rd: update gets overwritten by load (PPC undefined but harmless) */
			emit_load_gpr(RTMP0, ra); emit_load_gpr(RTMP1, rb);
			emit32(0x0B000000 | (RTMP1 << 16) | (RTMP0 << 5) | RTMP0);
			a64_mov_reg(A64_FP, RTMP0);
			emit_guarded_load_zero_invalid(RTMP0, RTMP1, 2, rd);
			emit_store_gpr(A64_FP, ra); /* update rA after memory access */
			emit_store_gpr(RTMP1, rd);
			return true;
		case 439: /* sthux rS,rA,rB */
			emit_load_gpr(RTMP1, PPC_RS(op));
			emit32(0x5AC00400 | (RTMP1 << 5) | RTMP1);
			emit_load_gpr(RTMP0, ra); emit_load_gpr(RTMP2, rb);
			emit32(0x0B000000 | (RTMP2 << 16) | (RTMP0 << 5) | RTMP0);
			a64_mov_reg(A64_FP, RTMP0);
			emit_guarded_store_noop_invalid(RTMP0, RTMP1, 2);
			emit_store_gpr(A64_FP, ra); /* update rA after memory access */
			return true;
		case 375: /* lhaux rD,rA,rB */
			/* ra==0: use 0 as base; ra==rd: update gets overwritten by load (PPC undefined but harmless) */
			emit_load_gpr(RTMP0, ra); emit_load_gpr(RTMP1, rb);
			emit32(0x0B000000 | (RTMP1 << 16) | (RTMP0 << 5) | RTMP0);
			a64_mov_reg(A64_FP, RTMP0);
			emit_guarded_load_zero_invalid(RTMP0, RTMP1, 3, rd);
			emit_store_gpr(A64_FP, ra); /* update rA after memory access */
			emit_store_gpr(RTMP1, rd);
			return true;
		case 55: /* lwzux rD,rA,rB */
			/* ra==0: use 0 as base; ra==rd: update gets overwritten by load (PPC undefined but harmless) */
			emit_load_gpr(RTMP0, ra); emit_load_gpr(RTMP1, rb);
			emit32(0x0B000000 | (RTMP1 << 16) | (RTMP0 << 5) | RTMP0);
			a64_mov_reg(A64_FP, RTMP0);
			emit_guarded_load_zero_invalid(RTMP0, RTMP1, 4, rd);
			emit_store_gpr(A64_FP, ra); /* update rA after memory access */
			emit_store_gpr(RTMP1, rd);
			return true;
		case 183: /* stwux rS,rA,rB */
			emit_load_gpr(RTMP1, PPC_RS(op));
			emit32(0x5AC00800 | (RTMP1 << 5) | RTMP1);
			emit_load_gpr(RTMP0, ra); emit_load_gpr(RTMP2, rb);
			emit32(0x0B000000 | (RTMP2 << 16) | (RTMP0 << 5) | RTMP0);
			a64_mov_reg(A64_FP, RTMP0);
			emit_guarded_store_noop_invalid(RTMP0, RTMP1, 4);
			emit_store_gpr(A64_FP, ra); /* update rA after memory access */
			return true;
		case 790: /* lhbrx rD,rA,rB */
			emit_load_gpr(RTMP0, ra == 0 ? rb : ra);
			if (ra != 0) { emit_load_gpr(RTMP1, rb); emit32(0x0B000000 | (RTMP1 << 16) | (RTMP0 << 5) | RTMP0); }
			emit_load_gpr(RTMP1, rd);
			emit_load_imm32(RTMP2, 2);
			emit_load_imm64(RTMP4, (uint64_t)(uintptr_t)sheepshaver_jit_safe_load_reversed);
			emit32(0xD63F0000 | (RTMP4 << 5));
			emit_store_gpr(RTMP0, rd);
			return true;
		case 918: /* sthbrx rS,rA,rB */
			emit_load_gpr(RTMP1, PPC_RS(op));
			emit_load_gpr(RTMP0, ra == 0 ? rb : ra);
			if (ra != 0) { emit_load_gpr(RTMP2, rb); emit32(0x0B000000 | (RTMP2 << 16) | (RTMP0 << 5) | RTMP0); }
			emit_load_imm32(RTMP2, 2);
			emit_load_imm64(RTMP4, (uint64_t)(uintptr_t)sheepshaver_jit_safe_store_reversed);
			emit32(0xD63F0000 | (RTMP4 << 5));
			return true;
		case 534: /* lwbrx rD,rA,rB */
			emit_load_gpr(RTMP0, ra == 0 ? rb : ra);
			if (ra != 0) { emit_load_gpr(RTMP1, rb); emit32(0x0B000000 | (RTMP1 << 16) | (RTMP0 << 5) | RTMP0); }
			emit_load_gpr(RTMP1, rd);
			emit_load_imm32(RTMP2, 4);
			emit_load_imm64(RTMP4, (uint64_t)(uintptr_t)sheepshaver_jit_safe_load_reversed);
			emit32(0xD63F0000 | (RTMP4 << 5));
			emit_store_gpr(RTMP0, rd);
			return true;
		case 662: /* stwbrx rS,rA,rB */
			emit_load_gpr(RTMP1, PPC_RS(op));
			emit_load_gpr(RTMP0, ra == 0 ? rb : ra);
			if (ra != 0) { emit_load_gpr(RTMP2, rb); emit32(0x0B000000 | (RTMP2 << 16) | (RTMP0 << 5) | RTMP0); }
			emit_load_imm32(RTMP2, 4);
			emit_load_imm64(RTMP4, (uint64_t)(uintptr_t)sheepshaver_jit_safe_store_reversed);
			emit32(0xD63F0000 | (RTMP4 << 5));
			return true;

		case 535: /* lfsx frD,rA,rB */
			emit_load_gpr(RTMP0, ra == 0 ? rb : ra);
			if (ra != 0) { emit_load_gpr(RTMP1, rb); emit32(0x0B000000 | (RTMP1 << 16) | (RTMP0 << 5) | RTMP0); }
			emit_call_fp_load_helper(RTMP0, rd, false);
			return true;
		case 567: /* lfsux frD,rA,rB */
			emit_load_ea_base(ra); emit_load_gpr(RTMP1, rb);
			emit32(0x0B000000 | (RTMP1 << 16) | (RTMP0 << 5) | RTMP0);
			a64_mov_reg(A64_FP, RTMP0);
			emit_call_fp_load_helper(RTMP0, rd, false);
			emit_store_gpr(A64_FP, ra);
			return true;
		case 599: /* lfdx frD,rA,rB */
			emit_load_gpr(RTMP0, ra == 0 ? rb : ra);
			if (ra != 0) { emit_load_gpr(RTMP1, rb); emit32(0x0B000000 | (RTMP1 << 16) | (RTMP0 << 5) | RTMP0); }
			emit_call_fp_load_helper(RTMP0, rd, true);
			return true;
		case 631: /* lfdux frD,rA,rB */
			emit_load_ea_base(ra); emit_load_gpr(RTMP1, rb);
			emit32(0x0B000000 | (RTMP1 << 16) | (RTMP0 << 5) | RTMP0);
			a64_mov_reg(A64_FP, RTMP0);
			emit_call_fp_load_helper(RTMP0, rd, true);
			emit_store_gpr(A64_FP, ra);
			return true;
		case 663: /* stfsx frS,rA,rB */
			emit_load_gpr(RTMP0, ra == 0 ? rb : ra);
			if (ra != 0) { emit_load_gpr(RTMP2, rb); emit32(0x0B000000 | (RTMP2 << 16) | (RTMP0 << 5) | RTMP0); }
			emit_call_fp_store_helper(RTMP0, PPC_RS(op), false);
			return true;
		case 695: /* stfsux frS,rA,rB */
			emit_load_gpr(RTMP0, ra); emit_load_gpr(RTMP2, rb);
			emit32(0x0B000000 | (RTMP2 << 16) | (RTMP0 << 5) | RTMP0);
			a64_mov_reg(A64_FP, RTMP0);
			emit_call_fp_store_helper(RTMP0, PPC_RS(op), false);
			emit_store_gpr(A64_FP, ra);
			return true;
		case 727: /* stfdx frS,rA,rB */
			emit_load_gpr(RTMP0, ra == 0 ? rb : ra);
			if (ra != 0) { emit_load_gpr(RTMP2, rb); emit32(0x0B000000 | (RTMP2 << 16) | (RTMP0 << 5) | RTMP0); }
			emit_call_fp_store_helper(RTMP0, PPC_RS(op), true);
			return true;
		case 759: /* stfdux frS,rA,rB */
			emit_load_gpr(RTMP0, ra); emit_load_gpr(RTMP2, rb);
			emit32(0x0B000000 | (RTMP2 << 16) | (RTMP0 << 5) | RTMP0);
			a64_mov_reg(A64_FP, RTMP0);
			emit_call_fp_store_helper(RTMP0, PPC_RS(op), true);
			emit_store_gpr(A64_FP, ra);
			return true;
		case 1014: /* dcbz rA,rB — zero cache line (32 bytes) */
		{
			emit_load_gpr(RTMP0, ra == 0 ? rb : ra);
			if (ra != 0) { emit_load_gpr(RTMP1, rb); emit32(0x0B000000 | (RTMP1 << 16) | (RTMP0 << 5) | RTMP0); }
			/* Use the same memory-layer primitive as the interpreter instead of raw host stores. */
			emit_load_imm64(RTMP4, (uint64_t)(uintptr_t)sheepshaver_jit_dcbz);
			emit32(0xD63F0000 | (RTMP4 << 5)); /* BLR dcbz(ea=w0) */
			return true;
		}

		/* Cache management — mostly NOPs (no emulated data-cache hierarchy). */
		case 54:   /* dcbst — data cache block store */
		case 86:   /* dcbf  — data cache block flush */
		case 246:  /* dcbt  — data cache block touch (prefetch hint) */
		case 278:  /* dcbtst — data cache block touch for store */
			return true;
		case 982:  /* icbi rA,rB — instruction cache block invalidate */
			lazy_flush_cr0();
			ra_flush_all();
			/* Compute EA = (rA?GPR[rA]:0) + GPR[rB] into w0 and let the helper
			 * flush only if a compiled block overlaps that 32-byte line. */
			emit_load_gpr(RTMP0, PPC_RB(op));
			if (PPC_RA(op) != 0) {
				emit_load_gpr(RTMP1, PPC_RA(op));
				emit32(0x0B000000 | (RTMP1 << 16) | (RTMP0 << 5) | RTMP0); /* ADD W0,W0,W1 */
			}
			emit_load_imm64(RTMP4, (uint64_t)(uintptr_t)ppc_jit_aarch64_icbi);
			emit32(0xD63F0000 | (RTMP4 << 5)); /* BLR icbi(ea=w0) */
			emit_load_imm32(RTMP0, (int32_t)(pc + 4));
			a64_str_w_imm(RTMP0, RSTATE, PPCR_PC);
			emit_return_to_dispatch();
			return true;

		/* Memory barriers — NOPs (single-threaded emulator) */
		case 598:  /* sync  — synchronize */
		case 854:  /* eieio — enforce in-order execution of I/O */
			return true;
		case 512: /* mcrxr crD — move XER[SO,OV,CA] to CR field, clear XER flags */
		{
			uint32_t crd_f = (op >> 23) & 0x7;
			lazy_flush_cr0();
			/* Build nibble: bit3=SO, bit2=OV, bit1=CA, bit0=0 */
			emit32(0x39400000 | (PPCR_XER_SO << 10) | (RSTATE << 5) | RTMP0); /* LDRB so */
			emit_load_imm32(RTMP1, 3); emit32(0x1AC02000 | (RTMP1 << 16) | (RTMP0 << 5) | RTMP0); /* LSL #3 */
			emit32(0x39400000 | (PPCR_XER_OV << 10) | (RSTATE << 5) | RTMP1); /* LDRB ov */
			emit_load_imm32(RTMP2, 2); emit32(0x1AC02000 | (RTMP2 << 16) | (RTMP1 << 5) | RTMP1); /* LSL #2 */
			emit32(0x2A000000 | (RTMP1 << 16) | (RTMP0 << 5) | RTMP0); /* OR */
			emit32(0x39400000 | (PPCR_XER_CA << 10) | (RSTATE << 5) | RTMP1); /* LDRB ca */
			emit_load_imm32(RTMP2, 1); emit32(0x1AC02000 | (RTMP2 << 16) | (RTMP1 << 5) | RTMP1); /* LSL #1 */
			emit32(0x2A000000 | (RTMP1 << 16) | (RTMP0 << 5) | RTMP0); /* OR */
			/* RTMP0 = {SO,OV,CA,0} nibble. Insert into CR field */
			uint32_t dst_sh = (7 - crd_f) * 4;
			if (dst_sh) { emit_load_imm32(RTMP1, dst_sh); emit32(0x1AC02000 | (RTMP1 << 16) | (RTMP0 << 5) | RTMP0); }
			lazy_flush_cr0();
			a64_ldr_w_imm(RTMP1, RSTATE, PPCR_CR);
			emit_load_imm32(RTMP2, ~(0xFU << dst_sh));
			emit32(0x0A000000 | (RTMP2 << 16) | (RTMP1 << 5) | RTMP1);
			emit32(0x2A000000 | (RTMP0 << 16) | (RTMP1 << 5) | RTMP1);
			a64_str_w_imm(RTMP1, RSTATE, PPCR_CR);
			/* Clear XER SO/OV/CA */
			a64_movz(RTMP0, 0, 0);
			emit32(0x39000000 | (PPCR_XER_SO << 10) | (RSTATE << 5) | RTMP0);
			emit32(0x39000000 | (PPCR_XER_OV << 10) | (RSTATE << 5) | RTMP0);
			emit32(0x39000000 | (PPCR_XER_CA << 10) | (RSTATE << 5) | RTMP0);
			return true;
		}
		case 20: /* lwarx rD,rA,rB — load word and reserve */
			/* CR0 first: emit_materialize_cr0 clobbers RTMP0/1/2 (see lwzx). */
			lazy_flush_cr0();
			emit_load_gpr(RTMP0, ra == 0 ? rb : ra);
			if (ra != 0) { emit_load_gpr(RTMP1, rb); emit32(0x0B000000 | (RTMP1 << 16) | (RTMP0 << 5) | RTMP0); }
			ra_flush_all();
			/* RTMP0 = EA; call sheepshaver_jit_lwarx(regs, ea) -> loads value AND sets the
			 * reservation (reserve_valid/addr) like the interpreter. Args: x0=regs, x1=ea. */
			a64_mov_reg(RTMP1, RTMP0);  /* x1 = ea */
			a64_mov_reg(RTMP0, RSTATE); /* x0 = regs */
			emit_load_imm64(RTMP4, (uint64_t)(uintptr_t)sheepshaver_jit_lwarx);
			emit32(0xD63F0000 | (RTMP4 << 5));
			ra_reset();
			emit_store_gpr(RTMP0, rd);
			return true;
		case 150: /* stwcx. rS,rA,rB — store word conditional (honors reservation) */
			/* CR0 first: emit_materialize_cr0 clobbers RTMP0/1/2 (see lwzx). */
			lazy_flush_cr0();
			emit_load_gpr(RTMP1, PPC_RS(op)); /* arg1 = value (W1) */
			emit_load_gpr(RTMP0, ra == 0 ? rb : ra);
			if (ra != 0) { emit_load_gpr(RTMP2, rb); emit32(0x0B000000 | (RTMP2 << 16) | (RTMP0 << 5) | RTMP0); }
			ra_flush_all();
			/* RTMP0 = EA, RTMP1 = value; call sheepshaver_jit_stwcx(regs, ea, value) ->
			 * returns 1 if the reservation held (store done), 0 if it failed.
			 * Args: x0=regs, x1=ea, x2=value. */
			a64_mov_reg(RTMP2, RTMP1);  /* x2 = value */
			a64_mov_reg(RTMP1, RTMP0);  /* x1 = ea */
			a64_mov_reg(RTMP0, RSTATE); /* x0 = regs */
			emit_load_imm64(RTMP4, (uint64_t)(uintptr_t)sheepshaver_jit_stwcx);
			emit32(0xD63F0000 | (RTMP4 << 5)); /* RTMP0 = ok (0/1) */
			ra_reset();
			/* CR0 = clear; EQ = ok; SO = XER.SO (mirrors execute_stwcx). Build the
			 * 4-bit field (ok<<1)|SO then shift into CR0 position and merge — same
			 * pattern as cmp/cmpi codegen. */
			emit_load_imm32(RTMP1, 1); emit32(0x1AC02000 | (RTMP1 << 16) | (RTMP0 << 5) | RTMP0); /* LSLV RTMP0, RTMP0, #1 -> EQ position */
			emit_or_xer_so_into_cr_nibble(RTMP0); /* | XER.SO into bit 0 */
			emit_load_imm32(RTMP1, 28); emit32(0x1AC02000 | (RTMP1 << 16) | (RTMP0 << 5) | RTMP0); /* LSLV RTMP0, RTMP0, #28 -> CR0 field */
			lazy_flush_cr0();
			a64_ldr_w_imm(RTMP1, RSTATE, PPCR_CR);
			emit_load_imm32(RTMP2, 0x0FFFFFFF);
			emit32(0x0A000000 | (RTMP2 << 16) | (RTMP1 << 5) | RTMP1); /* AND: clear CR0 field */
			emit32(0x2A000000 | (RTMP0 << 16) | (RTMP1 << 5) | RTMP1); /* ORR: merge new CR0 */
			a64_str_w_imm(RTMP1, RSTATE, PPCR_CR);
			return true;

		case 595: /* mfsr — not in interpreter decode table; must not compile
		         * (interpreter treats as execute_illegal → skip with ignoreillegal) */
			return false;
		case 659: /* mfsrin — same */
			return false;

		case 83: /* mfmsr rD — match interpreter's simplified MSR value */
			emit_load_imm32(RTMP0, 0xf072);
			emit_store_gpr(RTMP0, rd);
			return true;
		case 310: /* eciwx rD,rA,rB — external control in word: NOP */
			return true;
		case 438: /* ecowx rS,rA,rB — external control out word: NOP */
			return true;

		case 822: /* dss — data stream stop: NOP */
			return true;
		case 342: /* dst — data stream touch: NOP */
			return true;
		case 374: /* dstst — data stream touch for store: NOP */
			return true;


		case 597: /* lswi rD,rA,NB */
		{
			uint32_t nb_field = rb;
			uint32_t nb = nb_field == 0 ? 32 : nb_field;
			if (ra == 0) { a64_movz(RTMP0, 0, 0); }
			else { emit_load_gpr(RTMP0, ra); }
			uint32_t r = rd;
			uint32_t bytes_done = 0;
			while (bytes_done < nb) {
				if (nb - bytes_done >= 4) {
					emit32(0xB9400000 | (RTMP0 << 5) | RTMP1);
					emit32(0x5AC00800 | (RTMP1 << 5) | RTMP1);
					a64_str_w_imm(RTMP1, RSTATE, PPCR_GPR(r));
					if (bytes_done + 4 < nb) emit32(0x11001000 | (RTMP0 << 5) | RTMP0);
					bytes_done += 4;
				} else {
					a64_movz(RTMP1, 0, 0);
					for (uint32_t b = 0; b < nb - bytes_done; b++) {
						emit32(0x38401400 | (RTMP0 << 5) | RTMP2);
						uint32_t sh = (3 - b) * 8;
						if (sh) { emit_load_imm32(3, sh); emit32(0x1AC02000 | (3 << 16) | (RTMP2 << 5) | RTMP2); }
						emit32(0x2A000000 | (RTMP2 << 16) | (RTMP1 << 5) | RTMP1);
					}
					a64_str_w_imm(RTMP1, RSTATE, PPCR_GPR(r));
					bytes_done = nb;
				}
				r = (r + 1) & 31;
			}
			return true;
		}
		case 725: /* stswi rS,rA,NB */
		{
			uint32_t nb_field = rb;
			uint32_t nb = nb_field == 0 ? 32 : nb_field;
			if (ra == 0) { a64_movz(RTMP0, 0, 0); }
			else { emit_load_gpr(RTMP0, ra); }
			uint32_t r = PPC_RS(op);
			uint32_t bytes_done = 0;
			while (bytes_done < nb) {
				if (nb - bytes_done >= 4) {
					a64_ldr_w_imm(RTMP1, RSTATE, PPCR_GPR(r));
					emit32(0x5AC00800 | (RTMP1 << 5) | RTMP1);
					emit32(0xB8004400 | (RTMP0 << 5) | RTMP1);
					bytes_done += 4;
				} else {
					a64_ldr_w_imm(RTMP1, RSTATE, PPCR_GPR(r));
					for (uint32_t b = 0; b < nb - bytes_done; b++) {
						a64_mov_reg(RTMP2, RTMP1);
						uint32_t sh = (3 - b) * 8;
						if (sh) { emit_load_imm32(3, sh); emit32(0x1AC02400 | (3 << 16) | (RTMP2 << 5) | RTMP2); }
						emit32(0x38001400 | (RTMP0 << 5) | RTMP2);
					}
					bytes_done = nb;
				}
				r = (r + 1) & 31;
			}
			return true;
		}
		case 533: /* lswx rD,rA,rB — runtime byte count from XER */
			emit_load_ea_base(ra);
			emit_load_gpr(RTMP1, rb);
			emit32(0x0B000000 | (RTMP1 << 16) | (RTMP0 << 5) | RTMP0);
			ra_flush_all();
			emit_lswx_runtime_count(rd);
			ra_reset();
			return true;
		case 661: /* stswx rS,rA,rB — runtime byte count from XER */
			emit_load_ea_base(ra);
			emit_load_gpr(RTMP1, rb);
			emit32(0x0B000000 | (RTMP1 << 16) | (RTMP0 << 5) | RTMP0);
			ra_flush_all();
			emit_stswx_runtime_count(PPC_RS(op));
			ra_reset();
			return true;



		/* === 64-bit G5/PPC970 XO31 instructions === */

		case 27: /* sld rA,rS,rB */
			emit_load_gpr64(RTMP0, PPC_RS(op));
			emit_load_gpr(RTMP1, rb);
			emit32(0x9AC02000 | (RTMP1 << 16) | (RTMP0 << 5) | RTMP0); /* LSL Xd,Xn,Xm */
			emit_store_gpr64(RTMP0, ra);
			if (op & 1) lazy_update_cr0(RTMP0);
			return true;

		case 539: /* srd rA,rS,rB */
			emit_load_gpr64(RTMP0, PPC_RS(op));
			emit_load_gpr(RTMP1, rb);
			emit32(0x9AC02400 | (RTMP1 << 16) | (RTMP0 << 5) | RTMP0); /* LSR Xd,Xn,Xm */
			emit_store_gpr64(RTMP0, ra);
			if (op & 1) lazy_update_cr0(RTMP0);
			return true;

		case 794: /* srad rA,rS,rB — EXCLUDED: CA semantics not yet exact */
		case 826: /* sradi rA,rS,SH — EXCLUDED: CA semantics not yet exact */
			/* These algebraic doubleword shifts must set XER.CA when negative bits are
			 * shifted out. The old native handlers forced CA=0 (a known simplification),
			 * which is observably wrong for code that reads XER/record forms. Delegate to
			 * the interpreter until exact shifted-out-bit logic is implemented. */
			return false;

		case 58: /* cntlzd rA,rS */
			emit_load_gpr64(RTMP0, PPC_RS(op));
			emit32(0xDAC01000 | (RTMP0 << 5) | RTMP0); /* CLZ Xd,Xn */
			emit_store_gpr(RTMP0, ra);
			a64_str_w_imm(31, RSTATE, PPCR_GPR_HI(ra));
			if (op & 1) lazy_update_cr0(RTMP0);
			return true;

		case 986: /* extsw rA,rS — sign-extend word to doubleword */
			emit_load_gpr(RTMP0, PPC_RS(op));
			emit32(0x93407C00 | (RTMP0 << 5) | RTMP0); /* SXTW Xd,Wn */
			emit_store_gpr64(RTMP0, ra);
			if (op & 1) lazy_update_cr0(RTMP0);
			return true;

		case 233: /* mulld rD,rA,rB */
			emit_load_gpr64(RTMP0, ra);
			emit_load_gpr64_tmp(RTMP1, rb, RTMP2); /* don't clobber RTMP0 operand */
			emit32(0x9B007C00 | (RTMP1 << 16) | (RTMP0 << 5) | RTMP0); /* MUL Xd,Xn,Xm */
			emit_store_gpr64(RTMP0, rd);
			if (op & 1) lazy_update_cr0(RTMP0);
			return true;

		case 9: /* mulhdu rD,rA,rB */
			emit_load_gpr64(RTMP0, ra);
			emit_load_gpr64_tmp(RTMP1, rb, RTMP2); /* don't clobber RTMP0 operand */
			emit32(0x9BC07C00 | (RTMP1 << 16) | (RTMP0 << 5) | RTMP0); /* UMULH Xd,Xn,Xm */
			emit_store_gpr64(RTMP0, rd);
			if (op & 1) lazy_update_cr0(RTMP0);
			return true;

		case 73: /* mulhd rD,rA,rB */
			emit_load_gpr64(RTMP0, ra);
			emit_load_gpr64_tmp(RTMP1, rb, RTMP2); /* don't clobber RTMP0 operand */
			emit32(0x9B407C00 | (RTMP1 << 16) | (RTMP0 << 5) | RTMP0); /* SMULH Xd,Xn,Xm */
			emit_store_gpr64(RTMP0, rd);
			if (op & 1) lazy_update_cr0(RTMP0);
			return true;

		case 457: /* divdu rD,rA,rB */
			emit_load_gpr64(RTMP0, ra);
			emit_load_gpr64_tmp(RTMP1, rb, RTMP2); /* don't clobber RTMP0 operand */
			emit32(0x9AC00800 | (RTMP1 << 16) | (RTMP0 << 5) | RTMP0); /* UDIV Xd,Xn,Xm */
			emit_store_gpr64(RTMP0, rd);
			if (op & 1) lazy_update_cr0(RTMP0);
			return true;

		case 489: /* divd rD,rA,rB */
			emit_load_gpr64(RTMP0, ra);
			emit_load_gpr64_tmp(RTMP1, rb, RTMP2); /* don't clobber RTMP0 operand */
			emit32(0x9AC00C00 | (RTMP1 << 16) | (RTMP0 << 5) | RTMP0); /* SDIV Xd,Xn,Xm */
			emit_store_gpr64(RTMP0, rd);
			if (op & 1) lazy_update_cr0(RTMP0);
			return true;

		/* 64-bit load/store indexed — EXCLUDED: raw memory paths need guarded 64-bit helpers */
		case 21:  /* ldx */
		case 53:  /* ldux */
		case 149: /* stdx */
		case 181: /* stdux */
			return false;

		case 84:  /* ldarx rD,rA,rB — EXCLUDED: reservation semantics not implemented */
		case 214: /* stdcx. rS,rA,rB — EXCLUDED: reservation semantics not implemented */
			/* The old native handlers repeated the 32-bit lwarx/stwcx. bug class: ldarx was
			 * a plain load and stdcx. always succeeded. Guest atomic acquire/retry loops need
			 * real reserve_valid/reserve_addr checks (and 64-bit store-on-success) before
			 * these can be compiled safely. Delegate until exact helpers exist. */
			return false;

		case 4: /* tw — trap word */
			/* In SheepShaver boot ROM paths these trap words are used as guard rails
			 * with ignoreillegal enabled.  Treat them as non-trapping so direct JIT can
			 * keep compiling the surrounding threaded-dispatch blocks. */
			return true;

									default:
			jit_xo_miss[(op >> 1) & 0x3FF]++;
			return false;
		}
	}

	case 32: /* lwz rD,d(rA) */
		rd = PPC_RD(op); ra = PPC_RA(op); simm = PPC_SIMM(op);
		if (ra == 0) {
			emit_load_imm32(RTMP0, (int32_t)simm);
		} else {
			emit_load_gpr(RTMP0, ra);
			if (simm) {
				emit_load_imm32(RTMP1, (int32_t)simm);
				emit32(0x0B000000 | (RTMP1 << 16) | (RTMP0 << 5) | RTMP0);
			}
		}
		emit_guarded_load_zero_invalid(RTMP0, RTMP1, 4, rd);
		emit_store_gpr(RTMP1, rd);
		return true;

	case 36: /* stw rS,d(rA) */
		rd = PPC_RS(op); ra = PPC_RA(op); simm = PPC_SIMM(op);
		emit_load_gpr(RTMP1, rd);                  /* value to store */
		emit32(0x5AC00800 | (RTMP1 << 5) | RTMP1); /* REV (byte-swap) */
		emit_load_ea_base(ra);                     /* base address (rA==0 means absolute) */
		if (simm) {
			emit_load_imm32(RTMP2, (int32_t)simm);
			emit32(0x0B000000 | (RTMP2 << 16) | (RTMP0 << 5) | RTMP0);
		}
		emit_guarded_store_noop_invalid(RTMP0, RTMP1, 4);
		return true;

	case 34: /* lbz rD,d(rA) */
		rd = PPC_RD(op); ra = PPC_RA(op); simm = PPC_SIMM(op);
		emit_load_ea_base(ra);
		if (simm) { emit_load_imm32(RTMP1, (int32_t)simm); emit32(0x0B000000 | (RTMP1 << 16) | (RTMP0 << 5) | RTMP0); }
		emit_guarded_load_zero_invalid(RTMP0, RTMP1, 1, rd);
		emit_store_gpr(RTMP1, rd);
		return true;

	case 38: /* stb rS,d(rA) */
		rd = PPC_RS(op); ra = PPC_RA(op); simm = PPC_SIMM(op);
		emit_load_gpr(RTMP1, rd);
		emit_load_ea_base(ra);
		if (simm) { emit_load_imm32(RTMP2, (int32_t)simm); emit32(0x0B000000 | (RTMP2 << 16) | (RTMP0 << 5) | RTMP0); }
		emit_guarded_store_noop_invalid(RTMP0, RTMP1, 1);
		return true;

	case 40: /* lhz rD,d(rA) */
		rd = PPC_RD(op); ra = PPC_RA(op); simm = PPC_SIMM(op);
		emit_load_ea_base(ra);
		if (simm) { emit_load_imm32(RTMP1, (int32_t)simm); emit32(0x0B000000 | (RTMP1 << 16) | (RTMP0 << 5) | RTMP0); }
		emit_guarded_load_zero_invalid(RTMP0, RTMP1, 2, rd);
		emit_store_gpr(RTMP1, rd);
		return true;

	case 44: /* sth rS,d(rA) */
		rd = PPC_RS(op); ra = PPC_RA(op); simm = PPC_SIMM(op);
		emit_load_gpr(RTMP1, rd);
		emit32(0x5AC00400 | (RTMP1 << 5) | RTMP1); /* REV16 */
		emit_load_ea_base(ra);
		if (simm) { emit_load_imm32(RTMP2, (int32_t)simm); emit32(0x0B000000 | (RTMP2 << 16) | (RTMP0 << 5) | RTMP0); }
		emit_guarded_store_noop_invalid(RTMP0, RTMP1, 2);
		return true;

	case 12: /* addic rD,rA,SIMM (sets XER[CA]) */
		rd = PPC_RD(op); ra = PPC_RA(op); simm = PPC_SIMM(op);
		emit_load_gpr(RTMP0, ra);
		emit_load_imm32(RTMP1, (int32_t)simm);
		/* ADDS Wd, Wn, Wm (sets NZCV — we use C for carry-out) */
		emit32(0x2B000000 | (RTMP1 << 16) | (RTMP0 << 5) | RTMP0);
		emit_store_gpr(RTMP0, rd);
		emit_write_xer_ca_from_carry();
		return true;

	case 21: /* rlwinm rA,rS,SH,MB,ME */
	{
		uint32_t rs = PPC_RS(op);
		ra = PPC_RA(op);
		uint32_t sh = (op >> 11) & 0x1F;
		uint32_t mb = (op >> 6) & 0x1F;
		uint32_t me = (op >> 1) & 0x1F;
		int s = gpr_in(rs, RTMP0);
		int d = gpr_out(ra, RTMP0);
		int cur = s;
		/* Rotate left by SH: EXTR d,s,s,#(32-SH) (writes d, leaves cached rS intact) */
		if (sh) {
			uint32_t ror_amt = (32 - sh) & 0x1F;
			emit32(0x13800000 | (s << 16) | (ror_amt << 10) | (s << 5) | d);
			cur = d;
		}
		/* Apply mask MB..ME */
		uint32_t mask = 0;
		if (mb <= me) {
			for (uint32_t i = mb; i <= me; i++) mask |= (0x80000000U >> i);
		} else {
			for (uint32_t i = 0; i <= me; i++) mask |= (0x80000000U >> i);
			for (uint32_t i = mb; i <= 31; i++) mask |= (0x80000000U >> i);
		}
		if (mask != 0xFFFFFFFF) {
			emit_load_imm32(RTMP1, (int32_t)mask);
			emit32(0x0A000000 | (RTMP1 << 16) | (cur << 5) | d); /* AND d, cur, mask */
			cur = d;
		}
		if (cur != d) emit32(0x2A0003E0 | (cur << 16) | d); /* MOV d, cur (sh==0 && mask==FFFF copy) */
		gpr_out_commit(ra, d);
		if (op & 1) lazy_update_cr0(d); /* rlwinm. updates CR0 */
		return true;
	}

	case 20: /* rlwimi rA,rS,SH,MB,ME (insert) */
	{
		uint32_t rs = PPC_RS(op);
		ra = PPC_RA(op);
		uint32_t sh = (op >> 11) & 0x1F;
		uint32_t mb = (op >> 6) & 0x1F;
		uint32_t me = (op >> 1) & 0x1F;
		/* Rotate rS left by SH */
		emit_load_gpr(RTMP0, rs);
		if (sh) {
			uint32_t ror_amt = (32 - sh) & 0x1F;
			emit32(0x13800000 | (RTMP0 << 16) | (ror_amt << 10) | (RTMP0 << 5) | RTMP0);
		}
		/* Compute mask */
		uint32_t mask = 0;
		if (mb <= me) {
			for (uint32_t i = mb; i <= me; i++) mask |= (0x80000000U >> i);
		} else {
			for (uint32_t i = 0; i <= me; i++) mask |= (0x80000000U >> i);
			for (uint32_t i = mb; i <= 31; i++) mask |= (0x80000000U >> i);
		}
		/* rA = (rotated_rS & mask) | (rA & ~mask) */
		emit_load_imm32(RTMP1, (int32_t)mask);
		emit32(0x0A000000 | (RTMP1 << 16) | (RTMP0 << 5) | RTMP0); /* rotated & mask */
		emit_load_gpr(RTMP2, ra);
		emit_load_imm32(RTMP1, (int32_t)~mask);
		emit32(0x0A000000 | (RTMP1 << 16) | (RTMP2 << 5) | RTMP2); /* rA & ~mask */
		emit32(0x2A000000 | (RTMP2 << 16) | (RTMP0 << 5) | RTMP0); /* OR */
		emit_store_gpr(RTMP0, ra);
		if (op & 1) lazy_update_cr0(RTMP0); /* rlwimi. updates CR0 */
		return true;
	}

	case 33: /* lwzu rD,d(rA) — load word and update rA */
		rd = PPC_RD(op); ra = PPC_RA(op); simm = PPC_SIMM(op);
		/* ra==0: use 0 as base; ra==rd: update gets overwritten by load (PPC undefined but harmless) */
		emit_load_gpr(RTMP0, ra);
		emit_load_imm32(RTMP1, (int32_t)simm);
		emit32(0x0B000000 | (RTMP1 << 16) | (RTMP0 << 5) | RTMP0); /* effective addr */
		a64_mov_reg(A64_FP, RTMP0); /* preserve EA across helper; x29 is callee-saved */
		emit_guarded_load_zero_invalid(RTMP0, RTMP1, 4, rd);
		emit_store_gpr(A64_FP, ra); /* update rA after memory access */
		emit_store_gpr(RTMP1, rd);
		return true;

	case 37: /* stwu rS,d(rA) — store word and update rA */
		rd = PPC_RS(op); ra = PPC_RA(op); simm = PPC_SIMM(op);
		emit_load_gpr(RTMP1, rd);
		emit32(0x5AC00800 | (RTMP1 << 5) | RTMP1); /* REV */
		emit_load_gpr(RTMP0, ra);
		emit_load_imm32(RTMP2, (int32_t)simm);
		emit32(0x0B000000 | (RTMP2 << 16) | (RTMP0 << 5) | RTMP0); /* effective addr */
		a64_mov_reg(A64_FP, RTMP0); /* preserve EA across helper; x29 is callee-saved */
		emit_guarded_store_noop_invalid(RTMP0, RTMP1, 4);
		emit_store_gpr(A64_FP, ra); /* update rA after memory access */
		return true;


	case 8: /* subfic rD,rA,SIMM (rD = SIMM - rA, set CA) */
		rd = PPC_RD(op); ra = PPC_RA(op); simm = PPC_SIMM(op);
		emit_load_imm32(RTMP0, (int32_t)simm);
		emit_load_gpr(RTMP1, ra);
		/* ARM64 SUBS: Wd = SIMM - rA, sets C = !borrow = (SIMM >= rA unsigned) = PPC CA */
		emit32(0x6B000000 | (RTMP1 << 16) | (RTMP0 << 5) | RTMP0); /* SUBS Wd, SIMM, rA */
		emit_store_gpr(RTMP0, rd);
		emit_write_xer_ca_from_carry();
		return true;


	case 10: /* cmpli (cmplwi) crD,rA,UIMM */
	{
		uint32_t crd = (op >> 23) & 0x7;
		ra = PPC_RA(op); uimm = PPC_UIMM(op);
		lazy_flush_cr0();
		int s = gpr_in(ra, RTMP0);
		emit_load_imm32(RTMP1, (int32_t)(uint32_t)uimm);
		/* Unsigned compare: CMP Wn, Wm */
		emit32(0x6B000000 | (RTMP1 << 16) | (s << 5) | 0x1F);
		/* Build CR field from unsigned comparison:
		   LT = unsigned less (ARM64 CC = carry clear)
		   GT = unsigned greater (ARM64 CC = carry set AND not zero)
		   EQ = equal */
		emit32(0xD53B4200 | RTMP2); /* MRS NZCV */
		a64_movz(RTMP0, 0, 0);
		emit_load_imm32(RTMP1, 8); /* LT */
		/* CSEL RTMP0, RTMP1, RTMP0, CC (unsigned less = carry clear) */
		emit32(0x1A800000 | (RTMP0 << 16) | (0x3 << 12) | (RTMP1 << 5) | RTMP0);
		emit_load_imm32(RTMP1, 4); /* GT */
		/* CSEL RTMP0, RTMP1, RTMP0, HI (unsigned greater) */
		emit32(0x1A800000 | (RTMP0 << 16) | (0x8 << 12) | (RTMP1 << 5) | RTMP0);
		emit_load_imm32(RTMP1, 2); /* EQ */
		/* CSEL RTMP0, RTMP1, RTMP0, EQ */
		emit32(0x1A800000 | (RTMP0 << 16) | (0x0 << 12) | (RTMP1 << 5) | RTMP0);
		/* OR in XER[SO] as bit 0 */
		emit_or_xer_so_into_cr_nibble(RTMP0);
		uint32_t shift = (7 - crd) * 4;
		if (shift) { emit_load_imm32(RTMP1, shift); emit32(0x1AC02000 | (RTMP1 << 16) | (RTMP0 << 5) | RTMP0); }
		lazy_flush_cr0();
		a64_ldr_w_imm(RTMP1, RSTATE, PPCR_CR);
		emit_load_imm32(RTMP2, ~(0xF << shift));
		emit32(0x0A000000 | (RTMP2 << 16) | (RTMP1 << 5) | RTMP1);
		emit32(0x2A000000 | (RTMP0 << 16) | (RTMP1 << 5) | RTMP1);
		a64_str_w_imm(RTMP1, RSTATE, PPCR_CR);
		return true;
	}

	case 11: /* cmpi (cmpwi) crD,rA,SIMM */
	{
		uint32_t crd = (op >> 23) & 0x7;
		ra = PPC_RA(op); simm = PPC_SIMM(op);
		lazy_flush_cr0();
		int s = gpr_in(ra, RTMP0);
		emit_load_imm32(RTMP1, (int32_t)simm);
		/* Signed compare: CMP Wn, Wm */
		emit32(0x6B000000 | (RTMP1 << 16) | (s << 5) | 0x1F); /* SUBS WZR,Wn,Wm */
		/* Build CR field using CSEL: LT/GT/EQ (signed conditions) */
		a64_movz(RTMP0, 0, 0);
		emit_load_imm32(RTMP1, 8); /* LT */
		/* CSEL RTMP0, RTMP1, RTMP0, LT (signed less than: N!=V) */
		emit32(0x1A800000 | (RTMP0 << 16) | (0xB << 12) | (RTMP1 << 5) | RTMP0);
		emit_load_imm32(RTMP1, 4); /* GT */
		/* CSEL RTMP0, RTMP1, RTMP0, GT (signed greater than: Z==0 && N==V) */
		emit32(0x1A800000 | (RTMP0 << 16) | (0xC << 12) | (RTMP1 << 5) | RTMP0);
		emit_load_imm32(RTMP1, 2); /* EQ */
		/* CSEL RTMP0, RTMP1, RTMP0, EQ */
		emit32(0x1A800000 | (RTMP0 << 16) | (0x0 << 12) | (RTMP1 << 5) | RTMP0);
		/* OR in XER[SO] as bit 0 */
		emit_or_xer_so_into_cr_nibble(RTMP0);
		uint32_t shift = (7 - crd) * 4;
		if (shift) { emit_load_imm32(RTMP1, shift); emit32(0x1AC02000 | (RTMP1 << 16) | (RTMP0 << 5) | RTMP0); }
		/* Load current CR, clear target field, OR in new value */
		lazy_flush_cr0();
		a64_ldr_w_imm(RTMP1, RSTATE, PPCR_CR);
		emit_load_imm32(RTMP2, ~(0xF << shift));
		emit32(0x0A000000 | (RTMP2 << 16) | (RTMP1 << 5) | RTMP1); /* AND (clear) */
		emit32(0x2A000000 | (RTMP0 << 16) | (RTMP1 << 5) | RTMP1); /* ORR (merge) */
		a64_str_w_imm(RTMP1, RSTATE, PPCR_CR);
		return true;
	}

	case 16: /* bc/bdnz/bdz/beq/bne family */
	{
		uint32_t bo = (op >> 21) & 0x1F;
		uint32_t bi = (op >> 16) & 0x1F;
		int16_t bd = ((op & 0xFFFC) ^ 0x8000) - 0x8000;
		bool aa = (op >> 1) & 1;
		bool lk = op & 1;
		uint32_t target_pc = aa ? (uint32_t)(int32_t)bd : (pc + bd);

		/* PPC ISA BO field (5 bits, MSB-first):
		   BO[0] (0x10): 1=don't test condition
		   BO[1] (0x08): condition sense (branch if CR[BI]=BO[1])
		   BO[2] (0x04): 1=don't decrement/test CTR
		   BO[3] (0x02): CTR sense (0=CTR≠0, 1=CTR==0)
		   BO[4] (0x01): prediction hint */
		bool no_ctr_test = (bo & 0x04); /* BO[2]=1: skip CTR decrement+test */
		bool ctr_eq_zero = (bo & 0x02); /* BO[3]=1: branch if CTR==0 (bdz) */
		bool no_cond_test = (bo & 0x10); /* BO[0]=1: skip condition test */
		bool cond_bit_val = (bo & 0x08); /* BO[1]=1: branch if CR[BI]=1 */

		/* bcl supported: lk=1 saves pc+4 to LR before branching */

		if (!no_ctr_test && no_cond_test) {
			/* bdnz or bdz (CTR-only, no condition test) */
			emit_save_lr_if_link(pc, lk);
			a64_ldr_w_imm(RTMP0, RSTATE, PPCR_CTR);
			emit32(0x51000400 | (RTMP0 << 5) | RTMP0); /* SUB Wd, Wn, #1 */
			a64_str_w_imm(RTMP0, RSTATE, PPCR_CTR);

			if (!ctr_eq_zero) {
				/* bdnz: branch if CTR != 0. Always return to dispatcher for
				 * conditional edges so pending interrupts are observed between
				 * loop iterations, matching interpreter block boundaries. */
				/* Not taken: CBZ skips to after epilogue */
				uint32_t *skip_loc = jit_code_ptr;
				emit32(0); /* placeholder CBZ */
				lazy_flush_cr0();
				emit_epilogue_with_pc(target_pc); /* taken path */
				/* Patch skip: CBZ RTMP0, <here> */
				int32_t skip_off = (int32_t)((uint8_t *)jit_code_ptr - (uint8_t *)skip_loc);
				*skip_loc = 0x34000000 | (((skip_off >> 2) & 0x7FFFF) << 5) | RTMP0;
				return true;
			} else {
				/* bdz: branch if CTR == 0. Return to dispatcher for both paths. */
				/* Not taken: CBNZ skips to after epilogue */
				uint32_t *skip_loc = jit_code_ptr;
				emit32(0); /* placeholder CBNZ */
				lazy_flush_cr0();
				emit_epilogue_with_pc(target_pc); /* taken path */
				int32_t skip_off = (int32_t)((uint8_t *)jit_code_ptr - (uint8_t *)skip_loc);
				*skip_loc = 0x35000000 | (((skip_off >> 2) & 0x7FFFF) << 5) | RTMP0;
				return true;
			}
		}

		if (no_ctr_test && !no_cond_test) {
			/* Pure conditional branch: test CR[BI] only, no CTR */
			uint32_t bit_pos = 31 - bi;
			emit_save_lr_if_link(pc, lk);
			lazy_flush_cr0();
			a64_ldr_w_imm(RTMP0, RSTATE, PPCR_CR);
			if (bit_pos) {
				emit_load_imm32(RTMP1, bit_pos);
				emit32(0x1AC02400 | (RTMP1 << 16) | (RTMP0 << 5) | RTMP0); /* LSR */
			}
			emit32(0x12000000 | (RTMP0 << 5) | RTMP0); /* AND #1 */
			/* BO[3] (bit 1 of BO): 1=branch if set, 0=branch if clear */
			bool branch_if_set = cond_bit_val;
			/* Return to dispatcher for conditional branch targets, including
			 * intra-block targets, so interrupt/special-flag timing matches
			 * interpreter block execution. */
			if (branch_if_set) {
				uint32_t *skip_loc = jit_code_ptr;
				emit32(0); /* placeholder CBZ */
				lazy_flush_cr0();
				emit_epilogue_with_pc(target_pc); /* taken path */
				/* Not-taken path: PC = pc + 4 */
				int32_t skip_off = (int32_t)((uint8_t *)jit_code_ptr - (uint8_t *)skip_loc);
				*skip_loc = 0x34000000 | (((skip_off >> 2) & 0x7FFFF) << 5) | RTMP0;
				lazy_flush_cr0();
				emit_epilogue_with_pc(pc + 4); /* not-taken path */
			} else {
				uint32_t *skip_loc = jit_code_ptr;
				emit32(0); /* placeholder CBNZ */
				lazy_flush_cr0();
				emit_epilogue_with_pc(target_pc); /* taken path */
				/* Not-taken path: PC = pc + 4 */
				int32_t skip_off = (int32_t)((uint8_t *)jit_code_ptr - (uint8_t *)skip_loc);
				*skip_loc = 0x35000000 | (((skip_off >> 2) & 0x7FFFF) << 5) | RTMP0;
				lazy_flush_cr0();
				emit_epilogue_with_pc(pc + 4); /* not-taken path */
			}
			return true;
		}

		if (no_ctr_test && no_cond_test) {
			/* Unconditional: BO=1x1xx → always branch */
			emit_save_lr_if_link(pc, lk);
			lazy_flush_cr0();
			emit_epilogue_with_pc(target_pc);
			return true;
		}

		if (!no_ctr_test && !no_cond_test) {
			/* Decrement CTR AND test condition — branch only if BOTH pass */
			/* bcl not yet implemented for this BO combo — fall to interpreter */
			if (lk) return false;

			/* Decrement CTR */
			a64_ldr_w_imm(RTMP0, RSTATE, PPCR_CTR);
			emit32(0x51000400 | (RTMP0 << 5) | RTMP0); /* SUB Wd, Wn, #1 */
			a64_str_w_imm(RTMP0, RSTATE, PPCR_CTR);

			/* Compute ctr_ok: 1 if CTR passes test, 0 otherwise */
			emit32(0x7100001F | (RTMP0 << 5)); /* CMP Wn, #0 */
			if (ctr_eq_zero)
				emit32(0x1A9F17E0 | RTMP0); /* CSET RTMP0, EQ */
			else
				emit32(0x1A9F07E0 | RTMP0); /* CSET RTMP0, NE */

			/* Compute cond_ok: extract CR[BI], match against BO[1] */
			uint32_t bit_pos = 31 - bi;
			lazy_flush_cr0();
			a64_ldr_w_imm(RTMP1, RSTATE, PPCR_CR);
			if (bit_pos) { emit_load_imm32(RTMP2, bit_pos); emit32(0x1AC02400 | (RTMP2 << 16) | (RTMP1 << 5) | RTMP1); }
			emit32(0x12000000 | (RTMP1 << 5) | RTMP1); /* AND #1 */
			if (!cond_bit_val) {
				/* Invert: branch if CR[BI]=0 */
				emit_load_imm32(RTMP2, 1);
				emit32(0x4A000000 | (RTMP2 << 16) | (RTMP1 << 5) | RTMP1); /* EOR #1 */
			}

			/* Branch if ctr_ok AND cond_ok */
			emit32(0x0A000000 | (RTMP1 << 16) | (RTMP0 << 5) | RTMP0); /* AND */
			uint32_t *skip_loc = jit_code_ptr;
			emit32(0); /* placeholder CBZ */
			lazy_flush_cr0();
			emit_epilogue_with_pc(target_pc); /* taken */
			int32_t skip_off = (int32_t)((uint8_t *)jit_code_ptr - (uint8_t *)skip_loc);
			*skip_loc = 0x34000000 | (((skip_off >> 2) & 0x7FFFF) << 5) | RTMP0;
			lazy_flush_cr0();
			emit_epilogue_with_pc(pc + 4); /* not taken */
			return true;
		}

		return false; /* unhandled BO pattern */
	}

	case 19: /* CR ops, bclr, bcctr, isync */
	{
		uint32_t xo = (op >> 1) & 0x3FF;
		switch (xo) {
		case 16: /* bclr — branch conditional to LR */
		{
			uint32_t bo = (op >> 21) & 0x1F;
			uint32_t bi = (op >> 16) & 0x1F;
			bool lk = op & 1;
			bool no_ctr_test = (bo & 0x04);   /* BO[2]=1: skip CTR decrement+test */
			bool ctr_eq_zero = (bo & 0x02);   /* BO[3]=1: branch if CTR==0 */
			bool no_cond_test = (bo & 0x10);  /* BO[0]=1: skip condition test */
			bool cond_bit_val = (bo & 0x08);  /* BO[1]=1: branch if CR[BI]=1 */

			/* Materialize pending CR0 before reading LR; CR materialization uses
			 * temporary registers and must not corrupt the saved branch target. */
			lazy_flush_cr0();

			/* bclrl/bdnzlr branches to the old LR, then optional LK writes LR=pc+4. */
			a64_ldr_w_imm(RTMP2, RSTATE, PPCR_LR); /* taken target = old LR */
			emit_clear_branch_target_low_bits(RTMP2);
			if (lk) { emit_load_imm32(RTMP1, (int32_t)(pc + 4)); a64_str_w_imm(RTMP1, RSTATE, PPCR_LR); }

			/* RTMP0 = branch decision (1=taken, 0=fall through). */
			a64_movz(RTMP0, 1, 0);

			if (!no_ctr_test) {
				a64_ldr_w_imm(RTMP0, RSTATE, PPCR_CTR);
				emit32(0x51000400 | (RTMP0 << 5) | RTMP0); /* SUB Wd, Wn, #1 */
				a64_str_w_imm(RTMP0, RSTATE, PPCR_CTR);
				emit32(0x7100001F | (RTMP0 << 5)); /* CMP Wn, #0 */
				if (ctr_eq_zero)
					emit32(0x1A9F17E0 | RTMP0); /* CSET RTMP0, EQ */
				else
					emit32(0x1A9F07E0 | RTMP0); /* CSET RTMP0, NE */
			}

			if (!no_cond_test) {
				uint32_t bit_pos = 31 - bi;
				lazy_flush_cr0();
				a64_ldr_w_imm(RTMP1, RSTATE, PPCR_CR);
				if (bit_pos) {
					emit_load_imm32(RTMP3, bit_pos);
					emit32(0x1AC02400 | (RTMP3 << 16) | (RTMP1 << 5) | RTMP1); /* LSR */
				}
				emit32(0x12000000 | (RTMP1 << 5) | RTMP1); /* AND #1 */
				if (!cond_bit_val) {
					emit_load_imm32(RTMP3, 1);
					emit32(0x4A000000 | (RTMP3 << 16) | (RTMP1 << 5) | RTMP1); /* EOR #1 */
				}
				if (!no_ctr_test)
					emit32(0x0A000000 | (RTMP1 << 16) | (RTMP0 << 5) | RTMP0); /* AND ctr_ok & cond_ok */
				else
					a64_mov_reg(RTMP0, RTMP1);
			}

			emit_load_imm32(RTMP1, (int32_t)(pc + 4)); /* not-taken target */
			emit32(0x7100001F | (RTMP0 << 5)); /* CMP branch decision, #0 */
			/* RTMP1 = decision ? old_LR : pc+4 */
			emit32(0x1A800000 | (RTMP1 << 16) | (0x1 << 12) | (RTMP2 << 5) | RTMP1); /* CSEL NE */
			/* In SheepShaver ignore-invalid-access mode, a null indirect branch target
			 * from threaded ROM glue acts like an ignored helper call. Continue with
			 * the not-taken target instead of returning an unmapped PC to GATE3. */
			emit_load_imm32(RTMP3, (int32_t)(pc + 4));
			emit_cmp_w_imm(RTMP1, 0);
			emit32(0x1A800000 | (RTMP1 << 16) | (0x0 << 12) | (RTMP3 << 5) | RTMP1); /* CSEL EQ fallback */
			a64_str_w_imm(RTMP1, RSTATE, PPCR_PC);
			lazy_flush_cr0();
			ra_flush_all();
			a64_ldp_post(27, 28, A64_SP, 16);
			a64_ldp_post(25, 26, A64_SP, 16);
			a64_ldp_post(23, 24, A64_SP, 16);
			a64_ldp_post(21, 22, A64_SP, 16);
			a64_ldp_post(19, RSTATE, A64_SP, 16);
			a64_ldp_post(A64_FP, A64_LR, A64_SP, 16);
			a64_ret();
			return true;
		}
		case 528: /* bcctr — branch conditional to CTR */
		{
			uint32_t bo = (op >> 21) & 0x1F;
			uint32_t bi = (op >> 16) & 0x1F;
			bool lk = op & 1;
			if (!(bo & 0x04))
				return false; /* interpreter decrements/tests CTR for these BO forms; target is CTR too */
			if ((bo & 0x14) == 0x14) { /* unconditional bctr */
				if (lk) { emit_load_imm32(RTMP0, (int32_t)(pc + 4)); a64_str_w_imm(RTMP0, RSTATE, PPCR_LR); }
				a64_ldr_w_imm(RTMP0, RSTATE, PPCR_CTR);
				emit_clear_branch_target_low_bits(RTMP0);
				emit_load_imm32(RTMP1, (int32_t)(pc + 4));
				emit_cmp_w_imm(RTMP0, 0);
				emit32(0x1A800000 | (RTMP0 << 16) | (0x0 << 12) | (RTMP1 << 5) | RTMP0); /* CSEL EQ fallback */
				a64_str_w_imm(RTMP0, RSTATE, PPCR_PC);
				lazy_flush_cr0();
				ra_flush_all();
				a64_ldp_post(27, 28, A64_SP, 16);
				a64_ldp_post(25, 26, A64_SP, 16);
				a64_ldp_post(23, 24, A64_SP, 16);
				a64_ldp_post(21, 22, A64_SP, 16);
				a64_ldp_post(19, RSTATE, A64_SP, 16);
				a64_ldp_post(A64_FP, A64_LR, A64_SP, 16);
				a64_ret();
				return true;
			}
			/* Conditional bcctr: test CR[BI] */
			{
				uint32_t bit_pos = 31 - bi;
				lazy_flush_cr0();
				a64_ldr_w_imm(RTMP0, RSTATE, PPCR_CR);
				if (bit_pos) { emit_load_imm32(RTMP1, bit_pos); emit32(0x1AC02400 | (RTMP1 << 16) | (RTMP0 << 5) | RTMP0); }
				emit32(0x12000000 | (RTMP0 << 5) | RTMP0);
				bool branch_if_true = (bo >> 3) & 1;
				if (lk) { emit_load_imm32(RTMP1, (int32_t)(pc + 4)); a64_str_w_imm(RTMP1, RSTATE, PPCR_LR); }
				a64_ldr_w_imm(RTMP1, RSTATE, PPCR_CTR);
				emit_clear_branch_target_low_bits(RTMP1);
				emit_load_imm32(RTMP2, (int32_t)(pc + 4));
				if (branch_if_true) {
					emit32(0x35000000 | (2 << 5) | RTMP0);
					a64_mov_reg(RTMP1, RTMP2);
				} else {
					emit32(0x34000000 | (2 << 5) | RTMP0);
					a64_mov_reg(RTMP1, RTMP2);
				}
				emit_cmp_w_imm(RTMP1, 0);
				emit32(0x1A800000 | (RTMP1 << 16) | (0x0 << 12) | (RTMP2 << 5) | RTMP1); /* CSEL EQ fallback */
				a64_str_w_imm(RTMP1, RSTATE, PPCR_PC);
				lazy_flush_cr0();
				ra_flush_all();
				a64_ldp_post(27, 28, A64_SP, 16);
				a64_ldp_post(25, 26, A64_SP, 16);
				a64_ldp_post(23, 24, A64_SP, 16);
				a64_ldp_post(21, 22, A64_SP, 16);
				a64_ldp_post(19, RSTATE, A64_SP, 16);
				a64_ldp_post(A64_FP, A64_LR, A64_SP, 16);
				a64_ret();
				return true;
			}
		}
		case 150: /* isync — serialize execution; icbi performs cache invalidation */
			lazy_flush_cr0();
			ra_flush_all();
			emit_load_imm32(RTMP0, (int32_t)(pc + 4));
			a64_str_w_imm(RTMP0, RSTATE, PPCR_PC);
			emit_return_to_dispatch();
			return true;

		case 0: /* mcrf crfD,crfS — copy CR field */
		{
			uint32_t crfD = (op >> 23) & 0x7;
			uint32_t crfS = (op >> 18) & 0x7;
			if (crfD == crfS) return true; /* NOP */
			lazy_flush_cr0();
			a64_ldr_w_imm(RTMP0, RSTATE, PPCR_CR);
			uint32_t src_sh = (7 - crfS) * 4;
			uint32_t dst_sh = (7 - crfD) * 4;
			/* Extract source field */
			a64_mov_reg(RTMP1, RTMP0);
			if (src_sh) { emit_load_imm32(RTMP2, src_sh); emit32(0x1AC02400 | (RTMP2 << 16) | (RTMP1 << 5) | RTMP1); /* LSR */ }
			emit_load_imm32(RTMP2, 0xF);
			emit32(0x0A000000 | (RTMP2 << 16) | (RTMP1 << 5) | RTMP1); /* AND */
			/* Shift to destination position */
			if (dst_sh) { emit_load_imm32(RTMP2, dst_sh); emit32(0x1AC02000 | (RTMP2 << 16) | (RTMP1 << 5) | RTMP1); /* LSL */ }
			/* Clear destination field and OR in new value */
			emit_load_imm32(RTMP2, ~(0xFU << dst_sh));
			emit32(0x0A000000 | (RTMP2 << 16) | (RTMP0 << 5) | RTMP0); /* AND clear dest */
			emit32(0x2A000000 | (RTMP1 << 16) | (RTMP0 << 5) | RTMP0); /* ORR merge */
			a64_str_w_imm(RTMP0, RSTATE, PPCR_CR);
			return true;
		}

		/* CR logical operations: crand, cror, crxor, crnor, crandc, creqv, crorc, crnand */
		case 257: /* crand  crbD,crbA,crbB */
		case 449: /* cror   crbD,crbA,crbB */
		case 193: /* crxor  crbD,crbA,crbB */
		case 33:  /* crnor  crbD,crbA,crbB */
		case 129: /* crandc crbD,crbA,crbB */
		case 289: /* creqv  crbD,crbA,crbB */
		case 417: /* crorc  crbD,crbA,crbB */
		case 225: /* crnand crbD,crbA,crbB */
		{
			uint32_t crbD = (op >> 21) & 0x1F;
			uint32_t crbA = (op >> 16) & 0x1F;
			uint32_t crbB = (op >> 11) & 0x1F;
			lazy_flush_cr0();
			a64_ldr_w_imm(RTMP0, RSTATE, PPCR_CR);
			/* Extract bit A: (CR >> (31-crbA)) & 1 → RTMP1 */
			a64_mov_reg(RTMP1, RTMP0);
			if (31 - crbA) { emit_load_imm32(RTMP2, 31 - crbA); emit32(0x1AC02400 | (RTMP2 << 16) | (RTMP1 << 5) | RTMP1); }
			emit_load_imm32(RTMP2, 1);
			emit32(0x0A000000 | (RTMP2 << 16) | (RTMP1 << 5) | RTMP1); /* AND #1 */
			/* Extract bit B: (CR >> (31-crbB)) & 1 → RTMP2 */
			a64_mov_reg(RTMP2, RTMP0);
			if (31 - crbB) { uint32_t sh = 31 - crbB; emit_load_imm32(RTMP0, sh); emit32(0x1AC02400 | (RTMP0 << 16) | (RTMP2 << 5) | RTMP2); }
			emit_load_imm32(RTMP0, 1);
			emit32(0x0A000000 | (RTMP0 << 16) | (RTMP2 << 5) | RTMP2); /* AND #1 */
			/* Compute result bit → RTMP1 */
			switch (xo) {
			case 257: /* crand:  a & b */
				emit32(0x0A000000 | (RTMP2 << 16) | (RTMP1 << 5) | RTMP1); break;
			case 449: /* cror:   a | b */
				emit32(0x2A000000 | (RTMP2 << 16) | (RTMP1 << 5) | RTMP1); break;
			case 193: /* crxor:  a ^ b */
				emit32(0x4A000000 | (RTMP2 << 16) | (RTMP1 << 5) | RTMP1); break;
			case 33:  /* crnor:  ~(a | b) = NOR */
				emit32(0x2A000000 | (RTMP2 << 16) | (RTMP1 << 5) | RTMP1); /* OR */
				emit32(0x2A2003E0 | (RTMP1 << 16) | RTMP1); /* MVN Wd,Wn = ORN Wd,WZR,Wn */
				emit_load_imm32(RTMP2, 1);
				emit32(0x0A000000 | (RTMP2 << 16) | (RTMP1 << 5) | RTMP1); /* AND #1 */
				break;
			case 129: /* crandc: a & ~b */
				emit32(0x0A200000 | (RTMP2 << 16) | (RTMP1 << 5) | RTMP1); /* BIC */ break;
			case 289: /* creqv:  ~(a ^ b) = XNOR */
				emit32(0x4A000000 | (RTMP2 << 16) | (RTMP1 << 5) | RTMP1); /* XOR */
				emit32(0x2A2003E0 | (RTMP1 << 16) | RTMP1); /* MVN */
				emit_load_imm32(RTMP2, 1);
				emit32(0x0A000000 | (RTMP2 << 16) | (RTMP1 << 5) | RTMP1); /* AND #1 */
				break;
			case 417: /* crorc:  a | ~b */
				emit32(0x2A200000 | (RTMP2 << 16) | (RTMP1 << 5) | RTMP1); /* ORN: a | ~b (full 32-bit) */
				emit_load_imm32(RTMP2, 1);
				emit32(0x0A000000 | (RTMP2 << 16) | (RTMP1 << 5) | RTMP1); /* AND #1: ~b sets bits 1..31, mask back to the single CR bit */
				break;
			case 225: /* crnand: ~(a & b) */
				emit32(0x0A000000 | (RTMP2 << 16) | (RTMP1 << 5) | RTMP1); /* AND */
				emit32(0x2A2003E0 | (RTMP1 << 16) | RTMP1); /* MVN */
				emit_load_imm32(RTMP2, 1);
				emit32(0x0A000000 | (RTMP2 << 16) | (RTMP1 << 5) | RTMP1); /* AND #1 */
				break;
			}
			/* Write result bit into CR at position (31-crbD) */
			lazy_flush_cr0();
			a64_ldr_w_imm(RTMP0, RSTATE, PPCR_CR); /* reload CR */
			uint32_t dst_bit = 31 - crbD;
			emit_load_imm32(RTMP2, ~(1u << dst_bit));
			emit32(0x0A000000 | (RTMP2 << 16) | (RTMP0 << 5) | RTMP0); /* AND: clear dest bit */
			if (dst_bit) { emit_load_imm32(RTMP2, dst_bit); emit32(0x1AC02000 | (RTMP2 << 16) | (RTMP1 << 5) | RTMP1); /* LSL result */ }
			emit32(0x2A000000 | (RTMP1 << 16) | (RTMP0 << 5) | RTMP0); /* ORR: merge */
			a64_str_w_imm(RTMP0, RSTATE, PPCR_CR);
			return true;
		}
		default:
			return false; /* unknown opcode 19 sub-op: stop compilation */
		}
	}

	case 17: /* sc — system call: fall back so interpreter raises it */
		return false;

	case 18: /* b/bl (unconditional branch) */
	{
		int32_t li = ((op & 0x03FFFFFC) ^ 0x02000000) - 0x02000000;
		bool lk = op & 1;
		bool aa = op & 2;
		uint32_t target = aa ? (uint32_t)li : (pc + li);
		/* Branch target is an address, not an opcode. Do not reject addresses
		 * based on their high bits; if the target contains a SheepShaver opcode-6
		 * instruction, the direct JIT handles it explicitly. */
		if (lk) {
			emit_load_imm32(RTMP0, (int32_t)(pc + 4));
			a64_str_w_imm(RTMP0, RSTATE, PPCR_LR);
		}
		lazy_flush_cr0();
		emit_epilogue_with_pc(target);
		return true;
	}

	case 6: /* SheepShaver custom EMUL_OP / EXEC_NATIVE opcode */
		lazy_flush_cr0();
		ra_flush_all();
		a64_mov_reg(RTMP0, RSTATE); /* arg0: regs */
		switch (op & 0x3F) {
		case 0: /* EMUL_RETURN */
			emit_load_imm64(RTMP4, (uint64_t)(uintptr_t)sheepshaver_jit_emul_return);
			emit32(0xD63F0000 | (RTMP4 << 5));
			break;
		case 1: /* EXEC_RETURN */
			emit_load_imm64(RTMP4, (uint64_t)(uintptr_t)sheepshaver_jit_exec_return);
			emit32(0xD63F0000 | (RTMP4 << 5));
			break;
		case 2: { /* EXEC_NATIVE */
			uint32_t selector = (op >> 6) & 0x3F;
			/* Match interpreter execute_sheep(): run the native op FIRST, then
			 * pc = (FN ? lr() : pc+4) evaluated AFTER it. Do NOT capture LR here
			 * (it may be changed by the native op). Encode FN (opcode bit 12) in
			 * bit 31 of the selector arg; pass pc+4 as the fall-through pc. */
			uint32_t sel_arg = selector | ((op & (1u << 12)) ? 0x80000000u : 0u);
			emit_load_imm32(RTMP1, (int32_t)sel_arg);
			emit_load_imm32(RTMP2, (int32_t)(pc + 4));
			emit_load_imm64(RTMP4, (uint64_t)(uintptr_t)sheepshaver_jit_execute_native_op);
			emit32(0xD63F0000 | (RTMP4 << 5));
			break;
		}
		default: { /* EMUL_OP */
			uint32_t emul_op = (op & 0x3F) - 3;
			emit_load_imm32(RTMP1, (int32_t)emul_op);
			emit_load_imm32(RTMP2, (int32_t)(pc + 4));
			emit_load_imm64(RTMP4, (uint64_t)(uintptr_t)sheepshaver_jit_execute_emul_op);
			emit32(0xD63F0000 | (RTMP4 << 5));
			break;
		}
		}
		ra_reset();
		emit_return_to_dispatch();
		return true;

	case 42: /* lha rD,d(rA) — load halfword algebraic (sign-extended) */
		rd = PPC_RD(op); ra = PPC_RA(op); simm = PPC_SIMM(op);
		emit_load_ea_base(ra);
		if (simm) { emit_load_imm32(RTMP1, (int32_t)simm); emit32(0x0B000000 | (RTMP1 << 16) | (RTMP0 << 5) | RTMP0); }
		emit_guarded_load_zero_invalid(RTMP0, RTMP1, 3, rd);
		emit_store_gpr(RTMP1, rd);
		return true;

	case 2: /* tdi — trap doubleword immediate: fall back to interpreter */
	case 3: /* twi — trap word immediate: fall back so trap conditions are evaluated */
		return false;

	case 4: /* AltiVec via NEON */
	{
		uint32_t vxo = op & 0x7FF;
		uint32_t vao = op & 0x3F;
		uint32_t vd = VR_VD(op), va = VR_VA(op), vb = VR_VB(op), vc = VR_VC(op);
		switch (vxo) {
		case 0: emit_load_vr(0,va); emit_load_vr(1,vb); emit32(0x4E208400|(1<<16)|(0<<5)|0); emit_store_vr(0,vd); return true;
		case 64: emit_load_vr(0,va); emit_load_vr(1,vb); emit32(0x4E608400|(1<<16)|(0<<5)|0); emit_store_vr(0,vd); return true;
		case 128: emit_load_vr(0,va); emit_load_vr(1,vb); emit32(0x4EA08400|(1<<16)|(0<<5)|0); emit_store_vr(0,vd); return true;
		case 10: emit_load_vr(0,va); emit_load_vr(1,vb); emit32(0x4E20D400|(1<<16)|(0<<5)|0); emit_store_vr(0,vd); return true;
		case 1024: emit_load_vr(0,va); emit_load_vr(1,vb); emit32(0x6E208400|(1<<16)|(0<<5)|0); emit_store_vr(0,vd); return true;
		case 1088: emit_load_vr(0,va); emit_load_vr(1,vb); emit32(0x6E608400|(1<<16)|(0<<5)|0); emit_store_vr(0,vd); return true;
		case 1152: emit_load_vr(0,va); emit_load_vr(1,vb); emit32(0x6EA08400|(1<<16)|(0<<5)|0); emit_store_vr(0,vd); return true;
		case 74: emit_load_vr(0,va); emit_load_vr(1,vb); emit32(0x4EA0D400|(1<<16)|(0<<5)|0); emit_store_vr(0,vd); return true;
		case 1028: emit_load_vr(0,va); emit_load_vr(1,vb); emit32(0x4E201C00|(1<<16)|(0<<5)|0); emit_store_vr(0,vd); return true;
		case 1092: emit_load_vr(0,va); emit_load_vr(1,vb); emit32(0x4E601C00|(1<<16)|(0<<5)|0); emit_store_vr(0,vd); return true;
		case 1156: emit_load_vr(0,va); emit_load_vr(1,vb); emit32(0x4EA01C00|(1<<16)|(0<<5)|0); emit_store_vr(0,vd); return true;
		case 1220: emit_load_vr(0,va); emit_load_vr(1,vb); emit32(0x6E201C00|(1<<16)|(0<<5)|0); emit_store_vr(0,vd); return true;
		case 1284: emit_load_vr(0,va); emit_load_vr(1,vb); emit32(0x4EA01C00|(1<<16)|(0<<5)|0); emit32(0x6E205800|(0<<5)|0); emit_store_vr(0,vd); return true;
		case 1034: emit_load_vr(0,va); emit_load_vr(1,vb); emit32(0x4E20F400|(1<<16)|(0<<5)|0); emit_store_vr(0,vd); return true;
		case 1098: emit_load_vr(0,va); emit_load_vr(1,vb); emit32(0x4EA0F400|(1<<16)|(0<<5)|0); emit_store_vr(0,vd); return true;
		case 266: emit_load_vr(0,vb); emit32(0x4EA1D800|(0<<5)|0); emit_store_vr(0,vd); return true;
		case 330: emit_load_vr(0,vb); emit32(0x6EA1D800|(0<<5)|0); emit_store_vr(0,vd); return true;
		case 394: emit_load_vr(0,vb); emit32(0x4E218800|(0<<5)|0); emit_store_vr(0,vd); return true;
		case 458: emit_load_vr(0,vb); emit32(0x4EA19800|(0<<5)|0); emit_store_vr(0,vd); return true;
		case 6: emit_load_vr(0,va); emit_load_vr(1,vb); emit32(0x6E208C00|(1<<16)|(0<<5)|0); emit_store_vr(0,vd); return true;
		case 70: emit_load_vr(0,va); emit_load_vr(1,vb); emit32(0x6E608C00|(1<<16)|(0<<5)|0); emit_store_vr(0,vd); return true;
		case 134: emit_load_vr(0,va); emit_load_vr(1,vb); emit32(0x6EA08C00|(1<<16)|(0<<5)|0); emit_store_vr(0,vd); return true;
		case 198: emit_load_vr(0,va); emit_load_vr(1,vb); emit32(0x4E20E400|(1<<16)|(0<<5)|0); emit_store_vr(0,vd); return true;
		case 908: { int32_t s=((va&0x1F)|(va&0x10?0xFFFFFFE0:0)); emit_load_imm32(RTMP0,s); emit32(0x4E040C00|(RTMP0<<5)|0); emit_store_vr(0,vd); return true; }
		case 844: { int32_t s=((va&0x1F)|(va&0x10?0xFFFFFFE0:0)); emit_load_imm32(RTMP0,s&0xFFFF); emit32(0x4E020C00|(RTMP0<<5)|0); emit_store_vr(0,vd); return true; }
		case 780: { int32_t s=((va&0x1F)|(va&0x10?0xFFFFFFE0:0)); emit_load_imm32(RTMP0,s&0xFF); emit32(0x4E010C00|(RTMP0<<5)|0); emit_store_vr(0,vd); return true; }

		case 258: emit_load_vr(0,va); emit_load_vr(1,vb); emit32(0x4E206400|(1<<16)|(0<<5)|0); emit_store_vr(0,vd); return true; /* vmaxsb SMAX.16B */
		case 322: emit_load_vr(0,va); emit_load_vr(1,vb); emit32(0x4E606400|(1<<16)|(0<<5)|0); emit_store_vr(0,vd); return true; /* vmaxsh SMAX.8H */
		case 386: emit_load_vr(0,va); emit_load_vr(1,vb); emit32(0x4EA06400|(1<<16)|(0<<5)|0); emit_store_vr(0,vd); return true; /* vmaxsw SMAX.4S */
		case 2: emit_load_vr(0,va); emit_load_vr(1,vb); emit32(0x6E206400|(1<<16)|(0<<5)|0); emit_store_vr(0,vd); return true; /* vmaxub UMAX.16B */
		case 66: emit_load_vr(0,va); emit_load_vr(1,vb); emit32(0x6E606400|(1<<16)|(0<<5)|0); emit_store_vr(0,vd); return true; /* vmaxuh UMAX.8H */
		case 130: emit_load_vr(0,va); emit_load_vr(1,vb); emit32(0x6EA06400|(1<<16)|(0<<5)|0); emit_store_vr(0,vd); return true; /* vmaxuw UMAX.4S */
		case 770: emit_load_vr(0,va); emit_load_vr(1,vb); emit32(0x4E206C00|(1<<16)|(0<<5)|0); emit_store_vr(0,vd); return true; /* vminsb SMIN.16B */
		case 834: emit_load_vr(0,va); emit_load_vr(1,vb); emit32(0x4E606C00|(1<<16)|(0<<5)|0); emit_store_vr(0,vd); return true; /* vminsh SMIN.8H */
		case 898: emit_load_vr(0,va); emit_load_vr(1,vb); emit32(0x4EA06C00|(1<<16)|(0<<5)|0); emit_store_vr(0,vd); return true; /* vminsw SMIN.4S */
		case 514: emit_load_vr(0,va); emit_load_vr(1,vb); emit32(0x6E206C00|(1<<16)|(0<<5)|0); emit_store_vr(0,vd); return true; /* vminub UMIN.16B */
		case 578: emit_load_vr(0,va); emit_load_vr(1,vb); emit32(0x6E606C00|(1<<16)|(0<<5)|0); emit_store_vr(0,vd); return true; /* vminuh UMIN.8H */
		case 642: emit_load_vr(0,va); emit_load_vr(1,vb); emit32(0x6EA06C00|(1<<16)|(0<<5)|0); emit_store_vr(0,vd); return true; /* vminuw UMIN.4S */
		case 260: /* vslb — EXCLUDED: hardcoded encoding is SRSHL, not logical USHL */
		case 324: /* vslh — EXCLUDED: hardcoded encoding is SRSHL, not logical USHL */
		case 388: /* vslw — EXCLUDED: hardcoded encoding is SRSHL, not logical USHL */
		case 772: /* vsrb — EXCLUDED: hardcoded encoding is NEG+SRSHL, not logical right shift */
		case 836: /* vsrh — EXCLUDED: hardcoded encoding is NEG+SRSHL, not logical right shift */
		case 900: /* vsrw — EXCLUDED: hardcoded encoding is NEG+SRSHL, not logical right shift */
			return false;
		case 516: emit_load_vr(0,va); emit_load_vr(1,vb); emit32(0x4E204400|(1<<16)|(0<<5)|0); emit_store_vr(0,vd); return true; /* vsrab SSHL.16B (arith) */
		case 580: emit_load_vr(0,va); emit_load_vr(1,vb); emit32(0x6E60B800|(1<<5)|1); emit32(0x4E604400|(1<<16)|(0<<5)|0); emit_store_vr(0,vd); return true; /* vsrah */
		case 644: emit_load_vr(0,va); emit_load_vr(1,vb); emit32(0x6EA0B800|(1<<5)|1); emit32(0x4EA04400|(1<<16)|(0<<5)|0); emit_store_vr(0,vd); return true; /* vsraw */
		case 4:   /* vrlb — EXCLUDED: rotate-left was mapped to shift */
		case 68:  /* vrlh — EXCLUDED: rotate-left was mapped to shift */
		case 132: /* vrlw — EXCLUDED: rotate-left was mapped to shift */
			return false;
		case 524: { uint32_t idx=va; emit_load_vr(0,vb); emit32(0x4E010400|((idx*2+1)<<16)|(0<<5)|0); emit_store_vr(0,vd); return true; } /* vspltb DUP.16B */
		case 588: { uint32_t idx=va; emit_load_vr(0,vb); emit32(0x4E020400|((idx*4+2)<<16)|(0<<5)|0); emit_store_vr(0,vd); return true; } /* vsplth DUP.8H */
		case 652: { uint32_t idx=va; emit_load_vr(0,vb); emit32(0x4E040400|((idx*8+4)<<16)|(0<<5)|0); emit_store_vr(0,vd); return true; } /* vspltw DUP.4S */
		case 522: emit_load_vr(0,vb); emit32(0x4EA18800|(0<<5)|0); emit_store_vr(0,vd); return true; /* vrfip FRINTP */
		case 586: emit_load_vr(0,vb); emit32(0x4E219800|(0<<5)|0); emit_store_vr(0,vd); return true; /* vrfim FRINTM */
		case 966: /* vcmpbfp — EXCLUDED: bounded-FP compare semantics not implemented */
			return false;
		case 454: emit_load_vr(0,va); emit_load_vr(1,vb); emit32(0x6E20E400|(1<<16)|(0<<5)|0); emit_store_vr(0,vd); return true; /* vcmpgefp FCMGE */
		case 774: emit_load_vr(0,va); emit_load_vr(1,vb); emit32(0x4E203400|(1<<16)|(0<<5)|0); emit_store_vr(0,vd); return true; /* vcmpgtsb CMGT.16B (signed) */
		case 838: emit_load_vr(0,va); emit_load_vr(1,vb); emit32(0x4E603400|(1<<16)|(0<<5)|0); emit_store_vr(0,vd); return true; /* vcmpgtsh */
		case 902: emit_load_vr(0,va); emit_load_vr(1,vb); emit32(0x4EA03400|(1<<16)|(0<<5)|0); emit_store_vr(0,vd); return true; /* vcmpgtsw */
		case 518: emit_load_vr(0,va); emit_load_vr(1,vb); emit32(0x6E203400|(1<<16)|(0<<5)|0); emit_store_vr(0,vd); return true; /* vcmpgtub CMHI.16B (unsigned) */
		case 582: emit_load_vr(0,va); emit_load_vr(1,vb); emit32(0x6E603400|(1<<16)|(0<<5)|0); emit_store_vr(0,vd); return true; /* vcmpgtuh */
		case 646: emit_load_vr(0,va); emit_load_vr(1,vb); emit32(0x6EA03400|(1<<16)|(0<<5)|0); emit_store_vr(0,vd); return true; /* vcmpgtuw */
		case 1282: /* vavgub — EXCLUDED: hardcoded encoding disassembles as SMAXP, not rounded average */
		case 1346: /* vavguh — EXCLUDED: hardcoded encoding disassembles as SMAXP, not rounded average */
		case 1410: /* vavguw — EXCLUDED: hardcoded encoding disassembles as SMAXP, not rounded average */
		case 1794: /* vavgsb — EXCLUDED until signed average encoding/lane order is verified */
		case 1858: /* vavgsh — EXCLUDED until signed average encoding/lane order is verified */
		case 1922: /* vavgsw — EXCLUDED until signed average encoding/lane order is verified */
		case 768:  /* vaddubs — EXCLUDED: hardcoded encoding is UABA and VSCR.SAT is not updated */
		case 832:  /* vadduhs — EXCLUDED: hardcoded encoding is UABA and VSCR.SAT is not updated */
		case 896:  /* vadduws — EXCLUDED: hardcoded encoding is UABA and VSCR.SAT is not updated */
		case 1792: /* vsububs — EXCLUDED: native path does not update VSCR.SAT */
		case 1856: /* vsubuhs — EXCLUDED: native path does not update VSCR.SAT */
		case 1920: /* vsubuws — EXCLUDED: native path does not update VSCR.SAT */
		case 512:  /* vaddsbs — EXCLUDED: hardcoded encoding is SABA and VSCR.SAT is not updated */
		case 576:  /* vaddshs — EXCLUDED: hardcoded encoding is SABA and VSCR.SAT is not updated */
		case 640:  /* vaddsws — EXCLUDED: hardcoded encoding is SABA and VSCR.SAT is not updated */
		case 1536: /* vsubsbs — EXCLUDED: native path does not update VSCR.SAT */
		case 1600: /* vsubshs — EXCLUDED: native path does not update VSCR.SAT */
			return false;
		case 12:  /* vmrghb — EXCLUDED: hardcoded encoding is FMAXNM, not ZIP1 */
		case 76:  /* vmrghh — EXCLUDED: hardcoded encoding is FMAXNM, not ZIP1 */
		case 140: /* vmrghw — EXCLUDED: hardcoded encoding is FMINNM, not ZIP1 */
		case 268: /* vmrglb — EXCLUDED: hardcoded encoding is FCVTAS, not ZIP2 */
		case 332: /* vmrglh — EXCLUDED: hardcoded encoding is FCVTAS, not ZIP2 */
		case 396: /* vmrglw — EXCLUDED: hardcoded encoding is URECPE, not ZIP2 */
			return false;

		case 846: /* vcfsx — EXCLUDED: UIMM scale is ignored and encoding direction needs proof */
		case 910: /* vcfux — EXCLUDED: UIMM scale is ignored; hardcoded word disassembles as FCVTAU */
		case 970: /* vctsxs — EXCLUDED: UIMM scale/VSCR.SAT semantics not implemented */
		case 906: /* vctuxs — EXCLUDED: UIMM scale/VSCR.SAT semantics not implemented */
			return false;
		case 354: /* vexptefp — EXCLUDED: FRECPE approximation is not PPC vexptefp semantics */
		case 418: /* vlogefp — EXCLUDED: FRECPE approximation is not PPC vlogefp semantics */
			return false;
		case 8:   /* vmuloub — EXCLUDED: hardcoded encoding is narrow MUL, not odd-lane UMULL */
		case 72:  /* vmulouh — EXCLUDED: hardcoded encoding is SMLSL-like, not odd-lane UMULL */
		case 264: /* vmuleub — EXCLUDED: hardcoded encoding is SMLSL-like, not even-lane UMULL2 */
		case 328: /* vmuleuh — EXCLUDED: hardcoded encoding is SMLSL-like, not even-lane UMULL2 */
		case 776: /* vmulosb — EXCLUDED: hardcoded encoding is narrow MUL, not odd-lane SMULL */
		case 840: /* vmulosh — EXCLUDED until exact odd-lane SMULL encoding is verified */
		case 520: /* vmulesb — EXCLUDED until exact even-lane SMULL2 encoding is verified */
		case 584: /* vmulesh — EXCLUDED until exact even-lane SMULL2 encoding is verified */
			return false;
		case 14: emit_load_vr(0,vb); emit32(0x0E212800|(0<<5)|0); emit_store_vr(0,vd); return true; /* vpkuhum UZP1.8H (narrow) */
		case 78: emit_load_vr(0,vb); emit32(0x0E612800|(0<<5)|0); emit_store_vr(0,vd); return true; /* vpkuwum UZP1.4S */
		case 270: /* vpkshus — EXCLUDED: saturating pack needs exact signedness/lane order and VSCR.SAT */
		case 334: /* vpkswus — EXCLUDED: saturating pack needs exact signedness/lane order and VSCR.SAT */
		case 398: /* vpkshss — EXCLUDED: hardcoded encoding/comment mismatch; VSCR.SAT not updated */
		case 462: /* vpkswss — EXCLUDED: hardcoded encoding/comment mismatch; VSCR.SAT not updated */
		case 142: /* vpkuhus — EXCLUDED: saturating pack needs exact unsigned semantics and VSCR.SAT */
		case 206: /* vpkuwus — EXCLUDED: saturating pack needs exact unsigned semantics and VSCR.SAT */
			return false;
		case 814: emit_load_vr(0,vb); emit32(0x0E212800|(0<<5)|0); emit_store_vr(0,vd); return true; /* vupkhsb SXTL.8H (unpack high signed byte) */
		case 878: emit_load_vr(0,vb); emit32(0x0E612800|(0<<5)|0); emit_store_vr(0,vd); return true; /* vupkhsh SXTL.4S */
		case 942: emit_load_vr(0,vb); emit32(0x4E212800|(0<<5)|0); emit_store_vr(0,vd); return true; /* vupklsb SXTL2.8H */
		case 1006: emit_load_vr(0,vb); emit32(0x4E612800|(0<<5)|0); emit_store_vr(0,vd); return true; /* vupklsh SXTL2.4S */
		case 452: { uint32_t sh=(op>>6)&0xF; emit_load_vr(0,va); emit_load_vr(1,vb); emit32(0x6E010000|(sh<<11)); emit_store_vr(0,vd); return true; } /* vsldoi EXT.16B */
		case 1036: /* vsl — EXCLUDED: whole-vector bit shift was mapped to per-byte shift */
		case 1100: /* vsr — EXCLUDED: whole-vector bit shift was mapped to per-byte shift */
			return false;
		case 1604: /* mtvscr — EXCLUDED: must update architectural VSCR */
		case 1540: /* mfvscr — EXCLUDED: must read architectural VSCR */
			return false;
		case 782: /* vpkpx — EXCLUDED: approximate narrow is not exact pixel pack semantics */
			return false;
		case 974: /* vupkhpx — unpack high pixel (widen) */
			emit_load_vr(0, vb);
			emit32(0x2F10A400 | (0 << 5) | 0);
			emit_store_vr(0, vd); return true;
		case 1038: /* vupklpx — unpack low pixel */
			emit_load_vr(0, vb);
			emit32(0x6F10A400 | (0 << 5) | 0);
			emit_store_vr(0, vd); return true;
		case 1928: /* vsum4ubs */
			emit_load_vr(0, va); emit_load_vr(1, vb);
			emit32(0x6E202800 | (0 << 5) | 0);
			emit32(0x6E602800 | (0 << 5) | 0);
			emit32(0x4EA08400 | (1 << 16) | (0 << 5) | 0);
			emit_store_vr(0, vd); return true;
		case 1672: /* vsum4sbs */
			emit_load_vr(0, va); emit_load_vr(1, vb);
			emit32(0x4E202800 | (0 << 5) | 0);
			emit32(0x4E602800 | (0 << 5) | 0);
			emit32(0x4EA08400 | (1 << 16) | (0 << 5) | 0);
			emit_store_vr(0, vd); return true;
		case 1608: /* vsum4shs */
			emit_load_vr(0, va); emit_load_vr(1, vb);
			emit32(0x4E602800 | (0 << 5) | 0);
			emit32(0x4EA08400 | (1 << 16) | (0 << 5) | 0);
			emit_store_vr(0, vd); return true;
		case 1800: /* vsum2sws */
			emit_load_vr(0, va); emit_load_vr(1, vb);
			emit32(0x4EA02800 | (0 << 5) | 0);
			emit32(0x0EA12800 | (0 << 5) | 0);
			emit32(0x4EA08400 | (1 << 16) | (0 << 5) | 0);
			emit_store_vr(0, vd); return true;
		case 1932: /* vsumsws — sum all words */
			emit_load_vr(0, va); emit_load_vr(1, vb);
			emit32(0x4EB1B800 | (0 << 5) | 0);
			emit32(0x4EA08400 | (1 << 16) | (0 << 5) | 0);
			emit_store_vr(0, vd); return true;
		case 1356: /* vslo — EXCLUDED: pass-through is not exact octet-shift semantics */
		case 1420: /* vsro — EXCLUDED: pass-through is not exact octet-shift semantics */
			return false;
		default: break;
		}
		switch (vao) {
		case 46: emit_load_vr(0,va); emit_load_vr(1,vc); emit_load_vr(2,vb); emit32(0x4E21CC00|(1<<16)|(0<<5)|2); emit_store_vr(2,vd); return true;
		case 47: emit_load_vr(0,va); emit_load_vr(1,vc); emit_load_vr(2,vb); emit32(0x4EA1CC00|(1<<16)|(0<<5)|2); emit_store_vr(2,vd); return true;
		case 43: /* vperm — mask control bytes to PPC's 0..31 selector range before TBL */
			emit_load_vr(0,va); emit_load_vr(1,vb); emit_load_vr(2,vc);
			emit32(0x4F00E7E3); /* MOVI v3.16b,#0x1f */
			emit32(0x4E231C42); /* AND v2.16b,v2.16b,v3.16b */
			emit32(0x4E002000|(2<<16)|(0<<5)|0); /* TBL v0.16b,{v0-v1},v2 */
			emit_store_vr(0,vd); return true;
		case 42: emit_load_vr(0,va); emit_load_vr(1,vb); emit_load_vr(2,vc); emit32(0x6E601C00|(0<<16)|(1<<5)|2); emit_store_vr(2,vd); return true; /* vsel: BSL mask=vc, true=vb, false=va */

		case 32: /* vmhaddshs — EXCLUDED: FMLA approximation is not exact saturated halfword semantics */
		case 33: /* vmhraddshs — EXCLUDED: approximation is not exact rounded saturated semantics */
			return false;
		case 34: emit_load_vr(0,va); emit_load_vr(1,vc); emit_load_vr(2,vb); emit32(0x4E609C00|(1<<16)|(0<<5)|0); emit32(0x4E608400|(2<<16)|(0<<5)|0); emit_store_vr(0,vd); return true; /* vmladduhm MUL+ADD */
		case 36: /* vmsumubm — EXCLUDED: native sequence is approximate/wrong vector-sum semantics */
		case 37: /* vmsummbm — EXCLUDED: native sequence is approximate/wrong vector-sum semantics */
		case 38: /* vmsumuhm — EXCLUDED: old native sequence emitted undefined AArch64 for this XO */
		case 39: /* vmsumuhs — EXCLUDED: saturated vector sum must update VSCR.SAT exactly */
		case 40: /* vmsumshm — EXCLUDED: native sequence is approximate/wrong vector-sum semantics */
		case 41: /* vmsumshs — EXCLUDED: saturated vector sum must update VSCR.SAT exactly */
			return false;
		default: return false;
		}
	}

	case 7: /* mulli rD,rA,SIMM */
		rd = PPC_RD(op); ra = PPC_RA(op); simm = PPC_SIMM(op);
		emit_load_gpr(RTMP0, ra);
		emit_load_imm32(RTMP1, (int32_t)simm);
		emit32(0x1B007C00 | (RTMP1 << 16) | (RTMP0 << 5) | RTMP0); /* MUL Wd,Wn,Wm */
		emit_store_gpr(RTMP0, rd);
		return true;

	case 13: /* addic. rD,rA,SIMM (sets XER[CA] + CR0) */
		rd = PPC_RD(op); ra = PPC_RA(op); simm = PPC_SIMM(op);
		emit_load_gpr(RTMP0, ra);
		emit_load_imm32(RTMP1, (int32_t)simm);
		emit32(0x2B000000 | (RTMP1 << 16) | (RTMP0 << 5) | RTMP0); /* ADDS */
		emit_store_gpr(RTMP0, rd);
		emit_write_xer_ca_from_carry();
		lazy_update_cr0(RTMP0);
		return true;

	case 35: /* lbzu rD,d(rA) */
		rd = PPC_RD(op); ra = PPC_RA(op); simm = PPC_SIMM(op);
		/* ra==0: use 0 as base; ra==rd: update gets overwritten by load (PPC undefined but harmless) */
		emit_load_gpr(RTMP0, ra);
		emit_load_imm32(RTMP1, (int32_t)simm);
		emit32(0x0B000000 | (RTMP1 << 16) | (RTMP0 << 5) | RTMP0);
		emit_store_gpr(RTMP0, ra);
		emit_guarded_load_zero_invalid(RTMP0, RTMP1, 1, rd);
		emit_store_gpr(RTMP1, rd);
		return true;

	case 39: /* stbu rS,d(rA) */
		rd = PPC_RS(op); ra = PPC_RA(op); simm = PPC_SIMM(op);
		emit_load_gpr(RTMP1, rd);
		emit_load_gpr(RTMP0, ra);
		emit_load_imm32(RTMP2, (int32_t)simm);
		emit32(0x0B000000 | (RTMP2 << 16) | (RTMP0 << 5) | RTMP0);
		emit_store_gpr(RTMP0, ra);
		emit_guarded_store_noop_invalid(RTMP0, RTMP1, 1);
		return true;

	case 41: /* lhzu rD,d(rA) */
		rd = PPC_RD(op); ra = PPC_RA(op); simm = PPC_SIMM(op);
		/* ra==0: use 0 as base; ra==rd: update gets overwritten by load (PPC undefined but harmless) */
		emit_load_gpr(RTMP0, ra);
		emit_load_imm32(RTMP1, (int32_t)simm);
		emit32(0x0B000000 | (RTMP1 << 16) | (RTMP0 << 5) | RTMP0);
		emit_store_gpr(RTMP0, ra);
		emit_guarded_load_zero_invalid(RTMP0, RTMP1, 2, rd);
		emit_store_gpr(RTMP1, rd);
		return true;

	case 43: /* lhau rD,d(rA) */
		rd = PPC_RD(op); ra = PPC_RA(op); simm = PPC_SIMM(op);
		/* ra==0: use 0 as base; ra==rd: update gets overwritten by load (PPC undefined but harmless) */
		emit_load_gpr(RTMP0, ra);
		emit_load_imm32(RTMP1, (int32_t)simm);
		emit32(0x0B000000 | (RTMP1 << 16) | (RTMP0 << 5) | RTMP0);
		emit_store_gpr(RTMP0, ra);
		emit_guarded_load_zero_invalid(RTMP0, RTMP1, 3, rd);
		emit_store_gpr(RTMP1, rd);
		return true;

	case 45: /* sthu rS,d(rA) */
		rd = PPC_RS(op); ra = PPC_RA(op); simm = PPC_SIMM(op);
		emit_load_gpr(RTMP1, rd);
		emit32(0x5AC00400 | (RTMP1 << 5) | RTMP1);
		emit_load_gpr(RTMP0, ra);
		emit_load_imm32(RTMP2, (int32_t)simm);
		emit32(0x0B000000 | (RTMP2 << 16) | (RTMP0 << 5) | RTMP0);
		emit_store_gpr(RTMP0, ra);
		emit_guarded_store_noop_invalid(RTMP0, RTMP1, 2);
		return true;

	case 49: /* lfsu frD,d(rA) */
		rd = PPC_RD(op); ra = PPC_RA(op); simm = PPC_SIMM(op);
		emit_load_ea_base(ra);
		emit_load_imm32(RTMP1, (int32_t)simm);
		emit32(0x0B000000 | (RTMP1 << 16) | (RTMP0 << 5) | RTMP0);
		a64_mov_reg(A64_FP, RTMP0);
		emit_call_fp_load_helper(RTMP0, rd, false);
		emit_store_gpr(A64_FP, ra);
		return true;

	case 51: /* lfdu frD,d(rA) */
		rd = PPC_RD(op); ra = PPC_RA(op); simm = PPC_SIMM(op);
		emit_load_ea_base(ra);
		emit_load_imm32(RTMP1, (int32_t)simm);
		emit32(0x0B000000 | (RTMP1 << 16) | (RTMP0 << 5) | RTMP0);
		a64_mov_reg(A64_FP, RTMP0);
		emit_call_fp_load_helper(RTMP0, rd, true);
		emit_store_gpr(A64_FP, ra);
		return true;

	case 53: /* stfsu frS,d(rA) */
		rd = PPC_RS(op); ra = PPC_RA(op); simm = PPC_SIMM(op);
		emit_load_gpr(RTMP0, ra);
		emit_load_imm32(RTMP2, (int32_t)simm);
		emit32(0x0B000000 | (RTMP2 << 16) | (RTMP0 << 5) | RTMP0);
		a64_mov_reg(A64_FP, RTMP0);
		emit_call_fp_store_helper(RTMP0, rd, false);
		emit_store_gpr(A64_FP, ra);
		return true;

	case 55: /* stfdu frS,d(rA) */
		rd = PPC_RS(op); ra = PPC_RA(op); simm = PPC_SIMM(op);
		emit_load_gpr(RTMP0, ra);
		emit_load_imm32(RTMP2, (int32_t)simm);
		emit32(0x0B000000 | (RTMP2 << 16) | (RTMP0 << 5) | RTMP0);
		a64_mov_reg(A64_FP, RTMP0);
		emit_call_fp_store_helper(RTMP0, rd, true);
		emit_store_gpr(A64_FP, ra);
		return true;

	case 46: /* lmw rD,d(rA) — load multiple words */
	{
		rd = PPC_RD(op); ra = PPC_RA(op); simm = PPC_SIMM(op);
		emit_load_ea_base(ra);
		if (simm) { emit_load_imm32(RTMP1, (int32_t)simm); emit32(0x0B000000 | (RTMP1 << 16) | (RTMP0 << 5) | RTMP0); }
		for (uint32_t r = rd; r < 32; r++) {
			emit32(0xB9400000 | (RTMP0 << 5) | RTMP1); /* LDR Wt, [Xn] */
			emit32(0x5AC00800 | (RTMP1 << 5) | RTMP1); /* REV */
			a64_str_w_imm(RTMP1, RSTATE, PPCR_GPR(r));
			if (r < 31) emit32(0x11001000 | (RTMP0 << 5) | RTMP0); /* ADD Wn, Wn, #4 */
		}
		return true;
	}

	case 47: /* stmw rS,d(rA) — store multiple words */
	{
		rd = PPC_RS(op); ra = PPC_RA(op); simm = PPC_SIMM(op);
		emit_load_ea_base(ra);
		if (simm) { emit_load_imm32(RTMP1, (int32_t)simm); emit32(0x0B000000 | (RTMP1 << 16) | (RTMP0 << 5) | RTMP0); }
		for (uint32_t r = rd; r < 32; r++) {
			a64_ldr_w_imm(RTMP1, RSTATE, PPCR_GPR(r));
			emit32(0x5AC00800 | (RTMP1 << 5) | RTMP1); /* REV */
			emit32(0xB9000000 | (RTMP0 << 5) | RTMP1); /* STR Wt, [Xn] */
			if (r < 31) emit32(0x11001000 | (RTMP0 << 5) | RTMP0); /* ADD +4 */
		}
		return true;
	}

	case 48: /* lfs frD,d(rA) — load float single */
		rd = PPC_RD(op); ra = PPC_RA(op); simm = PPC_SIMM(op);
		emit_load_ea_base(ra);
		if (simm) { emit_load_imm32(RTMP1, (int32_t)simm); emit32(0x0B000000 | (RTMP1 << 16) | (RTMP0 << 5) | RTMP0); }
		emit_call_fp_load_helper(RTMP0, rd, false);
		return true;

	case 50: /* lfd frD,d(rA) — load float double */
		rd = PPC_RD(op); ra = PPC_RA(op); simm = PPC_SIMM(op);
		emit_load_ea_base(ra);
		if (simm) { emit_load_imm32(RTMP1, (int32_t)simm); emit32(0x0B000000 | (RTMP1 << 16) | (RTMP0 << 5) | RTMP0); }
		emit_call_fp_load_helper(RTMP0, rd, true);
		return true;

	case 52: /* stfs frS,d(rA) — store float single */
		rd = PPC_RS(op); ra = PPC_RA(op); simm = PPC_SIMM(op);
		emit_load_ea_base(ra);
		if (simm) { emit_load_imm32(RTMP2, (int32_t)simm); emit32(0x0B000000 | (RTMP2 << 16) | (RTMP0 << 5) | RTMP0); }
		emit_call_fp_store_helper(RTMP0, rd, false);
		return true;

	case 54: /* stfd frS,d(rA) — store float double */
		rd = PPC_RS(op); ra = PPC_RA(op); simm = PPC_SIMM(op);
		emit_load_ea_base(ra);
		if (simm) { emit_load_imm32(RTMP2, (int32_t)simm); emit32(0x0B000000 | (RTMP2 << 16) | (RTMP0 << 5) | RTMP0); }
		emit_call_fp_store_helper(RTMP0, rd, true);
		return true;

	case 63: /* double-precision FP ops */
	{
		uint32_t xo10 = (op >> 1) & 0x3FF;
		uint32_t xo5 = (op >> 1) & 0x1F;
		uint32_t frd = PPC_RD(op);
		uint32_t fra = PPC_RA(op);
		uint32_t frb = (op >> 11) & 0x1F;
		uint32_t frc = (op >> 6) & 0x1F;

		/* X-form FP ops (10-bit XO) */
		switch (xo10) {
		case 72: /* fmr frD,frB — FP move register */
			emit_load_fpr(0, frb);
			emit_store_fpr(0, frd);
			return true;

		case 40: /* fneg frD,frB — FP negate */
			emit_load_fpr(0, frb);
			emit32(0x1E614000 | (0 << 5) | 0); /* FNEG Dd, Dn */
			emit_store_fpr(0, frd);
			return true;

		case 264: /* fabs frD,frB — FP absolute value */
			emit_load_fpr(0, frb);
			emit32(0x1E60C000 | (0 << 5) | 0); /* FABS Dd, Dn */
			emit_store_fpr(0, frd);
			return true;

		case 136: /* fnabs frD,frB — FP negative absolute */
			emit_load_fpr(0, frb);
			emit32(0x1E60C000 | (0 << 5) | 0); /* FABS */
			emit32(0x1E614000 | (0 << 5) | 0); /* FNEG */
			emit_store_fpr(0, frd);
			return true;

		case 0:  /* fcmpu crD,frA,frB — EXCLUDED: unordered/FPSCR semantics not exact */
		case 32: /* fcmpo crD,frA,frB — EXCLUDED: unordered/FPSCR semantics not exact */
			/* ARM64 FCMP reports unordered as V=1, which the old CSEL sequence treated as LT,
			 * while the interpreter sets FU (CR field bit 0) and updates FPSCR.FPCC. fcmpo also
			 * has ordered-compare exception behaviour. Delegate until the full FPCC/exception
			 * semantics are implemented exactly. */
			return false;

		case 12: /* frsp frD,frB — round to single precision */
			emit_load_fpr(0, frb);
			emit32(0x1E624000 | (0 << 5) | 0); /* FCVT Sd, Dd */
			emit32(0x1E22C000 | (0 << 5) | 0); /* FCVT Dd, Sd */
			emit_store_fpr(0, frd);
			return true;

		case 14: /* fctiw frD,frB — EXCLUDED: FPSCR.RN rounding/exception semantics not exact */
			/* The old native handler used FCVTZS (round toward zero), which is fctiwz
			 * semantics. fctiw must obey FPSCR.RN (default nearest), update FPSCR exception
			 * bits, and optionally CR1 for Rc. Delegate until exact semantics are native. */
			return false;

		case 15: /* fctiwz frD,frB — convert to integer word (round toward zero) */
			emit_load_fpr(0, frb);
			emit32(0x9E780000 | (0 << 5) | RTMP0); /* FCVTZS Xd, Dn */
			emit32(0x9E670000 | (RTMP0 << 5) | 0); /* FMOV Dd, Xn */
			emit_store_fpr(0, frd);
			return true;

		case 583: /* mffs frD — move from FPSCR */
			a64_ldr_w_imm(RTMP0, RSTATE, PPCR_FPSCR);
			emit32(0x9E670000 | (RTMP0 << 5) | 0); /* FMOV Dd, Xn */
			emit_store_fpr(0, frd);
			return true;

		case 711: /* mtfsfi crfD,IMM — set FPSCR field to 4-bit immediate */
		{
			uint32_t crfD = (op >> 23) & 0x7;
			uint32_t imm = (op >> 12) & 0xF;
			uint32_t shift = (7 - crfD) * 4;
			a64_ldr_w_imm(RTMP0, RSTATE, PPCR_FPSCR);
			emit_load_imm32(RTMP1, ~(0xF << shift));
			emit32(0x0A000000 | (RTMP1 << 16) | (RTMP0 << 5) | RTMP0); /* clear field */
			emit_load_imm32(RTMP1, imm << shift);
			emit32(0x2A000000 | (RTMP1 << 16) | (RTMP0 << 5) | RTMP0); /* set field */
			a64_str_w_imm(RTMP0, RSTATE, PPCR_FPSCR);
			if (crfD == 7) emit_sync_fpscr_rounding(); /* field 7 contains RN */
			return true;
		}

		case 70: /* mtfsb0 crbD — clear FPSCR bit */
		{
			uint32_t crbD = (op >> 21) & 0x1F;
			a64_ldr_w_imm(RTMP0, RSTATE, PPCR_FPSCR);
			emit_load_imm32(RTMP1, ~(1u << (31 - crbD)));
			emit32(0x0A000000 | (RTMP1 << 16) | (RTMP0 << 5) | RTMP0);
			a64_str_w_imm(RTMP0, RSTATE, PPCR_FPSCR);
			if (crbD >= 30) emit_sync_fpscr_rounding(); /* RN bits */
			return true;
		}

		case 38: /* mtfsb1 crbD — set FPSCR bit */
		{
			uint32_t crbD = (op >> 21) & 0x1F;
			a64_ldr_w_imm(RTMP0, RSTATE, PPCR_FPSCR);
			emit_load_imm32(RTMP1, 1u << (31 - crbD));
			emit32(0x2A000000 | (RTMP1 << 16) | (RTMP0 << 5) | RTMP0);
			a64_str_w_imm(RTMP0, RSTATE, PPCR_FPSCR);
			if (crbD >= 30) emit_sync_fpscr_rounding();
			return true;
		}

		case 134: /* mtfsf FM,frB — move to FPSCR fields */
		{
			uint32_t fm = (op >> 17) & 0xFF;
			emit_load_fpr(0, frb);
			emit32(0x9E660000 | (0 << 5) | RTMP0); /* FMOV Xn, Dd */
			/* Build mask from FM (each bit enables a 4-bit field) */
			uint32_t mask = 0;
			for (int i = 0; i < 8; i++)
				if (fm & (1 << (7 - i))) mask |= (0xF << ((7 - i) * 4));
			a64_ldr_w_imm(RTMP1, RSTATE, PPCR_FPSCR);
			emit_load_imm32(RTMP2, ~mask);
			emit32(0x0A000000 | (RTMP2 << 16) | (RTMP1 << 5) | RTMP1); /* clear target fields */
			emit_load_imm32(RTMP2, mask);
			emit32(0x0A000000 | (RTMP2 << 16) | (RTMP0 << 5) | RTMP0); /* mask source */
			emit32(0x2A000000 | (RTMP0 << 16) | (RTMP1 << 5) | RTMP1); /* merge */
			a64_str_w_imm(RTMP1, RSTATE, PPCR_FPSCR);
			if (fm & 1) emit_sync_fpscr_rounding(); /* field 7 (RN) modified */
			return true;
		}

		case 23: /* fsel frD,frA,frC,frB — if frA >= 0 then frC else frB */
			emit_load_fpr(0, fra);
			emit_load_fpr(1, frc);
			emit_load_fpr(2, frb);
			/* Compare frA with 0.0 */
			emit32(0x1E602010 | (0 << 5)); /* FCMP Dn, #0.0 */
			/* FCSEL Dd, Dc, Db, GE */
			emit32(0x1E600C00 | (2 << 16) | (0xA << 12) | (1 << 5) | 0); /* FCSEL D0,D1,D2,GE */
			emit_store_fpr(0, frd);
			return true;
		
		case 64: /* mcrfs crD,crS — move from FPSCR field to CR field */
		{
			uint32_t crd_f = (op >> 23) & 0x7;
			uint32_t crs_f = (op >> 18) & 0x7;
			/* Read FPSCR field and write to CR field */
			a64_ldr_w_imm(RTMP0, RSTATE, PPCR_FPSCR);
			uint32_t src_sh = (7 - crs_f) * 4;
			uint32_t dst_sh = (7 - crd_f) * 4;
			a64_mov_reg(RTMP1, RTMP0);
			if (src_sh) { emit_load_imm32(RTMP2, src_sh); emit32(0x1AC02400 | (RTMP2 << 16) | (RTMP1 << 5) | RTMP1); }
			emit_load_imm32(RTMP2, 0xF);
			emit32(0x0A000000 | (RTMP2 << 16) | (RTMP1 << 5) | RTMP1);
			if (dst_sh) { emit_load_imm32(RTMP2, dst_sh); emit32(0x1AC02000 | (RTMP2 << 16) | (RTMP1 << 5) | RTMP1); }
			lazy_flush_cr0();
			a64_ldr_w_imm(RTMP0, RSTATE, PPCR_CR);
			emit_load_imm32(RTMP2, ~(0xFU << dst_sh));
			emit32(0x0A000000 | (RTMP2 << 16) | (RTMP0 << 5) | RTMP0);
			emit32(0x2A000000 | (RTMP1 << 16) | (RTMP0 << 5) | RTMP0);
			a64_str_w_imm(RTMP0, RSTATE, PPCR_CR);
			return true;
		}

		case 26: /* frsqrte frD,frB — reciprocal square root estimate */
			emit_load_fpr(0, frb);
			emit32(0x1E61C000 | (0 << 5) | 0); /* FSQRT Dd,Dn */
			emit32(0x1E6E1000 | 1); /* FMOV D1, #1.0 */
			emit32(0x1E611800 | (0 << 16) | (1 << 5) | 0); /* FDIV D0, D1, D0 */
			emit_store_fpr(0, frd);
			return true;

		case 22: /* fsqrt frD,frB — floating-point square root (double) */
			emit_load_fpr(0, frb);
			emit32(0x1E61C000 | (0 << 5) | 0); /* FSQRT Dd, Dn */
			emit_store_fpr(0, frd);
			return true;
		default: break; /* fall through to 5-bit XO check */
		}

		/* A-form FP ops (5-bit XO) */
		switch (xo5) {
		case 21: /* fadd frD,frA,frB */
			emit_load_fpr(0, fra);
			emit_load_fpr(1, frb);
			emit32(0x1E602800 | (1 << 16) | (0 << 5) | 0); /* FADD Dd, Dn, Dm */
			emit_store_fpr(0, frd);
			return true;

		case 20: /* fsub frD,frA,frB */
			emit_load_fpr(0, fra);
			emit_load_fpr(1, frb);
			emit32(0x1E603800 | (1 << 16) | (0 << 5) | 0); /* FSUB Dd, Dn, Dm */
			emit_store_fpr(0, frd);
			return true;

		case 25: /* fmul frD,frA,frC */
			emit_load_fpr(0, fra);
			emit_load_fpr(1, frc);
			emit32(0x1E600800 | (1 << 16) | (0 << 5) | 0); /* FMUL Dd, Dn, Dm */
			emit_store_fpr(0, frd);
			return true;

		case 18: /* fdiv frD,frA,frB */
			emit_load_fpr(0, fra);
			emit_load_fpr(1, frb);
			emit32(0x1E601800 | (1 << 16) | (0 << 5) | 0); /* FDIV Dd, Dn, Dm */
			emit_store_fpr(0, frd);
			return true;

		case 29: /* fmadd frD,frA,frC,frB = frA*frC+frB */
			emit_load_fpr(0, fra);
			emit_load_fpr(1, frc);
			emit_load_fpr(2, frb);
			emit32(0x1F400000 | (1 << 16) | (2 << 10) | (0 << 5) | 0); /* FMADD Dd,Dn,Dm,Da */
			emit_store_fpr(0, frd);
			return true;

		case 28: /* fmsub frD,frA,frC,frB = frA*frC-frB */
			emit_load_fpr(0, fra);
			emit_load_fpr(1, frc);
			emit_load_fpr(2, frb);
			emit32(0x1F408000 | (1 << 16) | (2 << 10) | (0 << 5) | 0); /* FMSUB */
			emit_store_fpr(0, frd);
			return true;

		case 31: /* fnmadd frD,frA,frC,frB = -(frA*frC+frB) */
			emit_load_fpr(0, fra);
			emit_load_fpr(1, frc);
			emit_load_fpr(2, frb);
			emit32(0x1F600000 | (1 << 16) | (2 << 10) | (0 << 5) | 0); /* FNMADD */
			emit_store_fpr(0, frd);
			return true;

		case 30: /* fnmsub frD,frA,frC,frB = -(frA*frC-frB) */
			emit_load_fpr(0, fra);
			emit_load_fpr(1, frc);
			emit_load_fpr(2, frb);
			emit32(0x1F608000 | (1 << 16) | (2 << 10) | (0 << 5) | 0); /* FNMSUB */
			emit_store_fpr(0, frd);
			return true;

		/* 64-bit FP conversions (G5/PPC970) */
		case 814: /* fctid frD,frB — FP to 64-bit integer (round per FPSCR) */
			emit_load_fpr(0, frb);
			emit32(0x9E700000 | (0 << 5) | RTMP0); /* FCVTNS Xd, Dn (round to nearest) */
			/* Store as 64-bit integer in FPR slot (PPC stores int result in FPR) */
			emit32(0x9E670000 | (RTMP0 << 5) | 0); /* FMOV Dd, Xn */
			emit_store_fpr(0, frd);
			return true;

		case 815: /* fctidz frD,frB — FP to 64-bit integer (round toward zero) */
			emit_load_fpr(0, frb);
			emit32(0x9E780000 | (0 << 5) | RTMP0); /* FCVTZS Xd, Dn */
			emit32(0x9E670000 | (RTMP0 << 5) | 0); /* FMOV Dd, Xn */
			emit_store_fpr(0, frd);
			return true;

		case 846: /* fcfid frD,frB — 64-bit integer to FP */
			emit_load_fpr(0, frb);
			emit32(0x9E660000 | (0 << 5) | RTMP0); /* FMOV Xn, Dd */
			emit32(0x9E620000 | (RTMP0 << 5) | 0); /* SCVTF Dd, Xn */
			emit_store_fpr(0, frd);
			return true;

		default:
			return false;
		}
	}

		return true;

	case 30: /* rld* — 64-bit rotate/shift family */
	{
		uint32_t rs = PPC_RS(op);
		ra = PPC_RA(op);
		uint32_t sub = (op >> 1) & 0xF; /* bits 27-30 determine sub-instruction */
		/* For immediate variants (sub 0-7) the sub-opcode occupies bits 27-29 (3 bits)
		 * while bit 30 is SH[5].  Without normalisation, rldicl/rldicr/rldic/rldimi
		 * with sh>=32 (SH[5]=1) would have sub=1/3/5/7 instead of 0/2/4/6, causing
		 * the wrong handler to execute.  Strip the SH[5] bit by halving sub. */
		if (sub < 8) sub >>= 1;
		bool rc = op & 1;
		/* Load 64-bit source */
		emit_load_gpr64(RTMP0, rs);
		switch (sub) {
		case 0: /* rldicl — rotate left doubleword then clear left */
		case 1: /* rldicr — rotate left doubleword then clear right */
		case 2: /* rldic  — rotate left doubleword then clear (both sides) */
		case 3: /* rldimi — rotate left doubleword then mask insert */
		{
			uint32_t sh = ((op >> 11) & 0x1F) | ((op & 2) << 4); /* 6-bit shift: sh[0:4] | sh[5] */
			uint32_t mb_or_me = ((op >> 6) & 0x1F) | (op & 0x20); /* 6-bit mask field */
			/* ROL Xd,Xn,#sh = ROR Xd,Xn,#(64-sh) */
			if (sh > 0 && sh < 64)
				emit32(0x93C00000 | (RTMP0 << 16) | (((64 - sh) & 63) << 10) | (RTMP0 << 5) | RTMP0);
			/* Apply mask:
			 * rldicl (sub 0): clear left mb bits  — LSL mb; LSR mb
			 * rldicr (sub 1): clear right (63-me) bits — LSR (63-me); LSL (63-me)
			 * rldic  (sub 2): clear left mb AND clear right sh bits
			 * rldimi (sub 3): insert into RA with mask bits mb..(63-sh) */
			if (sub == 3) {
				/* rldimi: RA = (ROTL64(RS,sh) & mask) | (RA & ~mask)
				 * mask = ARM bits sh..(63-mb): computed at JIT compile time.
				 * Uses MOVZ/MOVK to load 64-bit mask, then AND + BIC + ORR. */
				int start_bit = (int)sh;
				int stop_bit  = 63 - (int)mb_or_me;
				uint64_t mask;
				if (start_bit <= stop_bit) {
					int nbits = stop_bit - start_bit + 1;
					mask = (nbits >= 64) ? ~UINT64_C(0)
					      : ((UINT64_C(1) << nbits) - 1) << start_bit;
				} else {
					/* Wrapping: bits 0..stop_bit and start_bit..63 */
					mask = ((UINT64_C(1) << (stop_bit + 1)) - 1) |
					       ~((UINT64_C(1) << start_bit) - 1);
				}
				emit_load_imm64(RTMP1, mask);
				/* RTMP0 = rotated & mask */
				emit32(0x8A000000 | (RTMP1 << 16) | (RTMP0 << 5) | RTMP0); /* AND Xd,Xn,Xm */
				/* Load full 64-bit RA without clobbering RTMP0: RTMP1 can be reused,
				 * and the mask is reloaded before BIC. */
				emit_load_gpr64_tmp(RTMP2, ra, RTMP1);
				emit_load_imm64(RTMP1, mask);
				/* RTMP2 = RA & ~mask */
				emit32(0x8A200000 | (RTMP1 << 16) | (RTMP2 << 5) | RTMP2); /* BIC Xd,Xn,Xm */
				/* RTMP0 = merged result */
				emit32(0xAA000000 | (RTMP2 << 16) | (RTMP0 << 5) | RTMP0); /* ORR Xd,Xn,Xm */
			}
			/* rldicl (sub 0): clear top mb_or_me bits */
			if (sub == 0) {
				if (mb_or_me > 0 && mb_or_me < 64) {
					emit_lsl64_imm(RTMP0, RTMP0, mb_or_me);
					emit_lsr64_imm(RTMP0, RTMP0, mb_or_me);
				}
			/* rldicr (sub 1): clear bottom (63-me) bits */
			} else if (sub == 1) {
				uint32_t clrr = 63 - mb_or_me;
				if (clrr > 0 && clrr < 64) {
					emit_lsr64_imm(RTMP0, RTMP0, clrr);
					emit_lsl64_imm(RTMP0, RTMP0, clrr);
				}
			/* rldic (sub 2): clear top mb bits AND clear bottom sh bits */
			} else if (sub == 2) {
				if (mb_or_me > 0 && mb_or_me < 64) {
					emit_lsl64_imm(RTMP0, RTMP0, mb_or_me);
					emit_lsr64_imm(RTMP0, RTMP0, mb_or_me);
				}
				if (sh > 0 && sh < 64) {
					emit_lsr64_imm(RTMP0, RTMP0, sh);
					emit_lsl64_imm(RTMP0, RTMP0, sh);
				}
			}
			/* sub 3 (rldimi): mask-insert already done above, RTMP0 holds final result */
			emit_store_gpr64(RTMP0, ra);
			if (rc) lazy_update_cr0(RTMP0); /* uses low 32 bits for CR0 */
			return true;
		}
		case 8: /* rldcl — rotate left doubleword then clear left (register shift) */
		case 9: /* rldcr — rotate left doubleword then clear right (register shift) */
		{
			uint32_t rb = (op >> 11) & 0x1F; /* RB = shift register */
			uint32_t mb = ((op >> 6) & 0x1F) | (op & 0x20); /* 6-bit mask field */
			emit_load_gpr(RTMP1, rb);
			/* ROL Xd,Xn,Xm: ARM64 has RORV; ROL by sh = ROR by (64-sh)
			 * NEG RTMP2, RTMP1  (gives -sh; RORV uses low 6 bits so -sh ≡ 64-sh mod 64) */
			emit32(0xCB0003E0 | (RTMP1 << 16) | RTMP2); /* SUB Xd,XZR,Xn = NEG */
			emit32(0x9AC02C00 | (RTMP2 << 16) | (RTMP0 << 5) | RTMP0); /* RORV Xd,Xn,Xm */
			/* Apply mask: clear left mb bits (rldcl) or clear right (63-me) bits (rldcr) */
			if (sub == 8) { /* rldcl: clear top mb bits */
				if (mb > 0 && mb < 64) {
					emit_lsl64_imm(RTMP0, RTMP0, mb);
					emit_lsr64_imm(RTMP0, RTMP0, mb);
				}
			} else { /* rldcr: clear bottom (63-me) bits */
				uint32_t clrr = 63 - mb;
				if (clrr > 0 && clrr < 64) {
					emit_lsr64_imm(RTMP0, RTMP0, clrr);
					emit_lsl64_imm(RTMP0, RTMP0, clrr);
				}
			}
			emit_store_gpr64(RTMP0, ra);
			if (rc) lazy_update_cr0(RTMP0);
			return true;
		}
		default:
			return false;
		}
	}

	case 58: /* ld/ldu/lwa — EXCLUDED: raw 64-bit memory path needs guarded helpers */
		return false;

	case 62: /* std/stdu — EXCLUDED: raw 64-bit memory path needs guarded helpers */
		return false;

	case 56: /* lq — EXCLUDED: raw paired 64-bit memory path needs guarded helpers */
		return false;

	case 59: /* single-precision FP ops */
	{
		uint32_t xo5 = (op >> 1) & 0x1F;
		uint32_t frd = PPC_RD(op);
		uint32_t fra = PPC_RA(op);
		uint32_t frb = (op >> 11) & 0x1F;
		uint32_t frc = (op >> 6) & 0x1F;
		(void)fra; (void)frc; (void)frb; (void)frd;
		/* Single-precision: compute in double, round to single, store as double */
		switch (xo5) {
		case 21: /* fadds */
			emit_load_fpr(0, fra);
			emit_load_fpr(1, frb);
			emit32(0x1E602800 | (1 << 16) | (0 << 5) | 0); /* FADD (double) */
			/* Round to single: FCVT Sd, Dd then FCVT Dd, Sd */
			emit32(0x1E624000 | (0 << 5) | 0); /* FCVT Sd, Dd */
			emit32(0x1E22C000 | (0 << 5) | 0); /* FCVT Dd, Sd */
			emit_store_fpr(0, frd);
			return true;
		case 20: /* fsubs */
			emit_load_fpr(0, fra);
			emit_load_fpr(1, frb);
			emit32(0x1E603800 | (1 << 16) | (0 << 5) | 0);
			emit32(0x1E624000 | (0 << 5) | 0);
			emit32(0x1E22C000 | (0 << 5) | 0);
			emit_store_fpr(0, frd);
			return true;
		case 25: /* fmuls */
			emit_load_fpr(0, fra);
			emit_load_fpr(1, frc);
			emit32(0x1E600800 | (1 << 16) | (0 << 5) | 0);
			emit32(0x1E624000 | (0 << 5) | 0);
			emit32(0x1E22C000 | (0 << 5) | 0);
			emit_store_fpr(0, frd);
			return true;
		case 18: /* fdivs */
			emit_load_fpr(0, fra);
			emit_load_fpr(1, frb);
			emit32(0x1E601800 | (1 << 16) | (0 << 5) | 0);
			emit32(0x1E624000 | (0 << 5) | 0);
			emit32(0x1E22C000 | (0 << 5) | 0);
			emit_store_fpr(0, frd);
			return true;
		case 29: /* fmadds */
			emit_load_fpr(0, fra); emit_load_fpr(1, frc); emit_load_fpr(2, frb);
			emit32(0x1F400000 | (1 << 16) | (2 << 10) | (0 << 5) | 0);
			emit32(0x1E624000 | (0 << 5) | 0); emit32(0x1E22C000 | (0 << 5) | 0);
			emit_store_fpr(0, frd); return true;
		case 28: /* fmsubs */
			emit_load_fpr(0, fra); emit_load_fpr(1, frc); emit_load_fpr(2, frb);
			emit32(0x1F408000 | (1 << 16) | (2 << 10) | (0 << 5) | 0);
			emit32(0x1E624000 | (0 << 5) | 0); emit32(0x1E22C000 | (0 << 5) | 0);
			emit_store_fpr(0, frd); return true;
		case 31: /* fnmadds */
			emit_load_fpr(0, fra); emit_load_fpr(1, frc); emit_load_fpr(2, frb);
			emit32(0x1F600000 | (1 << 16) | (2 << 10) | (0 << 5) | 0);
			emit32(0x1E624000 | (0 << 5) | 0); emit32(0x1E22C000 | (0 << 5) | 0);
			emit_store_fpr(0, frd); return true;
		case 30: /* fnmsubs */
			emit_load_fpr(0, fra); emit_load_fpr(1, frc); emit_load_fpr(2, frb);
			emit32(0x1F608000 | (1 << 16) | (2 << 10) | (0 << 5) | 0);
			emit32(0x1E624000 | (0 << 5) | 0); emit32(0x1E22C000 | (0 << 5) | 0);
			emit_store_fpr(0, frd); return true;
		case 24: /* fres frD,frB — EXCLUDED: old native path emitted undefined AArch64 and only approximate semantics */
			return false;

		case 22: /* fsqrts frD,frB — floating-point square root (single) */
			emit_load_fpr(0, frb);
			emit32(0x1E61C000 | (0 << 5) | 0); /* FSQRT Dd, Dn (double precision) */
			emit32(0x1E624000 | (0 << 5) | 0); /* FCVT Sd, Dd (round to single) */
			emit32(0x1E22C000 | (0 << 5) | 0); /* FCVT Dd, Sd (widen back) */
			emit_store_fpr(0, frd); return true;
		default:
			return false; /* unknown opcode: stop compilation */
		}
	}

	default:
		jit_miss_count[opc]++;
		return false;
	}
}

/* ---- Public API ---- */

bool ppc_jit_aarch64_init(size_t cache_size_kb)
{
	jit_cache_size = cache_size_kb * 1024;
	jit_cache_base = (uint8_t *)jit_cache_alloc(jit_cache_size);
	if (!jit_cache_base) {
		fprintf(stderr, "PPC-JIT-A64: failed to allocate %zu KB code cache\n", cache_size_kb);
		return false;
	}
	jit_cache_wp = (uint32_t *)jit_cache_base;
	jit_cache_end = (uint32_t *)(jit_cache_base + jit_cache_size);
	jit_bc_flush();
	fprintf(stderr, "PPC-JIT-A64: code cache %zu KB at %p, block cache %d buckets / %d pool\n",
	        cache_size_kb, jit_cache_base, JIT_BC_BUCKETS, JIT_BC_POOL);
	return true;
}

void ppc_jit_aarch64_exit(void)
{
	jit_report_misses();
	if (jit_cache_base) {
		jit_cache_free(jit_cache_base, jit_cache_size);
		jit_cache_base = NULL;
	}
}

void ppc_jit_aarch64_flush(void)
{
	/* Reset code cache write pointer and invalidate block address cache.
	 * Called on Mac OS icbi/isync events or when the JIT must start fresh.
	 * Contract: see SheepShaver/docs/AARCH64_JIT_RUNTIME_CONTRACT.md — flush discipline. */
	jit_cache_wp = (uint32_t *)jit_cache_base;
	jit_bc_flush();
}

/* icbi (instruction cache block invalidate) targeted handler.
 *
 * The guest issues icbi per 32-byte line when it writes or relocates code
 * (driver/CFM loads, Mixed-Mode/68k glue, MakeDataExecutable). The semantics:
 * any cached translation of instructions in that line is now stale and must be
 * dropped. The previous JIT handler responded by flushing the ENTIRE code
 * cache on every icbi -> measured ~3550 full flushes per boot, each wiping a
 * near-empty cache (the JIT never accumulated code) -> the working set was
 * recompiled from scratch thousands of times. That was the dominant host-CPU sink.
 *
 * Correct + cheap: only flush when a live compiled block's contiguous guest range
 * [pc, pc + n_insns*4) actually overlaps the icbi'd line. If nothing is compiled
 * there (the common case: code being written, not executed), there is provably
 * nothing to invalidate, so we skip the flush entirely. When we DO flush, the
 * behaviour is identical to before (full flush handles direct-chaining safely),
 * so this introduces no new chain-coherency risk. */
extern "C" void ppc_jit_aarch64_icbi(uint32_t ea)
{
	const uint64_t line_start = (uint64_t)(ea & ~31u);
	const uint64_t line_end   = line_start + 32u;
	/* Fast reject: if the icbi'd line lies entirely outside the compiled-PC span,
	 * no block can overlap it, so skip the O(pool) scan. The span is a conservative
	 * superset of live block ranges, so this never misses a real overlap. Use
	 * 64-bit endpoints so high 32-bit guest addresses cannot wrap line_end/bend. */
	if (line_end <= jit_bc_span_min || line_start >= jit_bc_span_max)
		return;
	for (int i = 0; i < jit_bc_pool_next; i++) {
		const struct jit_bc_entry *e = &jit_bc_pool[i];
		if (!e->code) continue; /* invalidated slot */
		const uint64_t bstart = (uint64_t)e->pc;
		const uint64_t bend   = bstart + (uint64_t)e->n_insns * 4u;
		/* overlap test: [bstart,bend) intersects [line_start,line_end) */
		if (bstart < line_end && bend > line_start) {
			ppc_jit_aarch64_flush();
			return;
		}
	}
	/* No compiled block overlaps the icbi'd line: nothing to invalidate. */
}

void ppc_jit_aarch64_invalidate_pc(uint32_t pc)
{
	(void)pc;
	/* Per-PC cache unlinking is not sufficient once direct chains have been
	 * back-patched: an older block may still contain a B to the invalidated
	 * block's chain_code and would bypass the cache lookup entirely. This API is
	 * used only for containment/corrupt-block eviction, so correctness wins over
	 * preserving the rest of the cache: flush all code and chain patch sites. */
	ppc_jit_aarch64_flush();
}

static bool opcode_may_touch_guest_memory(uint32_t op) {
	uint32_t opc = op >> 26;
	if ((opc >= 32 && opc <= 56) || opc == 58 || opc == 62)
		return true; /* D/DS-form scalar/FP/string/64-bit load-store family */
	if (opc == 4)
		return true; /* AltiVec includes faultable lvx/stvx forms; keep conservative */
	if (opc == 31) {
		uint32_t xo = (op >> 1) & 0x3FF;
		switch (xo) {
		case 20: case 21: case 23: case 53: case 54: case 55: case 84: case 87:
		case 119: case 149: case 150: case 151: case 181: case 183: case 214: case 215:
		case 247: case 279: case 311: case 343: case 375: case 407: case 439:
		case 535: case 567: case 597: case 599: case 631: case 663: case 695:
		case 725: case 727: case 759: case 1014:
			return true;
		default:
			break;
		}
	}
	return false;
}

/* Conservative RA gate: the current register-cache scaffold is path-insensitive.
 * Enable it for straight-line blocks (no internal conditional branches). Guest-memory
 * accesses ARE now allowed: a flush+reset RA barrier is emitted before each one so the
 * register struct is authoritative across the access (helper/MMIO/fault paths read and
 * may modify guest state via RSTATE). Internal conditional branches remain disqualifying
 * until per-label/per-fault RA state is implemented. */
static bool block_allows_register_allocation(uint32_t pc, const uint8_t *host_base, uint32_t guest_base, size_t region_size) {
	uint32_t cur_pc = pc;
	const uint64_t guest_end = (uint64_t)guest_base + region_size;
	for (int i = 0; i < 512; i++, cur_pc += 4) {
		if (cur_pc < guest_base || (uint64_t)cur_pc + 4 > guest_end)
			break;
		const uint8_t *p = host_base + (cur_pc - guest_base);
		uint32_t op = ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
		              ((uint32_t)p[2] << 8) | p[3];
		if (op == 0x00000000 || op == 0x4E800020) break;
		uint32_t opc = op >> 26;
		/* Guest-memory opcodes no longer disqualify the block: a flush+reset RA
		 * barrier is emitted before each such access in the compile loop, keeping
		 * the struct authoritative across the access. Internal conditional branches
		 * still do (the cache scaffold is path-insensitive: a branch target reached
		 * with a different mapping than the fall-through would read wrong regs). */
		if (opc == 16) return false; /* bc/bdnz/bdz can branch within the block */
		if (opc == 18) break;        /* b/bl terminates the block */
		if (opc == 19) {
			uint32_t xo = (op >> 1) & 0x3FF;
			if (xo == 16 || xo == 528) break; /* bclr/bcctr terminate */
		}
	}
	return true;
}

bool ppc_jit_aarch64_compile(
	uint32_t pc,
	const uint8_t *host_base,
	uint32_t guest_base,
	size_t region_size,
	ppc_jit_block *out)
{
	/* Block address cache lookup — return cached block without recompiling.
	 * Contract: see AARCH64_JIT_RUNTIME_CONTRACT.md — block lifecycle. */
	const struct jit_bc_entry *cached = jit_bc_lookup(pc);
	if (cached) {
		/* A cached block's code MUST point inside the code cache. Under heavy
		 * icbi/isync flushing the dispatch was observed to call fn(jblk.code)
		 * with code pointing outside the cache (a mapped library ELF header) ->
		 * wild BLR -> SIGILL. Validate and, if corrupt, drop the stale entry and
		 * recompile fresh (safe: a block is always recompilable from guest RAM). */
		uint8_t *cc = (uint8_t *)cached->code;
		if (cc >= jit_cache_base && cc < jit_cache_base + jit_cache_size) {
			out->code       = cached->code;
			out->chain_code = cached->chain_code;
			out->code_size    = 0; /* not tracked for cached entries */
			out->ppc_start_pc = pc;
			out->ppc_end_pc   = pc; /* not tracked for cached entries */
			out->n_insns      = 0; /* not tracked for cached entries */
			out->complete     = cached->complete;
			return true;
		}
		/* Stale/corrupt cache invariant: a direct predecessor may already have been
		 * patched to this entry's chain_code, so a per-PC unlink would not be enough. */
		ppc_jit_aarch64_flush();
		/* stale/corrupt entry: drop it and recompile fresh from a clean cache */
	}

	if (!jit_cache_wp || jit_cache_wp >= jit_cache_end - 2048) {
		/* Code cache full — flush everything and start over. The 2048-word (8KB)
		 * margin guarantees a fresh block has room to compile before the
		 * per-instruction overflow guard below can trip; the old 256-word margin
		 * was far smaller than a large block's emission (guarded load/store
		 * sequences, unrolled string ops), so a block compiled near the end
		 * overflowed past jit_cache_end into the adjacent mapping -> executing it
		 * ran off the cache into foreign bytes -> wild branch / SIGILL. */
		fprintf(stderr, "PPC-JIT-A64: code cache full, flushing\n");
		ppc_jit_aarch64_flush();
		if (!jit_cache_wp) return false;
	}

	uint32_t *code_start = jit_cache_wp;
	jit_code_ptr = jit_cache_wp;
	jit_compiling_block_pc = pc;

	/* Prologue: save callee-saved regs, set x20 = regs ptr from x0 */
	a64_stp_pre(A64_FP, A64_LR, A64_SP, -16);
	a64_stp_pre(19, RSTATE, A64_SP, -16);  /* save x19, x20 */
	a64_stp_pre(21, 22, A64_SP, -16);      /* save x21, x22 */
	a64_stp_pre(23, 24, A64_SP, -16);      /* save x23, x24 */
	a64_stp_pre(25, 26, A64_SP, -16);      /* save x25, x26 */
	a64_stp_pre(27, 28, A64_SP, -16);      /* save x27, x28 */
	a64_mov_reg(RSTATE, A64_X0);

	/* Chain entry: code position after prologue.
	 * Other blocks chain here via B <chain_code> — RSTATE (x20) must
	 * already be valid and callee-saved regs remain on the outer frame. */
	uint32_t *chain_entry_start = jit_code_ptr;

	jit_blocks_attempted++;
	uint32_t cur_pc = pc;
	int n_compiled = 0;
	bool complete = true;
	bool emitted_exit = false;
	insn_count = 0;
	lazy_cr0_valid = false;
	lazy_cr0_reg = -1;
	ra_reset();
	ra_enabled = block_allows_register_allocation(pc, host_base, guest_base, region_size);
	const uint64_t guest_end = (uint64_t)guest_base + region_size;

	for (int i = 0; i < 512; i++) {
		if (cur_pc < guest_base || (uint64_t)cur_pc + 4 > guest_end)
			break;

		/* Per-instruction overflow guard: never let a block's emitted code cross
		 * jit_cache_end. A single PPC instruction can expand to several KB: the
		 * runtime-count lswx generator emits >1024 words in the worst case, so use
		 * the same 2048-word (8KB) margin as the fresh-block cache-full pre-check. */
		if (n_compiled > 0 && jit_code_ptr >= jit_cache_end - 2048) {
			lazy_flush_cr0();
			emit_epilogue_with_pc(cur_pc);
			emitted_exit = true;
			complete = false;
			break;
		}

		const uint8_t *p = host_base + (cur_pc - guest_base);
		uint32_t op = ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
		              ((uint32_t)p[2] << 8) | p[3];

		if (op == 0x4E800020) { /* blr — block terminator */
			lazy_flush_cr0();
			ra_flush_all();
			a64_ldr_w_imm(RTMP0, RSTATE, PPCR_LR);
			emit_clear_branch_target_low_bits(RTMP0);
			a64_str_w_imm(RTMP0, RSTATE, PPCR_PC);
			a64_ldp_post(27, 28, A64_SP, 16);
				a64_ldp_post(25, 26, A64_SP, 16);
				a64_ldp_post(23, 24, A64_SP, 16);
				a64_ldp_post(21, 22, A64_SP, 16);
				a64_ldp_post(19, RSTATE, A64_SP, 16);
				a64_ldp_post(A64_FP, A64_LR, A64_SP, 16);
				a64_ret();
			emitted_exit = true;
			n_compiled++;
			cur_pc += 4;
			break;
		}

		/* Check if this is a block-terminating opcode */
		uint32_t term_opc = op >> 26;
		bool is_terminator = (term_opc == 18 || term_opc == 6); /* b/bl or SheepShaver helper */
		if (term_opc == 19) {
			uint32_t term_xo = (op >> 1) & 0x3FF;
			if (term_xo == 16 || term_xo == 528) is_terminator = true; /* bclr/bcctr */
			if (term_xo == 150) is_terminator = true; /* isync: serializes + returns to dispatch */
		}
		if (term_opc == 31 && ((op >> 1) & 0x3FF) == 982) is_terminator = true; /* icbi: flushes JIT cache + returns to dispatch; MUST end the block so the loop never emits live code (or compile-time chains) past the cache-reset point */

		if (op == 0x00000000) { /* illegal — end of test code / zero-filled memory */
			if (n_compiled == 0) return false; /* don't compile empty blocks */
			lazy_flush_cr0();
			emit_epilogue_with_pc(cur_pc);
			emitted_exit = true;
			n_compiled++;
			cur_pc += 4;
			break;
		}

		/* Record instruction offset for intra-block branches */
		if (insn_count < 512) {
			insn_code_offset[insn_count] = jit_code_ptr;
			insn_ppc_pc[insn_count] = cur_pc;
			insn_count++;
		}

		/* RA barrier: before any guest-memory access, write back all dirty cached
		 * GPRs and drop the cache so the struct is authoritative across the access.
		 * The guarded load/store helper (and any MMIO re-entry or fault/skip path)
		 * reads — and may modify — guest GPRs via RSTATE, so cached-only dirty values
		 * must be in the struct before the access, and post-access reads must reload
		 * in case the struct changed. This makes RA-enabled memory-touching blocks
		 * exactly equivalent to direct struct LDR/STR at every memory boundary while
		 * still caching the straight-line arithmetic runs between accesses. */
		if (ra_enabled && opcode_may_touch_guest_memory(op)) {
			ra_flush_all();
			ra_reset();
		}

		if (!compile_one(op, cur_pc)) {
			jit_total_miss++;
			jit_miss_count[op >> 26]++;
			jit_cum_fail_opc[op >> 26]++;
			if ((op >> 26) == 31) jit_cum_fail_xo31[(op >> 1) & 0x3FF]++;
			jit_cum_fail_total++;
			lazy_flush_cr0();
			emit_epilogue_with_pc(cur_pc);
			emitted_exit = true;
			complete = false;
			break;
		}

		jit_total_hit++;
		n_compiled++;
		cur_pc += 4;

		/* Block-terminating opcodes: compile_one() already emitted the terminal
		 * epilogue/return, even when it ended in a direct chain branch instead of
		 * a RET. Mark that so the outer post-pass doesn't append a spurious
		 * fallthrough epilogue at cur_pc. */
		if (is_terminator) {
			emitted_exit = true;
			break;
		}
	}

	/* Track why blocks are incomplete */
	if (!complete && 0) {
	}

	/* Periodic report */
	if ((jit_blocks_attempted) % 100000 == 0 && jit_blocks_attempted > 0)
		jit_report_misses();

	/* If the block ran off the end of our straight-line window without any
	 * explicit terminator/failure epilogue, end it at the next PPC PC. */
	if (!emitted_exit && n_compiled > 0 && jit_code_ptr > code_start) {
		lazy_flush_cr0();
		emit_epilogue_with_pc(cur_pc);
		complete = false;
	}

	size_t code_bytes = (uint8_t *)jit_code_ptr - (uint8_t *)code_start;
	jit_cache_flush(code_start, code_bytes);
	jit_cache_wp = jit_code_ptr;

	out->code = code_start;
	out->code_size = code_bytes;
	out->ppc_start_pc = pc;
	out->ppc_end_pc = cur_pc;
	out->n_insns = n_compiled;

	/* Cumulative miss report — doesn't clear counters */
	{
		static uint32_t cum_opc[64] = {0};
		static uint32_t cum_xo31[1024] = {0};
		static uint32_t cum_total = 0;
		static uint32_t cum_report_at = 100000;
		
		if (!complete) {
			/* Record the opcode that caused the failure */
			if (cur_pc >= guest_base && (uint64_t)cur_pc + 4 <= (uint64_t)guest_base + region_size) {
				const uint8_t *fail_p = host_base + (cur_pc - guest_base);
				uint32_t fail_op = ((uint32_t)fail_p[0] << 24) | ((uint32_t)fail_p[1] << 16) |
				                   ((uint32_t)fail_p[2] << 8) | fail_p[3];
				uint32_t fail_opc = fail_op >> 26;
				cum_opc[fail_opc]++;
				if (fail_opc == 31) cum_xo31[(fail_op >> 1) & 0x3FF]++;
				cum_total++;
			}
		}
		
		if (jit_blocks_attempted >= cum_report_at) {
			cum_report_at += 100000;
			if (jit_cum_fail_total == 0)
				goto skip_cum_report;
			fprintf(stderr, "PPC-JIT-A64-CUM: %u fail opcodes in %u blocks (%u attempted), top blockers:\n", jit_cum_fail_total, jit_blocks_attempted - jit_blocks_complete, jit_blocks_attempted);
			/* Copy arrays for sorted output without destroying data */
			uint32_t tmp_opc[64]; memcpy(tmp_opc, jit_cum_fail_opc, sizeof(tmp_opc));
			for (int pass = 0; pass < 15; pass++) {
				uint32_t max_v = 0; int max_i = -1;
				for (int i = 0; i < 64; i++) if (tmp_opc[i] > max_v) { max_v = tmp_opc[i]; max_i = i; }
				if (max_i < 0 || max_v == 0) break;
				fprintf(stderr, "  opc=%d: %u blocks\n", max_i, max_v);
				tmp_opc[max_i] = 0;
			}
			uint32_t tmp_xo[1024]; memcpy(tmp_xo, jit_cum_fail_xo31, sizeof(tmp_xo));
			fprintf(stderr, "PPC-JIT-A64-CUM: top XO31 blockers:\n");
			for (int pass = 0; pass < 10; pass++) {
				uint32_t max_v = 0; int max_i = -1;
				for (int i = 0; i < 1024; i++) if (tmp_xo[i] > max_v) { max_v = tmp_xo[i]; max_i = i; }
				if (max_i < 0 || max_v == 0) break;
				fprintf(stderr, "  XO=%d: %u blocks\n", max_i, max_v);
				tmp_xo[max_i] = 0;
			}
		}
	skip_cum_report: ;
	}

	out->complete = complete;
	if (complete && n_compiled > 0) jit_blocks_complete++;

	/* Insert into block address cache so future executions skip recompilation.
	 * chain_entry_start is the code position immediately after the prologue;
	 * other blocks can branch directly there to skip the callee-save overhead.
	 * Contract: see AARCH64_JIT_RUNTIME_CONTRACT.md — block lifecycle. */
	if (n_compiled > 0)
		jit_bc_insert(pc, code_start, chain_entry_start, complete, n_compiled);

	out->chain_code = chain_entry_start;

	return n_compiled > 0;
}

#endif /* __aarch64__ */
