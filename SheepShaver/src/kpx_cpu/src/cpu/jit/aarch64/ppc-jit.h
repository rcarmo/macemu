/*
 *  ppc-jit.h — PPC → AArch64 direct codegen JIT interface
 */

#ifndef PPC_JIT_H
#define PPC_JIT_H

#include <stdint.h>
#include <stddef.h>

#ifdef __aarch64__

struct powerpc_registers;

struct ppc_jit_block {
	uint32_t *code;       /* normal ABI entry point (with prologue) */
	uint32_t *chain_code; /* chain entry point (after prologue) */
	size_t    code_size;
	uint32_t  ppc_start_pc;
	uint32_t  ppc_end_pc;
	int       n_insns;
	bool      complete;
};

bool ppc_jit_aarch64_init(size_t cache_size_kb);
void ppc_jit_aarch64_exit(void);
void ppc_jit_aarch64_flush(void);
void ppc_jit_aarch64_invalidate_pc(uint32_t pc);

#ifdef SS_JIT_BENCH_CENSUS
struct ppc_jit_bench_stats {
	uint64_t compile_requests;
	uint64_t cache_hits;
	uint64_t fresh_attempts;
	uint64_t fresh_success;
	uint64_t fresh_complete;
	uint64_t fresh_partial;
	uint64_t compile_failures;
	uint64_t full_flushes;
	uint64_t generation_start;
	uint64_t generation_current;
};
struct ppc_jit_bench_exec_stats {
	uint64_t native_dispatches;
	uint64_t native_retired;
	uint64_t interpreter_blocks;
	uint64_t interpreter_retired;
	uint64_t skip_disabled;
	uint64_t skip_region;
	uint64_t skip_compile_false;
	uint64_t skip_gate3;
};
void ppc_jit_aarch64_bench_stats_reset(void);
void ppc_jit_aarch64_bench_stats_snapshot(ppc_jit_bench_stats *out);
void ppc_jit_aarch64_bench_exec_reset(void);
void ppc_jit_aarch64_bench_exec_snapshot(ppc_jit_bench_exec_stats *out);
#endif

bool ppc_jit_aarch64_compile(
	uint32_t pc,
	const uint8_t *host_base,
	uint32_t guest_base,
	size_t region_size,
	ppc_jit_block *out
);

typedef void (*ppc_jit_entry_fn)(void *regs);

#endif /* __aarch64__ */
#endif /* PPC_JIT_H */
