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
