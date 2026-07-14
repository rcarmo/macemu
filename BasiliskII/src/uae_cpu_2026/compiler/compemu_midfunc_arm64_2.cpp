/*
 * compiler/compemu_midfunc_arm.cpp - Native MIDFUNCS for AARCH64 (JIT v2)
 *
 * Copyright (c) 2019 TomB
 *
 * Inspired by Christian Bauer's Basilisk II
 *
 *  Original 68040 JIT compiler for UAE, copyright 2000-2002 Bernd Meyer
 *
 *  Adaptation for Basilisk II and improvements, copyright 2000-2002
 *    Gwenole Beauchesne
 *
 *  Basilisk II (C) 1997-2002 Christian Bauer
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 *  Note:
 *  	File is included by compemu_support.cpp
 *
 */

extern const uae_u32 ARM_CCR_MAP[] = { 0, ARM_C_FLAG, // 1 C
                                ARM_V_FLAG, // 2 V
                                ARM_C_FLAG | ARM_V_FLAG, // 3 VC
                                ARM_Z_FLAG, // 4 Z
                                ARM_Z_FLAG | ARM_C_FLAG, // 5 ZC
                                ARM_Z_FLAG | ARM_V_FLAG, // 6 ZV
                                ARM_Z_FLAG | ARM_C_FLAG | ARM_V_FLAG, // 7 ZVC
                                ARM_N_FLAG, // 8 N
                                ARM_N_FLAG | ARM_C_FLAG, // 9 NC
                                ARM_N_FLAG | ARM_V_FLAG, // 10 NV
                                ARM_N_FLAG | ARM_C_FLAG | ARM_V_FLAG, // 11 NVC
                                ARM_N_FLAG | ARM_Z_FLAG, // 12 NZ
                                ARM_N_FLAG | ARM_Z_FLAG | ARM_C_FLAG, // 13 NZC
                                ARM_N_FLAG | ARM_Z_FLAG | ARM_V_FLAG, // 14 NZV
                                ARM_N_FLAG | ARM_Z_FLAG | ARM_C_FLAG | ARM_V_FLAG, // 15 NZVC
};


#define DUPLICACTE_CARRY            \
  if (needed_flags & FLAG_X) {      \
    int x = writereg(FLAGX);     		\
    if (flags_carry_inverted)       \
      CSET_xc(x, NATIVE_CC_CC);     \
    else                            \
      CSET_xc(x, NATIVE_CC_CS);     \
    unlock2(x);                     \
  }

/* A runtime count-zero branch may skip DUPLICACTE_CARRY, but the allocator
 * observes both emitted paths as one linear stream.  Materialise and lock the
 * old X value before such a branch so the skipped-write path retains a valid
 * binding and both paths merge with identical ownership. */
#define LOCK_X_FOR_RUNTIME_JOIN                \
  int runtime_join_x = -1;                     \
  if (needed_flags & FLAG_X)                    \
    runtime_join_x = rmw(FLAGX)
#define UNLOCK_X_FOR_RUNTIME_JOIN              \
  if (runtime_join_x >= 0)                      \
    unlock2(runtime_join_x)

/* Publish one emitted value bit as host C while preserving the N/Z/V state
 * already established for the guest result.  This is deliberately branchless:
 * fixed TBZ skip distances made the flag path depend on instruction geometry. */
#define PUBLISH_CARRY_FROM_BIT(source, bit, scratch) \
  do {                                               \
    MRS_NZCV_x(REG_WORK4);                           \
    UBFX_xxii(scratch, source, bit, 1);               \
    BFI_xxii(REG_WORK4, scratch, 29, 1);              \
    MSR_NZCV_x(REG_WORK4);                           \
  } while (0)

/*
 * ADD
 * Operand Syntax: 	<ea>, Dn
 * 					Dn, <ea>
 *
 * Operand Size: 8,16,32
 *
 * X Set the same as the carry bit.
 * N Set if the result is negative. Cleared otherwise.
 * Z Set if the result is zero. Cleared otherwise.
 * V Set if an overflow is generated. Cleared otherwise.
 * C Set if a carry is generated. Cleared otherwise.
 *
 */
MIDFUNC(3,jnf_ADD_im8,(W4 d, RR4 s, IM8 v))
{
	int s_is_d = (s == d);
	if(s_is_d) {
		s = d = rmw(d);
	} else {
		s = readreg(s);
		d = writereg(d);
	}

	ADD_wwi(d, s, v & 0xff);

	EXIT_REGS(d, s);
}
MENDFUNC(3,jnf_ADD_im8,(W4 d, RR4 s, IM8 v))

MIDFUNC(2,jnf_ADD_b_imm,(RW1 d, IM8 v))
{
	if (isconst(d)) {
		live.state[d].val = (live.state[d].val & 0xffffff00) | ((live.state[d].val + v) & 0x000000ff);
		return;
	}

	INIT_REG_b(d);

	if(targetIsReg) {
		ADD_wwi(REG_WORK1, d, v & 0xff);
		BFI_wwii(d, REG_WORK1, 0, 8);
	} else {
		ADD_wwi(d, d, v & 0xff);
	}

	unlock2(d);
}
MENDFUNC(2,jnf_ADD_b_imm,(RW1 d, IM8 v))

MIDFUNC(2,jnf_ADD_b,(RW1 d, RR1 s))
{
	if (isconst(s)) {
		COMPCALL(jnf_ADD_b_imm)(d, live.state[s].val);
		return;
	}

	INIT_REGS_b(d, s);

	if(targetIsReg) {
		ADD_www(REG_WORK1, d, s);
		BFI_wwii(d, REG_WORK1, 0, 8);
	} else {
		ADD_www(d, d, s);
	}

	EXIT_REGS(d, s);
}
MENDFUNC(2,jnf_ADD_b,(RW1 d, RR1 s))

MIDFUNC(2,jnf_ADD_w_imm,(RW2 d, IM16 v))
{
	INIT_REG_w(d);

	if(targetIsReg) {
		if(v >= 0 && v <= 0xfff) {
			ADD_wwi(REG_WORK1, d, v);
		} else {
			MOV_xi(REG_WORK1, v & 0xffff);
			ADD_www(REG_WORK1, d, REG_WORK1);
		}
		BFI_wwii(d, REG_WORK1, 0, 16);
	} else{
		if(v >= 0 && v <= 0xfff) {
			ADD_wwi(d, d, v);
		} else {
			MOV_xi(REG_WORK1, v & 0xffff);
			ADD_www(d, d, REG_WORK1);
		}
	}

	unlock2(d);
}
MENDFUNC(2,jnf_ADD_w_imm,(RW2 d, IM16 v))

MIDFUNC(2,jnf_ADD_w,(RW2 d, RR2 s))
{
	if (isconst(s)) {
		COMPCALL(jnf_ADD_w_imm)(d, live.state[s].val);
		return;
	}

	INIT_REGS_w(d, s);

	if(targetIsReg) {
		ADD_www(REG_WORK1, d, s);
		BFI_wwii(d, REG_WORK1, 0, 16);
	} else {
		ADD_www(d, d, s);
	}

	EXIT_REGS(d, s);
}
MENDFUNC(2,jnf_ADD_w,(RW2 d, RR2 s))

MIDFUNC(2,jnf_ADD_l_imm,(RW4 d, IM32 v))
{
	if (isconst(d)) {
		live.state[d].val = live.state[d].val + v;
		return;
	}

	d = rmw(d);

	if(v >= 0 && v <= 0xfff) {
		ADD_wwi(d, d, v);
	} else {
		// never reached...
		LOAD_U32(REG_WORK1, v);
		ADD_www(d, d, REG_WORK1);
	}

	unlock2(d);
}
MENDFUNC(2,jnf_ADD_l_imm,(RW4 d, IM32 v))

MIDFUNC(2,jnf_ADD_l,(RW4 d, RR4 s))
{
	if (isconst(d) && isconst(s)) {
		COMPCALL(jnf_ADD_l_imm)(d, live.state[s].val);
		return;
	}
	if (isconst(s) && (uae_s32)live.state[s].val >= 0 && (uae_s32)live.state[s].val <= 0xfff) {
		COMPCALL(jnf_ADD_l_imm)(d, live.state[s].val);
		return;
	}

	INIT_REGS_l(d, s);

	ADD_www(d, d, s);

	EXIT_REGS(d, s);
}
MENDFUNC(2,jnf_ADD_l,(RW4 d, RR4 s))

MIDFUNC(2,jff_ADD_b_imm,(RW1 d, IM8 v))
{
	INIT_REG_b(d);

	MOV_xish(REG_WORK2, (v & 0xff) << 8, 16);
	ADDS_wwwLSLi(REG_WORK1, REG_WORK2, d, 24);
	BFXIL_xxii(d, REG_WORK1, 24, 8);

	flags_carry_inverted = false;
	DUPLICACTE_CARRY

	unlock2(d);
}
MENDFUNC(2,jff_ADD_b_imm,(RW1 d, IM8 v))

MIDFUNC(2,jff_ADD_b,(RW1 d, RR1 s))
{
	if (isconst(s)) {
		COMPCALL(jff_ADD_b_imm)(d, live.state[s].val);
		return;
	}

	INIT_REGS_b(d, s);

	LSL_wwi(REG_WORK2, s, 24);
	ADDS_wwwLSLi(REG_WORK1, REG_WORK2, d, 24);
	BFXIL_xxii(d, REG_WORK1, 24, 8);

	flags_carry_inverted = false;
	DUPLICACTE_CARRY

	EXIT_REGS(d, s);
}
MENDFUNC(2,jff_ADD_b,(RW1 d, RR1 s))

MIDFUNC(2,jff_ADD_w_imm,(RW2 d, IM16 v))
{
	INIT_REG_w(d);

	MOV_xish(REG_WORK1, v & 0xffff, 16);
	ADDS_wwwLSLi(REG_WORK1, REG_WORK1, d, 16);
	BFXIL_xxii(d, REG_WORK1, 16, 16);

	flags_carry_inverted = false;
	DUPLICACTE_CARRY

	unlock2(d);
}
MENDFUNC(2,jff_ADD_w_imm,(RW2 d, IM16 v))

MIDFUNC(2,jff_ADD_w,(RW2 d, RR2 s))
{
	if (isconst(s)) {
		COMPCALL(jff_ADD_w_imm)(d, live.state[s].val);
		return;
	}

	INIT_REGS_w(d, s);

	LSL_wwi(REG_WORK1, s, 16);
	ADDS_wwwLSLi(REG_WORK1, REG_WORK1, d, 16);
	BFXIL_xxii(d, REG_WORK1, 16, 16);

	flags_carry_inverted = false;
	DUPLICACTE_CARRY

	EXIT_REGS(d, s);
}
MENDFUNC(2,jff_ADD_w,(RW2 d, RR2 s))

MIDFUNC(2,jff_ADD_l_imm,(RW4 d, IM32 v))
{
	d = rmw(d);

	if(v >= 0 && v <= 0xfff) {
		ADDS_wwi(d, d, v);
	} else {
		// never reached...
		LOAD_U32(REG_WORK2, v);
		ADDS_www(d, d, REG_WORK2);
	}

	flags_carry_inverted = false;
	DUPLICACTE_CARRY

	unlock2(d);
}
MENDFUNC(2,jff_ADD_l_imm,(RW4 d, IM32 v))

MIDFUNC(2,jff_ADD_l,(RW4 d, RR4 s))
{
	if (isconst(s) && (uae_s32)live.state[s].val >= 0 && (uae_s32)live.state[s].val <= 0xfff) {
		COMPCALL(jff_ADD_l_imm)(d, live.state[s].val);
		return;
	}

	INIT_REGS_l(d, s);

	ADDS_www(d, d, s);

	flags_carry_inverted = false;
	DUPLICACTE_CARRY

	EXIT_REGS(d, s);
}
MENDFUNC(2,jff_ADD_l,(RW4 d, RR4 s))

/*
 * ADDA
 * Operand Syntax: 	<ea>, An
 *
 * Operand Size: 16,32
 *
 * Flags: Not affected.
 *
 */
MIDFUNC(2,jnf_ADDA_w_imm,(RW4 d, IM16 v))
{
	if (isconst(d)) {
		live.state[d].val = live.state[d].val + (uae_s32)(uae_s16)v;
		return;
	}

	uae_s16 tmp = (uae_s16)v;
	d = rmw(d);
	if(tmp >= 0 && tmp <= 0xfff) {
		ADD_wwi(d, d, tmp);
	} else if (tmp >= -0xfff && tmp < 0) {
		SUB_wwi(d, d, -tmp);
	} else {
		SIGNED16_IMM_2_REG(REG_WORK1, tmp);
		ADD_www(d, d, REG_WORK1);
	}
	unlock2(d);
}
MENDFUNC(2,jnf_ADDA_w_imm,(RW4 d, IM16 v))

MIDFUNC(2,jnf_ADDA_w,(RW4 d, RR2 s))
{
	if (isconst(s)) {
		COMPCALL(jnf_ADDA_w_imm)(d, live.state[s].val & 0xffff);
		return;
	}

	INIT_REGS_w(d, s);

	ADD_wwwEX(d, d, s, EX_SXTH);

	EXIT_REGS(d, s);
}
MENDFUNC(2,jnf_ADDA_w,(RW4 d, RR2 s))

MIDFUNC(2,jnf_ADDA_l_imm,(RW4 d, IM32 v))
{
	if (isconst(d)) {
		set_const(d, live.state[d].val + v);
		return;
	}

	d = rmw(d);

	if(v >= 0 && v <= 0xfff) {
		ADD_wwi(d, d, v);
	} else if (v >= -0xfff && v < 0) {
		SUB_wwi(d, d, -v);
	} else {
		LOAD_U32(REG_WORK1, v);
		ADD_www(d, d, REG_WORK1);
	}

	unlock2(d);
}
MENDFUNC(2,jnf_ADDA_l_imm,(RW4 d, IM32 v))

MIDFUNC(2,jnf_ADDA_l,(RW4 d, RR4 s))
{
	if (isconst(s)) {
		COMPCALL(jnf_ADDA_l_imm)(d, live.state[s].val);
		return;
	}

	INIT_REGS_l(d, s);

	ADD_www(d, d, s);

	EXIT_REGS(d, s);
}
MENDFUNC(2,jnf_ADDA_l,(RW4 d, RR4 s))

/*
 * ADDX
 * Operand Syntax: 	Dy, Dx
 * 					-(Ay), -(Ax)
 *
 * Operand Size: 8,16,32
 *
 * X Set the same as the carry bit.
 * N Set if the result is negative. Cleared otherwise.
 * Z Cleared if the result is nonzero; unchanged otherwise.
 * V Set if an overflow is generated. Cleared otherwise.
 * C Set if a carry is generated. Cleared otherwise.
 *
 * Attention: Z is cleared only if the result is nonzero. Unchanged otherwise
 *
 */
MIDFUNC(2,jnf_ADDX_b,(RW1 d, RR1 s))
{
	int x = readreg(FLAGX);

	INIT_REGS_b(d, s);

	if(s_is_d) {
		ADD_wwwLSLi(REG_WORK1, x, d, 1);
	} else {
		ADD_www(REG_WORK1, d, s);
		ADD_www(REG_WORK1, REG_WORK1, x);
	}
	BFI_wwii(d, REG_WORK1, 0, 8);

	EXIT_REGS(d, s);
	unlock2(x);
}
MENDFUNC(2,jnf_ADDX_b,(RW1 d, RR1 s))

MIDFUNC(2,jnf_ADDX_w,(RW2 d, RR2 s))
{
	int x = readreg(FLAGX);

	INIT_REGS_w(d, s);

	if(s_is_d) {
		ADD_wwwLSLi(REG_WORK1, x, d, 1);
	} else {
		ADD_www(REG_WORK1, d, s);
		ADD_www(REG_WORK1, REG_WORK1, x);
	}
	BFI_wwii(d, REG_WORK1, 0, 16);

	EXIT_REGS(d, s);
	unlock2(x);
}
MENDFUNC(2,jnf_ADDX_w,(RW2 d, RR2 s))

MIDFUNC(2,jnf_ADDX_l,(RW4 d, RR4 s))
{
	int x = readreg(FLAGX);

	if(s != d && isconst(s) && live.state[s].val >= 0 && live.state[s].val <= 0xfff) {
		d = rmw(d);
		ADD_wwi(d, d, live.state[s].val);
		ADD_www(d, d, x);
		unlock2(d);
		unlock2(x);
		return;
	}

	INIT_REGS_l(d, s);

	if(s_is_d) {
		ADD_wwwLSLi(d, x, d, 1);
	} else {
		ADD_www(d, d, s);
		ADD_www(d, d, x);
	}

	EXIT_REGS(d, s);
	unlock2(x);
}
MENDFUNC(2,jnf_ADDX_l,(RW4 d, RR4 s))

MIDFUNC(2,jff_ADDX_b,(RW1 d, RR1 s))
{
	INIT_REGS_b(d, s);
	int x = rmw(FLAGX);

	// REG_WORK1 must be all-ones: bits 0-23 are padding for the byte BFI+ADCS
	// carry chain, and also serves as the all-ones value for sticky-Z CSEL.
	MOVN_xi(REG_WORK1, 0);
	if (needed_flags & FLAG_Z) {
		MOVN_xish(REG_WORK2, 0x4000, 16); // inverse Z flag
		CSEL_xxxc(REG_WORK2, REG_WORK2, REG_WORK1, NATIVE_CC_NE);
	}

	// Restore X to carry (don't care about other flags)
	SUBS_wwi(REG_WORK3, x, 1);

	BFI_xxii(REG_WORK1, s, 24, 8);
	LSL_wwi(REG_WORK3, d, 24);
	ADCS_www(REG_WORK1, REG_WORK1, REG_WORK3);
	BFXIL_xxii(d, REG_WORK1, 24, 8);

	MRS_NZCV_x(REG_WORK1);

	if (needed_flags & FLAG_Z) {
		// Fix Z flag: ADCS Z is always 0 due to all-ones padding in lower bits.
		UBFX_wwii(REG_WORK3, d, 0, 8);
		CMP_wi(REG_WORK3, 0);
		SET_xxZflag(REG_WORK3, REG_WORK1);
		CSEL_xxxc(REG_WORK1, REG_WORK3, REG_WORK1, NATIVE_CC_EQ);
		AND_xxx(REG_WORK1, REG_WORK1, REG_WORK2); // apply ADDX sticky-Z
	}
	if (needed_flags & FLAG_X)
		UBFX_xxii(x, REG_WORK1, 29, 1); // Duplicate carry
	MSR_NZCV_x(REG_WORK1);

	flags_carry_inverted = false;
	unlock2(x);
	EXIT_REGS(d, s);
}
MENDFUNC(2,jff_ADDX_b,(RW1 d, RR1 s))

MIDFUNC(2,jff_ADDX_w,(RW2 d, RR2 s))
{
	INIT_REGS_w(d, s);
	int x = rmw(FLAGX);

	// REG_WORK1 must be all-ones: bits 0-15 are padding for the word BFI+ADCS
	// carry chain, and also serves as the all-ones value for sticky-Z CSEL.
	MOVN_xi(REG_WORK1, 0);
	if (needed_flags & FLAG_Z) {
		MOVN_xish(REG_WORK2, 0x4000, 16); // inverse Z flag
		CSEL_xxxc(REG_WORK2, REG_WORK2, REG_WORK1, NATIVE_CC_NE);
	}

	// Restore X to carry (don't care about other flags)
	SUBS_wwi(REG_WORK3, x, 1);

	BFI_xxii(REG_WORK1, s, 16, 16);
	LSL_wwi(REG_WORK3, d, 16);
	ADCS_www(REG_WORK1, REG_WORK1, REG_WORK3);
	BFXIL_xxii(d, REG_WORK1, 16, 16);

	MRS_NZCV_x(REG_WORK1);

	if (needed_flags & FLAG_Z) {
		// Fix Z flag: ADCS Z is always 0 due to all-ones padding in lower bits.
		UBFX_wwii(REG_WORK3, d, 0, 16);
		CMP_wi(REG_WORK3, 0);
		SET_xxZflag(REG_WORK3, REG_WORK1);
		CSEL_xxxc(REG_WORK1, REG_WORK3, REG_WORK1, NATIVE_CC_EQ);
		AND_xxx(REG_WORK1, REG_WORK1, REG_WORK2); // apply ADDX sticky-Z
	}
	if (needed_flags & FLAG_X)
		UBFX_xxii(x, REG_WORK1, 29, 1); // Duplicate carry
	MSR_NZCV_x(REG_WORK1);

	flags_carry_inverted = false;
	unlock2(x);
	EXIT_REGS(d, s);
}
MENDFUNC(2,jff_ADDX_w,(RW2 d, RR2 s))

MIDFUNC(2,jff_ADDX_l,(W4 d, RR4 s))
{
	INIT_REGS_l(d, s);
	int x = rmw(FLAGX);

	if (needed_flags & FLAG_Z) {
		MOVN_xi(REG_WORK1, 0);
		MOVN_xish(REG_WORK2, 0x4000, 16); // inverse Z flag
		CSEL_xxxc(REG_WORK2, REG_WORK2, REG_WORK1, NATIVE_CC_NE);
	}

	// Restore X to carry (don't care about other flags)
	SUBS_wwi(REG_WORK3, x, 1);

	ADCS_www(d, d, s);

	MRS_NZCV_x(REG_WORK1);
	if (needed_flags & FLAG_Z)
		AND_xxx(REG_WORK1, REG_WORK1, REG_WORK2);
	if (needed_flags & FLAG_X)
		UBFX_xxii(x, REG_WORK1, 29, 1); // Duplicate carry
	MSR_NZCV_x(REG_WORK1);

	flags_carry_inverted = false;
	unlock2(x);
	EXIT_REGS(d, s);
}
MENDFUNC(2,jff_ADDX_l,(W4 d, RR4 s))

/*
 * ANDSR
 * Operand Syntax: 	#<data>, CCR
 *
 * Operand Size: 8
 *
 * X Cleared if bit 4 of immediate operand is zero. Unchanged otherwise.
 * N Cleared if bit 3 of immediate operand is zero. Unchanged otherwise.
 * Z Cleared if bit 2 of immediate operand is zero. Unchanged otherwise.
 * V Cleared if bit 1 of immediate operand is zero. Unchanged otherwise.
 * C Cleared if bit 0 of immediate operand is zero. Unchanged otherwise.
 *
 */
MIDFUNC(2,jff_ANDSR,(IM32 s, IM8 x))
{
	MRS_NZCV_x(REG_WORK1);
	if(flags_carry_inverted) {
		EOR_xxCflag(REG_WORK1, REG_WORK1);
		flags_carry_inverted = false;
	}
	MOV_xish(REG_WORK2, (s >> 16), 16);
	AND_xxx(REG_WORK1, REG_WORK1, REG_WORK2);
	MSR_NZCV_x(REG_WORK1);

	if (!x) {
		int f = writereg(FLAGX);
		// Use 32-bit MOV for consistency (MOV_xi with 0 is safe, but MOV_wi is preferred).
		MOV_wi(f, 0);
		unlock2(f);
	}
}
MENDFUNC(2,jff_ANDSR,(IM32 s, IM8 x))

/*
 * AND
 * Operand Syntax: 	<ea>, Dn
 * 					Dn, <ea>
 *
 * Operand Size: 8,16,32
 *
 * X Not affected.
 * N Set if the most significant bit of the result is set. Cleared otherwise.
 * Z Set if the result is zero. Cleared otherwise.
 * V Always cleared.
 * C Always cleared.
 *
 */
MIDFUNC(2,jnf_AND_b_imm,(RW1 d, IM8 v))
{
	if (isconst(d)) {
		live.state[d].val = (live.state[d].val & 0xffffff00) | ((live.state[d].val & v) & 0x000000ff);
		return;
	}

	INIT_REG_b(d);

	MOVN_xi(REG_WORK1, (~v) & 0xff);
	AND_www(d, d, REG_WORK1);

	unlock2(d);
}
MENDFUNC(2,jnf_AND_b_imm,(RW1 d, IM8 v))

MIDFUNC(2,jnf_AND_b,(RW1 d, RR1 s))
{
	if (isconst(s)) {
		COMPCALL(jnf_AND_b_imm)(d, live.state[s].val);
		return;
	}

	INIT_REGS_b(d, s);

	if(targetIsReg) {
		AND_www(REG_WORK1, d, s);
		BFI_wwii(d, REG_WORK1, 0, 8);
	} else {
		AND_www(d, d, s);
	}

	EXIT_REGS(d, s);
}
MENDFUNC(2,jnf_AND_b,(RW1 d, RR1 s))

MIDFUNC(2,jnf_AND_w_imm,(RW2 d, IM16 v))
{
	if (isconst(d)) {
		live.state[d].val = (live.state[d].val & 0xffff0000) | ((live.state[d].val & v) & 0x0000ffff);
		return;
	}

	INIT_REG_w(d);

	MOVN_xi(REG_WORK1, (~v));
	AND_www(d, d, REG_WORK1);

	unlock2(d);
}
MENDFUNC(2,jnf_AND_w_imm,(RW2 d, IM16 v))

MIDFUNC(2,jnf_AND_w,(RW2 d, RR2 s))
{
	if (isconst(s)) {
		COMPCALL(jnf_AND_w_imm)(d, live.state[s].val);
		return;
	}

	INIT_REGS_w(d, s);

	if(targetIsReg) {
		AND_www(REG_WORK1, d, s);
		BFI_wwii(d, REG_WORK1, 0, 16);
	} else {
		AND_www(d, d, s);
	}

	EXIT_REGS(d, s);
}
MENDFUNC(2,jnf_AND_w,(RW2 d, RR2 s))

MIDFUNC(2,jnf_AND_l_imm,(RW4 d, IM32 v))
{
	if(isconst(d)) {
		live.state[d].val = live.state[d].val & v;
		return;
	}

	d = rmw(d);

	LOAD_U32(REG_WORK1, v);
	AND_www(d, d, REG_WORK1);

	unlock2(d);
}
MENDFUNC(2,jnf_AND_l_imm,(RW4 d, IM32 v))

MIDFUNC(2,jnf_AND_l,(RW4 d, RR4 s))
{
	if (isconst(s)) {
		COMPCALL(jnf_AND_l_imm)(d, live.state[s].val);
		return;
	}

	INIT_REGS_l(d, s);

	AND_www(d, d, s);

	EXIT_REGS(d, s);
}
MENDFUNC(2,jnf_AND_l,(RW4 d, RR4 s))

MIDFUNC(2,jff_AND_b_imm,(RW1 d, IM8 v))
{
	INIT_REG_b(d);

	SIGNED8_REG_2_REG(REG_WORK1, d);
	SIGNED8_IMM_2_REG(REG_WORK2, v);
	if(targetIsReg) {
		ANDS_www(REG_WORK1, REG_WORK1, REG_WORK2);
		BFI_wwii(d, REG_WORK1, 0, 8);
	} else {
		ANDS_www(d, REG_WORK1, REG_WORK2);
	}

	flags_carry_inverted = false;
	unlock2(d);
}
MENDFUNC(2,jff_AND_b_imm,(RW1 d, IM8 v))

MIDFUNC(2,jff_AND_b,(RW1 d, RR1 s))
{
	if (isconst(s)) {
		COMPCALL(jff_AND_b_imm)(d, live.state[s].val);
		return;
	}

	INIT_REGS_b(d, s);

	SIGNED8_REG_2_REG(REG_WORK1, d);
	SIGNED8_REG_2_REG(REG_WORK2, s);
	if(targetIsReg) {
		ANDS_www(REG_WORK1, REG_WORK1, REG_WORK2);
		BFI_wwii(d, REG_WORK1, 0, 8);
	} else {
		ANDS_www(d, REG_WORK1, REG_WORK2);
	}

	flags_carry_inverted = false;
	EXIT_REGS(d, s);
}
MENDFUNC(2,jff_AND_b,(RW1 d, RR1 s))

MIDFUNC(2,jff_AND_w_imm,(RW2 d, IM16 v))
{
	INIT_REG_w(d);

	SIGNED16_REG_2_REG(REG_WORK1, d);
	SIGNED16_IMM_2_REG(REG_WORK2, v);
	if(targetIsReg) {
		ANDS_www(REG_WORK1, REG_WORK1, REG_WORK2);
		BFI_wwii(d, REG_WORK1, 0, 16);
	} else {
		ANDS_www(d, REG_WORK1, REG_WORK2);
	}

	flags_carry_inverted = false;
	unlock2(d);
}
MENDFUNC(2,jff_AND_w_imm,(RW2 d, IM16 v))

MIDFUNC(2,jff_AND_w,(RW2 d, RR2 s))
{
	if (isconst(s)) {
		COMPCALL(jff_AND_w_imm)(d, live.state[s].val);
		return;
	}

	INIT_REGS_w(d, s);

	SIGNED16_REG_2_REG(REG_WORK1, d);
	SIGNED16_REG_2_REG(REG_WORK2, s);
	if(targetIsReg) {
		ANDS_www(REG_WORK1, REG_WORK1, REG_WORK2);
		BFI_wwii(d, REG_WORK1, 0, 16);
	} else {
		ANDS_www(d, REG_WORK1, REG_WORK2);
	}

	flags_carry_inverted = false;
	EXIT_REGS(d, s);
}
MENDFUNC(2,jff_AND_w,(RW2 d, RR2 s))

MIDFUNC(2,jff_AND_l_imm,(RW4 d, IM32 v))
{
	d = rmw(d);

	LOAD_U32(REG_WORK1, v);
	ANDS_www(d, d, REG_WORK1);

	flags_carry_inverted = false;
	unlock2(d);
}
MENDFUNC(2,jff_AND_l_imm,(RW4 d, IM32 v))

MIDFUNC(2,jff_AND_l,(RW4 d, RR4 s))
{
	if (isconst(s)) {
		COMPCALL(jff_AND_l_imm)(d, live.state[s].val);
		return;
	}

	INIT_REGS_l(d, s);

	ANDS_www(d, d, s);

	flags_carry_inverted = false;
	EXIT_REGS(d, s);
}
MENDFUNC(2,jff_AND_l,(RW4 d, RR4 s))

/*
 * ASL
 * Operand Syntax: 	Dx, Dy
 * 					#<data>, Dy
 *					<ea>
 *
 * Operand Size: 8,16,32
 *
 * X Set according to the last bit shifted out of the operand. Unaffected for a shift count of zero.
 * N Set if the most significant bit of the result is set. Cleared otherwise.
 * Z Set if the result is zero. Cleared otherwise.
 * V Set if the most significant bit is changed at any time during the shift operation. Cleared otherwise.
 * C Set according to the last bit shifted out of the operand. Cleared for a shift count of zero.
 *
 * The immediate helpers also serve constant-folded register counts and must
 * therefore accept the complete masked register-count domain, 0 <= i <= 63.
 *
 */
MIDFUNC(2,jff_ASL_b_imm,(RW1 d, IM8 i))
{
	if(i)
		d = rmw(d);
	else
		d = readreg(d);

	LSL_wwi(REG_WORK3, d, 24);
	if (i) {
		LSL_xxi(REG_WORK2, REG_WORK3, i);
		BFXIL_xxii(d, REG_WORK2, 24, 8);  // result is ready
		TST_ww(REG_WORK2, REG_WORK2);     // NZ correct, VC cleared

		PUBLISH_CARRY_FROM_BIT(REG_WORK2, 32, REG_WORK2);

		if (needed_flags & FLAG_V) {
			// Zero has no sign transition at any legal six-bit register count.
			MRS_NZCV_x(REG_WORK4);
			CLS_ww(REG_WORK1, REG_WORK3);
			CMP_wi(REG_WORK3, 0);
			MOV_wi(REG_WORK2, 63);
			CSEL_wwwc(REG_WORK1, REG_WORK2, REG_WORK1, NATIVE_CC_EQ);
			CMP_wi(REG_WORK1, i);
			SET_xxVflag(REG_WORK3, REG_WORK4);
			CSEL_xxxc(REG_WORK4, REG_WORK4, REG_WORK3, NATIVE_CC_GE);
			MSR_NZCV_x(REG_WORK4);
		}

		flags_carry_inverted = false;
		DUPLICACTE_CARRY
	} else {
		TST_ww(REG_WORK3, REG_WORK3);
		flags_carry_inverted = false;
	}

	unlock2(d);
}
MENDFUNC(2,jff_ASL_b_imm,(RW1 d, IM8 i))

MIDFUNC(2,jff_ASL_w_imm,(RW2 d, IM8 i))
{
	if(i)
		d = rmw(d);
	else
		d = readreg(d);

	LSL_wwi(REG_WORK3, d, 16);
	if (i) {
		LSL_xxi(REG_WORK2, REG_WORK3, i);
		BFXIL_xxii(d, REG_WORK2, 16, 16); // result is ready
		TST_ww(REG_WORK2, REG_WORK2);     // NZ correct, VC cleared

		PUBLISH_CARRY_FROM_BIT(REG_WORK2, 32, REG_WORK2);

		if (needed_flags & FLAG_V) {
			// Zero has no sign transition at any legal six-bit register count.
			MRS_NZCV_x(REG_WORK4);
			CLS_ww(REG_WORK1, REG_WORK3);
			CMP_wi(REG_WORK3, 0);
			MOV_wi(REG_WORK2, 63);
			CSEL_wwwc(REG_WORK1, REG_WORK2, REG_WORK1, NATIVE_CC_EQ);
			CMP_wi(REG_WORK1, i);
			SET_xxVflag(REG_WORK3, REG_WORK4);
			CSEL_xxxc(REG_WORK4, REG_WORK4, REG_WORK3, NATIVE_CC_GE);
			MSR_NZCV_x(REG_WORK4);
		}

		flags_carry_inverted = false;
		DUPLICACTE_CARRY
	} else {
		TST_ww(REG_WORK3, REG_WORK3);
		flags_carry_inverted = false;
	}

	unlock2(d);
}
MENDFUNC(2,jff_ASL_w_imm,(RW2 d, IM8 i))

MIDFUNC(2,jff_ASL_l_imm,(RW4 d, IM8 i))
{
	if(i)
		d = rmw(d);
	else
		d = readreg(d);

	if (i) {
		if (needed_flags & FLAG_V)
			MOV_ww(REG_WORK3, d);
		LSL_xxi(d, d, i);
		TST_ww(d, d);               // NZ correct, VC cleared

		PUBLISH_CARRY_FROM_BIT(d, 32, REG_WORK2);

		if (needed_flags & FLAG_V) {
			// Zero has no sign transition at any legal six-bit register count.
			MRS_NZCV_x(REG_WORK4);
			CLS_ww(REG_WORK1, REG_WORK3);
			CMP_wi(REG_WORK3, 0);
			MOV_wi(REG_WORK2, 63);
			CSEL_wwwc(REG_WORK1, REG_WORK2, REG_WORK1, NATIVE_CC_EQ);
			CMP_wi(REG_WORK1, i);
			SET_xxVflag(REG_WORK3, REG_WORK4);
			CSEL_xxxc(REG_WORK4, REG_WORK4, REG_WORK3, NATIVE_CC_GE);
			MSR_NZCV_x(REG_WORK4);
		}

		flags_carry_inverted = false;
		DUPLICACTE_CARRY

		// Clean upper 32 bits of d after 64-bit LSL_xxi used for carry extraction
		MOV_ww(d, d);
	} else {
		TST_ww(d, d);
		flags_carry_inverted = false;
	}

	unlock2(d);
}
MENDFUNC(2,jff_ASL_l_imm,(RW4 d, IM8 i))

MIDFUNC(2,jff_ASL_b_reg,(RW1 d, RR4 i))
{
	if(isconst(i)) {
		COMPCALL(jff_ASL_b_imm)(d, live.state[i].val & 0x3f);
		return;
	}

	i = readreg(i);
	d = rmw(d);
	LOCK_X_FOR_RUNTIME_JOIN;

	LSL_wwi(REG_WORK3, d, 24);
	ANDS_ww3f(REG_WORK1, i);
	uae_u32* branch_shift_nonzero = (uae_u32*)get_target();
	BNE_i(0);

	// shift count is 0
	TST_ww(REG_WORK3, REG_WORK3);     // NZ correct, VC cleared
	uae_u32* branchadd = (uae_u32*)get_target();
	B_i(0); // <end>

	write_jmp_target(branch_shift_nonzero, (uintptr)get_target());
	// shift count > 0
	LSL_xxx(REG_WORK2, REG_WORK3, REG_WORK1);
	BFXIL_xxii(d, REG_WORK2, 24, 8);  // result is ready
	TST_ww(REG_WORK2, REG_WORK2);     // NZ correct, VC cleared

	PUBLISH_CARRY_FROM_BIT(REG_WORK2, 32, REG_WORK2);

	if (needed_flags & FLAG_V) {
		// Zero never changes sign, even when the six-bit count exceeds 31.
		// Map its CLS sentinel from 31 to 63, then publish V branchlessly
		// when count exceeds the source's leading-sign-bit capacity.
		MRS_NZCV_x(REG_WORK4);
		CLS_ww(REG_WORK2, REG_WORK3);
		CMP_wi(REG_WORK3, 0);
		MOV_wi(REG_WORK3, 63);
		CSEL_wwwc(REG_WORK2, REG_WORK3, REG_WORK2, NATIVE_CC_EQ);
		CMP_ww(REG_WORK2, REG_WORK1);
		SET_xxVflag(REG_WORK3, REG_WORK4);
		CSEL_xxxc(REG_WORK4, REG_WORK4, REG_WORK3, NATIVE_CC_GE);
		MSR_NZCV_x(REG_WORK4);
	}

	flags_carry_inverted = false;
	DUPLICACTE_CARRY

	// <end>
	write_jmp_target(branchadd, (uintptr)get_target());

	UNLOCK_X_FOR_RUNTIME_JOIN;
	unlock2(d);
	unlock2(i);
}
MENDFUNC(2,jff_ASL_b_reg,(RW1 d, RR4 i))

MIDFUNC(2,jff_ASL_w_reg,(RW2 d, RR4 i))
{
	if(isconst(i)) {
		COMPCALL(jff_ASL_w_imm)(d, live.state[i].val & 0x3f);
		return;
	}

	i = readreg(i);
	d = rmw(d);
	LOCK_X_FOR_RUNTIME_JOIN;

	LSL_wwi(REG_WORK3, d, 16);
	ANDS_ww3f(REG_WORK1, i);
	uae_u32* branch_shift_nonzero = (uae_u32*)get_target();
	BNE_i(0);

	// shift count is 0
	TST_ww(REG_WORK3, REG_WORK3);     // NZ correct, VC cleared
	uae_u32* branchadd = (uae_u32*)get_target();
	B_i(0); // <end>

	write_jmp_target(branch_shift_nonzero, (uintptr)get_target());
	// shift count > 0
	LSL_xxx(REG_WORK2, REG_WORK3, REG_WORK1);
	BFXIL_xxii(d, REG_WORK2, 16, 16); // result is ready
	TST_ww(REG_WORK2, REG_WORK2);     // NZ correct, VC cleared

	PUBLISH_CARRY_FROM_BIT(REG_WORK2, 32, REG_WORK2);

	if (needed_flags & FLAG_V) {
		// Zero never changes sign, even when the six-bit count exceeds 31.
		// Map its CLS sentinel from 31 to 63, then publish V branchlessly
		// when count exceeds the source's leading-sign-bit capacity.
		MRS_NZCV_x(REG_WORK4);
		CLS_ww(REG_WORK2, REG_WORK3);
		CMP_wi(REG_WORK3, 0);
		MOV_wi(REG_WORK3, 63);
		CSEL_wwwc(REG_WORK2, REG_WORK3, REG_WORK2, NATIVE_CC_EQ);
		CMP_ww(REG_WORK2, REG_WORK1);
		SET_xxVflag(REG_WORK3, REG_WORK4);
		CSEL_xxxc(REG_WORK4, REG_WORK4, REG_WORK3, NATIVE_CC_GE);
		MSR_NZCV_x(REG_WORK4);
	}

	flags_carry_inverted = false;
	DUPLICACTE_CARRY

	// <end>
	write_jmp_target(branchadd, (uintptr)get_target());

	UNLOCK_X_FOR_RUNTIME_JOIN;
	unlock2(d);
	unlock2(i);
}
MENDFUNC(2,jff_ASL_w_reg,(RW2 d, RR4 i))

MIDFUNC(2,jff_ASL_l_reg,(RW4 d, RR4 i))
{
	if(isconst(i)) {
		COMPCALL(jff_ASL_l_imm)(d, live.state[i].val & 0x3f);
		return;
	}

	i = readreg(i);
	d = rmw(d);
	LOCK_X_FOR_RUNTIME_JOIN;

	ANDS_ww3f(REG_WORK1, i);
	uae_u32* branch_shift_nonzero = (uae_u32*)get_target();
	BNE_i(0);

	// shift count is 0
	TST_ww(d, d);     // NZ correct, VC cleared
	uae_u32* branchadd = (uae_u32*)get_target();
	B_i(0); // <end>

	write_jmp_target(branch_shift_nonzero, (uintptr)get_target());
	// shift count > 0
	if (needed_flags & FLAG_V)
		MOV_ww(REG_WORK3, d);
	LSL_xxx(d, d, REG_WORK1);
	TST_ww(d, d);                     // NZ correct, VC cleared

	PUBLISH_CARRY_FROM_BIT(d, 32, REG_WORK2);

	if (needed_flags & FLAG_V) {
		// Zero never changes sign, even when the six-bit count exceeds 31.
		// Map its CLS sentinel from 31 to 63, then publish V branchlessly
		// when count exceeds the source's leading-sign-bit capacity.
		MRS_NZCV_x(REG_WORK4);
		CLS_ww(REG_WORK2, REG_WORK3);
		CMP_wi(REG_WORK3, 0);
		MOV_wi(REG_WORK3, 63);
		CSEL_wwwc(REG_WORK2, REG_WORK3, REG_WORK2, NATIVE_CC_EQ);
		CMP_ww(REG_WORK2, REG_WORK1);
		SET_xxVflag(REG_WORK3, REG_WORK4);
		CSEL_xxxc(REG_WORK4, REG_WORK4, REG_WORK3, NATIVE_CC_GE);
		MSR_NZCV_x(REG_WORK4);
	}

	flags_carry_inverted = false;
	DUPLICACTE_CARRY

	// Clean upper 32 bits of d after 64-bit LSL_xxx used for carry extraction
	MOV_ww(d, d);

	// <end>
	write_jmp_target(branchadd, (uintptr)get_target());

	UNLOCK_X_FOR_RUNTIME_JOIN;
	unlock2(d);
	unlock2(i);
}
MENDFUNC(2,jff_ASL_l_reg,(RW4 d, RR4 i))

/*
 * ASLW
 * Operand Syntax: 	<ea>
 *
 * Operand Size: 16
 *
 * X Set according to the last bit shifted out of the operand.
 * N Set if the most significant bit of the result is set. Cleared otherwise.
 * Z Set if the result is zero. Cleared otherwise.
 * V Set if the most significant bit is changed at any time during the shift operation. Cleared otherwise.
 * C Set according to the last bit shifted out of the operand.
 *
 * Target is never a register.
 */
MIDFUNC(1,jnf_ASLW,(RW2 d))
{
	d = rmw(d);

	LSL_wwi(d, d, 1);

	unlock2(d);
}
MENDFUNC(1,jnf_ASLW,(RW2 d))

MIDFUNC(1,jff_ASLW,(RW2 d))
{
	d = rmw(d);

	LSL_wwi(REG_WORK1, d, 17);
	TST_ww(REG_WORK1, REG_WORK1);

	if (needed_flags & FLAG_V) {
		/* Publish V = old bit 15 xor old bit 14 and C = old bit 15
		 * without fixed-displacement control flow. */
		MRS_NZCV_x(REG_WORK4);
		EOR_wwwLSLi(REG_WORK1, d, d, 1);
		UBFX_xxii(REG_WORK2, d, 15, 1);
		BFI_xxii(REG_WORK4, REG_WORK2, 29, 1);
		UBFX_xxii(REG_WORK2, REG_WORK1, 15, 1);
		BFI_xxii(REG_WORK4, REG_WORK2, 28, 1);
		MSR_NZCV_x(REG_WORK4);
	} else {
		PUBLISH_CARRY_FROM_BIT(d, 15, REG_WORK2);
	}
	LSL_wwi(d, d, 1);

	flags_carry_inverted = false;
	DUPLICACTE_CARRY

	unlock2(d);
}
MENDFUNC(1,jff_ASLW,(RW2 d))

/*
 * ASR
 * Operand Syntax: 	Dx, Dy
 * 					#<data>, Dy
 *					<ea>
 *
 * Operand Size: 8,16,32
 *
 * X Set according to the last bit shifted out of the operand. Unaffected for a shift count of zero.
 * N Set if the most significant bit of the result is set. Cleared otherwise.
 * Z Set if the result is zero. Cleared otherwise.
 * V Set if the most significant bit is changed at any time during the shift operation. Cleared otherwise. Shift right -> always 0
 * C Set according to the last bit shifted out of the operand. Cleared for a shift count of zero.
 *
 */
MIDFUNC(2,jnf_ASR_b_imm,(RW1 d, IM8 i))
{
	if(i) {
		d = rmw(d);

		SIGNED8_REG_2_REG(REG_WORK1, d);
		if(i > 31)
			i = 31;
		ASR_wwi(REG_WORK1, REG_WORK1, i);
		BFI_wwii(d, REG_WORK1, 0, 8);

		unlock2(d);
	}
}
MENDFUNC(2,jnf_ASR_b_imm,(RW1 d, IM8 i))

MIDFUNC(2,jnf_ASR_w_imm,(RW2 d, IM8 i))
{
	if(i) {
		d = rmw(d);

		SIGNED16_REG_2_REG(REG_WORK1, d);
		if(i > 31)
			i = 31;
		ASR_wwi(REG_WORK1, REG_WORK1, i);
		BFI_wwii(d, REG_WORK1, 0, 16);

		unlock2(d);
	}
}
MENDFUNC(2,jnf_ASR_w_imm,(RW2 d, IM8 i))

MIDFUNC(2,jnf_ASR_l_imm,(RW4 d, IM8 i))
{
	if(i) {
		d = rmw(d);

		if(i > 31)
			i = 31;
		ASR_wwi(d, d, i);

		unlock2(d);
	}
}
MENDFUNC(2,jnf_ASR_l_imm,(RW4 d, IM8 i))

MIDFUNC(2,jff_ASR_b_imm,(RW1 d, IM8 i))
{
	if(i)
		d = rmw(d);
	else
		d = readreg(d);

	SIGNED8_REG_2_REG(REG_WORK1, d);
	if (i) {
		if(i > 31)
			i = 31;
		ASR_wwi(REG_WORK2, REG_WORK1, i);
		BFI_wwii(d, REG_WORK2, 0, 8);
		TST_ww(REG_WORK2, REG_WORK2);

		// Calculate C flag
		PUBLISH_CARRY_FROM_BIT(REG_WORK1, i - 1, REG_WORK2);

		flags_carry_inverted = false;
		DUPLICACTE_CARRY
	} else {
		TST_ww(REG_WORK1, REG_WORK1);
		flags_carry_inverted = false;
	}

	unlock2(d);
}
MENDFUNC(2,jff_ASR_b_imm,(RW1 d, IM8 i))

MIDFUNC(2,jff_ASR_w_imm,(RW2 d, IM8 i))
{
	if(i)
		d = rmw(d);
	else
		d = readreg(d);

	SIGNED16_REG_2_REG(REG_WORK1, d);
	if (i) {
		if(i > 31)
			i = 31;
		ASR_wwi(REG_WORK2, REG_WORK1, i);
		BFI_wwii(d, REG_WORK2, 0, 16);
		TST_ww(REG_WORK2, REG_WORK2);

		// Calculate C flag
		PUBLISH_CARRY_FROM_BIT(REG_WORK1, i - 1, REG_WORK2);

		flags_carry_inverted = false;
		DUPLICACTE_CARRY
	} else {
		TST_ww(REG_WORK1, REG_WORK1);
		flags_carry_inverted = false;
	}

	unlock2(d);
}
MENDFUNC(2,jff_ASR_w_imm,(RW2 d, IM8 i))

MIDFUNC(2,jff_ASR_l_imm,(RW4 d, IM8 i))
{
	if(i)
		d = rmw(d);
	else
		d = readreg(d);

	if (i) {
		SXTW_xw(REG_WORK1, d);
		if(i > 32)
			i = 32;
		ASR_xxi(d, REG_WORK1, i);
		TST_ww(d, d);

		// Calculate C flag
		PUBLISH_CARRY_FROM_BIT(REG_WORK1, i - 1, REG_WORK2);

		flags_carry_inverted = false;
		DUPLICACTE_CARRY

		// Clean upper 32 bits after 64-bit ASR_xxi
		MOV_ww(d, d);
	} else {
		TST_ww(d, d);
		flags_carry_inverted = false;
	}

	unlock2(d);
}
MENDFUNC(2,jff_ASR_l_imm,(RW4 d, IM8 i))

MIDFUNC(2,jnf_ASR_b_reg,(RW1 d, RR4 i))
{
	if (isconst(i)) {
		COMPCALL(jnf_ASR_b_imm)(d, live.state[i].val & 0x3f);
		return;
	}

	i = readreg(i);
	d = rmw(d);

	SIGNED8_REG_2_REG(REG_WORK1, d);
	SXTW_xw(REG_WORK1, REG_WORK1);
	AND_ww3f(REG_WORK2, i);
	ASR_xxx(REG_WORK1, REG_WORK1, REG_WORK2);
	BFI_wwii(d, REG_WORK1, 0, 8);

	unlock2(d);
	unlock2(i);
}
MENDFUNC(2,jnf_ASR_b_reg,(RW1 d, RR4 i))

MIDFUNC(2,jnf_ASR_w_reg,(RW2 d, RR4 i))
{
	if (isconst(i)) {
		COMPCALL(jnf_ASR_w_imm)(d, live.state[i].val & 0x3f);
		return;
	}

	i = readreg(i);
	d = rmw(d);

	SIGNED16_REG_2_REG(REG_WORK1, d);
	SXTW_xw(REG_WORK1, REG_WORK1);
	AND_ww3f(REG_WORK2, i);
	ASR_xxx(REG_WORK1, REG_WORK1, REG_WORK2);
	BFI_wwii(d, REG_WORK1, 0, 16);

	unlock2(d);
	unlock2(i);
}
MENDFUNC(2,jnf_ASR_w_reg,(RW2 d, RR4 i))

MIDFUNC(2,jnf_ASR_l_reg,(RW4 d, RR4 i))
{
	if (isconst(i)) {
		COMPCALL(jnf_ASR_l_imm)(d, live.state[i].val & 0x3f);
		return;
	}

	i = readreg(i);
	d = rmw(d);

	SXTW_xw(REG_WORK2, d);
	AND_ww3f(REG_WORK1, i);
	ASR_xxx(d, REG_WORK2, REG_WORK1);
	MOV_ww(d, d);

	unlock2(d);
	unlock2(i);
}
MENDFUNC(2,jnf_ASR_l_reg,(RW4 d, RR4 i))

MIDFUNC(2,jff_ASR_b_reg,(RW1 d, RR4 i))
{
	if (isconst(i)) {
		COMPCALL(jff_ASR_b_imm)(d, live.state[i].val & 0x3f);
		return;
	}

	i = readreg(i);
	d = rmw(d);
	LOCK_X_FOR_RUNTIME_JOIN;

	SIGNED8_REG_2_REG(REG_WORK3, d);
	SXTW_xw(REG_WORK3, REG_WORK3);
	ANDS_ww3f(REG_WORK1, i);
	uae_u32* branch_shift_nonzero = (uae_u32*)get_target();
	BNE_i(0);               // No shift -> X flag unchanged

	// shift count is 0
	TST_ww(REG_WORK3, REG_WORK3);     // NZ correct, VC cleared
	uae_u32* branchadd = (uae_u32*)get_target();
	B_i(0); // <end>

	write_jmp_target(branch_shift_nonzero, (uintptr)get_target());
	// shift count > 0
	ASR_xxx(REG_WORK2, REG_WORK3, REG_WORK1);
	BFI_wwii(d, REG_WORK2, 0, 8);
	TST_ww(REG_WORK2, REG_WORK2);

	// Calculate C Flag
	SUB_wwi(REG_WORK2, REG_WORK1, 1);
	ASR_xxx(REG_WORK2, REG_WORK3, REG_WORK2);
	PUBLISH_CARRY_FROM_BIT(REG_WORK2, 0, REG_WORK2);

	flags_carry_inverted = false;
	DUPLICACTE_CARRY

	// <end>
	write_jmp_target(branchadd, (uintptr)get_target());

	UNLOCK_X_FOR_RUNTIME_JOIN;
	unlock2(d);
	unlock2(i);
}
MENDFUNC(2,jff_ASR_b_reg,(RW1 d, RR4 i))

MIDFUNC(2,jff_ASR_w_reg,(RW2 d, RR4 i))
{
	if (isconst(i)) {
		COMPCALL(jff_ASR_w_imm)(d, live.state[i].val & 0x3f);
		return;
	}

	i = readreg(i);
	d = rmw(d);
	LOCK_X_FOR_RUNTIME_JOIN;

	SIGNED16_REG_2_REG(REG_WORK3, d);
	SXTW_xw(REG_WORK3, REG_WORK3);
	ANDS_ww3f(REG_WORK1, i);
	uae_u32* branch_shift_nonzero = (uae_u32*)get_target();
	BNE_i(0);               // No shift -> X flag unchanged

	// shift count is 0
	TST_ww(REG_WORK3, REG_WORK3);     // NZ correct, VC cleared
	uae_u32* branchadd = (uae_u32*)get_target();
	B_i(0); // <end>

	write_jmp_target(branch_shift_nonzero, (uintptr)get_target());
	// shift count > 0
	ASR_xxx(REG_WORK2, REG_WORK3, REG_WORK1);
	BFI_wwii(d, REG_WORK2, 0, 16);
	TST_ww(REG_WORK2, REG_WORK2);

	// Calculate C Flag
	SUB_wwi(REG_WORK2, REG_WORK1, 1);
	ASR_xxx(REG_WORK2, REG_WORK3, REG_WORK2);
	PUBLISH_CARRY_FROM_BIT(REG_WORK2, 0, REG_WORK2);

	flags_carry_inverted = false;
	DUPLICACTE_CARRY

	// <end>
	write_jmp_target(branchadd, (uintptr)get_target());

	UNLOCK_X_FOR_RUNTIME_JOIN;
	unlock2(d);
	unlock2(i);
}
MENDFUNC(2,jff_ASR_w_reg,(RW2 d, RR4 i))

MIDFUNC(2,jff_ASR_l_reg,(RW4 d, RR4 i))
{
	if (isconst(i)) {
		COMPCALL(jff_ASR_l_imm)(d, live.state[i].val & 0x3f);
		return;
	}

	i = readreg(i);
	d = rmw(d);
	LOCK_X_FOR_RUNTIME_JOIN;

	ANDS_ww3f(REG_WORK1, i);
	uae_u32* branch_shift_nonzero = (uae_u32*)get_target();
	BNE_i(0);               // No shift -> X flag unchanged

	// shift count is 0
	TST_ww(d, d);           // NZ correct, VC cleared
	uae_u32* branchadd = (uae_u32*)get_target();
	B_i(0); // <end>

	write_jmp_target(branch_shift_nonzero, (uintptr)get_target());
	// shift count > 0
	SXTW_xw(REG_WORK3, d);
	ASR_xxx(d, REG_WORK3, REG_WORK1);
	TST_ww(d, d);

	// Calculate C Flag
	SUB_wwi(REG_WORK2, REG_WORK1, 1);
	ASR_xxx(REG_WORK2, REG_WORK3, REG_WORK2);
	PUBLISH_CARRY_FROM_BIT(REG_WORK2, 0, REG_WORK2);

	flags_carry_inverted = false;
	DUPLICACTE_CARRY
	MOV_ww(d, d);

	// <end>
	write_jmp_target(branchadd, (uintptr)get_target());

	UNLOCK_X_FOR_RUNTIME_JOIN;
	unlock2(d);
	unlock2(i);
}
MENDFUNC(2,jff_ASR_l_reg,(RW4 d, RR4 i))

/*
 * ASRW
 * Operand Syntax: 	<ea>
 *
 * Operand Size: 16
 *
 * X Set according to the last bit shifted out of the operand.
 * N Set if the most significant bit of the result is set. Cleared otherwise.
 * Z Set if the result is zero. Cleared otherwise.
 * V Set if the most significant bit is changed at any time during the shift operation. Cleared otherwise. Shift right -> always 0
 * C Set according to the last bit shifted out of the operand.
 *
 * Target is never a register.
 */
MIDFUNC(1,jnf_ASRW,(RW2 d))
{
	d = rmw(d);

	SIGNED16_REG_2_REG(d, d);
	ASR_wwi(d, d, 1);

	unlock2(d);
}
MENDFUNC(1,jnf_ASRW,(RW2 d))

MIDFUNC(1,jff_ASRW,(RW2 d))
{
	d = rmw(d);

	SIGNED16_REG_2_REG(REG_WORK1, d);
	ASR_wwi(d, REG_WORK1, 1);
	TST_ww(d, d);

	PUBLISH_CARRY_FROM_BIT(REG_WORK1, 0, REG_WORK2);

	flags_carry_inverted = false;
	DUPLICACTE_CARRY

	unlock2(d);
}
MENDFUNC(1,jff_ASRW,(RW2 d))

/*
 * BCHG
 * Operand Syntax: 	Dn,<ea>
 *					#<data>,<ea>
 *
 *  Operand Size: 8,32
 *
 * X Not affected.
 * N Not affected.
 * Z Set if the bit changed was zero. Cleared otherwise.
 * V Not affected.
 * C Not affected.
 *
 */
/* BCHG.B: target is never a register */
/* BCHG.L: target is always a register */
MIDFUNC(2,jnf_BCHG_b_imm,(RW1 d, IM8 s))
{
	d = rmw(d);
	EOR_xxbit(d, d, s & 0x7);
	unlock2(d);
}
MENDFUNC(2,jnf_BCHG_b_imm,(RW1 d, IM8 s))

MIDFUNC(2,jnf_BCHG_l_imm,(RW4 d, IM8 s))
{
	d = rmw(d);
	EOR_xxbit(d, d, s & 0x1f);
	unlock2(d);
}
MENDFUNC(2,jnf_BCHG_l_imm,(RW4 d, IM8 s))

MIDFUNC(2,jnf_BCHG_b,(RW1 d, RR4 s))
{
	if (isconst(s)) {
		COMPCALL(jnf_BCHG_b_imm)(d, live.state[s].val);
		return;
	}

	s = readreg(s);
	d = rmw(d);

	UBFIZ_xxii(REG_WORK1, s, 0, 3); // REG_WORK1 = s & 7
	MOV_xi(REG_WORK2, 1);
	LSL_www(REG_WORK2, REG_WORK2, REG_WORK1);

	EOR_www(d, d, REG_WORK2);

	unlock2(d);
	unlock2(s);
}
MENDFUNC(2,jnf_BCHG_b,(RW1 d, RR4 s))

MIDFUNC(2,jnf_BCHG_l,(RW4 d, RR4 s))
{
	if (isconst(s)) {
		COMPCALL(jnf_BCHG_l_imm)(d, live.state[s].val);
		return;
	}

	INIT_REGS_l(d,s);

	UBFIZ_xxii(REG_WORK1, s, 0, 5); // REG_WORK1 = s & 31
	MOV_xi(REG_WORK2, 1);
	LSL_www(REG_WORK2, REG_WORK2, REG_WORK1);

	EOR_www(d, d, REG_WORK2);

	EXIT_REGS(d,s);
}
MENDFUNC(2,jnf_BCHG_l,(RW4 d, RR4 s))

MIDFUNC(2,jff_BCHG_b_imm,(RW1 d, IM8 s))
{
	d = rmw(d);

	MRS_NZCV_x(REG_WORK1);
	EOR_xxbit(d, d, s & 0x7);
	UBFX_xxii(REG_WORK2, d, s & 0x7, 1);
	BFI_xxii(REG_WORK1, REG_WORK2, 30, 1);
	MSR_NZCV_x(REG_WORK1);

	unlock2(d);
}
MENDFUNC(2,jff_BCHG_b_imm,(RW1 d, IM8 s))

MIDFUNC(2,jff_BCHG_l_imm,(RW4 d, IM8 s))
{
	d = rmw(d);

	MRS_NZCV_x(REG_WORK1);
	EOR_xxbit(d, d, s & 0x1f);
	UBFX_xxii(REG_WORK2, d, s & 0x1f, 1);
	BFI_xxii(REG_WORK1, REG_WORK2, 30, 1);
	MSR_NZCV_x(REG_WORK1);

	unlock2(d);
}
MENDFUNC(2,jff_BCHG_l_imm,(RW4 d, IM8 s))

MIDFUNC(2,jff_BCHG_b,(RW1 d, RR4 s))
{
	if (isconst(s)) {
		COMPCALL(jff_BCHG_b_imm)(d, live.state[s].val);
		return;
	}

	s = readreg(s);
	d = rmw(d);

	UBFIZ_xxii(REG_WORK1, s, 0, 3); // REG_WORK1 = s & 7
	MOV_xi(REG_WORK2, 1);
	LSL_www(REG_WORK2, REG_WORK2, REG_WORK1);

	MRS_NZCV_x(REG_WORK1);
	TST_ww(d, REG_WORK2);
	CSET_xc(REG_WORK3, NATIVE_CC_EQ);
	BFI_xxii(REG_WORK1, REG_WORK3, 30, 1);
	MSR_NZCV_x(REG_WORK1);
	EOR_www(d, d, REG_WORK2);

	unlock2(d);
	unlock2(s);
}
MENDFUNC(2,jff_BCHG_b,(RW1 d, RR4 s))

MIDFUNC(2,jff_BCHG_l,(RW4 d, RR4 s))
{
	if (isconst(s)) {
		COMPCALL(jff_BCHG_l_imm)(d, live.state[s].val);
		return;
	}

	INIT_REGS_l(d,s);

	UBFIZ_xxii(REG_WORK1, s, 0, 5); // REG_WORK1 = s & 31
	MOV_xi(REG_WORK2, 1);
	LSL_www(REG_WORK2, REG_WORK2, REG_WORK1);

	MRS_NZCV_x(REG_WORK1);
	TST_ww(d, REG_WORK2);
	CSET_xc(REG_WORK3, NATIVE_CC_EQ);
	BFI_xxii(REG_WORK1, REG_WORK3, 30, 1);
	MSR_NZCV_x(REG_WORK1);
	EOR_www(d, d, REG_WORK2);

	EXIT_REGS(d,s);
}
MENDFUNC(2,jff_BCHG_l,(RW4 d, RR4 s))

/*
 * BCLR
 * Operand Syntax: 	Dn,<ea>
 *					#<data>,<ea>
 *
 * Operand Size: 8,32
 *
 * X Not affected.
 * N Not affected.
 * Z Set if the bit cleared was zero. Cleared otherwise.
 * V Not affected.
 * C Not affected.
 *
 */
/* BCLR.B: target is never a register */
/* BCLR.L: target is always a register */
MIDFUNC(2,jnf_BCLR_b_imm,(RW1 d, IM8 s))
{
	d = rmw(d);
	CLEAR_xxbit(d, d, s & 0x7);
	unlock2(d);
}
MENDFUNC(2,jnf_BCLR_b_imm,(RW1 d, IM8 s))

MIDFUNC(2,jnf_BCLR_l_imm,(RW4 d, IM8 s))
{
	if(isconst(d)) {
		live.state[d].val = live.state[d].val & ~(1 << (s & 0x1f));
		return;
	}
	d = rmw(d);
	CLEAR_xxbit(d, d, s & 0x1f);
	unlock2(d);
}
MENDFUNC(2,jnf_BCLR_l_imm,(RW4 d, IM8 s))

MIDFUNC(2,jnf_BCLR_b,(RW1 d, RR4 s))
{
	if (isconst(s)) {
		COMPCALL(jnf_BCLR_b_imm)(d, live.state[s].val);
		return;
	}
	s = readreg(s);
	d = rmw(d);

	UBFIZ_xxii(REG_WORK1, s, 0, 3); // REG_WORK1 = s & 7
	MOV_xi(REG_WORK2, 1);
	LSL_www(REG_WORK2, REG_WORK2, REG_WORK1);

	BIC_www(d, d, REG_WORK2);

	unlock2(d);
	unlock2(s);
}
MENDFUNC(2,jnf_BCLR_b,(RW1 d, RR4 s))

MIDFUNC(2,jnf_BCLR_l,(RW4 d, RR4 s))
{
	if (isconst(s)) {
		COMPCALL(jnf_BCLR_l_imm)(d, live.state[s].val);
		return;
	}

	INIT_REGS_l(d,s);

	UBFIZ_xxii(REG_WORK1, s, 0, 5); // REG_WORK1 = s & 31
	MOV_xi(REG_WORK2, 1);
	LSL_www(REG_WORK2, REG_WORK2, REG_WORK1);

	BIC_www(d, d, REG_WORK2);

	EXIT_REGS(d,s);
}
MENDFUNC(2,jnf_BCLR_l,(RW4 d, RR4 s))

MIDFUNC(2,jff_BCLR_b_imm,(RW1 d, IM8 s))
{
	d = rmw(d);

	MRS_NZCV_x(REG_WORK1);
	CLEAR_xxZflag(REG_WORK1, REG_WORK1);
	TBNZ_wii(d, s & 0x7, 2);
	SET_xxZflag(REG_WORK1, REG_WORK1);
	MSR_NZCV_x(REG_WORK1);
	CLEAR_xxbit(d, d, s & 0x7);

	unlock2(d);
}
MENDFUNC(2,jff_BCLR_b_imm,(RW1 d, IM8 s))

MIDFUNC(2,jff_BCLR_l_imm,(RW4 d, IM8 s))
{
	d = rmw(d);

	MRS_NZCV_x(REG_WORK1);
	CLEAR_xxZflag(REG_WORK1, REG_WORK1);
	TBNZ_wii(d, s & 0x1f, 2);
	SET_xxZflag(REG_WORK1, REG_WORK1);
	MSR_NZCV_x(REG_WORK1);
	CLEAR_xxbit(d, d, s & 0x1f);

	unlock2(d);
}
MENDFUNC(2,jff_BCLR_l_imm,(RW4 d, IM8 s))

MIDFUNC(2,jff_BCLR_b,(RW1 d, RR4 s))
{
	if (isconst(s)) {
		COMPCALL(jff_BCLR_b_imm)(d, live.state[s].val);
		return;
	}

	s = readreg(s);
	d = rmw(d);

	UBFIZ_xxii(REG_WORK1, s, 0, 3); // REG_WORK1 = s & 7
	MOV_xi(REG_WORK2, 1);
	LSL_www(REG_WORK2, REG_WORK2, REG_WORK1);

	MRS_NZCV_x(REG_WORK1);
	TST_ww(d,REG_WORK2);
	CSET_xc(REG_WORK3, NATIVE_CC_EQ);
	BFI_xxii(REG_WORK1, REG_WORK3, 30, 1);
	MSR_NZCV_x(REG_WORK1);
	BIC_www(d, d, REG_WORK2);

	unlock2(d);
	unlock2(s);
}
MENDFUNC(2,jff_BCLR_b,(RW1 d, RR4 s))

MIDFUNC(2,jff_BCLR_l,(RW4 d, RR4 s))
{
	if (isconst(s)) {
		COMPCALL(jff_BCLR_l_imm)(d, live.state[s].val);
		return;
	}

	INIT_REGS_l(d,s);

	UBFIZ_xxii(REG_WORK1, s, 0, 5); // REG_WORK1 = s & 31
	MOV_xi(REG_WORK2, 1);
	LSL_www(REG_WORK2, REG_WORK2, REG_WORK1);

	MRS_NZCV_x(REG_WORK1);
	TST_ww(d,REG_WORK2);
	CSET_xc(REG_WORK3, NATIVE_CC_EQ);
	BFI_xxii(REG_WORK1, REG_WORK3, 30, 1);
	MSR_NZCV_x(REG_WORK1);
	BIC_www(d, d, REG_WORK2);

	EXIT_REGS(d,s);
}
MENDFUNC(2,jff_BCLR_l,(RW4 d, RR4 s))

/*
 * BFINS
 * Operand Syntax: 	#xxx.w,<ea>
 *
 * Operand Size: 32
 *
 * X Not affected.
 * N Set if the most significant bit of the bitfield is set. Cleared otherwise.
 * Z Set if the bitfield is zero. Cleared otherwise.
 * V Always cleared.
 * C Always cleared.
 *
 */
MIDFUNC(4,jnf_BFINS_ii,(RW4 d, RR4 s, IM8 offs, IM8 width))
{
	INIT_REGS_l(d,s);

	BFI_wwii(d, s, (32 - offs - width), width);
	if(32 - offs - width < 0) {
		BFI_xxii(d, s, (64 - offs - width), width);
		MOV_ww(d, d); // Clean upper 32 bits after 64-bit BFI for wrap-around case
	}

	EXIT_REGS(d,s);
}
MENDFUNC(4,jnf_BFINS_ii,(RW4 d, RR4 s, IM8 offs, IM8 width))

MIDFUNC(4,jff_BFINS_ii,(RW4 d, RR4 s, IM8 offs, IM8 width))
{
	INIT_REGS_l(d,s);

	SBFX_wwii(REG_WORK1, s, 0, width);
	BFI_wwii(d, REG_WORK1, (32 - offs - width), width);
	if(32 - offs - width < 0) {
		BFI_xxii(d, REG_WORK1, (64 - offs - width), width);
		MOV_ww(d, d); // Clean upper 32 bits after 64-bit BFI for wrap-around case
	}
	TST_ww(REG_WORK1, REG_WORK1);

	flags_carry_inverted = false;
	EXIT_REGS(d,s);
}
MENDFUNC(4,jff_BFINS_ii,(RW4 d, RR4 s, IM8 offs, IM8 width))

MIDFUNC(5,jnf_BFINS2_ii,(RW4 d, RW4 d2, RR4 s, IM8 offs, IM8 width))
{
	d2 = rmw(d2);
	INIT_REGS_l(d,s);

	SBFX_wwii(REG_WORK1, s, 0, width);
	BFI_xxii(d2, d, 32, 32);
	BFI_xxii(d2, REG_WORK1, (64 - offs - width), width);
	LSR_xxi(d, d2, 32);
	MOV_ww(d2, d2); // Clean upper 32 bits of d2 after 64-bit BFINS2 operations

	EXIT_REGS(d,s);
	unlock2(d2);
}
MENDFUNC(5,jnf_BFINS2_ii,(RW4 d, RW4 d2, RR4 s, IM8 offs, IM8 width))

MIDFUNC(5,jff_BFINS2_ii,(RW4 d, RW4 d2, RR4 s, IM8 offs, IM8 width))
{
	d2 = rmw(d2);
	INIT_REGS_l(d,s);

	SBFX_wwii(REG_WORK1, s, 0, width);
	BFI_xxii(d2, d, 32, 32);
	BFI_xxii(d2, REG_WORK1, (64 - offs - width), width);
	LSR_xxi(d, d2, 32);
	MOV_ww(d2, d2); // Clean upper 32 bits of d2 after 64-bit BFINS2 operations
	TST_ww(REG_WORK1, REG_WORK1);

	flags_carry_inverted = false;
	EXIT_REGS(d,s);
	unlock2(d2);
}
MENDFUNC(5,jff_BFINS2_ii,(RW4 d, RW4 d2, RR4 s, IM8 offs, IM8 width))

// Next only called when dest is D0-D7
MIDFUNC(4,jnf_BFINS_di,(RW4 d, RR4 s, RR4 offs, IM8 width))
{
	INIT_REGS_l(d,s);
	offs = readreg(offs);

	AND_xx1f(REG_WORK3, offs);
	MOV_xi(REG_WORK4, width);

	BFI_xxii(d, d, 32, 32);

	MOVN_xi(REG_WORK2, 0);
	LSR_www(REG_WORK2, REG_WORK2, REG_WORK4);
	BFI_xxii(REG_WORK2, REG_WORK2, 32, 32);
	ROR_xxx(REG_WORK2, REG_WORK2, REG_WORK3);
	AND_xxx(d, d, REG_WORK2);

	ROR_www(REG_WORK1, s, REG_WORK4);
	BFI_xxii(REG_WORK1, REG_WORK1, 32, 32);
	ROR_xxx(REG_WORK1, REG_WORK1, REG_WORK3);
	MVN_xx(REG_WORK2, REG_WORK2);
	AND_xxx(REG_WORK1, REG_WORK1, REG_WORK2);

	ORR_xxx(d, d, REG_WORK1);
	ROR_xxi(d, d, 32);
	MOV_ww(d, d); // Clean upper 32 bits after 64-bit BFINS operations

	unlock2(offs);
	EXIT_REGS(d,s);
}
MENDFUNC(4,jnf_BFINS_di,(RW4 d, RR4 s, RR4 offs, IM8 width))

MIDFUNC(4,jff_BFINS_di,(RW4 d, RR4 s, RR4 offs, IM8 width))
{
	INIT_REGS_l(d,s);
	offs = readreg(offs);

	AND_xx1f(REG_WORK3, offs);
	MOV_xi(REG_WORK4, width);

	BFI_xxii(d, d, 32, 32);

	MOVN_xi(REG_WORK2, 0);
	LSR_www(REG_WORK2, REG_WORK2, REG_WORK4);
	BFI_xxii(REG_WORK2, REG_WORK2, 32, 32);
	ROR_xxx(REG_WORK2, REG_WORK2, REG_WORK3);
	AND_xxx(d, d, REG_WORK2);

	ROR_www(REG_WORK1, s, REG_WORK4);
	BFI_xxii(REG_WORK1, REG_WORK1, 32, 32);
	ROR_xxx(REG_WORK1, REG_WORK1, REG_WORK3);
	MVN_xx(REG_WORK2, REG_WORK2);
	AND_xxx(REG_WORK1, REG_WORK1, REG_WORK2);

	ORR_xxx(d, d, REG_WORK1);
	ROR_xxi(d, d, 32);
	MOV_ww(d, d); // Clean upper 32 bits after 64-bit BFINS operations

	LSL_xxx(REG_WORK1, REG_WORK1, REG_WORK3);
	TST_xx(REG_WORK1, REG_WORK1);

	flags_carry_inverted = false;
	unlock2(offs);
	EXIT_REGS(d,s);
}
MENDFUNC(4,jff_BFINS_di,(RW4 d, RR4 s, RR4 offs, IM8 width))

MIDFUNC(4,jnf_BFINS_id,(RW4 d, RR4 s, IM8 offs, RR4 width))
{
	clobber_flags();

	INIT_REGS_l(d,s);
	width = readreg(width);

	MOV_xi(REG_WORK3, offs);
	ANDS_xx1f(REG_WORK4, width);
	BNE_i(2);
	MOV_xi(REG_WORK4, 0x20);

	BFI_xxii(d, d, 32, 32);

	MOVN_xi(REG_WORK2, 0);
	LSR_www(REG_WORK2, REG_WORK2, REG_WORK4);
	BFI_xxii(REG_WORK2, REG_WORK2, 32, 32);
	ROR_xxx(REG_WORK2, REG_WORK2, REG_WORK3);
	AND_xxx(d, d, REG_WORK2);

	ROR_www(REG_WORK1, s, REG_WORK4);
	BFI_xxii(REG_WORK1, REG_WORK1, 32, 32);
	ROR_xxx(REG_WORK1, REG_WORK1, REG_WORK3);
	MVN_xx(REG_WORK2, REG_WORK2);
	AND_xxx(REG_WORK1, REG_WORK1, REG_WORK2);

	ORR_xxx(d, d, REG_WORK1);
	ROR_xxi(d, d, 32);
	MOV_ww(d, d); // Clean upper 32 bits after 64-bit BFINS operations

	unlock2(width);
	EXIT_REGS(d,s);
}
MENDFUNC(4,jnf_BFINS_id,(RW4 d, RR4 s, IM8 offs, RR4 width))

MIDFUNC(4,jff_BFINS_id,(RW4 d, RR4 s, IM8 offs, RR4 width))
{
	INIT_REGS_l(d,s);
	width = readreg(width);

	MOV_xi(REG_WORK3, offs);
	ANDS_xx1f(REG_WORK4, width);
	BNE_i(2);
	MOV_xi(REG_WORK4, 0x20);

	BFI_xxii(d, d, 32, 32);

	MOVN_xi(REG_WORK2, 0);
	LSR_www(REG_WORK2, REG_WORK2, REG_WORK4);
	BFI_xxii(REG_WORK2, REG_WORK2, 32, 32);
	ROR_xxx(REG_WORK2, REG_WORK2, REG_WORK3);
	AND_xxx(d, d, REG_WORK2);

	ROR_www(REG_WORK1, s, REG_WORK4);
	BFI_xxii(REG_WORK1, REG_WORK1, 32, 32);
	ROR_xxx(REG_WORK1, REG_WORK1, REG_WORK3);
	MVN_xx(REG_WORK2, REG_WORK2);
	AND_xxx(REG_WORK1, REG_WORK1, REG_WORK2);

	ORR_xxx(d, d, REG_WORK1);
	ROR_xxi(d, d, 32);
	MOV_ww(d, d); // Clean upper 32 bits after 64-bit BFINS operations

	LSL_xxx(REG_WORK1, REG_WORK1, REG_WORK3);
	TST_xx(REG_WORK1, REG_WORK1);

	flags_carry_inverted = false;
	unlock2(width);
	EXIT_REGS(d,s);
}
MENDFUNC(4,jff_BFINS_id,(RW4 d, RR4 s, IM8 offs, RR4 width))

MIDFUNC(4,jnf_BFINS_dd,(RW4 d, RR4 s, RR4 offs, RR4 width))
{
	clobber_flags();

	INIT_REGS_l(d,s);
	offs = readreg(offs);
	width = readreg(width);

	AND_xx1f(REG_WORK3, offs);
	ANDS_xx1f(REG_WORK4, width);
	BNE_i(2);
	MOV_xi(REG_WORK4, 0x20);

	BFI_xxii(d, d, 32, 32);

	MOVN_xi(REG_WORK2, 0);
	LSR_www(REG_WORK2, REG_WORK2, REG_WORK4);
	BFI_xxii(REG_WORK2, REG_WORK2, 32, 32);
	ROR_xxx(REG_WORK2, REG_WORK2, REG_WORK3);
	AND_xxx(d, d, REG_WORK2);

	ROR_www(REG_WORK1, s, REG_WORK4);
	BFI_xxii(REG_WORK1, REG_WORK1, 32, 32);
	ROR_xxx(REG_WORK1, REG_WORK1, REG_WORK3);
	MVN_xx(REG_WORK2, REG_WORK2);
	AND_xxx(REG_WORK1, REG_WORK1, REG_WORK2);

	ORR_xxx(d, d, REG_WORK1);
	ROR_xxi(d, d, 32);
	MOV_ww(d, d); // Clean upper 32 bits after 64-bit BFINS operations

	unlock2(width);
	unlock2(offs);
	EXIT_REGS(d,s);
}
MENDFUNC(4,jnf_BFINS_dd,(RW4 d, RR4 s, RR4 offs, RR4 width))

MIDFUNC(4,jff_BFINS_dd,(RW4 d, RR4 s, RR4 offs, RR4 width))
{
	INIT_REGS_l(d,s);
	offs = readreg(offs);
	width = readreg(width);

	AND_xx1f(REG_WORK3, offs);
	ANDS_xx1f(REG_WORK4, width);
	BNE_i(2);
	MOV_xi(REG_WORK4, 0x20);

	BFI_xxii(d, d, 32, 32);

	MOVN_xi(REG_WORK2, 0);
	LSR_www(REG_WORK2, REG_WORK2, REG_WORK4);
	BFI_xxii(REG_WORK2, REG_WORK2, 32, 32);
	ROR_xxx(REG_WORK2, REG_WORK2, REG_WORK3);
	AND_xxx(d, d, REG_WORK2);

	ROR_www(REG_WORK1, s, REG_WORK4);
	BFI_xxii(REG_WORK1, REG_WORK1, 32, 32);
	ROR_xxx(REG_WORK1, REG_WORK1, REG_WORK3);
	MVN_xx(REG_WORK2, REG_WORK2);
	AND_xxx(REG_WORK1, REG_WORK1, REG_WORK2);

	ORR_xxx(d, d, REG_WORK1);
	ROR_xxi(d, d, 32);
	MOV_ww(d, d); // Clean upper 32 bits after 64-bit BFINS operations

	LSL_xxx(REG_WORK1, REG_WORK1, REG_WORK3);
	TST_xx(REG_WORK1, REG_WORK1);

	flags_carry_inverted = false;
	unlock2(width);
	unlock2(offs);
	EXIT_REGS(d,s);
}
MENDFUNC(4,jff_BFINS_dd,(RW4 d, RR4 s, RR4 offs, RR4 width))


// Next called when dest is <ea>
MIDFUNC(5,jnf_BFINS2_di,(RW4 d, RW4 d2, RR4 s, RR4 offs, IM8 width))
{
	d2 = rmw(d2);
	INIT_REGS_l(d,s);
	offs = readreg(offs);

	AND_xx1f(REG_WORK3, offs);
	MOV_xi(REG_WORK4, width);

	BFI_xxii(d2, d, 32, 32);

	MOVN_xi(REG_WORK2, 0);
	LSR_xxx(REG_WORK2, REG_WORK2, REG_WORK4);
	ROR_xxx(REG_WORK2, REG_WORK2, REG_WORK3);
	AND_xxx(d2, d2, REG_WORK2);

	ROR_xxx(REG_WORK1, s, REG_WORK4);
	ROR_xxx(REG_WORK1, REG_WORK1, REG_WORK3);
	MVN_xx(REG_WORK2, REG_WORK2);
	AND_xxx(REG_WORK1, REG_WORK1, REG_WORK2);

	ORR_xxx(d2, d2, REG_WORK1);
	LSR_xxi(d, d2, 32);
	MOV_ww(d2, d2); // Clean upper 32 bits of d2 after 64-bit BFINS2 operations

	unlock2(offs);
	EXIT_REGS(d,s);
	unlock2(d2);
}
MENDFUNC(5,jnf_BFINS2_di,(RW4 d, RW4 d2, RR4 s, RR4 offs, IM8 width))

MIDFUNC(5,jff_BFINS2_di,(RW4 d, RW4 d2, RR4 s, RR4 offs, IM8 width))
{
	d2 = rmw(d2);
	INIT_REGS_l(d,s);
	offs = readreg(offs);

	AND_xx1f(REG_WORK3, offs);
	MOV_xi(REG_WORK4, width);

	BFI_xxii(d2, d, 32, 32);

	MOVN_xi(REG_WORK2, 0);
	LSR_xxx(REG_WORK2, REG_WORK2, REG_WORK4);
	ROR_xxx(REG_WORK2, REG_WORK2, REG_WORK3);
	AND_xxx(d2, d2, REG_WORK2);

	ROR_xxx(REG_WORK1, s, REG_WORK4);
	ROR_xxx(REG_WORK1, REG_WORK1, REG_WORK3);
	MVN_xx(REG_WORK2, REG_WORK2);
	AND_xxx(REG_WORK1, REG_WORK1, REG_WORK2);

	ORR_xxx(d2, d2, REG_WORK1);
	LSR_xxi(d, d2, 32);
	MOV_ww(d2, d2); // Clean upper 32 bits of d2 after 64-bit BFINS2 operations

	LSL_xxx(REG_WORK1, REG_WORK1, REG_WORK3);
	TST_xx(REG_WORK1, REG_WORK1);

	flags_carry_inverted = false;
	unlock2(offs);
	EXIT_REGS(d,s);
	unlock2(d2);
}
MENDFUNC(5,jff_BFINS2_di,(RW4 d, RW4 d2, RR4 s, RR4 offs, IM8 width))

MIDFUNC(5,jnf_BFINS2_id,(RW4 d, RW4 d2, RR4 s, IM8 offs, RR4 width))
{
	clobber_flags();

	d2 = rmw(d2);
	INIT_REGS_l(d,s);
	width = readreg(width);

	MOV_xi(REG_WORK3, offs);
	ANDS_xx1f(REG_WORK4, width);
	BNE_i(2);
	MOV_xi(REG_WORK4, 0x20);

	BFI_xxii(d2, d, 32, 32);

	MOVN_xi(REG_WORK2, 0);
	LSR_xxx(REG_WORK2, REG_WORK2, REG_WORK4);
	ROR_xxx(REG_WORK2, REG_WORK2, REG_WORK3);
	AND_xxx(d2, d2, REG_WORK2);

	ROR_xxx(REG_WORK1, s, REG_WORK4);
	ROR_xxx(REG_WORK1, REG_WORK1, REG_WORK3);
	MVN_xx(REG_WORK2, REG_WORK2);
	AND_xxx(REG_WORK1, REG_WORK1, REG_WORK2);

	ORR_xxx(d2, d2, REG_WORK1);
	LSR_xxi(d, d2, 32);
	MOV_ww(d2, d2); // Clean upper 32 bits of d2 after 64-bit BFINS2 operations

	unlock2(width);
	EXIT_REGS(d,s);
	unlock2(d2);
}
MENDFUNC(5,jnf_BFINS2_id,(RW4 d, RW4 d2, RR4 s, IM8 offs, RR4 width))

MIDFUNC(5,jff_BFINS2_id,(RW4 d, RW4 d2, RR4 s, IM8 offs, RR4 width))
{
	d2 = rmw(d2);
	INIT_REGS_l(d,s);
	width = readreg(width);

	MOV_xi(REG_WORK3, offs);
	ANDS_xx1f(REG_WORK4, width);
	BNE_i(2);
	MOV_xi(REG_WORK4, 0x20);

	BFI_xxii(d2, d, 32, 32);

	MOVN_xi(REG_WORK2, 0);
	LSR_xxx(REG_WORK2, REG_WORK2, REG_WORK4);
	ROR_xxx(REG_WORK2, REG_WORK2, REG_WORK3);
	AND_xxx(d2, d2, REG_WORK2);

	ROR_xxx(REG_WORK1, s, REG_WORK4);
	ROR_xxx(REG_WORK1, REG_WORK1, REG_WORK3);
	MVN_xx(REG_WORK2, REG_WORK2);
	AND_xxx(REG_WORK1, REG_WORK1, REG_WORK2);

	ORR_xxx(d2, d2, REG_WORK1);
	LSR_xxi(d, d2, 32);
	MOV_ww(d2, d2); // Clean upper 32 bits of d2 after 64-bit BFINS2 operations

	LSL_xxx(REG_WORK1, REG_WORK1, REG_WORK3);
	TST_xx(REG_WORK1, REG_WORK1);

	flags_carry_inverted = false;
	unlock2(width);
	EXIT_REGS(d,s);
	unlock2(d2);
}
MENDFUNC(5,jff_BFINS2_id,(RW4 d, RW4 d2, RR4 s, IM8 offs, RR4 width))

MIDFUNC(5,jnf_BFINS2_dd,(RW4 d, RW4 d2, RR4 s, RR4 offs, RR4 width))
{
	clobber_flags();

	d2 = rmw(d2);
	INIT_REGS_l(d,s);
	offs = readreg(offs);
	width = readreg(width);

	AND_xx1f(REG_WORK3, offs);
	ANDS_xx1f(REG_WORK4, width);
	BNE_i(2);
	MOV_xi(REG_WORK4, 0x20);

	BFI_xxii(d2, d, 32, 32);

	MOVN_xi(REG_WORK2, 0);
	LSR_xxx(REG_WORK2, REG_WORK2, REG_WORK4);
	ROR_xxx(REG_WORK2, REG_WORK2, REG_WORK3);
	AND_xxx(d2, d2, REG_WORK2);

	ROR_xxx(REG_WORK1, s, REG_WORK4);
	ROR_xxx(REG_WORK1, REG_WORK1, REG_WORK3);
	MVN_xx(REG_WORK2, REG_WORK2);
	AND_xxx(REG_WORK1, REG_WORK1, REG_WORK2);

	ORR_xxx(d2, d2, REG_WORK1);
	LSR_xxi(d, d2, 32);
	MOV_ww(d2, d2); // Clean upper 32 bits of d2 after 64-bit BFINS2 operations

	unlock2(width);
	unlock2(offs);
	EXIT_REGS(d,s);
	unlock2(d2);
}
MENDFUNC(5,jnf_BFINS2_dd,(RW4 d, RW4 d2, RR4 s, RR4 offs, RR4 width))

MIDFUNC(5,jff_BFINS2_dd,(RW4 d, RW4 d2, RR4 s, RR4 offs, RR4 width))
{
	d2 = rmw(d2);
	INIT_REGS_l(d,s);
	offs = readreg(offs);
	width = readreg(width);

	AND_xx1f(REG_WORK3, offs);
	ANDS_xx1f(REG_WORK4, width);
	BNE_i(2);
	MOV_xi(REG_WORK4, 0x20);

	BFI_xxii(d2, d, 32, 32);

	MOVN_xi(REG_WORK2, 0);
	LSR_xxx(REG_WORK2, REG_WORK2, REG_WORK4);
	ROR_xxx(REG_WORK2, REG_WORK2, REG_WORK3);
	AND_xxx(d2, d2, REG_WORK2);

	ROR_xxx(REG_WORK1, s, REG_WORK4);
	ROR_xxx(REG_WORK1, REG_WORK1, REG_WORK3);
	MVN_xx(REG_WORK2, REG_WORK2);
	AND_xxx(REG_WORK1, REG_WORK1, REG_WORK2);

	ORR_xxx(d2, d2, REG_WORK1);
	LSR_xxi(d, d2, 32);
	MOV_ww(d2, d2); // Clean upper 32 bits of d2 after 64-bit BFINS2 operations

	LSL_xxx(REG_WORK1, REG_WORK1, REG_WORK3);
	TST_xx(REG_WORK1, REG_WORK1);

	flags_carry_inverted = false;
	unlock2(width);
	unlock2(offs);
	EXIT_REGS(d,s);
	unlock2(d2);
}
MENDFUNC(5,jff_BFINS2_dd,(RW4 d, RW4 d2, RR4 s, RR4 offs, RR4 width))

/*
 * BSET
 * Operand Syntax: 	Dn,<ea>
 *					#<data>,<ea>
 *
 *  Operand Size: 8,32
 *
 * X Not affected.
 * N Not affected.
 * Z Set if the bit set was zero. Cleared otherwise.
 * V Not affected.
 * C Not affected.
 *
 */
/* BSET.B: target is never a register */
/* BSET.L: target is always a register */
MIDFUNC(2,jnf_BSET_b_imm,(RW1 d, IM8 s))
{
	d = rmw(d);
	SET_xxbit(d, d, s & 0x7);
	unlock2(d);
}
MENDFUNC(2,jnf_BSET_b_imm,(RW1 d, IM8 s))

MIDFUNC(2,jnf_BSET_l_imm,(RW4 d, IM8 s))
{
	d = rmw(d);
	SET_xxbit(d, d, s & 0x1f);
	unlock2(d);
}
MENDFUNC(2,jnf_BSET_l_imm,(RW4 d, IM8 s))

MIDFUNC(2,jnf_BSET_b,(RW1 d, RR4 s))
{
	if (isconst(s)) {
		COMPCALL(jnf_BSET_b_imm)(d, live.state[s].val);
		return;
	}

	s = readreg(s);
	d = rmw(d);

	UBFIZ_xxii(REG_WORK1, s, 0, 3); // REG_WORK1 = s & 7
	MOV_xi(REG_WORK2, 1);
	LSL_www(REG_WORK2, REG_WORK2, REG_WORK1);

	ORR_www(d, d, REG_WORK2);

	unlock2(d);
	unlock2(s);
}
MENDFUNC(2,jnf_BSET_b,(RW1 d, RR4 s))

MIDFUNC(2,jnf_BSET_l,(RW4 d, RR4 s))
{
	if (isconst(s)) {
		COMPCALL(jnf_BSET_l_imm)(d, live.state[s].val);
		return;
	}

	INIT_REGS_l(d,s);

	UBFIZ_xxii(REG_WORK1, s, 0, 5); // REG_WORK1 = s & 31
	MOV_xi(REG_WORK2, 1);
	LSL_www(REG_WORK2, REG_WORK2, REG_WORK1);

	ORR_www(d, d, REG_WORK2);

	EXIT_REGS(d,s);
}
MENDFUNC(2,jnf_BSET_l,(RW4 d, RR4 s))

MIDFUNC(2,jff_BSET_b_imm,(RW1 d, IM8 s))
{
	d = rmw(d);

	MRS_NZCV_x(REG_WORK1);
	CLEAR_xxZflag(REG_WORK1, REG_WORK1);
	TBNZ_wii(d, s & 0x7, 2);
	SET_xxZflag(REG_WORK1, REG_WORK1);
	MSR_NZCV_x(REG_WORK1);
	SET_xxbit(d, d, s & 0x7);

	unlock2(d);
}
MENDFUNC(2,jff_BSET_b_imm,(RW1 d, IM8 s))

MIDFUNC(2,jff_BSET_l_imm,(RW4 d, IM8 s))
{
	d = rmw(d);

	MRS_NZCV_x(REG_WORK1);
	CLEAR_xxZflag(REG_WORK1, REG_WORK1);
	TBNZ_wii(d, s & 0x1f, 2);
	SET_xxZflag(REG_WORK1, REG_WORK1);
	MSR_NZCV_x(REG_WORK1);
	SET_xxbit(d, d, s & 0x1f);

	unlock2(d);
}
MENDFUNC(2,jff_BSET_l_imm,(RW4 d, IM8 s))

MIDFUNC(2,jff_BSET_b,(RW1 d, RR4 s))
{
	if (isconst(s)) {
		COMPCALL(jff_BSET_b_imm)(d, live.state[s].val);
		return;
	}

	s = readreg(s);
	d = rmw(d);

	UBFIZ_xxii(REG_WORK1, s, 0, 3); // REG_WORK1 = s & 7
	MOV_xi(REG_WORK2, 1);
	LSL_www(REG_WORK2, REG_WORK2, REG_WORK1);

	MRS_NZCV_x(REG_WORK1);
	TST_ww(d,REG_WORK2);
	CSET_xc(REG_WORK3, NATIVE_CC_EQ);
	BFI_xxii(REG_WORK1, REG_WORK3, 30, 1);
	MSR_NZCV_x(REG_WORK1);
	ORR_www(d, d, REG_WORK2);

	unlock2(d);
	unlock2(s);
}
MENDFUNC(2,jff_BSET_b,(RW1 d, RR4 s))

MIDFUNC(2,jff_BSET_l,(RW4 d, RR4 s))
{
	if (isconst(s)) {
		COMPCALL(jff_BSET_l_imm)(d, live.state[s].val);
		return;
	}

	INIT_REGS_l(d,s);

	UBFIZ_xxii(REG_WORK1, s, 0, 5); // REG_WORK1 = s & 31
	MOV_xi(REG_WORK2, 1);
	LSL_www(REG_WORK2, REG_WORK2, REG_WORK1);

	MRS_NZCV_x(REG_WORK1);
	TST_ww(d,REG_WORK2);
	CSET_xc(REG_WORK3, NATIVE_CC_EQ);
	BFI_xxii(REG_WORK1, REG_WORK3, 30, 1);
	MSR_NZCV_x(REG_WORK1);
	ORR_www(d, d, REG_WORK2);

	EXIT_REGS(d,s);
}
MENDFUNC(2,jff_BSET_l,(RW4 d, RR4 s))

/*
 * BTST
 * Operand Syntax: 	Dn,<ea>
 *					#<data>,<ea>
 *
 *  Operand Size: 8,32
 *
 * X Not affected
 * N Not affected
 * Z Set if the bit tested is zero. Cleared otherwise
 * V Not affected
 * C Not affected
 *
 */
/* BTST.B: target is never a register */
/* BTST.L: target is always a register */
MIDFUNC(2,jff_BTST_b_imm,(RR1 d, IM8 s))
{
	d = readreg(d);

	MRS_NZCV_x(REG_WORK1);
	CLEAR_xxZflag(REG_WORK1, REG_WORK1);
	TBNZ_wii(d, s & 0x7, 2); // skip next if bit is set
	SET_xxZflag(REG_WORK1, REG_WORK1);
	MSR_NZCV_x(REG_WORK1);

	unlock2(d);
}
MENDFUNC(2,jff_BTST_b_imm,(RR1 d, IM8 s))

MIDFUNC(2,jff_BTST_l_imm,(RR4 d, IM8 s))
{
	d = readreg(d);

	MRS_NZCV_x(REG_WORK1);
	CLEAR_xxZflag(REG_WORK1, REG_WORK1);
	TBNZ_wii(d, s & 0x1f, 2); // skip next if bit is set
	SET_xxZflag(REG_WORK1, REG_WORK1);
	MSR_NZCV_x(REG_WORK1);

	unlock2(d);
}
MENDFUNC(2,jff_BTST_l_imm,(RR4 d, IM8 s))

MIDFUNC(2,jff_BTST_b,(RR1 d, RR4 s))
{
	if (isconst(s)) {
		COMPCALL(jff_BTST_b_imm)(d, live.state[s].val);
		return;
	}

	s = readreg(s);
	d = readreg(d);

	UBFIZ_xxii(REG_WORK1, s, 0, 3); // REG_WORK1 = s & 7
	MOV_xi(REG_WORK2, 1);
	LSL_www(REG_WORK2, REG_WORK2, REG_WORK1);

	MRS_NZCV_x(REG_WORK1);
	TST_ww(d, REG_WORK2);
	CSET_xc(REG_WORK3, NATIVE_CC_EQ);
	BFI_xxii(REG_WORK1, REG_WORK3, 30, 1);
	MSR_NZCV_x(REG_WORK1);

	unlock2(d);
	unlock2(s);
}
MENDFUNC(2,jff_BTST_b,(RR1 d, RR4 s))

MIDFUNC(2,jff_BTST_l,(RR4 d, RR4 s))
{
	if (isconst(s)) {
		COMPCALL(jff_BTST_l_imm)(d, live.state[s].val);
		return;
	}

	int s_is_d = (s == d);
	d = readreg(d);
	if(!s_is_d)
		s = readreg(s);
	else
		s = d;

	UBFIZ_xxii(REG_WORK1, s, 0, 5); // REG_WORK1 = s & 31
	MOV_xi(REG_WORK2, 1);
	LSL_www(REG_WORK2, REG_WORK2, REG_WORK1);

	MRS_NZCV_x(REG_WORK1);
	TST_ww(d, REG_WORK2);
	CSET_xc(REG_WORK3, NATIVE_CC_EQ);
	BFI_xxii(REG_WORK1, REG_WORK3, 30, 1);
	MSR_NZCV_x(REG_WORK1);

	unlock2(d);
	if(!s_is_d)
		unlock2(s);
}
MENDFUNC(2,jff_BTST_l,(RR4 d, RR4 s))

/*
 * CLR
 * Operand Syntax: <ea>
 *
 * Operand Size: 8,16,32
 *
 * X Not affected.
 * N Always cleared.
 * Z Always set.
 * V Always cleared.
 * C Always cleared.
 *
 */
MIDFUNC(1,jnf_CLR_b,(W1 d))
{
	if(d >= 16) {
		set_const(d, 0);
		return;
	}
	INIT_WREG_b(d);
	CLEAR_LOW8_xx(d, d);
	// Fix 19: CLEAR_LOW8_xx uses 64-bit AND, preserving dirty upper 32 bits.
	MOV_ww(d, d);
	unlock2(d);
}
MENDFUNC(1,jnf_CLR_b,(W1 d))

MIDFUNC(1,jnf_CLR_w,(W2 d))
{
	if(d >= 16) {
		set_const(d, 0);
		return;
	}
	INIT_WREG_w(d);
	CLEAR_LOW16_xx(d, d);
	// Fix 19: CLEAR_LOW16_xx uses 64-bit AND, preserving dirty upper 32 bits.
	MOV_ww(d, d);
	unlock2(d);
}
MENDFUNC(1,jnf_CLR_w,(W2 d))

MIDFUNC(1,jnf_CLR_l,(W4 d))
{
	set_const(d, 0);
}
MENDFUNC(1,jnf_CLR_l,(W4 d))

MIDFUNC(1,jff_CLR_b,(W1 d))
{
	MOV_xish(REG_WORK1, 0x4000, 16); // set Z flag
	MSR_NZCV_x(REG_WORK1);
	flags_carry_inverted = false;
	if(d >= 16) {
		set_const(d, 0);
		return;
	}
	INIT_WREG_b(d);
	CLEAR_LOW8_xx(d, d);
	// Fix 19: CLEAR_LOW8_xx uses 64-bit AND, preserving dirty upper 32 bits.
	MOV_ww(d, d);
	unlock2(d);
}
MENDFUNC(1,jff_CLR_b,(W1 d))

MIDFUNC(1,jff_CLR_w,(W2 d))
{
	MOV_xish(REG_WORK1, 0x4000, 16); // set Z flag
	MSR_NZCV_x(REG_WORK1);
	flags_carry_inverted = false;
	if(d >= 16) {
		set_const(d, 0);
		return;
	}
	INIT_WREG_w(d);
	CLEAR_LOW16_xx(d, d);
	// Fix 19: CLEAR_LOW16_xx uses 64-bit AND, preserving dirty upper 32 bits.
	MOV_ww(d, d);
	unlock2(d);
}
MENDFUNC(1,jff_CLR_w,(W2 d))

MIDFUNC(1,jff_CLR_l,(W4 d))
{
	MOV_xish(REG_WORK1, 0x4000, 16); // set Z flag
	MSR_NZCV_x(REG_WORK1);
	flags_carry_inverted = false;
	set_const(d, 0);
}
MENDFUNC(1,jff_CLR_l,(W4 d))

/*
 * CMP
 * Operand Syntax: <ea>, Dn
 *
 * Operand Size: 8,16,32
 *
 * X Not affected.
 * N Set if the result is negative. Cleared otherwise.
 * Z Set if the result is zero. Cleared otherwise.
 * V Set if an overflow occurs. Cleared otherwise.
 * C Set if a borrow occurs. Cleared otherwise.
 *
 */
MIDFUNC(2,jff_CMP_b_imm,(RR1 d, IM8 v))
{
	if (isconst(d)) {
		uae_u8 tmp = (uae_u8)(live.state[d].val & 0xff);
		MOV_wish(REG_WORK1, tmp << 8, 16);
	} else {
		d = readreg(d);
		LSL_wwi(REG_WORK1, d, 24);
		unlock2(d);
	}

	MOV_wi(REG_WORK2, v & 0xff);
	CMP_wwLSLi(REG_WORK1, REG_WORK2, 24);

	MRS_NZCV_x(REG_WORK3);
	EOR_xxCflag(REG_WORK3, REG_WORK3);
	MSR_NZCV_x(REG_WORK3);
	flags_carry_inverted = false;
}
MENDFUNC(2,jff_CMP_b_imm,(RR1 d, IM8 v))

MIDFUNC(2,jff_CMP_b,(RR1 d, RR1 s))
{
	if (isconst(s)) {
		COMPCALL(jff_CMP_b_imm)(d, live.state[s].val);
		return;
	}

	if (isconst(d)) {
		uae_u8 tmp = (uae_u8)(live.state[d].val & 0xff);
		s = readreg(s);
		MOV_wish(REG_WORK1, tmp << 8, 16);
		CMP_wwLSLi(REG_WORK1, s, 24);
		unlock2(s);
	} else {
		INIT_RREGS_b(d, s);

		LSL_wwi(REG_WORK1, d, 24);
		CMP_wwLSLi(REG_WORK1, s, 24);

		EXIT_REGS(d,s);
	}
	MRS_NZCV_x(REG_WORK3);
	EOR_xxCflag(REG_WORK3, REG_WORK3);
	MSR_NZCV_x(REG_WORK3);
	flags_carry_inverted = false;
}
MENDFUNC(2,jff_CMP_b,(RR1 d, RR1 s))

MIDFUNC(2,jff_CMP_w_imm,(RR2 d, IM16 v))
{
	if (isconst(d)) {
		MOV_wish(REG_WORK1, (live.state[d].val & 0xffff), 16);
		MOV_wish(REG_WORK2, (v & 0xffff), 16);
		CMP_ww(REG_WORK1, REG_WORK2);
	} else {
		d = readreg(d);

		LSL_wwi(REG_WORK1, d, 16);
		MOV_xi(REG_WORK2, v);
		CMP_wwLSLi(REG_WORK1, REG_WORK2, 16);

		unlock2(d);
	}
	MRS_NZCV_x(REG_WORK3);
	EOR_xxCflag(REG_WORK3, REG_WORK3);
	MSR_NZCV_x(REG_WORK3);
	flags_carry_inverted = false;
}
MENDFUNC(2,jff_CMP_w_imm,(RR2 d, IM16 v))

MIDFUNC(2,jff_CMP_w,(RR2 d, RR2 s))
{
	if (isconst(s)) {
		COMPCALL(jff_CMP_w_imm)(d, live.state[s].val);
		return;
	}

	if (isconst(d)) {
		uae_u16 tmp = (uae_u16)(live.state[d].val & 0xffff);
		s = readreg(s);
		MOV_wish(REG_WORK1, tmp, 16);
		CMP_wwLSLi(REG_WORK1, s, 16);
		unlock2(s);
	} else {
		INIT_RREGS_w(d, s);

		LSL_wwi(REG_WORK1, d, 16);
		CMP_wwLSLi(REG_WORK1, s, 16);

		EXIT_REGS(d,s);
	}
	MRS_NZCV_x(REG_WORK3);
	EOR_xxCflag(REG_WORK3, REG_WORK3);
	MSR_NZCV_x(REG_WORK3);
	flags_carry_inverted = false;
}
MENDFUNC(2,jff_CMP_w,(RR2 d, RR2 s))

MIDFUNC(2,jff_CMP_l_imm,(RR4 d, IM32 v))
{
	if(isconst(d)) {
		uae_u32 newv = ((uae_u32)live.state[d].val) - ((uae_u32)v);
		int flgs = ((uae_s32)v) < 0;
		int flgo = ((uae_s32)live.state[d].val) < 0;
		int flgn = ((uae_s32)newv) < 0;
		uae_u32 f = 0;
		if(((uae_s32)newv) == 0)
			f |= (ARM_Z_FLAG >> 16);
		if((flgs != flgo) && (flgn != flgo))
			f |= (ARM_V_FLAG >> 16);
		if(((uae_u32)v) > ((uae_u32)live.state[d].val))
			f |= (ARM_C_FLAG >> 16);
		if(flgn != 0)
			f |= (ARM_N_FLAG >> 16);
		MOV_xish(REG_WORK1, f, 16);
		MSR_NZCV_x(REG_WORK1);

		flags_carry_inverted = false;
		return;
	}

	d = readreg(d);

	LOAD_U32(REG_WORK1, v);
	CMP_ww(d, REG_WORK1);

	MRS_NZCV_x(REG_WORK3);
	EOR_xxCflag(REG_WORK3, REG_WORK3);
	MSR_NZCV_x(REG_WORK3);
	flags_carry_inverted = false;
	unlock2(d);
}
MENDFUNC(2,jff_CMP_l_imm,(RR4 d, IM32 v))

MIDFUNC(2,jff_CMP_l,(RR4 d, RR4 s))
{
	if (isconst(s)) {
		COMPCALL(jff_CMP_l_imm)(d, live.state[s].val);
		return;
	}

	INIT_RREGS_l(d, s);

	CMP_ww(d, s);

	MRS_NZCV_x(REG_WORK3);
	EOR_xxCflag(REG_WORK3, REG_WORK3);
	MSR_NZCV_x(REG_WORK3);
	flags_carry_inverted = false;
	EXIT_REGS(d,s);
}
MENDFUNC(2,jff_CMP_l,(RR4 d, RR4 s))

/*
 * CMPA
 * Operand Syntax: 	<ea>, An
 *
 * Operand Size: 16,32
 *
 * X Not affected.
 * N Set if the result is negative. Cleared otherwise.
 * Z Set if the result is zero. Cleared otherwise.
 * V Set if an overflow occurs. Cleared otherwise.
 * C Set if a borrow occurs. Cleared otherwise.
 *
 */
MIDFUNC(2,jff_CMPA_w_imm,(RR2 d, IM16 v))
{
	uae_u16 tmp = (uae_u16)(v & 0xffff);
	d = readreg(d);
	SIGNED16_IMM_2_REG(REG_WORK1, tmp);
	CMP_ww(d, REG_WORK1);
	unlock2(d);

	MRS_NZCV_x(REG_WORK3);
	EOR_xxCflag(REG_WORK3, REG_WORK3);
	MSR_NZCV_x(REG_WORK3);
	flags_carry_inverted = false;
}
MENDFUNC(2,jff_CMPA_w_imm,(RR2 d, IM16 v))

MIDFUNC(2,jff_CMPA_w,(RR2 d, RR2 s))
{
	if (isconst(s)) {
		COMPCALL(jff_CMPA_w_imm)(d, live.state[s].val);
		return;
	}

	INIT_RREGS_w(d, s);
	CMP_wwEX(d, s, EX_SXTH);
	EXIT_REGS(d,s);

	MRS_NZCV_x(REG_WORK3);
	EOR_xxCflag(REG_WORK3, REG_WORK3);
	MSR_NZCV_x(REG_WORK3);
	flags_carry_inverted = false;
}
MENDFUNC(2,jff_CMPA_w,(RR2 d, RR2 s))

MIDFUNC(2,jff_CMPA_l_imm,(RR4 d, IM32 v))
{
	d = readreg(d);

	LOAD_U32(REG_WORK1, v);
	CMP_ww(d, REG_WORK1);

	MRS_NZCV_x(REG_WORK3);
	EOR_xxCflag(REG_WORK3, REG_WORK3);
	MSR_NZCV_x(REG_WORK3);
	flags_carry_inverted = false;
	unlock2(d);
}
MENDFUNC(2,jff_CMPA_l_imm,(RR4 d, IM32 v))

MIDFUNC(2,jff_CMPA_l,(RR4 d, RR4 s))
{
	if (isconst(s)) {
		COMPCALL(jff_CMPA_l_imm)(d, live.state[s].val);
		return;
	}

	INIT_RREGS_l(d, s);

	CMP_ww(d, s);

	MRS_NZCV_x(REG_WORK3);
	EOR_xxCflag(REG_WORK3, REG_WORK3);
	MSR_NZCV_x(REG_WORK3);
	flags_carry_inverted = false;
	EXIT_REGS(d,s);
}
MENDFUNC(2,jff_CMPA_l,(RR4 d, RR4 s))

/*
 * DBCC
 *
 */
MIDFUNC(2,jff_DBCC,(RW4 d, IM8 cc))
{
	d = rmw(d);

	FIX_INVERTED_CARRY

	// If cc true -> no branch, so we have to clear ARM_C_FLAG
	MOV_xish(REG_WORK1, 0x2000, 16); // set C flag
	MOV_xi(REG_WORK2, 0);
	switch(cc) {
		case 9: // LS
			CSEL_xxxc(REG_WORK1, REG_WORK2, REG_WORK1, NATIVE_CC_EQ);
			CSEL_xxxc(REG_WORK1, REG_WORK2, REG_WORK1, NATIVE_CC_CS);
			break;

		case 8: // HI
			MOV_xish(REG_WORK3, 0x2000, 16);
			CSEL_xxxc(REG_WORK1, REG_WORK2, REG_WORK1, NATIVE_CC_CC);
			CSEL_xxxc(REG_WORK1, REG_WORK3, REG_WORK1, NATIVE_CC_EQ);
			break;

		default:
			CSEL_xxxc(REG_WORK1, REG_WORK2, REG_WORK1, cc);
			break;
	}
	clobber_flags();
	MSR_NZCV_x(REG_WORK1);

	BCC_i(4); // If cc true -> no sub

	// sub (d, 1)
	LSL_wwi(REG_WORK2, d, 16);
	SUBS_wwish(REG_WORK2, REG_WORK2, 0x10, 1);
	BFXIL_xxii(d, REG_WORK2, 16, 16);

	// caller can now use register_branch(v1, v2, NATIVE_CC_CS);

	unlock2(d);
}
MENDFUNC(2,jff_DBCC,(RW4 d, IM8 cc))

/* Conditional arithmetic exceptions share one request lifecycle: publish the
 * exact opcode PC, clear any stale helper parameter/request, and tag the
 * eventual vector so the common format-2 boundary consumes that PC. */
STATIC_INLINE void prepare_arithmetic_exception(uintptr exception_idx)
{
	register_possible_exception_at_successor();
	MOV_wi(REG_WORK1, 0);
	STR_wXi(REG_WORK1, R_REGSTRUCT, exception_idx);
}

STATIC_INLINE void emit_arithmetic_exception(uae_u32 vector, uintptr exception_idx)
{
	MOV_wi(REG_WORK1, vector);
	SET_xxbit(REG_WORK1, REG_WORK1, 29); /* JIT_EXCEPTION_OLDPC_VALID */
	STR_wXi(REG_WORK1, R_REGSTRUCT, exception_idx);
}

/*
 * DIVU
 *
 * X Not affected.
 * N Set if the most significant bit of the result is set or overflow. Cleared otherwise.
 * Z Set if the result is zero. Cleared otherwise.
 * V Set if overflow. Cleared otherwise.
 * C Always cleared.
 *
 */
MIDFUNC(2,jnf_DIVU,(RW4 d, RR4 s))
{
	int init_regs_used = 0;
	int targetIsReg;
	int s_is_d;
	const uintptr exception_idx = (uintptr)(&regs.jit_exception) - (uintptr)(&regs);
	prepare_arithmetic_exception(exception_idx);
	if (isconst(s) && (uae_u16)live.state[s].val != 0) {
		uae_u16 tmp = (uae_u16)live.state[s].val;
		d = rmw(d);
		UNSIGNED16_IMM_2_REG(REG_WORK3, tmp);
	} else {
		targetIsReg = (d < 16);
		s_is_d = (s == d);
		if(!s_is_d)
			s = readreg(s);
		d = rmw(d);
		if(s_is_d)
			s = d;
		init_regs_used = 1;

		UNSIGNED16_REG_2_REG(REG_WORK3, s);
		CBNZ_wi(REG_WORK3, 5);    // src is not 0

		emit_arithmetic_exception(5, exception_idx);
		B_i(7);        // end_of_op
	}

	// src is not 0
	UDIV_www(REG_WORK1, d, REG_WORK3);

	LSR_wwi(REG_WORK2, REG_WORK1, 16); 							// if result of this is not 0, DIVU overflows -> no result
	CBNZ_wi(REG_WORK2, 4);

	// Here we have to calc remainder
	MSUB_wwww(REG_WORK2, REG_WORK1, REG_WORK3, d);
	LSL_wwi(d, REG_WORK2, 16);
	BFI_wwii(d, REG_WORK1, 0, 16);
	// end_of_op

	if (init_regs_used) {
		EXIT_REGS(d, s);
	} else {
		unlock2(d);
	}
}
MENDFUNC(2,jnf_DIVU,(RW4 d, R4 s))

MIDFUNC(2,jff_DIVU,(RW4 d, RR4 s))
{
	uae_u32* branchadd = NULL;
	uae_u32* branch_success;
	uae_u32* branch_overflow_end;
	int init_regs_used = 0;
	int targetIsReg;
	int s_is_d;
	const uintptr exception_idx = (uintptr)(&regs.jit_exception) - (uintptr)(&regs);
	prepare_arithmetic_exception(exception_idx);
	if (isconst(s) && (uae_u16)live.state[s].val != 0) {
		uae_u16 tmp = (uae_u16)live.state[s].val;
		d = rmw(d);
		UNSIGNED16_IMM_2_REG(REG_WORK3, tmp);
	} else {
		targetIsReg = (d < 16);
		s_is_d = (s == d);
		if(!s_is_d)
			s = readreg(s);
		d = rmw(d);
		if(s_is_d)
			s = d;
		init_regs_used = 1;

		UNSIGNED16_REG_2_REG(REG_WORK3, s);
		uae_u32* branchadd_not0 = (uae_u32*)get_target();
		CBNZ_wi(REG_WORK3, 0);     // src is not 0

		emit_arithmetic_exception(5, exception_idx);

		/* Match the interpreter contract exactly: word divide by zero clears
		 * only V. X/N/Z/C and the dividend remain unchanged in the frame. */
		MRS_NZCV_x(REG_WORK1);
		CLEAR_xxVflag(REG_WORK1, REG_WORK1);
		MSR_NZCV_x(REG_WORK1);
		branchadd = (uae_u32*)get_target();
		B_i(0);        // end_of_op
		write_jmp_target(branchadd_not0, (uintptr)get_target());
	}

	// src is not 0
	UDIV_www(REG_WORK1, d, REG_WORK3);

	LSR_wwi(REG_WORK2, REG_WORK1, 16); 							// if result of this is not 0, DIVU overflows
	branch_success = (uae_u32*)get_target();
	CBZ_wi(REG_WORK2, 0);
	// Overflow sets N/V, clears C, and preserves the previous Z value.
	MRS_NZCV_x(REG_WORK1);
	SET_xxbit(REG_WORK1, REG_WORK1, 31);
	SET_xxVflag(REG_WORK1, REG_WORK1);
	CLEAR_xxCflag(REG_WORK1, REG_WORK1);
	MSR_NZCV_x(REG_WORK1);
	branch_overflow_end = (uae_u32*)get_target();
	B_i(0);

	// Here we have to calc flags and remainder
	write_jmp_target(branch_success, (uintptr)get_target());
	LSL_wwi(REG_WORK2, REG_WORK1, 16);
	TST_ww(REG_WORK2, REG_WORK2);    // N and Z ok, C and V cleared

	MSUB_wwww(REG_WORK2, REG_WORK1, REG_WORK3, d);
	LSL_wwi(d, REG_WORK2, 16);
	BFI_wwii(d, REG_WORK1, 0, 16);

	// end_of_op
	write_jmp_target(branch_overflow_end, (uintptr)get_target());
	flags_carry_inverted = false;
	if (init_regs_used) {
		write_jmp_target(branchadd, (uintptr)get_target());
		EXIT_REGS(d, s);
	} else {
		unlock2(d);
	}
}
MENDFUNC(2,jff_DIVU,(RW4 d, RR4 s))

/*
 * DIVS
 *
 * X Not affected.
 * N Set if the most significant bit of the result is set or overflow. Cleared otherwise.
 * Z Set if the result is zero. Cleared otherwise.
 * V Set if overflow. Cleared otherwise.
 * C Always cleared.
 *
 */
MIDFUNC(2,jnf_DIVS,(RW4 d, RR4 s))
{
	uae_u32* branchadd;
	int init_regs_used = 0;
	int targetIsReg;
	int s_is_d;
	uae_s16 tmp;
	const uintptr exception_idx = (uintptr)(&regs.jit_exception) - (uintptr)(&regs);
	prepare_arithmetic_exception(exception_idx);
	if (isconst(s) && (uae_s16)live.state[s].val != 0) {
		tmp = (uae_s16)live.state[s].val;
		d = rmw(d);
		SIGNED16_IMM_2_REG(REG_WORK3, tmp);
	} else {
		targetIsReg = (d < 16);
		s_is_d = (s == d);
		if(!s_is_d)
			s = readreg(s);
		d = rmw(d);
		if(s_is_d)
			s = d;
		init_regs_used = 1;

		SIGNED16_REG_2_REG(REG_WORK3, s);
		CBNZ_wi(REG_WORK3, 5);     // src is not 0

		emit_arithmetic_exception(5, exception_idx);
		branchadd = (uae_u32*)get_target();
		B_i(0);        // end_of_op
	}

	// src is not 0
	SDIV_www(REG_WORK1, d, REG_WORK3);

	// check for overflow
	MOVN_wi(REG_WORK2, 0x7fff);           // REG_WORK2 is now 0xffff8000
	ANDS_www(REG_WORK3, REG_WORK1, REG_WORK2);
	BEQ_i(3); 														// positive result, no overflow
	CMP_ww(REG_WORK3, REG_WORK2);
	BNE_i(8);															// overflow -> end_of_op

	// Here we have to calc remainder
	if (init_regs_used)
		SIGNED16_REG_2_REG(REG_WORK3, s);
	else
		SIGNED16_IMM_2_REG(REG_WORK3, tmp);
	MSUB_wwww(REG_WORK2, REG_WORK1, REG_WORK3, d);		// REG_WORK2 contains remainder

	EOR_www(REG_WORK3, REG_WORK2, d);	  // If sign of remainder and first operand differs, change sign of remainder
	TBZ_wii(REG_WORK3, 31, 2);
	NEG_ww(REG_WORK2, REG_WORK2);

	LSL_wwi(d, REG_WORK2, 16);
	BFI_wwii(d, REG_WORK1, 0, 16);

	// end_of_op
	if (init_regs_used) {
		write_jmp_target(branchadd, (uintptr)get_target());
		EXIT_REGS(d, s);
	} else {
		unlock2(d);
	}
}
MENDFUNC(2,jnf_DIVS,(RW4 d, RR4 s))

MIDFUNC(2,jff_DIVS,(RW4 d, RR4 s))
{
	uae_u32* branchadd = NULL;
	uae_u32* branch_positive_fit;
	uae_u32* branch_negative_fit;
	uae_u32* branch_overflow_end;
	int init_regs_used = 0;
	int targetIsReg;
	int s_is_d;
	uae_s16 tmp;
	const uintptr exception_idx = (uintptr)(&regs.jit_exception) - (uintptr)(&regs);
	prepare_arithmetic_exception(exception_idx);
	/* Signed overflow detection uses ANDS/CMP; preserve incoming Z first. */
	MRS_NZCV_x(REG_WORK4);
	if (isconst(s) && (uae_s16)live.state[s].val != 0) {
		tmp = (uae_s16)live.state[s].val;
		d = rmw(d);
		SIGNED16_IMM_2_REG(REG_WORK3, tmp);
	} else {
		targetIsReg = (d < 16);
		s_is_d = (s == d);
		if(!s_is_d)
			s = readreg(s);
		d = rmw(d);
		if(s_is_d)
			s = d;
		init_regs_used = 1;

		SIGNED16_REG_2_REG(REG_WORK3, s);
		uae_u32* branchadd_not0 = (uae_u32*)get_target();
		CBNZ_wi(REG_WORK3, 0);     // src is not 0

		emit_arithmetic_exception(5, exception_idx);

		/* As for DIVU.W, the generated interpreter clears V only. */
		MRS_NZCV_x(REG_WORK1);
		CLEAR_xxVflag(REG_WORK1, REG_WORK1);
		MSR_NZCV_x(REG_WORK1);
		branchadd = (uae_u32*)get_target();
		B_i(0);        // end_of_op
		write_jmp_target(branchadd_not0, (uintptr)get_target());
	}

	// src is not 0
	SDIV_www(REG_WORK1, d, REG_WORK3);

	// check for overflow
	MOVN_wi(REG_WORK2, 0x7fff);           // REG_WORK2 is now 0xffff8000
	ANDS_www(REG_WORK3, REG_WORK1, REG_WORK2);
	branch_positive_fit = (uae_u32*)get_target();
	BEQ_i(0); 														// positive result, no overflow
	CMP_ww(REG_WORK3, REG_WORK2);
	branch_negative_fit = (uae_u32*)get_target();
	/* REG_WORK4 still carries the pre-division NZCV snapshot. */
	BEQ_i(0);															// no overflow

	// Overflow sets N/V, clears C, and preserves the previous Z value.
	MOV_xx(REG_WORK1, REG_WORK4);
	SET_xxbit(REG_WORK1, REG_WORK1, 31);
	SET_xxVflag(REG_WORK1, REG_WORK1);
	CLEAR_xxCflag(REG_WORK1, REG_WORK1);
	MSR_NZCV_x(REG_WORK1);
	branch_overflow_end = (uae_u32*)get_target();
	B_i(0);

	// calc flags
	write_jmp_target(branch_positive_fit, (uintptr)get_target());
	write_jmp_target(branch_negative_fit, (uintptr)get_target());
	LSL_wwi(REG_WORK2, REG_WORK1, 16);
	TST_ww(REG_WORK2, REG_WORK2);         // N and Z ok, C and V cleared

	// calc remainder
	if (init_regs_used)
		SIGNED16_REG_2_REG(REG_WORK3, s);
	else
		SIGNED16_IMM_2_REG(REG_WORK3, tmp);
	MSUB_wwww(REG_WORK2, REG_WORK1, REG_WORK3, d);		// REG_WORK2 contains remainder

	EOR_www(REG_WORK3, REG_WORK2, d);	  // If sign of remainder and first operand differs, change sign of remainder
	TBZ_wii(REG_WORK3, 31, 2);
	NEG_ww(REG_WORK2, REG_WORK2);

	LSL_wwi(d, REG_WORK2, 16);
	BFI_wwii(d, REG_WORK1, 0, 16);

	// end_of_op
	write_jmp_target(branch_overflow_end, (uintptr)get_target());
	flags_carry_inverted = false;
	if (init_regs_used) {
		write_jmp_target(branchadd, (uintptr)get_target());
		EXIT_REGS(d, s);
	} else {
		unlock2(d);
	}
}
MENDFUNC(2,jff_DIVS,(RW4 d, RR4 s))

MIDFUNC(3,jnf_DIVLU32,(RW4 d, RR4 s1, W4 rem))
{
	uae_u32 *branch_nonzero;
	uae_u32 *branch_zero_end;
	const uintptr exception_idx = (uintptr)(&regs.jit_exception) - (uintptr)(&regs);
	prepare_arithmetic_exception(exception_idx);
	s1 = readreg(s1);
	d = rmw(d);
	/* Divide-by-zero must leave both architectural destinations unchanged. */
	rem = rmw(rem);

	branch_nonzero = (uae_u32 *)get_target();
	CBNZ_wi(s1, 0);
	emit_arithmetic_exception(5, exception_idx);
	branch_zero_end = (uae_u32 *)get_target();
	B_i(0);
	write_jmp_target(branch_nonzero, (uintptr)get_target());

	UDIV_www(REG_WORK1, d, s1);
	MSUB_wwww(rem, s1, REG_WORK1, d);
	/* The quotient is architecturally last when rem aliases d. */
	MOV_ww(d, REG_WORK1);

	write_jmp_target(branch_zero_end, (uintptr)get_target());
	unlock2(rem);
	unlock2(d);
	unlock2(s1);
}
MENDFUNC(3,jnf_DIVLU32,(RW4 d, RR4 s1, W4 rem))

MIDFUNC(3,jff_DIVLU32,(RW4 d, RR4 s1, W4 rem))
{
	uae_u32 *branch_nonzero;
	uae_u32 *branch_zero_end;
	const uintptr exception_idx = (uintptr)(&regs.jit_exception) - (uintptr)(&regs);
	prepare_arithmetic_exception(exception_idx);
	s1 = readreg(s1);
	d = rmw(d);
	rem = rmw(rem);

	branch_nonzero = (uae_u32 *)get_target();
	CBNZ_wi(s1, 0);
	emit_arithmetic_exception(5, exception_idx);
	branch_zero_end = (uae_u32 *)get_target();
	B_i(0);
	write_jmp_target(branch_nonzero, (uintptr)get_target());

	UDIV_www(REG_WORK1, d, s1);
	MSUB_wwww(rem, s1, REG_WORK1, d);
	MOV_ww(d, REG_WORK1);
	TST_ww(REG_WORK1, REG_WORK1);

	write_jmp_target(branch_zero_end, (uintptr)get_target());
	flags_carry_inverted = false;
	unlock2(rem);
	unlock2(d);
	unlock2(s1);
}
MENDFUNC(3,jff_DIVLU32,(RW4 d, RR4 s1, W4 rem))

MIDFUNC(3,jnf_DIVLS32,(RW4 d, RR4 s1, W4 rem))
{
	uae_u32 *branch_nonzero;
	uae_u32 *branch_success;
	uae_u32 *branch_zero_end;
	uae_u32 *branch_overflow_end;
	const uintptr exception_idx = (uintptr)(&regs.jit_exception) - (uintptr)(&regs);
	prepare_arithmetic_exception(exception_idx);
	s1 = readreg(s1);
	d = rmw(d);
	rem = rmw(rem);

	branch_nonzero = (uae_u32 *)get_target();
	CBNZ_wi(s1, 0);
	emit_arithmetic_exception(5, exception_idx);
	branch_zero_end = (uae_u32 *)get_target();
	B_i(0);
	write_jmp_target(branch_nonzero, (uintptr)get_target());

	/* Divide in 64-bit signed space so INT32_MIN / -1 remains +0x80000000
	 * and can be rejected instead of inheriting AArch64 SDIV.W saturation. */
	SXTW_xw(REG_WORK3, d);
	SXTW_xw(REG_WORK4, s1);
	SDIV_xxx(REG_WORK1, REG_WORK3, REG_WORK4);
	SXTW_xw(REG_WORK2, REG_WORK1);
	CMP_xx(REG_WORK2, REG_WORK1);
	branch_success = (uae_u32 *)get_target();
	BEQ_i(0);
	branch_overflow_end = (uae_u32 *)get_target();
	B_i(0);

	write_jmp_target(branch_success, (uintptr)get_target());
	MSUB_xxxx(REG_WORK2, REG_WORK4, REG_WORK1, REG_WORK3);
	MOV_ww(rem, REG_WORK2);
	/* m68k_divl stores remainder first and quotient second. */
	MOV_ww(d, REG_WORK1);

	write_jmp_target(branch_zero_end, (uintptr)get_target());
	write_jmp_target(branch_overflow_end, (uintptr)get_target());
	unlock2(rem);
	unlock2(d);
	unlock2(s1);
}
MENDFUNC(3,jnf_DIVLS32,(RW4 d, RR4 s1, W4 rem))

MIDFUNC(3,jff_DIVLS32,(RW4 d, RR4 s1, W4 rem))
{
	uae_u32 *branch_nonzero;
	uae_u32 *branch_success;
	uae_u32 *branch_zero_end;
	uae_u32 *branch_overflow_end;
	int saved_flags;
	const uintptr exception_idx = (uintptr)(&regs.jit_exception) - (uintptr)(&regs);
	prepare_arithmetic_exception(exception_idx);
	s1 = readreg(s1);
	d = rmw(d);
	rem = rmw(rem);
	/* gencomp preserved the incoming CCR in FLAGTMP before DIVL. Keep that
	 * value available after the signed fit comparison clobbers host NZCV. */
	saved_flags = readreg(FLAGTMP);

	branch_nonzero = (uae_u32 *)get_target();
	CBNZ_wi(s1, 0);
	emit_arithmetic_exception(5, exception_idx);
	branch_zero_end = (uae_u32 *)get_target();
	B_i(0);
	write_jmp_target(branch_nonzero, (uintptr)get_target());

	SXTW_xw(REG_WORK3, d);
	SXTW_xw(REG_WORK4, s1);
	SDIV_xxx(REG_WORK1, REG_WORK3, REG_WORK4);
	SXTW_xw(REG_WORK2, REG_WORK1);
	CMP_xx(REG_WORK2, REG_WORK1);
	branch_success = (uae_u32 *)get_target();
	BEQ_i(0);

	/* Signed overflow leaves both destinations unchanged, sets N/V, clears C,
	 * and preserves the incoming Z and X values. */
	MOV_ww(REG_WORK2, saved_flags);
	SET_xxbit(REG_WORK2, REG_WORK2, 31);
	SET_xxVflag(REG_WORK2, REG_WORK2);
	CLEAR_xxCflag(REG_WORK2, REG_WORK2);
	MSR_NZCV_x(REG_WORK2);
	branch_overflow_end = (uae_u32 *)get_target();
	B_i(0);

	write_jmp_target(branch_success, (uintptr)get_target());
	MSUB_xxxx(REG_WORK2, REG_WORK4, REG_WORK1, REG_WORK3);
	MOV_ww(rem, REG_WORK2);
	MOV_ww(d, REG_WORK1);
	TST_ww(d, d);

	write_jmp_target(branch_zero_end, (uintptr)get_target());
	write_jmp_target(branch_overflow_end, (uintptr)get_target());
	flags_carry_inverted = false;
	unlock2(saved_flags);
	unlock2(rem);
	unlock2(d);
	unlock2(s1);
}
MENDFUNC(3,jff_DIVLS32,(RW4 d, RR4 s1, W4 rem))

/*
 * DIVLU64 — 64-bit unsigned divide
 * {dr:dq} / src → quotient in dq, remainder in dr
 * Overflow if quotient > 0xFFFFFFFF → sets V=1 and does not modify dq/dr
 */
MIDFUNC(3,jnf_DIVLU64,(RW4 dq, RW4 dr, RR4 src))
{
	uae_u32 *branch_nonzero;
	uae_u32 *branch_success;
	uae_u32 *branch_zero_end;
	uae_u32 *branch_overflow_end;
	const uintptr exception_idx = (uintptr)(&regs.jit_exception) - (uintptr)(&regs);
	prepare_arithmetic_exception(exception_idx);
	src = readreg(src);
	dq = rmw(dq);
	dr = rmw(dr);

	branch_nonzero = (uae_u32 *)get_target();
	CBNZ_wi(src, 0);
	emit_arithmetic_exception(5, exception_idx);
	branch_zero_end = (uae_u32 *)get_target();
	B_i(0);
	write_jmp_target(branch_nonzero, (uintptr)get_target());

	ORR_xxxLSLi(REG_WORK1, dq, dr, 32);
	UDIV_xxx(REG_WORK2, REG_WORK1, src);
	LSR_xxi(REG_WORK3, REG_WORK2, 32);
	branch_success = (uae_u32 *)get_target();
	CBZ_xi(REG_WORK3, 0);
	branch_overflow_end = (uae_u32 *)get_target();
	B_i(0);

	write_jmp_target(branch_success, (uintptr)get_target());
	MSUB_xxxx(REG_WORK3, src, REG_WORK2, REG_WORK1);
	/* Match m68k_divl's architecturally visible alias ordering: if dr and dq
	 * name the same register, the quotient write wins. */
	MOV_ww(dr, REG_WORK3);
	MOV_ww(dq, REG_WORK2);

	write_jmp_target(branch_zero_end, (uintptr)get_target());
	write_jmp_target(branch_overflow_end, (uintptr)get_target());
	unlock2(dr);
	unlock2(dq);
	unlock2(src);
}
MENDFUNC(3,jnf_DIVLU64,(RW4 dq, RW4 dr, RR4 src))

MIDFUNC(3,jff_DIVLU64,(RW4 dq, RW4 dr, RR4 src))
{
	uae_u32 *branch_nonzero;
	uae_u32 *branch_success;
	uae_u32 *branch_zero_end;
	uae_u32 *branch_overflow_end;
	const uintptr exception_idx = (uintptr)(&regs.jit_exception) - (uintptr)(&regs);
	prepare_arithmetic_exception(exception_idx);
	src = readreg(src);
	dq = rmw(dq);
	dr = rmw(dr);

	/* A zero divisor leaves the complete incoming CCR and both dividend
	 * registers unchanged.  The generator made that CCR live before entry. */
	branch_nonzero = (uae_u32 *)get_target();
	CBNZ_wi(src, 0);
	emit_arithmetic_exception(5, exception_idx);
	branch_zero_end = (uae_u32 *)get_target();
	B_i(0);
	write_jmp_target(branch_nonzero, (uintptr)get_target());

	ORR_xxxLSLi(REG_WORK1, dq, dr, 32);
	UDIV_xxx(REG_WORK2, REG_WORK1, src);
	LSR_xxi(REG_WORK3, REG_WORK2, 32);
	branch_success = (uae_u32 *)get_target();
	CBZ_xi(REG_WORK3, 0);

	/* Overflow: N=V=1, C=0, Z preserved; no result registers change. */
	MRS_NZCV_x(REG_WORK1);
	SET_xxbit(REG_WORK1, REG_WORK1, 31);
	SET_xxVflag(REG_WORK1, REG_WORK1);
	CLEAR_xxCflag(REG_WORK1, REG_WORK1);
	MSR_NZCV_x(REG_WORK1);
	branch_overflow_end = (uae_u32 *)get_target();
	B_i(0);

	write_jmp_target(branch_success, (uintptr)get_target());
	MSUB_xxxx(REG_WORK3, src, REG_WORK2, REG_WORK1);
	/* The quotient is the final architectural value when dr aliases dq. */
	MOV_ww(dr, REG_WORK3);
	MOV_ww(dq, REG_WORK2);
	TST_ww(REG_WORK2, REG_WORK2); /* N/Z from quotient; V=C=0 */

	write_jmp_target(branch_zero_end, (uintptr)get_target());
	write_jmp_target(branch_overflow_end, (uintptr)get_target());
	flags_carry_inverted = false;
	unlock2(dr);
	unlock2(dq);
	unlock2(src);
}
MENDFUNC(3,jff_DIVLU64,(RW4 dq, RW4 dr, RR4 src))

/*
 * DIVLS64 — 64-bit signed divide
 * {dr:dq} / src → quotient in dq, remainder in dr
 * Overflow if quotient doesn't fit in signed 32 bits → sets V=1
 */
MIDFUNC(3,jnf_DIVLS64,(RW4 dq, RW4 dr, RR4 src))
{
	uae_u32 *branch_nonzero;
	uae_u32 *branch_success;
	uae_u32 *branch_zero_end;
	uae_u32 *branch_overflow_end;
	const uintptr exception_idx = (uintptr)(&regs.jit_exception) - (uintptr)(&regs);
	prepare_arithmetic_exception(exception_idx);
	src = readreg(src);
	dq = rmw(dq);
	dr = rmw(dr);

	branch_nonzero = (uae_u32 *)get_target();
	CBNZ_wi(src, 0);
	emit_arithmetic_exception(5, exception_idx);
	branch_zero_end = (uae_u32 *)get_target();
	B_i(0);
	write_jmp_target(branch_nonzero, (uintptr)get_target());

	ORR_xxxLSLi(REG_WORK1, dq, dr, 32);
	SXTW_xw(REG_WORK4, src);
	SDIV_xxx(REG_WORK2, REG_WORK1, REG_WORK4);
	SXTW_xw(REG_WORK3, REG_WORK2);
	CMP_xx(REG_WORK3, REG_WORK2);
	branch_success = (uae_u32 *)get_target();
	BEQ_i(0);
	branch_overflow_end = (uae_u32 *)get_target();
	B_i(0);

	write_jmp_target(branch_success, (uintptr)get_target());
	MSUB_xxxx(REG_WORK3, REG_WORK4, REG_WORK2, REG_WORK1);
	/* Match m68k_divl's architecturally visible alias ordering. */
	MOV_ww(dr, REG_WORK3);
	MOV_ww(dq, REG_WORK2);

	write_jmp_target(branch_zero_end, (uintptr)get_target());
	write_jmp_target(branch_overflow_end, (uintptr)get_target());
	unlock2(dr);
	unlock2(dq);
	unlock2(src);
}
MENDFUNC(3,jnf_DIVLS64,(RW4 dq, RW4 dr, RR4 src))

MIDFUNC(3,jff_DIVLS64,(RW4 dq, RW4 dr, RR4 src))
{
	uae_u32 *branch_nonzero;
	uae_u32 *branch_success;
	uae_u32 *branch_zero_end;
	uae_u32 *branch_overflow_end;
	int saved_flags;
	const uintptr exception_idx = (uintptr)(&regs.jit_exception) - (uintptr)(&regs);
	prepare_arithmetic_exception(exception_idx);
	src = readreg(src);
	dq = rmw(dq);
	dr = rmw(dr);
	saved_flags = readreg(FLAGTMP);

	branch_nonzero = (uae_u32 *)get_target();
	CBNZ_wi(src, 0);
	emit_arithmetic_exception(5, exception_idx);
	branch_zero_end = (uae_u32 *)get_target();
	B_i(0);
	write_jmp_target(branch_nonzero, (uintptr)get_target());

	ORR_xxxLSLi(REG_WORK1, dq, dr, 32);
	SXTW_xw(REG_WORK4, src);
	SDIV_xxx(REG_WORK2, REG_WORK1, REG_WORK4);
	SXTW_xw(REG_WORK3, REG_WORK2);
	CMP_xx(REG_WORK3, REG_WORK2);
	branch_success = (uae_u32 *)get_target();
	BEQ_i(0);

	/* CMP clobbered host Z; reconstruct overflow flags from the saved CCR. */
	MOV_ww(REG_WORK1, saved_flags);
	SET_xxbit(REG_WORK1, REG_WORK1, 31);
	SET_xxVflag(REG_WORK1, REG_WORK1);
	CLEAR_xxCflag(REG_WORK1, REG_WORK1);
	MSR_NZCV_x(REG_WORK1);
	branch_overflow_end = (uae_u32 *)get_target();
	B_i(0);

	write_jmp_target(branch_success, (uintptr)get_target());
	MSUB_xxxx(REG_WORK3, REG_WORK4, REG_WORK2, REG_WORK1);
	/* The quotient is the final architectural value when dr aliases dq. */
	MOV_ww(dr, REG_WORK3);
	MOV_ww(dq, REG_WORK2);
	TST_ww(REG_WORK2, REG_WORK2); /* N/Z from quotient; V=C=0 */

	write_jmp_target(branch_zero_end, (uintptr)get_target());
	write_jmp_target(branch_overflow_end, (uintptr)get_target());
	flags_carry_inverted = false;
	unlock2(saved_flags);
	unlock2(dr);
	unlock2(dq);
	unlock2(src);
}
MENDFUNC(3,jff_DIVLS64,(RW4 dq, RW4 dr, RR4 src))

/*
 * EOR
 * Operand Syntax: 	Dn, <ea>
 *
 * Operand Size: 8,16,32
 *
 * X Not affected.
 * N Set if the most significant bit of the result is set. Cleared otherwise.
 * Z Set if the result is zero. Cleared otherwise.
 * V Always cleared.
 * C Always cleared.
 *
 */
MIDFUNC(2,jnf_EOR_b_imm,(RW1 d, IM8 v))
{
	INIT_REG_b(d);

	MOV_xi(REG_WORK1, (v & 0xff));
	EOR_www(d, d, REG_WORK1);

	unlock2(d);
}
MENDFUNC(2,jnf_EOR_b_imm,(RW1 d, IM8 v))

MIDFUNC(2,jnf_EOR_b,(RW1 d, RR1 s))
{
	if (isconst(s)) {
		COMPCALL(jnf_EOR_b_imm)(d, live.state[s].val);
		return;
	}

	INIT_REGS_b(d, s);

	if(targetIsReg) {
		EOR_www(REG_WORK1, d, s);
		BFI_wwii(d, REG_WORK1, 0, 8);
	} else {
		EOR_www(d, d, s);
	}

	EXIT_REGS(d, s);
}
MENDFUNC(2,jnf_EOR_b,(RW1 d, RR1 s))

MIDFUNC(2,jnf_EOR_w_imm,(RW2 d, IM16 v))
{
	INIT_REG_w(d);

	MOV_xi(REG_WORK1, v & 0xffff);
	EOR_www(d, d, REG_WORK1);

	unlock2(d);
}
MENDFUNC(2,jnf_EOR_w_imm,(RW2 d, IM16 v))

MIDFUNC(2,jnf_EOR_w,(RW2 d, RR2 s))
{
	if (isconst(s)) {
		COMPCALL(jnf_EOR_w_imm)(d, live.state[s].val);
		return;
	}

	INIT_REGS_w(d, s);

	EOR_www(REG_WORK1, d, s);
	BFI_wwii(d, REG_WORK1, 0, 16);

	EXIT_REGS(d, s);
}
MENDFUNC(2,jnf_EOR_w,(RW2 d, RR2 s))

MIDFUNC(2,jnf_EOR_l_imm,(RW4 d, IM32 v))
{
	if(isconst(d)) {
		live.state[d].val = live.state[d].val ^ v;
		return;
	}

	d = rmw(d);

	LOAD_U32(REG_WORK1, v);
	EOR_www(d, d, REG_WORK1);

	unlock2(d);
}
MENDFUNC(2,jnf_EOR_l_imm,(RW4 d, IM32 v))

MIDFUNC(2,jnf_EOR_l,(RW4 d, RR4 s))
{
	if (isconst(s)) {
		COMPCALL(jnf_EOR_l_imm)(d, live.state[s].val);
		return;
	}

	INIT_REGS_l(d, s);

	EOR_www(d, d, s);

	EXIT_REGS(d, s);
}
MENDFUNC(2,jnf_EOR_l,(RW4 d, RR4 s))

MIDFUNC(2,jff_EOR_b_imm,(RW1 d, IM8 v))
{
	INIT_REG_b(d);

	SIGNED8_REG_2_REG(REG_WORK1, d);
	SIGNED8_IMM_2_REG(REG_WORK2, v);
	if(targetIsReg) {
		EOR_www(REG_WORK1, REG_WORK1, REG_WORK2);
		BFI_wwii(d, REG_WORK1, 0, 8);
		TST_ww(REG_WORK1, REG_WORK1);
	} else {
		EOR_www(d, REG_WORK1, REG_WORK2);
		TST_ww(d, d);
	}

	flags_carry_inverted = false;
	unlock2(d);
}
MENDFUNC(2,jff_EOR_b_imm,(RW1 d, IM8 v))

MIDFUNC(2,jff_EOR_b,(RW1 d, RR1 s))
{
	if (isconst(s)) {
		COMPCALL(jff_EOR_b_imm)(d, live.state[s].val);
		return;
	}

	INIT_REGS_b(d, s);

	SIGNED8_REG_2_REG(REG_WORK1, d);
	SIGNED8_REG_2_REG(REG_WORK2, s);
	if(targetIsReg) {
		EOR_www(REG_WORK1, REG_WORK1, REG_WORK2);
		BFI_wwii(d, REG_WORK1, 0, 8);
		TST_ww(REG_WORK1, REG_WORK1);
	} else {
		EOR_www(d, REG_WORK1, REG_WORK2);
		TST_ww(d, d);
	}

	flags_carry_inverted = false;
	EXIT_REGS(d, s);
}
MENDFUNC(2,jff_EOR_b,(RW1 d, RR1 s))

MIDFUNC(2,jff_EOR_w_imm,(RW2 d, IM16 v))
{
	INIT_REG_w(d);

	SIGNED16_REG_2_REG(REG_WORK1, d);
	SIGNED16_IMM_2_REG(REG_WORK2, v);
	if(targetIsReg) {
		EOR_www(REG_WORK1, REG_WORK1, REG_WORK2);
		BFI_wwii(d, REG_WORK1, 0, 16);
		TST_ww(REG_WORK1, REG_WORK1);
	} else {
		EOR_www(d, REG_WORK1, REG_WORK2);
		TST_ww(d, d);
	}

	flags_carry_inverted = false;
	unlock2(d);
}
MENDFUNC(2,jff_EOR_w_imm,(RW2 d, IM16 v))

MIDFUNC(2,jff_EOR_w,(RW2 d, RR2 s))
{
	if (isconst(s)) {
		COMPCALL(jff_EOR_w_imm)(d, live.state[s].val);
		return;
	}

	INIT_REGS_w(d, s);

	SIGNED16_REG_2_REG(REG_WORK1, d);
	SIGNED16_REG_2_REG(REG_WORK2, s);
	if(targetIsReg) {
		EOR_www(REG_WORK1, REG_WORK1, REG_WORK2);
		BFI_wwii(d, REG_WORK1, 0, 16);
		TST_ww(REG_WORK1, REG_WORK1);
	} else {
		EOR_www(d, REG_WORK1, REG_WORK2);
		TST_ww(d, d);
	}

	flags_carry_inverted = false;
	EXIT_REGS(d, s);
}
MENDFUNC(2,jff_EOR_w,(RW2 d, RR2 s))

MIDFUNC(2,jff_EOR_l_imm,(RW4 d, IM32 v))
{
	d = rmw(d);

	LOAD_U32(REG_WORK1, v);
	EOR_www(d, d, REG_WORK1);
	TST_ww(d, d);

	flags_carry_inverted = false;
	unlock2(d);
}
MENDFUNC(2,jff_EOR_l_imm,(RW4 d, IM32 v))

MIDFUNC(2,jff_EOR_l,(RW4 d, RR4 s))
{
	if (isconst(s)) {
		COMPCALL(jff_EOR_l_imm)(d, live.state[s].val);
		return;
	}

	INIT_REGS_l(d, s);

	EOR_www(d, d, s);
	TST_ww(d, d);

	flags_carry_inverted = false;
	EXIT_REGS(d, s);
}
MENDFUNC(2,jff_EOR_l,(RW4 d, RR4 s))

/*
 * EORSR
 * Operand Syntax: 	#<data>, CCR
 *
 * Operand Size: 8
 *
 * X — Changed if bit 4 of immediate operand is one; unchanged otherwise.
 * N — Changed if bit 3 of immediate operand is one; unchanged otherwise.
 * Z — Changed if bit 2 of immediate operand is one; unchanged otherwise.
 * V — Changed if bit 1 of immediate operand is one; unchanged otherwise.
 * C — Changed if bit 0 of immediate operand is one; unchanged otherwise.
 *
 */
MIDFUNC(2,jff_EORSR,(IM32 s, IM8 x))
{
	MRS_NZCV_x(REG_WORK1);
	if(flags_carry_inverted) {
		EOR_xxCflag(REG_WORK1, REG_WORK1);
		flags_carry_inverted = false;
	}
	MOV_xish(REG_WORK2, (s >> 16), 16);
	EOR_www(REG_WORK1, REG_WORK1, REG_WORK2);
	MSR_NZCV_x(REG_WORK1);

	if (x) {
		int f = rmw(FLAGX);
		EOR_xxbit(f, f, 0);
		unlock2(f);
	}
}
MENDFUNC(2,jff_EORSR,(IM32 s, IM8 x))

/*
 * EXT
 * Operand Syntax: <ea>
 *
 * Operand Size: 16,32
 *
 * X Not affected.
 * N Set if the result is negative. Cleared otherwise.
 * Z Set if the result is zero. Cleared otherwise.
 * V Always cleared.
 * C Always cleared.
 *
 */
MIDFUNC(1,jnf_EXT_b,(RW4 d))
{
	if (isconst(d)) {
		live.state[d].val = (uae_s32)(uae_s8)live.state[d].val;
		return;
	}

	d = rmw(d);

	SIGNED8_REG_2_REG(d, d);

	unlock2(d);
}
MENDFUNC(1,jnf_EXT_b,(RW4 d))

MIDFUNC(1,jnf_EXT_w,(RW4 d))
{
	if (isconst(d)) {
		live.state[d].val = (live.state[d].val & 0xffff0000) | (((uae_s32)(uae_s8)live.state[d].val) & 0x0000ffff);
		return;
	}

	d = rmw(d);

	SIGNED8_REG_2_REG(REG_WORK1, d);
	BFI_wwii(d, REG_WORK1, 0, 16);

	unlock2(d);
}
MENDFUNC(1,jnf_EXT_w,(RW4 d))

MIDFUNC(1,jnf_EXT_l,(RW4 d))
{
	if (isconst(d)) {
		live.state[d].val = (uae_s32)(uae_s16)live.state[d].val;
		return;
	}

	d = rmw(d);

	SIGNED16_REG_2_REG(d, d);

	unlock2(d);
}
MENDFUNC(1,jnf_EXT_l,(RW4 d))

MIDFUNC(1,jff_EXT_b,(RW4 d))
{
	if (isconst(d)) {
		uae_u8 tmp = (uae_u8)live.state[d].val;
		d = writereg(d);
		SIGNED8_IMM_2_REG(d, tmp);
	} else {
		d = rmw(d);
		SIGNED8_REG_2_REG(d, d);
	}

	TST_ww(d, d);

	flags_carry_inverted = false;
	unlock2(d);
}
MENDFUNC(1,jff_EXT_b,(RW4 d))

MIDFUNC(1,jff_EXT_w,(RW4 d))
{
	if (isconst(d)) {
		uae_u8 tmp = (uae_u8)live.state[d].val;
		d = writereg(d);
		SIGNED8_IMM_2_REG(REG_WORK1, tmp);
	} else {
		d = rmw(d);
		SIGNED8_REG_2_REG(REG_WORK1, d);
	}

	TST_ww(REG_WORK1, REG_WORK1);
	BFI_wwii(d, REG_WORK1, 0, 16);

	flags_carry_inverted = false;
	unlock2(d);
}
MENDFUNC(1,jff_EXT_w,(RW4 d))

MIDFUNC(1,jff_EXT_l,(RW4 d))
{
	if(isconst(d)) {
		live.state[d].val = (uae_s32)(uae_s16)live.state[d].val;
		uae_u32 f = 0;
		if(((uae_s32)live.state[d].val) == 0)
			f |= (ARM_Z_FLAG >> 16);
		if(((uae_s32)live.state[d].val) < 0)
			f |= (ARM_N_FLAG >> 16);
		MOV_xish(REG_WORK1, f, 16);
		MSR_NZCV_x(REG_WORK1);

		flags_carry_inverted = false;
		return;
	}

	d = rmw(d);
	SIGNED16_REG_2_REG(d, d);
	TST_ww(d, d);

	flags_carry_inverted = false;
	unlock2(d);
}
MENDFUNC(1,jff_EXT_l,(RW4 d))

/*
 * LSL
 * Operand Syntax: 	Dx, Dy
 * 					#<data>, Dy
 *					<ea>
 *
 * Operand Size: 8,16,32
 *
 * X Set according to the last bit shifted out of the operand. Unaffected for a shift count of zero.
 * N Set if the result is negative. Cleared otherwise.
 * Z Set if the result is zero. Cleared otherwise.
 * V Always cleared.
 * C Set according to the last bit shifted out of the operand. Cleared for a shift count of zero.
 *
 */
MIDFUNC(2,jnf_LSL_b_imm,(RW1 d, IM8 i))
{
	if(i) {
		if (isconst(d)) {
			const uae_u32 result = i >= 8 ? 0 : ((live.state[d].val & 0xff) << i);
			live.state[d].val = (live.state[d].val & 0xffffff00) | result;
			return;
		}

		INIT_REG_b(d);

		if(i > 31)
			i = 31;
		LSL_wwi(REG_WORK1, d, i);
		BFI_wwii(d, REG_WORK1, 0, 8);

		unlock2(d);
	}
}
MENDFUNC(2,jnf_LSL_b_imm,(RW1 d, IM8 i))

MIDFUNC(2,jnf_LSL_w_imm,(RW2 d, IM8 i))
{
	if(i) {
		if (isconst(d)) {
			const uae_u32 result = i >= 16 ? 0 : ((live.state[d].val & 0xffff) << i);
			live.state[d].val = (live.state[d].val & 0xffff0000) | result;
			return;
		}

		INIT_REG_w(d);

		if(i > 31)
			i = 31;
		LSL_wwi(REG_WORK1, d, i);
		BFI_wwii(d, REG_WORK1, 0, 16);

		unlock2(d);
	}
}
MENDFUNC(2,jnf_LSL_w_imm,(RW2 d, IM8 i))

MIDFUNC(2,jnf_LSL_l_imm,(RW4 d, IM8 i))
{
	if(i) {
		if (isconst(d)) {
			live.state[d].val = i >= 32 ? 0 : live.state[d].val << i;
			return;
		}

		d = rmw(d);

		if(i >= 32)
			MOV_wi(d, 0);
		else
			LSL_wwi(d, d, i);

		unlock2(d);
	}
}
MENDFUNC(2,jnf_LSL_l_imm,(RW4 d, IM8 i))

MIDFUNC(2,jnf_LSL_b_reg,(RW1 d, RR4 i))
{
	if (isconst(i)) {
		COMPCALL(jnf_LSL_b_imm)(d, live.state[i].val & 0x3f);
		return;
	}

	INIT_REGS_b(d, i);

	AND_ww3f(REG_WORK1, i);
	UXTB_ww(REG_WORK2, d);
	LSL_xxx(REG_WORK2, REG_WORK2, REG_WORK1);
	BFI_wwii(d, REG_WORK2, 0, 8);

	EXIT_REGS(d, i);
}
MENDFUNC(2,jnf_LSL_b_reg,(RW1 d, RR4 i))

MIDFUNC(2,jnf_LSL_w_reg,(RW2 d, RR4 i))
{
	if (isconst(i)) {
		COMPCALL(jnf_LSL_w_imm)(d, live.state[i].val & 0x3f);
		return;
	}

	INIT_REGS_w(d, i);

	AND_ww3f(REG_WORK1, i);
	UXTH_ww(REG_WORK2, d);
	LSL_xxx(REG_WORK2, REG_WORK2, REG_WORK1);
	BFI_wwii(d, REG_WORK2, 0, 16);

	EXIT_REGS(d, i);
}
MENDFUNC(2,jnf_LSL_w_reg,(RW2 d, RR4 i))

MIDFUNC(2,jnf_LSL_l_reg,(RW4 d, RR4 i))
{
	if (isconst(i)) {
		const uae_u32 count = live.state[i].val & 0x3f;
		if(count >= 32)
			set_const(d, 0);
		else
			COMPCALL(jnf_LSL_l_imm)(d, count);
		return;
	}

	INIT_REGS_l(d, i);

	AND_ww3f(REG_WORK1, i);
	MOV_ww(REG_WORK2, d);
	LSL_xxx(d, REG_WORK2, REG_WORK1);
	MOV_ww(d, d);

	EXIT_REGS(d, i);
}
MENDFUNC(2,jnf_LSL_l_reg,(RW4 d, RR4 i))

MIDFUNC(2,jff_LSL_b_imm,(RW1 d, IM8 i))
{
	if (i) {
		d = rmw(d);
		if(i >= 8)
			MOV_wi(REG_WORK3, 0);
		else
			LSL_wwi(REG_WORK3, d, i + 24);
		TST_ww(REG_WORK3, REG_WORK3);

		if(i <= 8) {
			PUBLISH_CARRY_FROM_BIT(d, 8 - i, REG_WORK2);
		}
		flags_carry_inverted = false;
		DUPLICACTE_CARRY

		BFXIL_xxii(d, REG_WORK3, 24, 8);
	} else {
		d = readreg(d);
		LSL_wwi(REG_WORK3, d, 24);
		TST_ww(REG_WORK3, REG_WORK3);
		flags_carry_inverted = false;
	}

	unlock2(d);
}
MENDFUNC(2,jff_LSL_b_imm,(RW1 d, IM8 i))

MIDFUNC(2,jff_LSL_w_imm,(RW2 d, IM8 i))
{
	if (i) {
		d = rmw(d);
		if(i >= 16)
			MOV_wi(REG_WORK3, 0);
		else
			LSL_wwi(REG_WORK3, d, i + 16);
		TST_ww(REG_WORK3, REG_WORK3);

		if(i <= 16) {
			PUBLISH_CARRY_FROM_BIT(d, 16 - i, REG_WORK2);
		}
		flags_carry_inverted = false;
		DUPLICACTE_CARRY

		BFXIL_xxii(d, REG_WORK3, 16, 16);
	} else {
		d = readreg(d);
		LSL_wwi(REG_WORK3, d, 16);
		TST_ww(REG_WORK3, REG_WORK3);
		flags_carry_inverted = false;
	}

	unlock2(d);
}
MENDFUNC(2,jff_LSL_w_imm,(RW2 d, IM8 i))

MIDFUNC(2,jff_LSL_l_imm,(RW4 d, IM8 i))
{
	if (i) {
		d = rmw(d);
		if(i >= 32)
			MOV_wi(REG_WORK3, 0);
		else
			LSL_wwi(REG_WORK3, d, i);
		TST_ww(REG_WORK3, REG_WORK3);

		if(i <= 32) {
			PUBLISH_CARRY_FROM_BIT(d, 32 - i, REG_WORK2);
		}
		flags_carry_inverted = false;
		DUPLICACTE_CARRY
		MOV_ww(d, REG_WORK3);
	} else {
		d = readreg(d);
		TST_ww(d, d);
		flags_carry_inverted = false;
	}

	unlock2(d);
}
MENDFUNC(2,jff_LSL_l_imm,(RW4 d, IM8 i))

MIDFUNC(2,jff_LSL_b_reg,(RW1 d, RR4 i))
{
	if (isconst(i)) {
		COMPCALL(jff_LSL_b_imm)(d, live.state[i].val & 0x3f);
		return;
	}

	INIT_REGS_b(d, i);
	LOCK_X_FOR_RUNTIME_JOIN;

	LSL_wwi(REG_WORK3, d, 24);
	ANDS_ww3f(REG_WORK1, i);
	uae_u32* branchadd = (uae_u32*)get_target();
	BEQ_i(0);               // No shift -> X flag unchanged, C cleared

	// shift count > 0
	LSL_xxx(REG_WORK2, REG_WORK3, REG_WORK1);
	BFXIL_xxii(d, REG_WORK2, 24, 8);  // result is ready
	TST_ww(REG_WORK2, REG_WORK2);     // NZ correct, VC cleared

	// Calculate C Flag
	PUBLISH_CARRY_FROM_BIT(REG_WORK2, 32, REG_WORK2);

	flags_carry_inverted = false;
	DUPLICACTE_CARRY
	uae_u32* branch_shift_end = (uae_u32*)get_target();
	B_i(0);

	// No shift
	write_jmp_target(branchadd, (uintptr)get_target());
	TST_ww(REG_WORK3, REG_WORK3);
	write_jmp_target(branch_shift_end, (uintptr)get_target());

	UNLOCK_X_FOR_RUNTIME_JOIN;
	EXIT_REGS(d, i);
}
MENDFUNC(2,jff_LSL_b_reg,(RW1 d, RR4 i))

MIDFUNC(2,jff_LSL_w_reg,(RW2 d, RR4 i))
{
	if (isconst(i)) {
		COMPCALL(jff_LSL_w_imm)(d, live.state[i].val & 0x3f);
		return;
	}

	INIT_REGS_w(d, i);
	LOCK_X_FOR_RUNTIME_JOIN;

	LSL_wwi(REG_WORK3, d, 16);
	ANDS_ww3f(REG_WORK1, i);
	uae_u32* branchadd = (uae_u32*)get_target();
	BEQ_i(0);               // No shift -> X flag unchanged, C cleared

	LSL_xxx(REG_WORK2, REG_WORK3, REG_WORK1);
	BFXIL_xxii(d, REG_WORK2, 16, 16); // result is ready
	TST_ww(REG_WORK2, REG_WORK2);     // NZ correct, VC cleared

	// Calculate C Flag
	PUBLISH_CARRY_FROM_BIT(REG_WORK2, 32, REG_WORK2);

	flags_carry_inverted = false;
	DUPLICACTE_CARRY
	uae_u32* branch_shift_end = (uae_u32*)get_target();
	B_i(0);

	// No shift
	write_jmp_target(branchadd, (uintptr)get_target());
	TST_ww(REG_WORK3, REG_WORK3);
	write_jmp_target(branch_shift_end, (uintptr)get_target());

	UNLOCK_X_FOR_RUNTIME_JOIN;
	EXIT_REGS(d, i);
}
MENDFUNC(2,jff_LSL_w_reg,(RW2 d, RR4 i))

MIDFUNC(2,jff_LSL_l_reg,(RW4 d, RR4 i))
{
	if (isconst(i)) {
		COMPCALL(jff_LSL_l_imm)(d, live.state[i].val & 0x3f);
		return;
	}

	INIT_REGS_l(d, i);

	/* Branch-free count==0-correct codegen (was: internal BEQ whose count!=0
	   DUPLICACTE_CARRY did writereg(FLAGX) while the count==0 path did not, leaving
	   the FLAGX host-reg binding unreconciled at the merge -> wrong X for runtime
	   count==0 under register pressure). A single 64-bit LSL yields the correct
	   value for ALL counts 0..63, and carry=bit32 is 0 for count==0 (operand
	   zero-extended), so C=carry holds for both cases; only X needs the count==0
	   special-case X=(count==0)?X_old:carry, done with one writereg via CSEL. */
	AND_ww3f(REG_WORK1, i);                     /* count = i & 0x3f (value only) */
	MOV_ww(REG_WORK2, d);                       /* zero-extend operand into 64-bit work reg */
	LSL_xxx(REG_WORK2, REG_WORK2, REG_WORK1);   /* REG_WORK2 = operand << count; bit32 = carry */

	if (needed_flags & FLAG_X) {
		UBFX_xxii(REG_WORK3, REG_WORK2, 32, 1); /* carry 0/1 (=0 when count==0) */
		int x = rmw(FLAGX);                      /* old X (bit-0 convention) */
		CMP_wi(REG_WORK1, 0);                   /* Z = (count==0) */
		CSEL_wwwc(x, x, REG_WORK3, NATIVE_CC_EQ); /* X = (count==0) ? X_old : carry */
		unlock2(x);
	}

	MOV_ww(d, REG_WORK2);                       /* result = low 32 bits (zero-extended) */
	TST_ww(d, d);                               /* NZ from result, C/V cleared */

	/* C flag = carry-out (bit32); 0 for count==0 since operand is zero-extended */
	PUBLISH_CARRY_FROM_BIT(REG_WORK2, 32, REG_WORK2);

	flags_carry_inverted = false;

	EXIT_REGS(d, i);
}
MENDFUNC(2,jff_LSL_l_reg,(RW4 d, RR4 i))

/*
 * LSLW
 * Operand Syntax: 	<ea>
 *
 * Operand Size: 16
 *
 * X Set according to the last bit shifted out of the operand. Unaffected for a shift count of zero.
 * N Set if the result is negative. Cleared otherwise.
 * Z Set if the result is zero. Cleared otherwise.
 * V Always cleared.
 * C Set according to the last bit shifted out of the operand. Cleared for a shift count of zero.
 *
 * Target is never a register.
 */
MIDFUNC(1,jnf_LSLW,(RW2 d))
{
	if (isconst(d)) {
		live.state[d].val = (live.state[d].val << 1) & 0xffff;
		return;
	}

	d = rmw(d);

	LSL_wwi(d, d, 1);

	unlock2(d);
}
MENDFUNC(1,jnf_LSLW,(RW2 d))

MIDFUNC(1,jff_LSLW,(RW2 d))
{
	d = rmw(d);

	LSL_wwi(REG_WORK1, d, 17);
	TST_ww(REG_WORK1, REG_WORK1);

	PUBLISH_CARRY_FROM_BIT(d, 15, REG_WORK2);

	LSL_wwi(d, d, 1);

	flags_carry_inverted = false;
	DUPLICACTE_CARRY

	unlock2(d);
}
MENDFUNC(1,jff_LSLW,(RW2 d))

/*
 * LSR
 * Operand Syntax: 	Dx, Dy
 * 					#<data>, Dy
 *					<ea>
 *
 * Operand Size: 8,16,32
 *
 * X Set according to the last bit shifted out of the operand. Unaffected for a shift count of zero.
 * N Set if the result is negative. Cleared otherwise.
 * Z Set if the result is zero. Cleared otherwise.
 * V Always cleared.
 * C Set according to the last bit shifted out of the operand. Cleared for a shift count of zero.
 *
 */
MIDFUNC(2,jnf_LSR_b_imm,(RW1 d, IM8 i))
{
	if(i) {
		if (isconst(d)) {
			const uae_u32 result = i >= 8 ? 0 : ((live.state[d].val & 0xff) >> i);
			live.state[d].val = (live.state[d].val & 0xffffff00) | result;
			return;
		}

		INIT_REG_b(d);

		UNSIGNED8_REG_2_REG(REG_WORK1, d);
		if(i > 31)
			i = 31;
		LSR_wwi(REG_WORK1, REG_WORK1, i);
		BFI_wwii(d, REG_WORK1, 0, 8);

		unlock2(d);
	}
}
MENDFUNC(2,jnf_LSR_b_imm,(RW1 d, IM8 i))

MIDFUNC(2,jnf_LSR_w_imm,(RW2 d, IM8 i))
{
	if(i) {
		if (isconst(d)) {
			const uae_u32 result = i >= 16 ? 0 : ((live.state[d].val & 0xffff) >> i);
			live.state[d].val = (live.state[d].val & 0xffff0000) | result;
			return;
		}

		INIT_REG_w(d);

		UNSIGNED16_REG_2_REG(REG_WORK1, d);
		if(i > 31)
			i = 31;
		LSR_wwi(REG_WORK1, REG_WORK1, i);
		BFI_wwii(d, REG_WORK1, 0, 16);

		unlock2(d);
	}
}
MENDFUNC(2,jnf_LSR_w_imm,(RW2 d, IM8 i))

MIDFUNC(2,jnf_LSR_l_imm,(RW4 d, IM8 i))
{
	if(i) {
		if (isconst(d)) {
			live.state[d].val = i >= 32 ? 0 : live.state[d].val >> i;
			return;
		}

		d = rmw(d);

		if(i >= 32)
			MOV_wi(d, 0);
		else
			LSR_wwi(d, d, i);

		unlock2(d);
	}
}
MENDFUNC(2,jnf_LSR_l_imm,(RW4 d, IM8 i))

MIDFUNC(2,jff_LSR_b_imm,(RW1 d, IM8 i))
{
	if (i) {
		d = rmw(d);
		if(i >= 8)
			MOV_wi(REG_WORK1, 0);
		else {
			UNSIGNED8_REG_2_REG(REG_WORK1, d);
			LSR_wwi(REG_WORK1, REG_WORK1, i);
		}
		TST_ww(REG_WORK1, REG_WORK1);

		if(i <= 8) {
			PUBLISH_CARRY_FROM_BIT(d, i - 1, REG_WORK2);
		}
		BFI_wwii(d, REG_WORK1, 0, 8);
		flags_carry_inverted = false;
		DUPLICACTE_CARRY
	} else {
		d = readreg(d);
		SIGNED8_REG_2_REG(REG_WORK1, d);
		TST_ww(REG_WORK1, REG_WORK1);
		flags_carry_inverted = false;
	}

	unlock2(d);
}
MENDFUNC(2,jff_LSR_b_imm,(RW1 d, IM8 i))

MIDFUNC(2,jff_LSR_w_imm,(RW2 d, IM8 i))
{
	if (i) {
		d = rmw(d);
		if(i >= 16)
			MOV_wi(REG_WORK1, 0);
		else {
			UNSIGNED16_REG_2_REG(REG_WORK1, d);
			LSR_wwi(REG_WORK1, REG_WORK1, i);
		}
		TST_ww(REG_WORK1, REG_WORK1);

		if(i <= 16) {
			PUBLISH_CARRY_FROM_BIT(d, i - 1, REG_WORK2);
		}
		BFI_wwii(d, REG_WORK1, 0, 16);
		flags_carry_inverted = false;
		DUPLICACTE_CARRY
	} else {
		d = readreg(d);
		SIGNED16_REG_2_REG(REG_WORK1, d);
		TST_ww(REG_WORK1, REG_WORK1);
		flags_carry_inverted = false;
	}

	unlock2(d);
}
MENDFUNC(2,jff_LSR_w_imm,(RW2 d, IM8 i))

MIDFUNC(2,jff_LSR_l_imm,(RW4 d, IM8 i))
{
	if (i) {
		d = rmw(d);
		MOV_ww(REG_WORK1, d);
		if(i >= 32)
			MOV_wi(d, 0);
		else
			LSR_wwi(d, d, i);
		TST_ww(d, d);

		if(i <= 32) {
			PUBLISH_CARRY_FROM_BIT(REG_WORK1, i - 1, REG_WORK2);
		}
		flags_carry_inverted = false;
		DUPLICACTE_CARRY
	} else {
		d = readreg(d);
		TST_ww(d, d);
		flags_carry_inverted = false;
	}

	unlock2(d);
}
MENDFUNC(2,jff_LSR_l_imm,(RW4 d, IM8 i))

MIDFUNC(2,jnf_LSR_b_reg,(RW1 d, RR4 i))
{
	if (isconst(i)) {
		COMPCALL(jnf_LSR_b_imm)(d, live.state[i].val & 0x3f);
		return;
	}

	INIT_REGS_b(d, i);

	UNSIGNED8_REG_2_REG(REG_WORK1, d);
	AND_ww3f(REG_WORK2, i);
	LSR_xxx(REG_WORK1, REG_WORK1, REG_WORK2);
	BFI_wwii(d, REG_WORK1, 0, 8);

	EXIT_REGS(d, i);
}
MENDFUNC(2,jnf_LSR_b_reg,(RW1 d, RR4 i))

MIDFUNC(2,jnf_LSR_w_reg,(RW2 d, RR4 i))
{
	if (isconst(i)) {
		COMPCALL(jnf_LSR_w_imm)(d, live.state[i].val & 0x3f);
		return;
	}

	INIT_REGS_w(d, i);

	UNSIGNED16_REG_2_REG(REG_WORK1, d);
	AND_ww3f(REG_WORK2, i);
	LSR_xxx(REG_WORK1, REG_WORK1, REG_WORK2);
	BFI_wwii(d, REG_WORK1, 0, 16);

	EXIT_REGS(d, i);
}
MENDFUNC(2,jnf_LSR_w_reg,(RW2 d, RR4 i))

MIDFUNC(2,jnf_LSR_l_reg,(RW4 d, RR4 i))
{
	if (isconst(i)) {
		const uae_u32 count = live.state[i].val & 0x3f;
		if(count >= 32)
			set_const(d, 0);
		else
			COMPCALL(jnf_LSR_l_imm)(d, count);
		return;
	}

	INIT_REGS_l(d, i);

	AND_ww3f(REG_WORK1, i);
	MOV_ww(REG_WORK2, d);
	LSR_xxx(d, REG_WORK2, REG_WORK1);

	EXIT_REGS(d, i);
}
MENDFUNC(2,jnf_LSR_l_reg,(RW4 d, RR4 i))

MIDFUNC(2,jff_LSR_b_reg,(RW1 d, RR4 i))
{
	if (isconst(i)) {
		COMPCALL(jff_LSR_b_imm)(d, live.state[i].val & 0x3f);
		return;
	}

	INIT_REGS_b(d, i);
	LOCK_X_FOR_RUNTIME_JOIN;

	ANDS_ww3f(REG_WORK1, i);
	uae_u32* branchadd = (uae_u32*)get_target();
	BEQ_i(0);                       // No shift -> X flag unchanged

	UNSIGNED8_REG_2_REG(REG_WORK3, d);
	LSR_xxx(REG_WORK2, REG_WORK3, REG_WORK1);
	BFI_wwii(d, REG_WORK2, 0, 8);
	TST_ww(REG_WORK2, REG_WORK2);

	// Calculate C Flag
	SUB_wwi(REG_WORK2, REG_WORK1, 1);
	LSR_xxx(REG_WORK2, REG_WORK3, REG_WORK2);
	PUBLISH_CARRY_FROM_BIT(REG_WORK2, 0, REG_WORK2);

	flags_carry_inverted = false;
	DUPLICACTE_CARRY

	uae_u32* branch_shift_end = (uae_u32*)get_target();
	B_i(0);

	// No shift
	write_jmp_target(branchadd, (uintptr)get_target());
	SIGNED8_REG_2_REG(REG_WORK2, d);        // Make sure, sign is in MSB if shift count is 0 (to get correct N flag)
	TST_ww(REG_WORK2, REG_WORK2);
	write_jmp_target(branch_shift_end, (uintptr)get_target());

	UNLOCK_X_FOR_RUNTIME_JOIN;
	EXIT_REGS(d, i);
}
MENDFUNC(2,jff_LSR_b_reg,(RW1 d, RR4 i))

MIDFUNC(2,jff_LSR_w_reg,(RW2 d, RR4 i))
{
	if (isconst(i)) {
		COMPCALL(jff_LSR_w_imm)(d, live.state[i].val & 0x3f);
		return;
	}

	INIT_REGS_w(d, i);
	LOCK_X_FOR_RUNTIME_JOIN;

	ANDS_ww3f(REG_WORK1, i);
	uae_u32* branchadd = (uae_u32*)get_target();
	BEQ_i(0);                       // No shift -> X flag unchanged

	UXTH_ww(REG_WORK3, d);                  // Shift count is not 0 -> unsigned required
	LSR_xxx(REG_WORK2, REG_WORK3, REG_WORK1);
	BFI_wwii(d, REG_WORK2, 0, 16);
	TST_ww(REG_WORK2, REG_WORK2);

	// Calculate C Flag
	SUB_wwi(REG_WORK2, REG_WORK1, 1);
	LSR_xxx(REG_WORK2, REG_WORK3, REG_WORK2);
	PUBLISH_CARRY_FROM_BIT(REG_WORK2, 0, REG_WORK2);

	flags_carry_inverted = false;
	DUPLICACTE_CARRY

	uae_u32* branch_shift_end = (uae_u32*)get_target();
	B_i(0);

	// No shift
	write_jmp_target(branchadd, (uintptr)get_target());
	SIGNED16_REG_2_REG(REG_WORK2, d);       // Make sure, sign is in MSB if shift count is 0 (to get correct N flag)
	TST_ww(REG_WORK2, REG_WORK2);
	write_jmp_target(branch_shift_end, (uintptr)get_target());

	UNLOCK_X_FOR_RUNTIME_JOIN;
	EXIT_REGS(d, i);
}
MENDFUNC(2,jff_LSR_w_reg,(RW2 d, RR4 i))

MIDFUNC(2,jff_LSR_l_reg,(RW4 d, RR4 i))
{
	if (isconst(i)) {
		COMPCALL(jff_LSR_l_imm)(d, live.state[i].val & 0x3f);
		return;
	}

	INIT_REGS_l(d, i);
	LOCK_X_FOR_RUNTIME_JOIN;

	ANDS_ww3f(REG_WORK1, i);
	uae_u32* branchadd = (uae_u32*)get_target();
	BEQ_i(0);                       // No shift -> X flag unchanged

	MOV_ww(REG_WORK3, d);
	LSR_xxx(d, REG_WORK3, REG_WORK1);
	TST_ww(d, d);

	// Calculate C Flag
	SUB_wwi(REG_WORK2, REG_WORK1, 1);
	LSR_xxx(REG_WORK2, REG_WORK3, REG_WORK2);
	PUBLISH_CARRY_FROM_BIT(REG_WORK2, 0, REG_WORK2);

	flags_carry_inverted = false;
	DUPLICACTE_CARRY

	uae_u32* branch_shift_end = (uae_u32*)get_target();
	B_i(0);

	// No shift
	write_jmp_target(branchadd, (uintptr)get_target());
	TST_ww(d, d);
	write_jmp_target(branch_shift_end, (uintptr)get_target());

	UNLOCK_X_FOR_RUNTIME_JOIN;
	EXIT_REGS(d, i);
}
MENDFUNC(2,jff_LSR_l_reg,(RW4 d, RR4 i))

/*
 * LSRW
 * Operand Syntax: 	<ea>
 *
 * Operand Size: 16
 *
 * X Set according to the last bit shifted out of the operand. Unaffected for a shift count of zero.
 * N Set if the result is negative. Cleared otherwise.
 * Z Set if the result is zero. Cleared otherwise.
 * V Always cleared.
 * C Set according to the last bit shifted out of the operand. Cleared for a shift count of zero.
 *
 * Target is never a register.
 */
MIDFUNC(1,jnf_LSRW,(RW2 d))
{
	if (isconst(d)) {
		live.state[d].val = ((live.state[d].val & 0xffff) >> 1);
		return;
	}

	d = rmw(d);

	UNSIGNED16_REG_2_REG(d, d);
	LSR_wwi(d, d, 1);

	unlock2(d);
}
MENDFUNC(1,jnf_LSRW,(RW2 d))

MIDFUNC(1,jff_LSRW,(RW2 d))
{
	d = rmw(d);

	UNSIGNED16_REG_2_REG(REG_WORK3, d);
	LSR_wwi(d, REG_WORK3, 1);
	TST_ww(d, d);

	PUBLISH_CARRY_FROM_BIT(REG_WORK3, 0, REG_WORK2);

	flags_carry_inverted = false;
	DUPLICACTE_CARRY

	unlock2(d);
}
MENDFUNC(1,jff_LSRW,(RW2 d))

/*
 * MOVE
 * Operand Syntax: <ea>, <ea>
 *
 * Operand Size: 8,16,32
 *
 * X Not affected.
 * N Set if the result is negative. Cleared otherwise.
 * Z Set if the result is zero. Cleared otherwise.
 * V Always cleared.
 * C Always cleared.
 *
 */
MIDFUNC(2,jnf_MOVE_b_imm,(W1 d, IM8 s))
{
	if (isconst(d)) {
		live.state[d].val = (live.state[d].val & 0xffffff00) | (s & 0x000000ff);
		return;
	}

	d = rmw(d);

	MOV_xi(REG_WORK1, s & 0xff);
	BFI_wwii(d, REG_WORK1, 0, 8);

	unlock2(d);
}
MENDFUNC(2,jnf_MOVE_b_imm,(W1 d, IM8 s))

MIDFUNC(2,jnf_MOVE_w_imm,(W2 d, IM16 s))
{
	if (isconst(d)) {
		live.state[d].val = (live.state[d].val & 0xffff0000) | (s & 0x0000ffff);
		return;
	}

	d = rmw(d);

	// Fix 21: MOVK_xi preserves dirty bits in [63:32]. Use MOVK_wi which
	// writes to W register, zeroing [63:32] while preserving [31:16].
	MOVK_wi(d, s & 0xffff);

	unlock2(d);
}
MENDFUNC(2,jnf_MOVE_w_imm,(W2 d, IM16 s))

MIDFUNC(2,jnf_MOVE_b,(W1 d, RR1 s))
{
	if(s == d)
		return;
	if (isconst(s)) {
		COMPCALL(jnf_MOVE_b_imm)(d, live.state[s].val);
		return;
	}

	INIT_REGS_b(d, s);

	BFI_wwii(d, s, 0, 8);

	EXIT_REGS(d, s);
}
MENDFUNC(2,jnf_MOVE_b,(W1 d, RR1 s))

MIDFUNC(2,jnf_MOVE_w,(W2 d, RR2 s))
{
	if(s == d)
		return;
	if (isconst(s)) {
		COMPCALL(jnf_MOVE_w_imm)(d, live.state[s].val);
		return;
	}

	INIT_REGS_w(d, s);

	BFI_wwii(d, s, 0, 16);

	EXIT_REGS(d, s);
}
MENDFUNC(2,jnf_MOVE_w,(W2 d, RR2 s))

MIDFUNC(2,jnf_MOVE_l,(W4 d, RR4 s))
{
	mov_l_rr(d, s);
}
MENDFUNC(2,jnf_MOVE_l,(W4 d, RR4 s))

MIDFUNC(2,jff_MOVE_b_imm,(W1 d, IM8 s))
{
	d = rmw(d);

	if (s & 0x80) {
		MOVN_wi(REG_WORK1, (uae_u8) ~s);
	} else {
		MOV_xi(REG_WORK1, (uae_u8) s);
	}
	TST_ww(REG_WORK1, REG_WORK1);
	BFI_wwii(d, REG_WORK1, 0, 8);

	flags_carry_inverted = false;
	unlock2(d);
}
MENDFUNC(2,jff_MOVE_b_imm,(W1 d, IM8 s))

MIDFUNC(2,jff_MOVE_w_imm,(W2 d, IM16 s))
{
	if(isconst(d)) {
		live.state[d].val = (live.state[d].val & 0xffff0000) | (s & 0x0000ffff);
		uae_u32 f = 0;
		if((uae_s16)s == 0)
			f |= (ARM_Z_FLAG >> 16);
		if((uae_s16)s < 0)
			f |= (ARM_N_FLAG >> 16);
		MOV_xish(REG_WORK1, f, 16);
		MSR_NZCV_x(REG_WORK1);
		flags_carry_inverted = false;
		return;
	}

	d = rmw(d);

	SIGNED16_IMM_2_REG(REG_WORK1, (uae_u16)s);
	TST_ww(REG_WORK1, REG_WORK1);
	BFI_wwii(d, REG_WORK1, 0, 16);

	flags_carry_inverted = false;
	unlock2(d);
}
MENDFUNC(2,jff_MOVE_w_imm,(W2 d, IM16 s))

MIDFUNC(2,jff_MOVE_l_imm,(W4 d, IM32 s))
{
	set_const(d, s);
	uae_u32 f = 0;
	if(s == 0)
		f |= (ARM_Z_FLAG >> 16);
	if((uae_s32)s < 0)
		f |= (ARM_N_FLAG >> 16);
	MOV_xish(REG_WORK1, f, 16);
	MSR_NZCV_x(REG_WORK1);

	flags_carry_inverted = false;
}
MENDFUNC(2,jff_MOVE_l_imm,(W4 d, IM32 s))

MIDFUNC(2,jff_MOVE_b,(W1 d, RR1 s))
{
	if (isconst(s)) {
		COMPCALL(jff_MOVE_b_imm)(d, live.state[s].val);
		return;
	}

	int s_is_d = (s == d);
	if(!s_is_d) {
		s = readreg(s);
		d = rmw(d);
	} else {
		s = d = readreg(d);
	}

	SIGNED8_REG_2_REG(REG_WORK1, s);
	TST_ww(REG_WORK1, REG_WORK1);
	if(!s_is_d)
		BFI_wwii(d, REG_WORK1, 0, 8);

	flags_carry_inverted = false;
	EXIT_REGS(d, s);
}
MENDFUNC(2,jff_MOVE_b,(W1 d, RR1 s))

MIDFUNC(2,jff_MOVE_w,(W2 d, RR2 s))
{
	if (isconst(s)) {
		COMPCALL(jff_MOVE_w_imm)(d, live.state[s].val);
		return;
	}

	int s_is_d = (s == d);
	if(!s_is_d) {
		s = readreg(s);
		d = rmw(d);
	} else {
		s = d = readreg(d);
	}

	SIGNED16_REG_2_REG(REG_WORK1, s);
	TST_ww(REG_WORK1, REG_WORK1);
	if(!s_is_d)
		BFI_wwii(d, REG_WORK1, 0, 16);

	flags_carry_inverted = false;
	EXIT_REGS(d, s);
}
MENDFUNC(2,jff_MOVE_w,(W2 d, RR2 s))

MIDFUNC(2,jff_MOVE_l,(W4 d, RR4 s))
{
	if (isconst(s)) {
		COMPCALL(jff_MOVE_l_imm)(d, live.state[s].val);
		return;
	}

	int s_is_d = (s == d);
	s = readreg(s);

	if(!s_is_d) {
		d = writereg(d);
		MOV_ww(d, s);
	}
	TST_ww(s, s);

	flags_carry_inverted = false;
	if(!s_is_d)
		unlock2(d);
	unlock2(s);
}
MENDFUNC(2,jff_MOVE_l,(W4 d, RR4 s))

/*
 * MVMEL
 *
 * Flags: Not affected.
 *
 */
MIDFUNC(3,jnf_MVMEL_w,(W4 d, RR4 s, IM8 offset))
{
	s = readreg(s);
	d = writereg(d);

	LDRH_wXi(REG_WORK1, s, offset);
	REV16_ww(d, REG_WORK1);
	SXTH_ww(d, d);

	unlock2(d);
	unlock2(s);
}
MENDFUNC(3,jnf_MVMEL_w,(W4 d, RR4 s, IM8 offset))

MIDFUNC(3,jnf_MVMEL_l,(W4 d, RR4 s, IM8 offset))
{
	if (s == d || isconst(d) || isinreg(d)) {
		s = readreg(s);
		d = writereg(d);

		LDR_wXi(REG_WORK1, s, offset);
		REV_ww(d, REG_WORK1);

		unlock2(d);
		unlock2(s);
	} else {
		s = readreg(s);

		LDR_wXi(REG_WORK1, s, offset);
		REV_ww(REG_WORK2, REG_WORK1);
		uintptr idx = (uintptr)(&regs.regs[d]) - (uintptr) &regs;
		STR_wXi(REG_WORK2, R_REGSTRUCT, idx);

		unlock2(s);
	}
}
MENDFUNC(3,jnf_MVMEL_l,(W4 d, RR4 s, IM8 offset))

/*
 * MVMLE
 *
 * Flags: Not affected.
 *
 */
MIDFUNC(3,jnf_MVMLE_w,(RR4 d, RR4 s, IM8 offset))
{
	s = readreg(s);
	d = readreg(d);

	REV16_ww(REG_WORK1, s);
	STURH_wXi(REG_WORK1, d, offset);

	unlock2(d);
	unlock2(s);
}
MENDFUNC(3,jnf_MVMLE_w,(RR4 d, RR4 s, IM8 offset))

MIDFUNC(3,jnf_MVMLE_l,(RR4 d, RR4 s, IM8 offset))
{
	if (s == d || isconst(s) || isinreg(s)) {
		s = readreg(s);
		d = readreg(d);

		REV_ww(REG_WORK1, s);
		STUR_wXi(REG_WORK1, d, offset);

		unlock2(d);
		unlock2(s);
	} else {
		d = readreg(d);

		uintptr idx = (uintptr)(&regs.regs[s]) - (uintptr) &regs;
		LDR_wXi(REG_WORK2, R_REGSTRUCT, idx);
		REV_ww(REG_WORK1, REG_WORK2);
		STUR_wXi(REG_WORK1, d, offset);

		unlock2(d);
	}
}
MENDFUNC(3,jnf_MVMLE_l,(RR4 d, RR4 s, IM8 offset))

/*
 * MOVE16
 *
 * Flags: Not affected.
 *
 */
MIDFUNC(2,jnf_MOVE16,(RR4 d, RR4 s))
{
	s = readreg(s);
	d = readreg(d);

	CLEAR_LOW4_xx(REG_WORK3, s);
	CLEAR_LOW4_xx(REG_WORK4, d);

	/* CLEAR_LOW4_xx is a 64-bit logical op and can preserve dirty high
	   bits from virtual 32-bit address registers.  Build host pointers with
	   an explicit UXTW extension so MOVE16 cannot sign/garbage-extend guest
	   addresses into probes such as 0xfffff03b0000. */
	ADD_xxwEX(REG_WORK3, R_MEMSTART, REG_WORK3, EX_UXTW);
	ADD_xxwEX(REG_WORK4, R_MEMSTART, REG_WORK4, EX_UXTW);

	LDP_xxXi(REG_WORK1, REG_WORK2, REG_WORK3, 0);
	STP_xxXi(REG_WORK1, REG_WORK2, REG_WORK4, 0);

	unlock2(d);
	unlock2(s);
}
MENDFUNC(2,jnf_MOVE16,(RR4 d, RR4 s))

/*
 * MOVEA
 * Operand Syntax: 	<ea>, An
 *
 * Operand Size: 16,32
 *
 * Flags: Not affected.
 *
 */
MIDFUNC(2,jnf_MOVEA_w_imm,(W4 d, IM16 v))
{
	set_const(d, (uae_s32)(uae_s16)v);
}
MENDFUNC(2,jnf_MOVEA_w_imm,(W4 d, IM16 v))

MIDFUNC(2,jnf_MOVEA_w,(W4 d, RR2 s))
{
	if (isconst(s)) {
		COMPCALL(jnf_MOVEA_w_imm)(d, live.state[s].val);
		return;
	}

	INIT_REGS_l(d, s);

	SIGNED16_REG_2_REG(d, s);

	EXIT_REGS(d, s);
}
MENDFUNC(2,jnf_MOVEA_w,(W4 d, RR2 s))

MIDFUNC(2,jnf_MOVEA_l,(W4 d, RR4 s))
{
	mov_l_rr(d, s);
}
MENDFUNC(2,jnf_MOVEA_l,(W4 d, RR4 s))

/*
 * MULS
 * Operand Syntax: 	<ea>, Dn
 *
 * Operand Size: 16
 *
 * X Not affected.
 * N Set if the result is negative. Cleared otherwise.
 * Z Set if the result is zero. Cleared otherwise.
 * V Set if overflow. Cleared otherwise. (32 Bit multiply only)
 * C Always cleared.
 *
 */
MIDFUNC(2,jnf_MULS,(RW4 d, RR4 s))
{
	if (isconst(s)) {
		uae_s16 tmp = (uae_s16)live.state[s].val;
		d = rmw(d);
		SIGNED16_IMM_2_REG(REG_WORK1, tmp);
		SIGNED16_REG_2_REG(d, d);
		SMULL_xww(d, d, REG_WORK1);
		MOV_ww(d, d); // Clean upper 32 bits after 64-bit multiply
		unlock2(d);
		return;
	}

	INIT_REGS_l(d, s);

	SIGNED16_REG_2_REG(d, d);
	SIGNED16_REG_2_REG(REG_WORK1, s);
	SMULL_xww(d, d, REG_WORK1);
	MOV_ww(d, d); // Clean upper 32 bits after 64-bit multiply

	EXIT_REGS(d, s);
}
MENDFUNC(2,jnf_MULS,(RW4 d, RR4 s))

MIDFUNC(2,jff_MULS,(RW4 d, RR4 s))
{
	INIT_REGS_l(d, s);

	SIGNED16_REG_2_REG(d, d);
	SIGNED16_REG_2_REG(REG_WORK1, s);
	SMULL_xww(d, d, REG_WORK1);
	MOV_ww(d, d); // Clean upper 32 bits after 64-bit multiply
	TST_ww(d, d);

	flags_carry_inverted = false;
	EXIT_REGS(d, s);
}
MENDFUNC(2,jff_MULS,(RW4 d, RR4 s))

MIDFUNC(2,jnf_MULS32,(RW4 d, RR4 s))
{
	INIT_REGS_l(d, s);

	SMULL_xww(d, d, s);
	MOV_ww(d, d); // Clean upper 32 bits after 64-bit multiply

	EXIT_REGS(d, s);
}
MENDFUNC(2,jnf_MULS32,(RW4 d, RR4 s))

MIDFUNC(2,jff_MULS32,(RW4 d, RR4 s))
{
	INIT_REGS_l(d, s);

	SMULL_xww(d, d, s);
	/* m68k_mull() derives N/Z from the full mathematical product even when
	   only Dl is selected; a non-zero overflow with low word zero is not Z. */
	TST_xx(d, d);

	if (needed_flags & FLAG_V) {
		/* V is set only when the full signed product is not the sign extension
		   of its low 32 bits.  Preserve the full-product N/Z/C result while
		   deriving V branchlessly from that exact comparison. */
		MRS_NZCV_x(REG_WORK4);
		SXTW_xw(REG_WORK1, d);
		CMP_xx(d, REG_WORK1);
		CSET_xc(REG_WORK2, NATIVE_CC_NE);
		ORR_xxxLSLi(REG_WORK4, REG_WORK4, REG_WORK2, 28);
		MSR_NZCV_x(REG_WORK4);
	}
	MOV_ww(d, d); // Clean upper 32 bits after 64-bit multiply (after overflow check reads upper bits)
	flags_carry_inverted = false;
	EXIT_REGS(d, s);
}
MENDFUNC(2,jff_MULS32,(RW4 d, RR4 s))

/* A 64-bit MULL has two architectural destinations and one read-only source.
   Stage both inputs in reserved work registers before acquiring either output;
   then publish high first and low second, matching m68k_mull() when dh == dl.
   This also keeps a distinct Dn source unchanged and makes source/destination
   aliases independent of allocator placement. */
#define STAGE_MULL32_OPERAND(vreg, workreg) do { \
	if (isconst(vreg)) { \
		LOAD_U32(workreg, live.state[vreg].val); \
	} else { \
		int _mull_input = readreg(vreg); \
		MOV_ww(workreg, _mull_input); \
		unlock2(_mull_input); \
	} \
} while (0)

#define PUBLISH_MULL64_RESULT(dl, dh) do { \
	int _mull_hi = writereg(dh); \
	LSR_xxi(_mull_hi, REG_WORK3, 32); \
	unlock2(_mull_hi); \
	int _mull_lo = writereg(dl); \
	MOV_ww(_mull_lo, REG_WORK3); \
	unlock2(_mull_lo); \
} while (0)

MIDFUNC(3,jnf_MULS64,(W4 dl, W4 dh, RR4 s))
{
	STAGE_MULL32_OPERAND(dl, REG_WORK1);
	STAGE_MULL32_OPERAND(s, REG_WORK2);
	SMULL_xww(REG_WORK3, REG_WORK1, REG_WORK2);
	PUBLISH_MULL64_RESULT(dl, dh);
}
MENDFUNC(3,jnf_MULS64,(W4 dl, W4 dh, RR4 s))

MIDFUNC(3,jff_MULS64,(W4 dl, W4 dh, RR4 s))
{
	STAGE_MULL32_OPERAND(dl, REG_WORK1);
	STAGE_MULL32_OPERAND(s, REG_WORK2);
	SMULL_xww(REG_WORK3, REG_WORK1, REG_WORK2);
	TST_xx(REG_WORK3, REG_WORK3);
	PUBLISH_MULL64_RESULT(dl, dh);

	/* A signed 32x32 product always fits in the selected 64-bit result. */
	flags_carry_inverted = false;
}
MENDFUNC(3,jff_MULS64,(W4 dl, W4 dh, RR4 s))

/*
 * MULU
 * Operand Syntax: 	<ea>, Dn
 *
 * Operand Size: 16
 *
 * X Not affected.
 * N Set if the result is negative. Cleared otherwise.
 * Z Set if the result is zero. Cleared otherwise.
 * V Set if overflow. Cleared otherwise. (32 Bit multiply only)
 * C Always cleared.
 *
 */
MIDFUNC(2,jnf_MULU,(RW4 d, RR4 s))
{
	if (isconst(s)) {
		uae_u16 tmp = (uae_u16)live.state[s].val;
		d = rmw(d);
		UNSIGNED16_IMM_2_REG(REG_WORK1, tmp);
		UNSIGNED16_REG_2_REG(d, d);
		UMULL_xww(d, d, REG_WORK1);
		MOV_ww(d, d); // Clean upper 32 bits after 64-bit multiply
		unlock2(d);
		return;
	}

	INIT_REGS_l(d, s);

	UNSIGNED16_REG_2_REG(d, d);
	UNSIGNED16_REG_2_REG(REG_WORK1, s);
	UMULL_xww(d, d, REG_WORK1);
	MOV_ww(d, d); // Clean upper 32 bits after 64-bit multiply

	EXIT_REGS(d, s);
}
MENDFUNC(2,jnf_MULU,(RW4 d, RR4 s))

MIDFUNC(2,jff_MULU,(RW4 d, RR4 s))
{
	if (isconst(s)) {
		uae_u16 tmp = (uae_u16)live.state[s].val;
		d = rmw(d);
		UNSIGNED16_IMM_2_REG(REG_WORK1, tmp);
		UNSIGNED16_REG_2_REG(d, d);
		UMULL_xww(d, d, REG_WORK1);
		MOV_ww(d, d); // Clean upper 32 bits after 64-bit multiply
		TST_ww(d, d);
		flags_carry_inverted = false;
		unlock2(d);
		return;
	}

	INIT_REGS_l(d, s);

	UNSIGNED16_REG_2_REG(d, d);
	UNSIGNED16_REG_2_REG(REG_WORK1, s);
	UMULL_xww(d, d, REG_WORK1);
	MOV_ww(d, d); // Clean upper 32 bits after 64-bit multiply
	TST_ww(d, d);

	flags_carry_inverted = false;
	EXIT_REGS(d, s);
}
MENDFUNC(2,jff_MULU,(RW4 d, RR4 s))

MIDFUNC(2,jnf_MULU32,(RW4 d, RR4 s))
{
	INIT_REGS_l(d, s);

	UMULL_xww(d, d, s);
	MOV_ww(d, d); // Clean upper 32 bits after 64-bit multiply

	EXIT_REGS(d, s);
}
MENDFUNC(2,jnf_MULU32,(RW4 d, RR4 s))

MIDFUNC(2,jff_MULU32,(RW4 d, RR4 s))
{
	INIT_REGS_l(d, s);

	UMULL_xww(d, d, s);
	/* Match m68k_mull(): N/Z describe the full unsigned 64-bit product. */
	TST_xx(d, d);

	if (needed_flags & FLAG_V) {
		/* V is the non-zero high half.  Avoid an instruction-count branch and
		   restore the full-product N/Z/C bits after the comparison. */
		MRS_NZCV_x(REG_WORK4);
		LSR_xxi(REG_WORK1, d, 32);
		CMP_xi(REG_WORK1, 0);
		CSET_xc(REG_WORK2, NATIVE_CC_NE);
		ORR_xxxLSLi(REG_WORK4, REG_WORK4, REG_WORK2, 28);
		MSR_NZCV_x(REG_WORK4);
	}
	MOV_ww(d, d); // Clean upper 32 bits after overflow and full-product flag tests

	flags_carry_inverted = false;
	EXIT_REGS(d, s);
}
MENDFUNC(2,jff_MULU32,(RW4 d, RR4 s))

MIDFUNC(3,jnf_MULU64,(W4 dl, W4 dh, RR4 s))
{
	STAGE_MULL32_OPERAND(dl, REG_WORK1);
	STAGE_MULL32_OPERAND(s, REG_WORK2);
	UMULL_xww(REG_WORK3, REG_WORK1, REG_WORK2);
	PUBLISH_MULL64_RESULT(dl, dh);
}
MENDFUNC(3,jnf_MULU64,(W4 dl, W4 dh, RR4 s))

MIDFUNC(3,jff_MULU64,(W4 dl, W4 dh, RR4 s))
{
	STAGE_MULL32_OPERAND(dl, REG_WORK1);
	STAGE_MULL32_OPERAND(s, REG_WORK2);
	UMULL_xww(REG_WORK3, REG_WORK1, REG_WORK2);
	TST_xx(REG_WORK3, REG_WORK3);
	PUBLISH_MULL64_RESULT(dl, dh);

	/* An unsigned 32x32 product always fits in the selected 64-bit result. */
	flags_carry_inverted = false;
}
MENDFUNC(3,jff_MULU64,(W4 dl, W4 dh, RR4 s))

#undef PUBLISH_MULL64_RESULT
#undef STAGE_MULL32_OPERAND

/*
 * NEG
 * Operand Syntax: <ea>
 *
 * Operand Size: 8,16,32
 *
 * X Set the same as the carry bit.
 * N Set if the result is negative. Cleared otherwise.
 * Z Set if the result is zero. Cleared otherwise.
 * V Set if an overflow occurs. Cleared otherwise.
 * C Set if a borrow occurs. Cleared otherwise.
 *
 */
MIDFUNC(1,jnf_NEG_b,(RW1 d))
{
	INIT_REG_b(d);

	SIGNED8_REG_2_REG(REG_WORK1, d);
	NEG_ww(REG_WORK1, REG_WORK1);
	BFI_wwii(d, REG_WORK1, 0, 8);

	unlock2(d);
}
MENDFUNC(1,jnf_NEG_b,(RW1 d))

MIDFUNC(1,jnf_NEG_w,(RW2 d))
{
	INIT_REG_w(d);

	SIGNED16_REG_2_REG(REG_WORK1, d);
	NEG_ww(REG_WORK1, REG_WORK1);
	BFI_wwii(d, REG_WORK1, 0, 16);

	unlock2(d);
}
MENDFUNC(1,jnf_NEG_w,(RW2 d))

MIDFUNC(1,jnf_NEG_l,(RW4 d))
{
	d = rmw(d);

	NEG_ww(d, d);

	unlock2(d);
}
MENDFUNC(1,jnf_NEG_l,(RW4 d))

MIDFUNC(1,jff_NEG_b,(RW1 d))
{
	INIT_REG_b(d);

	SIGNED8_REG_2_REG(REG_WORK1, d);
	NEGS_ww(REG_WORK1, REG_WORK1);
	BFI_wwii(d, REG_WORK1, 0, 8);

	flags_carry_inverted = true;
	DUPLICACTE_CARRY

	unlock2(d);
}
MENDFUNC(1,jff_NEG_b,(RW1 d))

MIDFUNC(1,jff_NEG_w,(RW2 d))
{
	INIT_REG_w(d);

	SIGNED16_REG_2_REG(REG_WORK1, d);
	NEGS_ww(REG_WORK1, REG_WORK1);
	BFI_wwii(d, REG_WORK1, 0, 16);

	flags_carry_inverted = true;
	DUPLICACTE_CARRY

	unlock2(d);
}
MENDFUNC(1,jff_NEG_w,(RW2 d))

MIDFUNC(1,jff_NEG_l,(RW4 d))
{
	d = rmw(d);

	NEGS_ww(d, d);

	flags_carry_inverted = true;
	DUPLICACTE_CARRY

	unlock2(d);
}
MENDFUNC(1,jff_NEG_l,(RW4 d))

/*
 * NEGX
 * Operand Syntax: <ea>
 *
 * Operand Size: 8,16,32
 *
 * X Set the same as the carry bit.
 * N Set if the result is negative. Cleared otherwise.
 * Z Cleared if the result is nonzero; unchanged otherwise.
 * V Set if an overflow occurs. Cleared otherwise.
 * C Set if a borrow occurs. Cleared otherwise.
 *
 * Attention: Z is cleared only if the result is nonzero. Unchanged otherwise
 *
 */
MIDFUNC(1,jnf_NEGX_b,(RW1 d))
{
	int x = readreg(FLAGX);
	INIT_REG_b(d);
	clobber_flags();

	// Restore inverted X to carry (don't care about other flags)
	NEGS_ww(REG_WORK1, x);

	SIGNED8_REG_2_REG(REG_WORK1, d);
	NGC_ww(REG_WORK1, REG_WORK1);
	BFI_wwii(d, REG_WORK1, 0, 8);

	unlock2(d);
	unlock2(x);
}
MENDFUNC(1,jnf_NEGX_b,(RW1 d))

MIDFUNC(1,jnf_NEGX_w,(RW2 d))
{
	int x = readreg(FLAGX);
	INIT_REG_w(d);

	clobber_flags();

	// Restore inverted X to carry (don't care about other flags)
	NEGS_ww(REG_WORK1, x);

	SIGNED16_REG_2_REG(REG_WORK1, d);
	NGC_ww(REG_WORK1, REG_WORK1);
	BFI_wwii(d, REG_WORK1, 0, 16);

	unlock2(d);
	unlock2(x);
}
MENDFUNC(1,jnf_NEGX_w,(RW2 d))

MIDFUNC(1,jnf_NEGX_l,(RW4 d))
{
	int x = readreg(FLAGX);
	d = rmw(d);

	clobber_flags();

	// Restore inverted X to carry (don't care about other flags)
	NEGS_ww(REG_WORK1, x);

	NGC_ww(d, d);

	unlock2(d);
	unlock2(x);
}
MENDFUNC(1,jnf_NEGX_l,(RW4 d))

MIDFUNC(1,jff_NEGX_b,(RW1 d))
{
	INIT_REG_b(d);
	int x = rmw(FLAGX);

	MOVN_xi(REG_WORK2, 0);
	MOVN_xish(REG_WORK1, 0x4000, 16); // inverse Z flag
	CSEL_xxxc(REG_WORK2, REG_WORK1, REG_WORK2, NATIVE_CC_NE);

	// Restore inverted X to carry (don't care about other flags)
	NEGS_ww(REG_WORK1, x);

	SIGNED8_REG_2_REG(REG_WORK1, d);
	NGCS_ww(REG_WORK1, REG_WORK1);
	BFI_wwii(d, REG_WORK1, 0, 8);

	MRS_NZCV_x(REG_WORK4);
	EOR_xxCflag(REG_WORK4, REG_WORK4);
	AND_www(REG_WORK4, REG_WORK4, REG_WORK2);
	MSR_NZCV_x(REG_WORK4);
	flags_carry_inverted = false;
	if (needed_flags & FLAG_X)
		UBFX_wwii(x, REG_WORK4, 29, 1); // Duplicate carry

	unlock2(x);
	unlock2(d);
}
MENDFUNC(1,jff_NEGX_b,(RW1 d))

MIDFUNC(1,jff_NEGX_w,(RW2 d))
{
	INIT_REG_w(d);
	int x = rmw(FLAGX);

	MOVN_xi(REG_WORK2, 0);
	MOVN_xish(REG_WORK1, 0x4000, 16); // inverse Z flag
	CSEL_xxxc(REG_WORK2, REG_WORK1, REG_WORK2, NATIVE_CC_NE);

	// Restore inverted X to carry (don't care about other flags)
	NEGS_ww(REG_WORK1, x);

	SIGNED16_REG_2_REG(REG_WORK1, d);
	NGCS_ww(REG_WORK1, REG_WORK1);
	BFI_wwii(d, REG_WORK1, 0, 16);

	MRS_NZCV_x(REG_WORK4);
	EOR_xxCflag(REG_WORK4, REG_WORK4);
	AND_www(REG_WORK4, REG_WORK4, REG_WORK2);
	MSR_NZCV_x(REG_WORK4);
	flags_carry_inverted = false;
	if (needed_flags & FLAG_X)
		UBFX_wwii(x, REG_WORK4, 29, 1); // Duplicate carry

	unlock2(x);
	unlock2(d);
}
MENDFUNC(1,jff_NEGX_w,(RW2 d))

MIDFUNC(1,jff_NEGX_l,(RW4 d))
{
	d = rmw(d);
	int x = rmw(FLAGX);

	MOVN_xi(REG_WORK2, 0);
	MOVN_xish(REG_WORK1, 0x4000, 16); // inverse Z flag
	CSEL_xxxc(REG_WORK2, REG_WORK1, REG_WORK2, NATIVE_CC_NE);

	// Restore inverted X to carry (don't care about other flags)
	NEGS_ww(REG_WORK1, x);

	NGCS_ww(d, d);

	MRS_NZCV_x(REG_WORK4);
	EOR_xxCflag(REG_WORK4, REG_WORK4);
	AND_www(REG_WORK4, REG_WORK4, REG_WORK2);
	MSR_NZCV_x(REG_WORK4);
	flags_carry_inverted = false;
	if (needed_flags & FLAG_X)
		UBFX_wwii(x, REG_WORK4, 29, 1); // Duplicate carry

	unlock2(x);
	unlock2(d);
}
MENDFUNC(1,jff_NEGX_l,(RW4 d))

/*
 * NOT
 * Operand Syntax: <ea>
 *
 * Operand Size: 8,16,32
 *
 * X Not affected.
 * N Set if the result is negative. Cleared otherwise.
 * Z Set if the result is zero. Cleared otherwise.
 * V Always cleared.
 * C Always cleared.
 *
 */
MIDFUNC(1,jnf_NOT_b,(RW1 d))
{
	if (isconst(d)) {
		live.state[d].val = (live.state[d].val & 0xffffff00) | ((~live.state[d].val) & 0x000000ff);
		return;
	}

	INIT_REG_b(d);

	if(targetIsReg) {
		MVN_ww(REG_WORK1, d);
		BFI_wwii(d, REG_WORK1, 0, 8);
	} else {
		MVN_ww(d, d);
	}

	unlock2(d);
}
MENDFUNC(1,jnf_NOT_b,(RW1 d))

MIDFUNC(1,jnf_NOT_w,(RW2 d))
{
	if (isconst(d)) {
		live.state[d].val = (live.state[d].val & 0xffff0000) | ((~live.state[d].val) & 0x0000ffff);
		return;
	}

	INIT_REG_w(d);

	if(targetIsReg) {
		MVN_ww(REG_WORK1, d);
		BFI_wwii(d, REG_WORK1, 0, 16);
	} else {
		MVN_ww(d, d);
	}

	unlock2(d);
}
MENDFUNC(1,jnf_NOT_w,(RW2 d))

MIDFUNC(1,jnf_NOT_l,(RW4 d))
{
	if (isconst(d)) {
		live.state[d].val = ~live.state[d].val;
		return;
	}

	d = rmw(d);

	MVN_ww(d, d);

	unlock2(d);
}
MENDFUNC(1,jnf_NOT_l,(RW4 d))

MIDFUNC(1,jff_NOT_b,(RW1 d))
{
	INIT_REG_b(d);

	SIGNED8_REG_2_REG(REG_WORK1, d);
	if(targetIsReg) {
		MVN_ww(REG_WORK1, REG_WORK1);
		BFI_wwii(d, REG_WORK1, 0, 8);
		TST_ww(REG_WORK1, REG_WORK1);
	} else {
		MVN_ww(d, REG_WORK1);
		TST_ww(d, d);
	}

	flags_carry_inverted = false;
	unlock2(d);
}
MENDFUNC(1,jff_NOT_b,(RW1 d))

MIDFUNC(1,jff_NOT_w,(RW2 d))
{
	INIT_REG_w(d);

	SIGNED16_REG_2_REG(REG_WORK1, d);
	if(targetIsReg) {
		MVN_ww(REG_WORK1, REG_WORK1);
		BFI_wwii(d, REG_WORK1, 0, 16);
		TST_ww(REG_WORK1, REG_WORK1);
	} else {
		MVN_ww(d, REG_WORK1);
		TST_ww(d, d);
	}

	flags_carry_inverted = false;
	unlock2(d);
}
MENDFUNC(1,jff_NOT_w,(RW2 d))

MIDFUNC(1,jff_NOT_l,(RW4 d))
{
	d = rmw(d);

	MVN_ww(d, d);
	TST_ww(d, d);

	flags_carry_inverted = false;
	unlock2(d);
}
MENDFUNC(1,jff_NOT_l,(RW4 d))

/*
 * OR
 * Operand Syntax: 	<ea>, Dn
 *  				Dn, <ea>
 *
 * Operand Size: 8,16,32
 *
 * X Not affected.
 * N Set if the most significant bit of the result is set. Cleared otherwise.
 * Z Set if the result is zero. Cleared otherwise.
 * V Always cleared.
 * C Always cleared.
 *
 */
MIDFUNC(2,jnf_OR_b_imm,(RW1 d, IM8 v))
{
	if (isconst(d)) {
		live.state[d].val = (live.state[d].val & 0xffffff00) | ((live.state[d].val | v) & 0x000000ff);
		return;
	}

	INIT_REG_b(d);

	MOV_xi(REG_WORK2, v & 0xff);
	ORR_www(d, d, REG_WORK2);

	unlock2(d);
}
MENDFUNC(2,jnf_OR_b_imm,(RW1 d, IM8 v))

MIDFUNC(2,jnf_OR_b,(RW1 d, RR1 s))
{
	if (isconst(s)) {
		COMPCALL(jnf_OR_b_imm)(d, live.state[s].val);
		return;
	}

	INIT_REGS_b(d, s);

	if(targetIsReg) {
		ORR_www(REG_WORK1, d, s);
		BFI_wwii(d, REG_WORK1, 0, 8);
	} else {
		ORR_www(d, d, s);
	}

	EXIT_REGS(d, s);
}
MENDFUNC(2,jnf_OR_b,(RW1 d, RR1 s))

MIDFUNC(2,jnf_OR_w_imm,(RW2 d, IM16 v))
{
	if (isconst(d)) {
		live.state[d].val = (live.state[d].val & 0xffff0000) | ((live.state[d].val | v) & 0x0000ffff);
		return;
	}

	INIT_REG_w(d);

	MOV_xi(REG_WORK1, v & 0xffff);
	ORR_www(d, d, REG_WORK1);

	unlock2(d);
}
MENDFUNC(2,jnf_OR_w_imm,(RW2 d, IM16 v))

MIDFUNC(2,jnf_OR_w,(RW2 d, RR2 s))
{
	if (isconst(s)) {
		COMPCALL(jnf_OR_w_imm)(d, live.state[s].val);
		return;
	}

	INIT_REGS_w(d, s);

	if(targetIsReg) {
		ORR_www(REG_WORK1, d, s);
		BFI_wwii(d, REG_WORK1, 0, 16);
	} else {
		ORR_www(d, d, s);
	}

	EXIT_REGS(d, s);
}
MENDFUNC(2,jnf_OR_w,(RW2 d, RR2 s))

MIDFUNC(2,jnf_OR_l_imm,(RW4 d, IM32 v))
{
	if (isconst(d)) {
		live.state[d].val = live.state[d].val | v;
		return;
	}

	d = rmw(d);

	LOAD_U32(REG_WORK1, v);
	ORR_www(d, d, REG_WORK1);

	unlock2(d);
}
MENDFUNC(2,jnf_OR_l_imm,(RW4 d, IM32 v))

MIDFUNC(2,jnf_OR_l,(RW4 d, RR4 s))
{
	if (isconst(s)) {
		COMPCALL(jnf_OR_l_imm)(d, live.state[s].val);
		return;
	}

	INIT_REGS_l(d, s);

	ORR_www(d, d, s);

	EXIT_REGS(d, s);
}
MENDFUNC(2,jnf_OR_l,(RW4 d, RR4 s))

MIDFUNC(2,jff_OR_b_imm,(RW1 d, IM8 v))
{
	INIT_REG_b(d);

	SIGNED8_REG_2_REG(REG_WORK1, d);
	SIGNED8_IMM_2_REG(REG_WORK2, v);
	if(targetIsReg) {
		ORR_www(REG_WORK1, REG_WORK1, REG_WORK2);
		TST_ww(REG_WORK1, REG_WORK1);
		BFI_wwii(d, REG_WORK1, 0, 8);
	} else {
		ORR_www(d, REG_WORK1, REG_WORK2);
		TST_ww(d, d);
	}

	flags_carry_inverted = false;
	unlock2(d);
}
MENDFUNC(2,jff_OR_b_imm,(RW1 d, IM8 v))

MIDFUNC(2,jff_OR_b,(RW1 d, RR1 s))
{
	if (isconst(s)) {
		COMPCALL(jff_OR_b_imm)(d, live.state[s].val);
		return;
	}

	INIT_REGS_b(d, s);

	SIGNED8_REG_2_REG(REG_WORK1, d);
	SIGNED8_REG_2_REG(REG_WORK2, s);
	if(targetIsReg) {
		ORR_www(REG_WORK1, REG_WORK1, REG_WORK2);
		TST_ww(REG_WORK1, REG_WORK1);
		BFI_wwii(d, REG_WORK1, 0, 8);
	} else {
		ORR_www(d, REG_WORK1, REG_WORK2);
		TST_ww(d, d);
	}

	flags_carry_inverted = false;
	EXIT_REGS(d, s);
}
MENDFUNC(2,jff_OR_b,(RW1 d, RR1 s))

MIDFUNC(2,jff_OR_w_imm,(RW2 d, IM16 v))
{
	INIT_REG_w(d);

	SIGNED16_REG_2_REG(REG_WORK1, d);
	SIGNED16_IMM_2_REG(REG_WORK2, v);
	if(targetIsReg) {
		ORR_www(REG_WORK1, REG_WORK1, REG_WORK2);
		TST_ww(REG_WORK1, REG_WORK1);
		BFI_wwii(d, REG_WORK1, 0, 16);
	} else {
		ORR_www(d, REG_WORK1, REG_WORK2);
		TST_ww(d, d);
	}

	flags_carry_inverted = false;
	unlock2(d);
}
MENDFUNC(2,jff_OR_w_imm,(RW2 d, IM16 v))

MIDFUNC(2,jff_OR_w,(RW2 d, RR2 s))
{
	if (isconst(s)) {
		COMPCALL(jff_OR_w_imm)(d, live.state[s].val);
		return;
	}

	INIT_REGS_w(d, s);

	SIGNED16_REG_2_REG(REG_WORK1, d);
	SIGNED16_REG_2_REG(REG_WORK2, s);
	if(targetIsReg) {
		ORR_www(REG_WORK1, REG_WORK1, REG_WORK2);
		TST_ww(REG_WORK1, REG_WORK1);
		BFI_wwii(d, REG_WORK1, 0, 16);
	} else {
		ORR_www(d, REG_WORK1, REG_WORK2);
		TST_ww(d, d);
	}

	flags_carry_inverted = false;
	EXIT_REGS(d, s);
}
MENDFUNC(2,jff_OR_w,(RW2 d, RR2 s))

MIDFUNC(2,jff_OR_l_imm,(RW4 d, IM32 v))
{
	d = rmw(d);

	LOAD_U32(REG_WORK1, v);
	ORR_www(d, d, REG_WORK1);
	TST_ww(d, d);

	flags_carry_inverted = false;
	unlock2(d);
}
MENDFUNC(2,jff_OR_l_imm,(RW4 d, IM32 v))

MIDFUNC(2,jff_OR_l,(RW4 d, RR4 s))
{
	if (isconst(s)) {
		COMPCALL(jff_OR_l_imm)(d, live.state[s].val);
		return;
	}

	INIT_REGS_l(d, s);

	ORR_www(d, d, s);
	TST_ww(d, d);

	flags_carry_inverted = false;
	EXIT_REGS(d, s);
}
MENDFUNC(2,jff_OR_l,(RW4 d, RR4 s))

/*
 * ORSR
 * Operand Syntax: 	#<data>, CCR
 *
 * Operand Size: 8
 *
 * X — Set if bit 4 of immediate operand is one; unchanged otherwise.
 * N — Set if bit 3 of immediate operand is one; unchanged otherwise.
 * Z — Set if bit 2 of immediate operand is one; unchanged otherwise.
 * V — Set if bit 1 of immediate operand is one; unchanged otherwise.
 * C — Set if bit 0 of immediate operand is one; unchanged otherwise.
 *
 */
MIDFUNC(1,jff_ORSR,(IM32 s, IM8 x))
{
	MRS_NZCV_x(REG_WORK1);
	if (flags_carry_inverted) {
		EOR_xxCflag(REG_WORK1, REG_WORK1);
		flags_carry_inverted = false;
	}
	MOV_xish(REG_WORK2, (s >> 16), 16);
	ORR_www(REG_WORK1, REG_WORK1, REG_WORK2);
	MSR_NZCV_x(REG_WORK1);

	if (x) {
		int f = writereg(FLAGX);
		MOV_wi(f, 1);
		unlock2(f);
	}
}
MENDFUNC(2,jff_ORSR,(IM32 s, IM8 x))

/*
 * ROL
 * Operand Syntax: 	Dx, Dy
 * 					#<data>, Dy
 *					<ea>
 *
 * Operand Size: 8,16,32
 *
 * X Not affected.
 * N Set if the most significant bit of the result is set. Cleared otherwise.
 * Z Set if the result is zero. Cleared otherwise.
 * V Always cleared.
 * C Set according to the last bit rotated out of the operand. Cleared when the rotate count is zero.
 *
 */
MIDFUNC(2,jnf_ROL_b_imm,(RW1 d, IM8 i))
{
	if(i & 0x1f) {
		INIT_REG_b(d);

		LSL_wwi(REG_WORK1, d, 24);
		ORR_wwwLSRi(REG_WORK1, REG_WORK1, REG_WORK1, 8);
		ORR_wwwLSRi(REG_WORK1, REG_WORK1, REG_WORK1, 16);
		ROR_wwi(REG_WORK1, REG_WORK1, (32 - (i & 0x1f)));
		BFI_wwii(d, REG_WORK1, 0, 8);

		unlock2(d);
	}
}
MENDFUNC(2,jnf_ROL_b_imm,(RW1 d, IM8 i))

MIDFUNC(2,jnf_ROL_w_imm,(RW2 d, IM8 i))
{
	if(i & 0x1f) {
		INIT_REG_w(d);

		MOV_ww(REG_WORK1, d);
		BFI_wwii(REG_WORK1, REG_WORK1, 16, 16);
		ROR_wwi(REG_WORK1, REG_WORK1, (32 - (i & 0x1f)));
		BFI_wwii(d, REG_WORK1, 0, 16);

		unlock2(d);
	}
}
MENDFUNC(2,jnf_ROL_w_imm,(RW2 d, IM8 i))

MIDFUNC(2,jnf_ROL_l_imm,(RW4 d, IM8 i))
{
	if(i & 0x1f) {
		if (isconst(d)) {
			i = i & 31;
			live.state[d].val = (live.state[d].val << i) | (live.state[d].val >> (32-i));
			return;
		}

		d = rmw(d);

		ROR_wwi(d, d, (32 - (i & 0x1f)));

		unlock2(d);
	}
}
MENDFUNC(2,jnf_ROL_l_imm,(RW4 d, RR4 s, IM8 i))

MIDFUNC(2,jff_ROL_b_imm,(RW1 d, IM8 i))
{
	if(i)
		d = rmw(d);
	else
		d = readreg(d);

	LSL_wwi(REG_WORK1, d, 24);
	if (i) {
		ORR_wwwLSRi(REG_WORK1, REG_WORK1, REG_WORK1, 8);
		ORR_wwwLSRi(REG_WORK1, REG_WORK1, REG_WORK1, 16);
		if(i & 0x1f) {
			ROR_wwi(REG_WORK1, REG_WORK1, (32 - (i & 0x1f)));
		}
		TST_ww(REG_WORK1, REG_WORK1);
		BFI_wwii(d, REG_WORK1, 0, 8);

		MRS_NZCV_x(REG_WORK4);
		BFI_wwii(REG_WORK4, REG_WORK1, 29, 1); // Handle C flag
		MSR_NZCV_x(REG_WORK4);
	} else {
		TST_ww(REG_WORK1, REG_WORK1);
	}

	flags_carry_inverted = false;
	unlock2(d);
}
MENDFUNC(2,jff_ROL_b_imm,(RW1 d, IM8 i))

MIDFUNC(2,jff_ROL_w_imm,(RW2 d, IM8 i))
{
	if(i)
		d = rmw(d);
	else
		d = readreg(d);

	MOV_ww(REG_WORK1, d);
	BFI_wwii(REG_WORK1, REG_WORK1, 16, 16);
	if (i) {
		if(i & 0x1f)
			ROR_wwi(REG_WORK1, REG_WORK1, (32 - (i & 0x1f)));
		TST_ww(REG_WORK1, REG_WORK1);
		BFI_wwii(d, REG_WORK1, 0, 16);

		MRS_NZCV_x(REG_WORK4);
		BFI_wwii(REG_WORK4, REG_WORK1, 29, 1); // Handle C flag
		MSR_NZCV_x(REG_WORK4);
	} else {
		TST_ww(REG_WORK1, REG_WORK1);
	}

	flags_carry_inverted = false;
	unlock2(d);
}
MENDFUNC(2,jff_ROL_w_imm,(RW2 d, IM8 i))

MIDFUNC(2,jff_ROL_l_imm,(RW4 d, IM8 i))
{
	if (i) {
		if(i & 0x1f) {
			d = rmw(d);
			ROR_wwi(d, d, (32 - (i & 0x1f)));
		} else {
			d = readreg(d);
		}
		TST_ww(d, d);

		MRS_NZCV_x(REG_WORK4);
		BFI_wwii(REG_WORK4, d, 29, 1); // Handle C flag
		MSR_NZCV_x(REG_WORK4);
	} else {
		d = readreg(d);
		TST_ww(d, d);
	}

	flags_carry_inverted = false;
	unlock2(d);
}
MENDFUNC(2,jff_ROL_l_imm,(RW4 d, IM8 i))

MIDFUNC(2,jnf_ROL_b,(RW1 d, RR4 i))
{
	if (isconst(i)) {
		COMPCALL(jnf_ROL_b_imm)(d, (uae_u8)(live.state[i].val & 0x3f));
		return;
	}

	i = readreg(i);
	d = rmw(d);

	AND_ww3f(REG_WORK1, i);
	MOV_wi(REG_WORK2, 32);
	SUB_www(REG_WORK1, REG_WORK2, REG_WORK1);

	LSL_wwi(REG_WORK2, d, 24);
	ORR_wwwLSRi(REG_WORK2, REG_WORK2, REG_WORK2, 8);
	ORR_wwwLSRi(REG_WORK2, REG_WORK2, REG_WORK2, 16);
	ROR_www(REG_WORK2, REG_WORK2, REG_WORK1);
	BFI_wwii(d, REG_WORK2, 0, 8);

	unlock2(d);
	unlock2(i);
}
MENDFUNC(2,jnf_ROL_b,(RW1 d, RR4 i))

MIDFUNC(2,jnf_ROL_w,(RW2 d, RR4 i))
{
	if (isconst(i)) {
		COMPCALL(jnf_ROL_w_imm)(d, (uae_u8)(live.state[i].val & 0x3f));
		return;
	}

	i = readreg(i);
	d = rmw(d);

	AND_ww3f(REG_WORK1, i);
	MOV_wi(REG_WORK2, 32);
	SUB_www(REG_WORK1, REG_WORK2, REG_WORK1);

	MOV_ww(REG_WORK2, d);
	BFI_wwii(REG_WORK2, REG_WORK2, 16, 16);
	ROR_www(REG_WORK2, REG_WORK2, REG_WORK1);
	BFI_wwii(d, REG_WORK2, 0, 16);

	unlock2(d);
	unlock2(i);
}
MENDFUNC(2,jnf_ROL_w,(RW2 d, RR4 i))

MIDFUNC(2,jnf_ROL_l,(RW4 d, RR4 i))
{
	if (isconst(i)) {
		COMPCALL(jnf_ROL_l_imm)(d, (uae_u8)(live.state[i].val & 0x3f));
		return;
	}

	i = readreg(i);
	d = rmw(d);

	AND_ww3f(REG_WORK1, i);
	MOV_wi(REG_WORK2, 32);
	SUB_www(REG_WORK1, REG_WORK2, REG_WORK1);

	ROR_www(d, d, REG_WORK1);

	unlock2(d);
	unlock2(i);
}
MENDFUNC(2,jnf_ROL_l,(RW4 d, RR4 i))

MIDFUNC(2,jff_ROL_b,(RW1 d, RR4 i))
{
	if (isconst(i)) {
		COMPCALL(jff_ROL_b_imm)(d, (uae_u8)(live.state[i].val & 0x3f));
		return;
	}

	i = readreg(i);
	d = rmw(d);

	ANDS_ww3f(REG_WORK1, i);
	uae_u32* branch_rotate_nonzero = (uae_u32*)get_target();
	BNE_i(0);

	// rotate count is 0
	LSL_wwi(REG_WORK3, d, 24);
	TST_ww(REG_WORK3, REG_WORK3);     // NZ correct, VC cleared
	uae_u32* branchadd = (uae_u32*)get_target();
	B_i(0); // <end>

	write_jmp_target(branch_rotate_nonzero, (uintptr)get_target());
	MOV_wi(REG_WORK2, 32);
	SUB_www(REG_WORK1, REG_WORK2, REG_WORK1);

	LSL_wwi(REG_WORK2, d, 24);
	ORR_wwwLSRi(REG_WORK2, REG_WORK2, REG_WORK2, 8);
	ORR_wwwLSRi(REG_WORK2, REG_WORK2, REG_WORK2, 16);
	ROR_www(REG_WORK2, REG_WORK2, REG_WORK1);
	BFI_wwii(d, REG_WORK2, 0, 8);
	TST_ww(REG_WORK2, REG_WORK2);

	MRS_NZCV_x(REG_WORK4);
	BFI_wwii(REG_WORK4, d, 29, 1); // Handle C flag
	MSR_NZCV_x(REG_WORK4);

	// <end>
	write_jmp_target(branchadd, (uintptr)get_target());

	flags_carry_inverted = false;
	unlock2(d);
	unlock2(i);
}
MENDFUNC(2,jff_ROL_b,(RW1 d, RR4 i))

MIDFUNC(2,jff_ROL_w,(RW2 d, RR4 i))
{
	if (isconst(i)) {
		COMPCALL(jff_ROL_w_imm)(d, (uae_u8)(live.state[i].val & 0x3f));
		return;
	}

	i = readreg(i);
	d = rmw(d);

	ANDS_ww3f(REG_WORK1, i);
	uae_u32* branch_rotate_nonzero = (uae_u32*)get_target();
	BNE_i(0);

	// rotate count is 0
	LSL_wwi(REG_WORK3, d, 16);
	TST_ww(REG_WORK3, REG_WORK3);     // NZ correct, VC cleared
	uae_u32* branchadd = (uae_u32*)get_target();
	B_i(0); // <end>

	write_jmp_target(branch_rotate_nonzero, (uintptr)get_target());
	MOV_wi(REG_WORK2, 32);
	SUB_www(REG_WORK1, REG_WORK2, REG_WORK1);

	MOV_ww(REG_WORK2, d);
	BFI_wwii(REG_WORK2, REG_WORK2, 16, 16);
	ROR_www(REG_WORK2, REG_WORK2, REG_WORK1);
	BFI_wwii(d, REG_WORK2, 0, 16);
	TST_ww(REG_WORK2, REG_WORK2);

	MRS_NZCV_x(REG_WORK4);
	BFI_wwii(REG_WORK4, d, 29, 1); // Handle C flag
	MSR_NZCV_x(REG_WORK4);

	// <end>
	write_jmp_target(branchadd, (uintptr)get_target());

	flags_carry_inverted = false;
	unlock2(d);
	unlock2(i);
}
MENDFUNC(2,jff_ROL_w,(RW2 d, RR4 i))

MIDFUNC(2,jff_ROL_l,(RW4 d, RR4 i))
{
	if (isconst(i)) {
		COMPCALL(jff_ROL_l_imm)(d, (uae_u8)(live.state[i].val & 0x3f));
		return;
	}

	i = readreg(i);
	d = rmw(d);

	ANDS_ww3f(REG_WORK1, i);
	uae_u32* branch_rotate_nonzero = (uae_u32*)get_target();
	BNE_i(0);

	// rotate count is 0
	TST_ww(d, d);     // NZ correct, VC cleared
	uae_u32* branchadd = (uae_u32*)get_target();
	B_i(0); // <end>

	write_jmp_target(branch_rotate_nonzero, (uintptr)get_target());
	MOV_wi(REG_WORK2, 32);
	SUB_www(REG_WORK1, REG_WORK2, REG_WORK1);

	ROR_www(d, d, REG_WORK1);
	TST_ww(d, d);

	MRS_NZCV_x(REG_WORK4);
	BFI_wwii(REG_WORK4, d, 29, 1); // Handle C flag
	MSR_NZCV_x(REG_WORK4);

	// <end>
	write_jmp_target(branchadd, (uintptr)get_target());

	flags_carry_inverted = false;
	unlock2(d);
	unlock2(i);
}
MENDFUNC(2,jff_ROL_l,(RW4 d, RR4 i))

/*
 * ROLW
 * Operand Syntax: 	<ea>
 *
 * Operand Size: 16
 *
 * X Not affected.
 * N Set if the most significant bit of the result is set. Cleared otherwise.
 * Z Set if the result is zero. Cleared otherwise.
 * V Always cleared.
 * C Set according to the last bit rotated out of the operand. Cleared when the rotate count is zero.
 *
 * Target is never a register.
 */
MIDFUNC(1,jnf_ROLW,(RW2 d))
{
	d = rmw(d);

	BFI_wwii(d, d, 16, 16);
	ROR_wwi(d, d, (32 - 1));

	unlock2(d);
}
MENDFUNC(1,jnf_ROLW,(RW2 d))

MIDFUNC(1,jff_ROLW,(RW2 d))
{
	d = rmw(d);

	BFI_wwii(d, d, 16, 16);
	ROR_wwi(d, d, (32 - 1));
	TST_ww(d, d);

	MRS_NZCV_x(REG_WORK4);
	BFI_wwii(REG_WORK4, d, 29, 1); // Handle C flag
	MSR_NZCV_x(REG_WORK4);

	flags_carry_inverted = false;
	unlock2(d);
}
MENDFUNC(1,jff_ROLW,(RW2 d))

/*
 * ROXL
 * Operand Syntax: Dx, Dy
 * 				   #<data>, Dy
 *
 * Operand Size: 8,16,32
 *
 * X Set according to the last bit rotated out of the operand. Unchanged when the rotate count is zero.
 * N Set if the most significant bit of the result is set. Cleared otherwise.
 * Z Set if the result is zero. Cleared otherwise.
 * V Always cleared.
 * C Set according to the last bit rotated out of the operand. For an effective
 *   count of zero, X is unchanged and copied to C.
 *
 */
MIDFUNC(2,jnf_ROXL_b,(RW1 d, RR4 i))
{
	int x = readreg(FLAGX);
	INIT_REGS_b(d, i);

	clobber_flags();

	AND_ww3f(REG_WORK1, i);
	CMP_wi(REG_WORK1, 35);
	BLE_i(2);
	SUB_wwi(REG_WORK1, REG_WORK1, 36);
	CMP_wi(REG_WORK1, 17);
	BLE_i(2);
	SUB_wwi(REG_WORK1, REG_WORK1, 18);
	CMP_wi(REG_WORK1, 8);
	BLE_i(2);
	SUB_wwi(REG_WORK1, REG_WORK1, 9);
	uae_u32* branchadd = (uae_u32*)get_target();
	CBZ_wi(REG_WORK1, 0);			// end of op

	// need to rotate
	MOV_ww(REG_WORK2, d);
	BFI_wwii(REG_WORK2, x, 8, 1);         // move x to left side of d
	BFI_wwii(REG_WORK2, REG_WORK2, 9, 9); // duplicate 9 bits

	MOV_wi(REG_WORK3, 9);
	SUB_www(REG_WORK3, REG_WORK3, REG_WORK1);
	LSR_www(REG_WORK2, REG_WORK2, REG_WORK3);

	BFI_wwii(d, REG_WORK2, 0, 8);

	// end of op
	write_jmp_target(branchadd, (uintptr)get_target());

	unlock2(x);
	EXIT_REGS(d, i);
}
MENDFUNC(2,jnf_ROXL_b,(RW1 d, RR4 i))

MIDFUNC(2,jnf_ROXL_w,(RW2 d, RR4 i))
{
	int x = readreg(FLAGX);
	INIT_REGS_w(d, i);

	clobber_flags();

	AND_ww3f(REG_WORK1, i);
	CMP_wi(REG_WORK1, 33);
	BLE_i(2);
	SUB_wwi(REG_WORK1, REG_WORK1, 34);
	CMP_wi(REG_WORK1, 16);
	BLE_i(2);
	SUB_wwi(REG_WORK1, REG_WORK1, 17);
	uae_u32* branchadd = (uae_u32*)get_target();
	CBZ_wi(REG_WORK1, 0);			// end of op

	// need to rotate
	MOV_ww(REG_WORK2, d);
	BFI_wwii(REG_WORK2, x, 16, 1);          // move x to left side of d
	BFI_xxii(REG_WORK2, REG_WORK2, 17, 17); // duplicate 17 bits

	MOV_wi(REG_WORK3, 17);
	SUB_www(REG_WORK3, REG_WORK3, REG_WORK1);
	LSR_xxx(REG_WORK2, REG_WORK2, REG_WORK3);

	BFI_wwii(d, REG_WORK2, 0, 16);

	// end of op
	write_jmp_target(branchadd, (uintptr)get_target());

	unlock2(x);
	EXIT_REGS(d, i);
}
MENDFUNC(2,jnf_ROXL_w,(RW2 d, RR4 i))

MIDFUNC(2,jnf_ROXL_l,(RW4 d, RR4 i))
{
	int x = readreg(FLAGX);
	INIT_REGS_l(d, i);

	clobber_flags();

	AND_ww3f(REG_WORK1, i);
	CMP_wi(REG_WORK1, 32);
	BLE_i(2);
	SUB_wwi(REG_WORK1, REG_WORK1, 33);
	uae_u32* branchadd = (uae_u32*)get_target();
	CBZ_wi(REG_WORK1, 0);			// end of op

	// need to rotate
	MOV_ww(REG_WORK2, d);
	BFI_xxii(REG_WORK2, x, 32, 1);          // move x to left side of d
	BFI_xxii(REG_WORK2, REG_WORK2, 33, 31); // duplicate 31 bits

	MOV_wi(REG_WORK3, 33);
	SUB_www(REG_WORK3, REG_WORK3, REG_WORK1);
	LSR_xxx(d, REG_WORK2, REG_WORK3);
	MOV_ww(d, d); // Clean upper 32 bits after 64-bit LSR_xxx

	// end of op
	write_jmp_target(branchadd, (uintptr)get_target());

	unlock2(x);
	EXIT_REGS(d, i);
}
MENDFUNC(2,jnf_ROXL_l,(RW4 d, RR4 i))

MIDFUNC(2,jff_ROXL_b,(RW1 d, RR4 i))
{
	INIT_REGS_b(d, i);
	int x = rmw(FLAGX);

	AND_ww3f(REG_WORK1, i);
	CMP_wi(REG_WORK1, 35);
	BLE_i(2);
	SUB_wwi(REG_WORK1, REG_WORK1, 36);
	CMP_wi(REG_WORK1, 17);
	BLE_i(2);
	SUB_wwi(REG_WORK1, REG_WORK1, 18);
	CMP_wi(REG_WORK1, 8);
	BLE_i(2);
	SUB_wwi(REG_WORK1, REG_WORK1, 9);
	uae_u32* rotate_branch = (uae_u32*)get_target();
	CBNZ_wi(REG_WORK1, 0);			// need to rotate (patched below)

	LSL_wwi(REG_WORK1, d, 24);
	TST_ww(REG_WORK1, REG_WORK1);
	MRS_NZCV_x(REG_WORK4);
	BFI_wwii(REG_WORK4, x, 29, 1); // effective count zero: C = unchanged X
	MSR_NZCV_x(REG_WORK4);
	uae_u32* end_branch = (uae_u32*)get_target();
	B_i(0);			// end of op (patched below)

	// need to rotate
	write_jmp_target(rotate_branch, (uintptr)get_target());
	MOV_ww(REG_WORK2, d);
	BFI_wwii(REG_WORK2, x, 8, 1);         // move x to left side of d
	BFI_wwii(REG_WORK2, REG_WORK2, 9, 9); // duplicate 9 bits

	MOV_wi(REG_WORK3, 9);
	SUB_www(REG_WORK3, REG_WORK3, REG_WORK1);
	LSR_www(REG_WORK2, REG_WORK2, REG_WORK3);
	BFI_wwii(d, REG_WORK2, 0, 8);

	// Calculate NZ
	LSL_wwi(REG_WORK1, REG_WORK2, 24);
	TST_ww(REG_WORK1, REG_WORK1);

	// Calculate C: bit left of result
	MRS_NZCV_x(REG_WORK4);
	UBFX_wwii(x, REG_WORK2, 8, 1);
	BFI_wwii(REG_WORK4, x, 29, 1);
	MSR_NZCV_x(REG_WORK4);

	// end of op
	write_jmp_target(end_branch, (uintptr)get_target());

	flags_carry_inverted = false;
	unlock2(x);
	EXIT_REGS(d, i);
}
MENDFUNC(2,jff_ROXL_b,(RW1 d, RR4 i))

MIDFUNC(2,jff_ROXL_w,(RW2 d, RR4 i))
{
	INIT_REGS_w(d, i);
	int x = rmw(FLAGX);

	AND_ww3f(REG_WORK1, i);
	CMP_wi(REG_WORK1, 33);
	BLE_i(2);
	SUB_wwi(REG_WORK1, REG_WORK1, 34);
	CMP_wi(REG_WORK1, 16);
	BLE_i(2);
	SUB_wwi(REG_WORK1, REG_WORK1, 17);
	uae_u32* rotate_branch = (uae_u32*)get_target();
	CBNZ_wi(REG_WORK1, 0);			// need to rotate (patched below)

	LSL_wwi(REG_WORK1, d, 16);
	TST_ww(REG_WORK1, REG_WORK1);
	MRS_NZCV_x(REG_WORK4);
	BFI_wwii(REG_WORK4, x, 29, 1); // effective count zero: C = unchanged X
	MSR_NZCV_x(REG_WORK4);
	uae_u32* end_branch = (uae_u32*)get_target();
	B_i(0);			// end of op (patched below)

	// need to rotate
	write_jmp_target(rotate_branch, (uintptr)get_target());
	MOV_ww(REG_WORK2, d);
	BFI_wwii(REG_WORK2, x, 16, 1);          // move x to left side of d
	BFI_xxii(REG_WORK2, REG_WORK2, 17, 17); // duplicate 17 bits

	MOV_wi(REG_WORK3, 17);
	SUB_www(REG_WORK3, REG_WORK3, REG_WORK1);
	LSR_xxx(REG_WORK2, REG_WORK2, REG_WORK3);

	BFI_wwii(d, REG_WORK2, 0, 16);

	// Calculate NZ
	LSL_wwi(REG_WORK1, REG_WORK2, 16);
	TST_ww(REG_WORK1, REG_WORK1);

	// Calculate C: bit left of result
	MRS_NZCV_x(REG_WORK4);
	UBFX_wwii(x, REG_WORK2, 16, 1);
	BFI_wwii(REG_WORK4, x, 29, 1);
	MSR_NZCV_x(REG_WORK4);

	// end of op
	write_jmp_target(end_branch, (uintptr)get_target());

	flags_carry_inverted = false;
	unlock2(x);
	EXIT_REGS(d, i);
}
MENDFUNC(2,jff_ROXL_w,(RW2 d, RR4 i))

MIDFUNC(2,jff_ROXL_l,(RW4 d, RR4 i))
{
	INIT_REGS_l(d, i);
	int x = rmw(FLAGX);

	AND_ww3f(REG_WORK1, i);
	CMP_wi(REG_WORK1, 32);
	BLE_i(2);
	SUB_wwi(REG_WORK1, REG_WORK1, 33);
	uae_u32* rotate_branch = (uae_u32*)get_target();
	CBNZ_wi(REG_WORK1, 0);			// need to rotate (patched below)

	TST_ww(d, d);
	MRS_NZCV_x(REG_WORK4);
	BFI_wwii(REG_WORK4, x, 29, 1); // effective count zero: C = unchanged X
	MSR_NZCV_x(REG_WORK4);
	uae_u32* end_branch = (uae_u32*)get_target();
	B_i(0);			// end of op (patched below)

	// need to rotate
	write_jmp_target(rotate_branch, (uintptr)get_target());
	MOV_ww(REG_WORK2, d);
	BFI_xxii(REG_WORK2, x, 32, 1);          // move x to left side of d
	BFI_xxii(REG_WORK2, REG_WORK2, 33, 31); // duplicate 31 bits

	MOV_wi(REG_WORK3, 33);
	SUB_www(REG_WORK3, REG_WORK3, REG_WORK1);
	LSR_xxx(d, REG_WORK2, REG_WORK3);
	MOV_ww(d, d); // Clean upper 32 bits after 64-bit LSR_xxx

	// Calculate NZ
	TST_ww(d, d);

	// Calculate C
	MRS_NZCV_x(REG_WORK4);
	SUB_wwi(REG_WORK3, REG_WORK3, 1);
	LSR_xxx(REG_WORK2, REG_WORK2, REG_WORK3);
	UBFX_wwii(x, REG_WORK2, 0, 1);
	BFI_wwii(REG_WORK4, x, 29, 1);
	MSR_NZCV_x(REG_WORK4);

	// end of op
	write_jmp_target(end_branch, (uintptr)get_target());

	flags_carry_inverted = false;
	unlock2(x);
	EXIT_REGS(d, i);
}
MENDFUNC(2,jff_ROXL_l,(RW4 d, RR4 i))

/*
 * ROR
 * Operand Syntax: 	Dx, Dy
 * 					#<data>, Dy
 *					<ea>
 *
 * Operand Size: 8,16,32
 *
 * X Not affected.
 * N Set if the most significant bit of the result is set. Cleared otherwise.
 * Z Set if the result is zero. Cleared otherwise.
 * V Always cleared.
 * C Set according to the last bit rotated out of the operand. Cleared when the rotate count is zero.
 *
 */
MIDFUNC(2,jnf_ROR_b_imm,(RW1 d, IM8 i))
{
	if(i & 0x07) {
		INIT_REG_b(d);

		MOV_ww(REG_WORK1, d);
		BFI_wwii(REG_WORK1, REG_WORK1, 8, 8);
		ROR_wwi(REG_WORK1, REG_WORK1, i & 0x07);
		BFI_wwii(d, REG_WORK1, 0, 8);

		unlock2(d);
	}
}
MENDFUNC(2,jnf_ROR_b_imm,(RW1 d, IM8 i))

MIDFUNC(2,jnf_ROR_w_imm,(RW2 d, IM8 i))
{
	if(i & 0x0f) {
		INIT_REG_w(d);

		MOV_ww(REG_WORK1, d);
		BFI_wwii(REG_WORK1, REG_WORK1, 16, 16);
		ROR_wwi(REG_WORK1, REG_WORK1, i & 0x0f);
		BFI_wwii(d, REG_WORK1, 0, 16);

		unlock2(d);
	}
}
MENDFUNC(2,jnf_ROR_w_imm,(RW2 d, IM8 i))

MIDFUNC(2,jnf_ROR_l_imm,(RW4 d, IM8 i))
{
	if(i & 0x1f) {
		if (isconst(d)) {
			i = i & 31;
			live.state[d].val = (live.state[d].val >> i) | (live.state[d].val << (32-i));
			return;
		}

		d = rmw(d);

		ROR_wwi(d, d, i & 31);

		unlock2(d);
	}
}
MENDFUNC(2,jnf_ROR_l_imm,(RW4 d, IM8 i))

MIDFUNC(2,jff_ROR_b_imm,(RW1 d, IM8 i))
{
	if(i)
		d = rmw(d);
	else
		d = readreg(d);

	LSL_wwi(REG_WORK1, d, 24);
	if(i & 0x07) {
		ORR_wwwLSRi(REG_WORK1, REG_WORK1, REG_WORK1, 8);
		ORR_wwwLSRi(REG_WORK1, REG_WORK1, REG_WORK1, 16);
		ROR_wwi(REG_WORK1, REG_WORK1, i & 0x07);
		BFI_wwii(d, REG_WORK1, 0, 8);
	}
	TST_ww(REG_WORK1, REG_WORK1);
	if(i) {
		PUBLISH_CARRY_FROM_BIT(REG_WORK1, 31, REG_WORK3);
	}

	flags_carry_inverted = false;
	unlock2(d);
}
MENDFUNC(2,jff_ROR_b_imm,(RW1 d, IM8 i))

MIDFUNC(2,jff_ROR_w_imm,(RW2 d, IM8 i))
{
	if(i)
		d = rmw(d);
	else
		d = readreg(d);

	LSL_wwi(REG_WORK1, d, 16);
	if(i & 0x0f) {
		ORR_wwwLSRi(REG_WORK1, REG_WORK1, REG_WORK1, 16);
		ROR_wwi(REG_WORK1, REG_WORK1, i & 0x0f);
		BFI_wwii(d, REG_WORK1, 0, 16);
	}
	TST_ww(REG_WORK1, REG_WORK1);
	if (i) {
		PUBLISH_CARRY_FROM_BIT(REG_WORK1, 31, REG_WORK3);
	}

	flags_carry_inverted = false;
	unlock2(d);
}
MENDFUNC(2,jff_ROR_w_imm,(RW2 d, IM8 i))

MIDFUNC(2,jff_ROR_l_imm,(RW4 d, IM8 i))
{
	if(i)
		d = rmw(d);
	else
		d = readreg(d);

	if(i & 0x1f) {
		ROR_wwi(d, d, i & 0x1f);
	}
	TST_ww(d, d);
	if (i) {
		PUBLISH_CARRY_FROM_BIT(d, 31, REG_WORK3);
	}

	flags_carry_inverted = false;
	unlock2(d);
}
MENDFUNC(2,jff_ROR_l_imm,(RW4 d, IM8 i))

MIDFUNC(2,jnf_ROR_b,(RW1 d, RR4 i))
{
	if (isconst(i)) {
		COMPCALL(jnf_ROR_b_imm)(d, (uae_u8)(live.state[i].val & 0x3f));
		return;
	}

	i = readreg(i);
	d = rmw(d);

	LSL_wwi(REG_WORK1, d, 24);
	ORR_wwwLSRi(REG_WORK1, REG_WORK1, REG_WORK1, 8);
	ORR_wwwLSRi(REG_WORK1, REG_WORK1, REG_WORK1, 16);
	AND_ww3f(REG_WORK2, i);
	ROR_www(REG_WORK1, REG_WORK1, REG_WORK2);
	BFI_wwii(d, REG_WORK1, 0, 8);

	unlock2(d);
	unlock2(i);
}
MENDFUNC(2,jnf_ROR_b,(RW1 d, RR4 i))

MIDFUNC(2,jnf_ROR_w,(RW2 d, RR4 i))
{
	if (isconst(i)) {
		COMPCALL(jnf_ROR_w_imm)(d, (uae_u8)(live.state[i].val & 0x3f));
		return;
	}

	i = readreg(i);
	d = rmw(d);

	LSL_wwi(REG_WORK1, d, 16);
	ORR_wwwLSRi(REG_WORK1, REG_WORK1, REG_WORK1, 16);
	AND_ww3f(REG_WORK2, i);
	ROR_www(REG_WORK1, REG_WORK1, REG_WORK2);
	BFI_wwii(d, REG_WORK1, 0, 16);

	unlock2(d);
	unlock2(i);
}
MENDFUNC(2,jnf_ROR_w,(RW2 d, RR4 i))

MIDFUNC(2,jnf_ROR_l,(RW4 d, RR4 i))
{
	if (isconst(i)) {
		COMPCALL(jnf_ROR_l_imm)(d, (uae_u8)(live.state[i].val & 0x3f));
		return;
	}

	i = readreg(i);
	d = rmw(d);

	AND_ww3f(REG_WORK1, i);
	ROR_www(d, d, REG_WORK1);

	unlock2(d);
	unlock2(i);
}
MENDFUNC(2,jnf_ROR_l,(RW4 d, RR4 i))

MIDFUNC(2,jff_ROR_b,(RW1 d, RR4 i))
{
	if (isconst(i)) {
		COMPCALL(jff_ROR_b_imm)(d, (uae_u8)(live.state[i].val & 0x3f));
		return;
	}

	i = readreg(i);
	d = rmw(d);

	LSL_wwi(REG_WORK1, d, 24);
	ORR_wwwLSRi(REG_WORK1, REG_WORK1, REG_WORK1, 8);
	ORR_wwwLSRi(REG_WORK1, REG_WORK1, REG_WORK1, 16);
	AND_ww3f(REG_WORK2, i);
	ROR_www(REG_WORK1, REG_WORK1, REG_WORK2);
	BFI_wwii(d, REG_WORK1, 0, 8);
	TST_ww(REG_WORK1, REG_WORK1);

	uae_u32* branch_count_zero = (uae_u32*)get_target();
	CBZ_wi(REG_WORK2, 0); // C remains clear when the six-bit count is zero
	PUBLISH_CARRY_FROM_BIT(REG_WORK1, 31, REG_WORK3);
	write_jmp_target(branch_count_zero, (uintptr)get_target());

	flags_carry_inverted = false;
	unlock2(d);
	unlock2(i);
}
MENDFUNC(2,jff_ROR_b,(RW1 d, RR4 i))

MIDFUNC(2,jff_ROR_w,(RW2 d, RR4 i))
{
	if (isconst(i)) {
		COMPCALL(jff_ROR_w_imm)(d, (uae_u8)(live.state[i].val & 0x3f));
		return;
	}

	i = readreg(i);
	d = rmw(d);

	LSL_wwi(REG_WORK1, d, 16);
	BFXIL_wwii(REG_WORK1, REG_WORK1, 16, 16);
	AND_ww3f(REG_WORK2, i);
	ROR_www(REG_WORK1, REG_WORK1, REG_WORK2);
	BFI_wwii(d, REG_WORK1, 0, 16);
	TST_ww(REG_WORK1, REG_WORK1);

	uae_u32* branch_count_zero = (uae_u32*)get_target();
	CBZ_wi(REG_WORK2, 0); // C remains clear when the six-bit count is zero
	PUBLISH_CARRY_FROM_BIT(REG_WORK1, 31, REG_WORK3);
	write_jmp_target(branch_count_zero, (uintptr)get_target());

	flags_carry_inverted = false;
	unlock2(d);
	unlock2(i);
}
MENDFUNC(2,jff_ROR_w,(RW2 d, RR4 i))

MIDFUNC(2,jff_ROR_l,(RW4 d, RR4 i))
{
	if (isconst(i)) {
		COMPCALL(jff_ROR_l_imm)(d, (uae_u8)(live.state[i].val & 0x3f));
		return;
	}

	i = readreg(i);
	d = rmw(d);

	AND_ww3f(REG_WORK1, i);
	ROR_www(d, d, REG_WORK1);
	TST_ww(d, d);

	uae_u32* branch_count_zero = (uae_u32*)get_target();
	CBZ_wi(REG_WORK1, 0); // C remains clear when the six-bit count is zero
	PUBLISH_CARRY_FROM_BIT(d, 31, REG_WORK3);
	write_jmp_target(branch_count_zero, (uintptr)get_target());

	flags_carry_inverted = false;
	unlock2(d);
	unlock2(i);
}
MENDFUNC(2,jff_ROR_l,(RW4 d, RR4 i))

/*
 * RORW
 * Operand Syntax: 	<ea>
 *
 * Operand Size: 16
 *
 * X Not affected.
 * N Set if the most significant bit of the result is set. Cleared otherwise.
 * Z Set if the result is zero. Cleared otherwise.
 * V Always cleared.
 * C Set according to the last bit rotated out of the operand.
 *
 * Target is never a register.
 */
MIDFUNC(1,jnf_RORW,(RW2 d))
{
	d = rmw(d);

	BFI_wwii(d, d, 16, 16);
	ROR_wwi(d, d, 1);

	unlock2(d);
}
MENDFUNC(1,jnf_RORW,(RW2 d))

MIDFUNC(1,jff_RORW,(RW2 d))
{
	d = rmw(d);

	BFI_wwii(d, d, 16, 16);
	ROR_wwi(d, d, 1);
	TST_ww(d, d);

	PUBLISH_CARRY_FROM_BIT(d, 31, REG_WORK3);

	flags_carry_inverted = false;
	unlock2(d);
}
MENDFUNC(1,jff_RORW,(RW2 d))

/*
 * ROXR
 * Operand Syntax: Dx, Dy
 * 				   #<data>, Dy
 *
 * Operand Size: 8,16,32
 *
 * X Set according to the last bit rotated out of the operand. Unchanged when the rotate count is zero.
 * N Set if the most significant bit of the result is set. Cleared otherwise.
 * Z Set if the result is zero. Cleared otherwise.
 * V Always cleared.
 * C Set according to the last bit rotated out of the operand. For an effective
 *   count of zero, X is unchanged and copied to C.
 *
 */
MIDFUNC(2,jnf_ROXR_b,(RW1 d, RR4 i))
{
	int x = readreg(FLAGX);
	INIT_REGS_b(d, i);

	clobber_flags();

	AND_ww3f(REG_WORK1, i);
	CMP_wi(REG_WORK1, 35);
	BLE_i(2);
	SUB_wwi(REG_WORK1, REG_WORK1, 36);
	CMP_wi(REG_WORK1, 17);
	BLE_i(2);
	SUB_wwi(REG_WORK1, REG_WORK1, 18);
	CMP_wi(REG_WORK1, 8);
	BLE_i(2);
	SUB_wwi(REG_WORK1, REG_WORK1, 9);
	uae_u32* branchadd = (uae_u32*)get_target();
	CBZ_wi(REG_WORK1, 0);			// end of op

	// need to rotate
	MOV_ww(REG_WORK2, d);
	BFI_wwii(REG_WORK2, x, 8, 1);         // move x to left side of d
	BFI_wwii(REG_WORK2, REG_WORK2, 9, 9); // duplicate 9 bits

	LSR_www(REG_WORK2, REG_WORK2, REG_WORK1);
	BFI_wwii(d, REG_WORK2, 0, 8);

	// end of op
	write_jmp_target(branchadd, (uintptr)get_target());

	unlock2(x);
	EXIT_REGS(d, i);
}
MENDFUNC(2,jnf_ROXR_b,(RW1 d, RR4 i))

MIDFUNC(2,jnf_ROXR_w,(RW2 d, RR4 i))
{
	int x = readreg(FLAGX);
	INIT_REGS_w(d, i);

	clobber_flags();

	AND_ww3f(REG_WORK1, i);
	CMP_wi(REG_WORK1, 33);
	BLE_i(2);
	SUB_wwi(REG_WORK1, REG_WORK1, 34);
	CMP_wi(REG_WORK1, 16);
	BLE_i(2);
	SUB_wwi(REG_WORK1, REG_WORK1, 17);
	uae_u32* branchadd = (uae_u32*)get_target();
	CBZ_wi(REG_WORK1, 0);			// end of op

	// need to rotate
	MOV_ww(REG_WORK2, d);
	BFI_wwii(REG_WORK2, x, 16, 1);          // move x to left side of d
	BFI_xxii(REG_WORK2, REG_WORK2, 17, 17); // duplicate 17 bits

	LSR_xxx(REG_WORK2, REG_WORK2, REG_WORK1);
	BFI_wwii(d, REG_WORK2, 0, 16);

	// end of op
	write_jmp_target(branchadd, (uintptr)get_target());

	unlock2(x);
	EXIT_REGS(d, i);
}
MENDFUNC(2,jnf_ROXR_w,(RW2 d, RR4 i))

MIDFUNC(2,jnf_ROXR_l,(RW4 d, RR4 i))
{
	int x = readreg(FLAGX);
	INIT_REGS_l(d, i);

	clobber_flags();

	AND_ww3f(REG_WORK1, i);
	CMP_wi(REG_WORK1, 32);
	BLE_i(2);
	SUB_wwi(REG_WORK1, REG_WORK1, 33);
	uae_u32* branchadd = (uae_u32*)get_target();
	CBZ_wi(REG_WORK1, 0);			// end of op

	// need to rotate
	MOV_ww(REG_WORK2, d);
	BFI_xxii(REG_WORK2, x, 32, 1);          // move x to left side of d
	BFI_xxii(REG_WORK2, REG_WORK2, 33, 31); // duplicate 31 bits

	LSR_xxx(d, REG_WORK2, REG_WORK1);
	MOV_ww(d, d); // Clean upper 32 bits after 64-bit LSR_xxx

	// end of op
	write_jmp_target(branchadd, (uintptr)get_target());

	unlock2(x);
	EXIT_REGS(d, i);
}
MENDFUNC(2,jnf_ROXR_l,(RW4 d, RR4 i))

MIDFUNC(2,jff_ROXR_b,(RW1 d, RR4 i))
{
	INIT_REGS_b(d, i);
	int x = rmw(FLAGX);

	AND_ww3f(REG_WORK1, i);
	CMP_wi(REG_WORK1, 35);
	BLE_i(2);
	SUB_wwi(REG_WORK1, REG_WORK1, 36);
	CMP_wi(REG_WORK1, 17);
	BLE_i(2);
	SUB_wwi(REG_WORK1, REG_WORK1, 18);
	CMP_wi(REG_WORK1, 8);
	BLE_i(2);
	SUB_wwi(REG_WORK1, REG_WORK1, 9);
	uae_u32* rotate_branch = (uae_u32*)get_target();
	CBNZ_wi(REG_WORK1, 0);			// need to rotate (patched below)

	LSL_wwi(REG_WORK1, d, 24);
	TST_ww(REG_WORK1, REG_WORK1);
	MRS_NZCV_x(REG_WORK4);
	BFI_wwii(REG_WORK4, x, 29, 1); // effective count zero: C = unchanged X
	MSR_NZCV_x(REG_WORK4);
	uae_u32* end_branch = (uae_u32*)get_target();
	B_i(0);			// end of op (patched below)

	// need to rotate
	write_jmp_target(rotate_branch, (uintptr)get_target());
	MOV_ww(REG_WORK2, d);
	BFI_wwii(REG_WORK2, x, 8, 1);         // move x to left side of d
	BFI_wwii(REG_WORK2, REG_WORK2, 9, 9); // duplicate 9 bits

	LSR_www(REG_WORK3, REG_WORK2, REG_WORK1);
	BFI_wwii(d, REG_WORK3, 0, 8);

	// calc N and Z
	LSL_wwi(REG_WORK3, REG_WORK3, 24);
	TST_ww(REG_WORK3, REG_WORK3);

	// calc C and X
	SUB_wwi(REG_WORK1, REG_WORK1, 1);
	LSR_www(REG_WORK3, REG_WORK2, REG_WORK1);
	UBFIZ_wwii(x, REG_WORK3, 0, 1);
	PUBLISH_CARRY_FROM_BIT(x, 0, REG_WORK3);

	// end of op
	write_jmp_target(end_branch, (uintptr)get_target());

	flags_carry_inverted = false;
	unlock2(x);
	EXIT_REGS(d, i);
}
MENDFUNC(2,jff_ROXR_b,(RW1 d, RR4 i))

MIDFUNC(2,jff_ROXR_w,(RW2 d, RR4 i))
{
	INIT_REGS_w(d, i);
	int x = rmw(FLAGX);

	AND_ww3f(REG_WORK1, i);
	CMP_wi(REG_WORK1, 33);
	BLE_i(2);
	SUB_wwi(REG_WORK1, REG_WORK1, 34);
	CMP_wi(REG_WORK1, 16);
	BLE_i(2);
	SUB_wwi(REG_WORK1, REG_WORK1, 17);
	uae_u32* rotate_branch = (uae_u32*)get_target();
	CBNZ_wi(REG_WORK1, 0);			// need to rotate (patched below)

	LSL_wwi(REG_WORK1, d, 16);
	TST_ww(REG_WORK1, REG_WORK1);
	MRS_NZCV_x(REG_WORK4);
	BFI_wwii(REG_WORK4, x, 29, 1); // effective count zero: C = unchanged X
	MSR_NZCV_x(REG_WORK4);
	uae_u32* end_branch = (uae_u32*)get_target();
	B_i(0);			// end of op (patched below)

	// need to rotate
	write_jmp_target(rotate_branch, (uintptr)get_target());
	MOV_ww(REG_WORK2, d);
	BFI_wwii(REG_WORK2, x, 16, 1);          // move x to left side of d
	BFI_xxii(REG_WORK2, REG_WORK2, 17, 17); // duplicate 17 bits

	LSR_xxx(REG_WORK3, REG_WORK2, REG_WORK1);
	BFI_wwii(d, REG_WORK3, 0, 16);

	// calc N and Z
	LSL_wwi(REG_WORK3, REG_WORK3, 16);
	TST_ww(REG_WORK3, REG_WORK3);

	// calc C and X
	SUB_wwi(REG_WORK1, REG_WORK1, 1);
	LSR_www(REG_WORK3, REG_WORK2, REG_WORK1);
	UBFIZ_wwii(x, REG_WORK3, 0, 1);
	PUBLISH_CARRY_FROM_BIT(x, 0, REG_WORK3);

	// end of op
	write_jmp_target(end_branch, (uintptr)get_target());

	flags_carry_inverted = false;
	unlock2(x);
	EXIT_REGS(d, i);
}
MENDFUNC(2,jff_ROXR_w,(RW2 d, RR4 i))

MIDFUNC(2,jff_ROXR_l,(RW4 d, RR4 i))
{
	INIT_REGS_l(d, i);
	int x = rmw(FLAGX);

	AND_ww3f(REG_WORK1, i);
	CMP_wi(REG_WORK1, 32);
	BLE_i(2);
	SUB_wwi(REG_WORK1, REG_WORK1, 33);
	uae_u32* rotate_branch = (uae_u32*)get_target();
	CBNZ_wi(REG_WORK1, 0);			// need to rotate (patched below)

	TST_ww(d, d);
	MRS_NZCV_x(REG_WORK4);
	BFI_wwii(REG_WORK4, x, 29, 1); // effective count zero: C = unchanged X
	MSR_NZCV_x(REG_WORK4);
	uae_u32* end_branch = (uae_u32*)get_target();
	B_i(0);			// end of op (patched below)

	// need to rotate
	write_jmp_target(rotate_branch, (uintptr)get_target());
	MOV_ww(REG_WORK2, d);
	BFI_xxii(REG_WORK2, x, 32, 1);          // move x to left side of d
	BFI_xxii(REG_WORK2, REG_WORK2, 33, 31); // duplicate 31 bits

	LSR_xxx(d, REG_WORK2, REG_WORK1);
	MOV_ww(d, d); // Clean upper 32 bits after 64-bit LSR_xxx

	// Calculate NZ
	TST_ww(d, d);

	// Calculate C
	SUB_wwi(REG_WORK1, REG_WORK1, 1);
	LSR_xxx(REG_WORK3, REG_WORK2, REG_WORK1);
	UBFIZ_wwii(x, REG_WORK3, 0, 1);
	PUBLISH_CARRY_FROM_BIT(x, 0, REG_WORK3);

	// end of op
	write_jmp_target(end_branch, (uintptr)get_target());

	flags_carry_inverted = false;
	unlock2(x);
	EXIT_REGS(d, i);
}
MENDFUNC(2,jff_ROXR_l,(RW4 d, RR4 i))

/*
 * SCC
 *
 */
MIDFUNC(2,jnf_SCC,(W1 d, IM8 cc))
{
	/* The generator passes the architectural 0..15 M68K condition number,
	   never a generator-host/x86 or target-native encoding. Normalise the
	   carry representation once, then map the complete family explicitly.
	   CSETM publishes the required 0xff byte while preserving NZCV. */
	FIX_INVERTED_CARRY
	INIT_WREG_b(d);

	int native_cc = -1;
	switch (cc) {
	case 0: /* T */  LOAD_U32(REG_WORK1, 0xffffffff); break;
	case 1: /* F */  MOV_wi(REG_WORK1, 0); break;
	case 2: /* HI = !C && !Z; ARM HI uses the opposite C polarity. */
		CSETM_wc(REG_WORK1, NATIVE_CC_CC);
		CSETM_wc(REG_WORK2, NATIVE_CC_NE);
		AND_www(REG_WORK1, REG_WORK1, REG_WORK2);
		break;
	case 3: /* LS = C || Z; ARM LS uses the opposite C polarity. */
		CSETM_wc(REG_WORK1, NATIVE_CC_CS);
		CSETM_wc(REG_WORK2, NATIVE_CC_EQ);
		ORR_www(REG_WORK1, REG_WORK1, REG_WORK2);
		break;
	case 4: native_cc = NATIVE_CC_CC; break;
	case 5: native_cc = NATIVE_CC_CS; break;
	case 6: native_cc = NATIVE_CC_NE; break;
	case 7: native_cc = NATIVE_CC_EQ; break;
	case 8: native_cc = NATIVE_CC_VC; break;
	case 9: native_cc = NATIVE_CC_VS; break;
	case 10: native_cc = NATIVE_CC_PL; break;
	case 11: native_cc = NATIVE_CC_MI; break;
	case 12: native_cc = NATIVE_CC_GE; break;
	case 13: native_cc = NATIVE_CC_LT; break;
	case 14: native_cc = NATIVE_CC_GT; break;
	case 15: native_cc = NATIVE_CC_LE; break;
	default: jit_abort("invalid Scc condition %d", cc); break;
	}
	if (native_cc >= 0)
		CSETM_wc(REG_WORK1, native_cc);
	BFI_wwii(d, REG_WORK1, 0, 8);
	unlock2(d);
}
MENDFUNC(2,jnf_SCC,(W1 d, IM8 cc))

/*
 * SUB
 * Operand Syntax: 	<ea>, Dn
 * 					Dn, <ea>
 *
 * Operand Size: 8,16,32
 *
 * X Set the same as the carry bit.
 * N Set if the result is negative. Cleared otherwise.
 * Z Set if the result is zero. Cleared otherwise.
 * V Set if an overflow is generated. Cleared otherwise.
 * C Set if a carry is generated. Cleared otherwise.
 *
 */
MIDFUNC(2,jnf_SUB_b_imm,(RW1 d, IM8 v))
{
	if (isconst(d)) {
		live.state[d].val = (live.state[d].val & 0xffffff00) | (((live.state[d].val & 0xff) - (v & 0xff)) & 0x000000ff);
		return;
	}

	INIT_REG_b(d);

	if(targetIsReg) {
		SUB_wwi(REG_WORK1, d, v & 0xff);
		BFI_wwii(d, REG_WORK1, 0, 8);
	} else {
		SUB_wwi(d, d, v & 0xff);
	}

	unlock2(d);
}
MENDFUNC(2,jnf_SUB_b_imm,(RW1 d, IM8 v))

MIDFUNC(2,jnf_SUB_b,(RW1 d, RR1 s))
{
	if (isconst(s)) {
		COMPCALL(jnf_SUB_b_imm)(d, live.state[s].val);
		return;
	}

	INIT_REGS_b(d, s);

	if(targetIsReg) {
		SUB_www(REG_WORK1, d, s);
		BFI_wwii(d, REG_WORK1, 0, 8);
	} else {
		SUB_www(d, d, s);
	}

	EXIT_REGS(d, s);
}
MENDFUNC(2,jnf_SUB_b,(RW1 d, RR1 s))

MIDFUNC(2,jnf_SUB_w_imm,(RW2 d, IM16 v))
{
	if (isconst(d)) {
		live.state[d].val = (live.state[d].val & 0xffff0000) | (((live.state[d].val & 0xffff) - (v & 0xffff)) & 0x0000ffff);
		return;
	}

	INIT_REG_w(d);

	UNSIGNED16_IMM_2_REG(REG_WORK1, (uae_u16)v);
	if(targetIsReg) {
		SUB_www(REG_WORK1, d, REG_WORK1);
		BFI_wwii(d, REG_WORK1, 0, 16);
	} else{
		SUB_www(d, d, REG_WORK1);
	}

	unlock2(d);
}
MENDFUNC(2,jnf_SUB_w_imm,(RW2 d, IM16 v))

MIDFUNC(2,jnf_SUB_w,(RW2 d, RR2 s))
{
	if (isconst(s)) {
		COMPCALL(jnf_SUB_w_imm)(d, live.state[s].val);
		return;
	}

	INIT_REGS_w(d, s);

	if(targetIsReg) {
		SUB_www(REG_WORK1, d, s);
		BFI_wwii(d, REG_WORK1, 0, 16);
	} else{
		SUB_www(d, d, s);
	}

	EXIT_REGS(d, s);
}
MENDFUNC(2,jnf_SUB_w,(RW2 d, RR2 s))

MIDFUNC(2,jnf_SUB_l_imm,(RW2 d, IM32 v))
{
	if (isconst(d)) {
		live.state[d].val = live.state[d].val - v;
		return;
	}

	d = rmw(d);

	if(v >= 0 && v < 4096) {
		SUB_wwi(d, d, v);
	} else {
		LOAD_U32(REG_WORK1, v);
		SUB_www(d, d, REG_WORK1);
	}

	unlock2(d);
}
MENDFUNC(2,jnf_SUB_l_imm,(RW2 d, IM32 v))

MIDFUNC(2,jnf_SUB_l,(RW4 d, RR4 s))
{
	if (isconst(s)) {
		COMPCALL(jnf_SUB_l_imm)(d, live.state[s].val);
		return;
	}

	INIT_REGS_l(d, s);

	SUB_www(d, d, s);

	EXIT_REGS(d, s);
}
MENDFUNC(2,jnf_SUB_l,(RW4 d, RR4 s))

MIDFUNC(2,jff_SUB_b_imm,(RW1 d, IM8 v))
{
	INIT_REG_b(d);

	LSL_wwi(REG_WORK1, d, 24);
	MOV_wish(REG_WORK2, (v & 0xff) << 8, 16);
	SUBS_www(REG_WORK1, REG_WORK1, REG_WORK2);
	BFXIL_xxii(d, REG_WORK1, 24, 8);

	flags_carry_inverted = true;
	DUPLICACTE_CARRY

	unlock2(d);
}
MENDFUNC(2,jff_SUB_b_imm,(RW1 d, IM8 v))

MIDFUNC(2,jff_SUB_b,(RW1 d, RR1 s))
{
	if (isconst(s)) {
		COMPCALL(jff_SUB_b_imm)(d, live.state[s].val);
		return;
	}

	INIT_REGS_b(d, s);

	LSL_wwi(REG_WORK1, d, 24);
	SUBS_wwwLSLi(REG_WORK1, REG_WORK1, s, 24);
	BFXIL_xxii(d, REG_WORK1, 24, 8);

	flags_carry_inverted = true;
	DUPLICACTE_CARRY

	EXIT_REGS(d, s);
}
MENDFUNC(2,jff_SUB_b,(RW1 d, RR1 s))

MIDFUNC(2,jff_SUB_w_imm,(RW2 d, IM16 v))
{
	INIT_REG_w(d);

	MOV_xi(REG_WORK1, v);
	LSL_wwi(REG_WORK2, d, 16);
	SUBS_wwwLSLi(REG_WORK1, REG_WORK2, REG_WORK1, 16);
	BFXIL_xxii(d, REG_WORK1, 16, 16);

	flags_carry_inverted = true;
	DUPLICACTE_CARRY

	unlock2(d);
}
MENDFUNC(2,jff_SUB_w_imm,(RW2 d, IM16 v))

MIDFUNC(2,jff_SUB_w,(RW2 d, RR2 s))
{
	if (isconst(s)) {
		COMPCALL(jff_SUB_w_imm)(d, live.state[s].val);
		return;
	}

	INIT_REGS_w(d, s);

	LSL_wwi(REG_WORK1, d, 16);
	SUBS_wwwLSLi(REG_WORK1, REG_WORK1, s, 16);
	BFXIL_xxii(d, REG_WORK1, 16, 16);

	flags_carry_inverted = true;
	DUPLICACTE_CARRY

	EXIT_REGS(d, s);
}
MENDFUNC(2,jff_SUB_w,(RW2 d, RR2 s))

MIDFUNC(2,jff_SUB_l_imm,(RW4 d, IM32 v))
{
	d = rmw(d);

	if(v >= 0 && v < 4096) {
		SUBS_wwi(d, d, v);
	} else {
		LOAD_U32(REG_WORK1, v);
		SUBS_www(d, d, REG_WORK1);
	}

	flags_carry_inverted = true;
	DUPLICACTE_CARRY

	unlock2(d);
}
MENDFUNC(2,jff_SUB_l_imm,(RW4 d, IM32 v))

MIDFUNC(2,jff_SUB_l,(RW4 d, RR4 s))
{
	if (isconst(s)) {
		COMPCALL(jff_SUB_l_imm)(d, live.state[s].val);
		return;
	}

	INIT_REGS_l(d, s);

	SUBS_www(d, d, s);

	flags_carry_inverted = true;
	DUPLICACTE_CARRY

	EXIT_REGS(d, s);
}
MENDFUNC(2,jff_SUB_l,(RW4 d, RR4 s))

/*
 * SUBA
 *
 * Operand Syntax: 	<ea>, Dn
 *
 * Operand Size: 16,32
 *
 * Flags: Not affected.
 *
 */
MIDFUNC(2,jnf_SUBA_w_imm,(RW4 d, IM16 v))
{
	if (isconst(d)) {
		live.state[d].val = live.state[d].val - (uae_s32)(uae_s16)v;
		return;
	}

	d = rmw(d);
	if(v >= 0 && v < 4096) {
		SUB_wwi(d, d, v);
	} else {
		SIGNED16_IMM_2_REG(REG_WORK1, v);
		SUB_www(d, d, REG_WORK1);
	}
	unlock2(d);
}
MENDFUNC(2,jnf_SUBA_w_imm,(RW4 d, IM16 v))

MIDFUNC(2,jnf_SUBA_w,(RW4 d, RR2 s))
{
	if (isconst(s)) {
		COMPCALL(jnf_SUBA_w_imm)(d, live.state[s].val & 0xffff);
		return;
	}

	INIT_REGS_w(d, s);

	SUB_wwwEX(d, d, s, EX_SXTH);

	EXIT_REGS(d, s);
}
MENDFUNC(2,jnf_SUBA_w,(RW4 d, RR2 s))

MIDFUNC(2,jnf_SUBA_l_imm,(RW4 d, IM32 v))
{
	if (isconst(d)) {
		set_const(d, live.state[d].val - v);
		return;
	}

	d = rmw(d);

	if(v >= 0 && v < 4096) {
		SUB_wwi(d, d, v);
	} else {
		LOAD_U32(REG_WORK1, v);
		SUB_www(d, d, REG_WORK1);
	}

	unlock2(d);
}
MENDFUNC(2,jnf_SUBA_l_imm,(RW4 d, IM32 v))

MIDFUNC(2,jnf_SUBA_l,(RW4 d, RR4 s))
{
	if (isconst(s)) {
		COMPCALL(jnf_SUBA_l_imm)(d, live.state[s].val);
		return;
	}

	INIT_REGS_l(d, s);

	SUB_www(d, d, s);

	EXIT_REGS(d, s);
}
MENDFUNC(2,jnf_SUBA_l,(RW4 d, RR4 s))

/*
 * SUBX
 * Operand Syntax: 	Dy, Dx
 * 					-(Ay), -(Ax)
 *
 * Operand Size: 8,16,32
 *
 * X Set the same as the carry bit.
 * N Set if the result is negative. Cleared otherwise.
 * Z Cleared if the result is nonzero. Unchanged otherwise.
 * V Set if an overflow is generated. Cleared otherwise.
 * C Set if a carry is generated. Cleared otherwise.
 *
 * Attention: Z is cleared only if the result is nonzero. Unchanged otherwise
 *
 */
MIDFUNC(2,jnf_SUBX_b,(RW1 d, RR1 s))
{
	int x = readreg(FLAGX);
	INIT_REGS_b(d, s);

	clobber_flags();

	// Restore inverted X to carry (don't care about other flags)
	NEGS_ww(REG_WORK1, x);

	LSL_wwi(REG_WORK1, d, 24);
	LSL_wwi(REG_WORK2, s, 24);
	SBC_www(REG_WORK1, REG_WORK1, REG_WORK2);
	BFXIL_wwii(d, REG_WORK1, 24, 8);

	unlock2(x);
	EXIT_REGS(d, s);
}
MENDFUNC(2,jnf_SUBX_b,(RW1 d, RR1 s))

MIDFUNC(2,jnf_SUBX_w,(RW2 d, RR2 s))
{
	int x = readreg(FLAGX);
	INIT_REGS_w(d, s);

	clobber_flags();

	// Restore inverted X to carry (don't care about other flags)
	NEGS_ww(REG_WORK1, x);

	LSL_wwi(REG_WORK1, d, 16);
	LSL_wwi(REG_WORK2, s, 16);
	SBC_www(REG_WORK1, REG_WORK1, REG_WORK2);
	BFXIL_wwii(d, REG_WORK1, 16, 16);

	unlock2(x);
	EXIT_REGS(d, s);
}
MENDFUNC(2,jnf_SUBX_w,(RW2 d, RR2 s))

MIDFUNC(2,jnf_SUBX_l,(RW4 d, RR4 s))
{
	int x = readreg(FLAGX);
	INIT_REGS_l(d, s);

	clobber_flags();

	// Restore inverted X to carry (don't care about other flags)
	NEGS_ww(REG_WORK1, x);

	SBC_www(d, d, s);

	EXIT_REGS(d, s);
	unlock2(x);
}
MENDFUNC(2,jnf_SUBX_l,(RW4 d, RR4 s))

MIDFUNC(2,jff_SUBX_b,(RW1 d, RR1 s))
{
	INIT_REGS_b(d, s);
	int x = rmw(FLAGX);

	if (needed_flags & FLAG_Z) {
		MOVN_xi(REG_WORK2, 0);
		MOVN_xish(REG_WORK1, 0x4000, 16); // inverse Z flag
		CSEL_xxxc(REG_WORK2, REG_WORK1, REG_WORK2, NATIVE_CC_NE);
	}

	// Restore inverted X to carry (don't care about other flags)
	NEGS_ww(REG_WORK1, x);

	LSL_wwi(REG_WORK1, d, 24);
	LSL_wwi(REG_WORK3, s, 24);
	SBCS_www(REG_WORK1, REG_WORK1, REG_WORK3);
	BFXIL_wwii(d, REG_WORK1, 24, 8);

	MRS_NZCV_x(REG_WORK1);
	EOR_xxCflag(REG_WORK1, REG_WORK1);

	if (needed_flags & FLAG_Z) {
		// Fix Z flag: SBCS Z may be wrong when borrow propagates through lower zero bits.
		UBFX_wwii(REG_WORK3, d, 0, 8);
		CMP_wi(REG_WORK3, 0);
		SET_xxZflag(REG_WORK3, REG_WORK1);
		CSEL_xxxc(REG_WORK1, REG_WORK3, REG_WORK1, NATIVE_CC_EQ);
		AND_xxx(REG_WORK1, REG_WORK1, REG_WORK2); // apply SUBX sticky-Z
	}
	MSR_NZCV_x(REG_WORK1);
	flags_carry_inverted = false;
	if (needed_flags & FLAG_X)
		UBFX_xxii(x, REG_WORK1, 29, 1); // Duplicate carry

	unlock2(x);
	EXIT_REGS(d, s);
}
MENDFUNC(2,jff_SUBX_b,(RW1 d, RR1 s))

MIDFUNC(2,jff_SUBX_w,(RW2 d, RR2 s))
{
	INIT_REGS_w(d, s);
	int x = rmw(FLAGX);

	if (needed_flags & FLAG_Z) {
		MOVN_xi(REG_WORK2, 0);
		MOVN_xish(REG_WORK1, 0x4000, 16); // inverse Z flag
		CSEL_xxxc(REG_WORK2, REG_WORK1, REG_WORK2, NATIVE_CC_NE);
	}

	// Restore inverted X to carry (don't care about other flags)
	NEGS_ww(REG_WORK1, x);

	LSL_wwi(REG_WORK1, d, 16);
	LSL_wwi(REG_WORK3, s, 16);
	SBCS_www(REG_WORK1, REG_WORK1, REG_WORK3);
	BFXIL_wwii(d, REG_WORK1, 16, 16);

	MRS_NZCV_x(REG_WORK1);
	EOR_xxCflag(REG_WORK1, REG_WORK1);

	if (needed_flags & FLAG_Z) {
		// Fix Z flag: SBCS Z may be wrong when borrow propagates through lower zero bits.
		UBFX_wwii(REG_WORK3, d, 0, 16);
		CMP_wi(REG_WORK3, 0);
		SET_xxZflag(REG_WORK3, REG_WORK1);
		CSEL_xxxc(REG_WORK1, REG_WORK3, REG_WORK1, NATIVE_CC_EQ);
		AND_xxx(REG_WORK1, REG_WORK1, REG_WORK2); // apply SUBX sticky-Z
	}
	MSR_NZCV_x(REG_WORK1);
	flags_carry_inverted = false;
	if (needed_flags & FLAG_X)
		UBFX_xxii(x, REG_WORK1, 29, 1); // Duplicate carry

	unlock2(x);
	EXIT_REGS(d, s);
}
MENDFUNC(2,jff_SUBX_w,(RW2 d, RR2 s))

MIDFUNC(2,jff_SUBX_l,(RW4 d, RR4 s))
{
	INIT_REGS_l(d, s);
	int x = rmw(FLAGX);

	if (needed_flags & FLAG_Z) {
		MOVN_xi(REG_WORK2, 0);
		MOVN_xish(REG_WORK1, 0x4000, 16); // inverse Z flag
		CSEL_xxxc(REG_WORK2, REG_WORK1, REG_WORK2, NATIVE_CC_NE);
	}

	// Restore inverted X to carry (don't care about other flags)
	NEGS_ww(REG_WORK1, x);

	SBCS_www(d, d, s);

	MRS_NZCV_x(REG_WORK1);
	EOR_xxCflag(REG_WORK1, REG_WORK1);
	if (needed_flags & FLAG_Z)
		AND_xxx(REG_WORK1, REG_WORK1, REG_WORK2);
	MSR_NZCV_x(REG_WORK1);
	flags_carry_inverted = false;
	if (needed_flags & FLAG_X)
		UBFX_xxii(x, REG_WORK1, 29, 1); // Duplicate carry

	unlock2(x);
	EXIT_REGS(d, s);
}
MENDFUNC(2,jff_SUBX_l,(RW4 d, RR4 s))

/*
 * ABCD/SBCD/NBCD
 *
 * Match the authoritative gencpu.c 68040 algorithms exactly, including their
 * behaviour for non-decimal input nibbles.  The arithmetic cores leave the
 * byte result in REG_WORK2 and decimal carry/borrow in REG_WORK3.  Every
 * conditional correction uses a patched branch target: fixed instruction
 * counts are not stable when an immediate materialisation changes shape.
 *
 * Every generated form preserves the architecturally unchanged N/V bits,
 * computes sticky Z (old Z && result == 0), publishes C, and copies C to X.
 * BCD therefore has no flag-dead handler split that can leave architectural
 * NZVC stale at a block or diagnostic-observer boundary.
 */
STATIC_INLINE void emit_bcd_flags(int result, int carry)
{
	/* REG_WORK4 holds the incoming NZCV and is not touched by the cores. */
	UBFX_wwii(REG_WORK1, result, 0, 8);
	CMP_wi(REG_WORK1, 0); /* sticky Z is based on the truncated byte result */
	MRS_NZCV_x(REG_WORK1);
	UBFX_wwii(REG_WORK1, REG_WORK1, 30, 1); /* result Z */
	UBFX_wwii(REG_WORK2, REG_WORK4, 30, 1); /* incoming sticky Z */
	AND_www(REG_WORK1, REG_WORK1, REG_WORK2);
	BFI_wwii(REG_WORK4, REG_WORK1, 30, 1);
	BFI_wwii(REG_WORK4, carry, 29, 1);
	MSR_NZCV_x(REG_WORK4);
	flags_carry_inverted = false;
}

STATIC_INLINE void emit_abcd_b(int d, int s, int x)
{
	/* newv_lo = low(src) + low(dst) + X */
	UBFX_wwii(REG_WORK1, s, 0, 4);
	UBFX_wwii(REG_WORK2, d, 0, 4);
	ADD_www(REG_WORK1, REG_WORK1, REG_WORK2);
	ADD_www(REG_WORK1, REG_WORK1, x);

	/* newv = high(src) + high(dst) + newv_lo */
	UBFX_wwii(REG_WORK2, s, 4, 4);
	UBFX_wwii(REG_WORK3, d, 4, 4);
	ADD_www(REG_WORK2, REG_WORK2, REG_WORK3);
	LSL_wwi(REG_WORK2, REG_WORK2, 4);
	ADD_www(REG_WORK2, REG_WORK2, REG_WORK1);

	/* if (newv_lo > 9) newv += 6 */
	CMP_wi(REG_WORK1, 9);
	uae_u32 *low_ok = (uae_u32 *)get_target();
	BLS_i(0);
	ADD_wwi(REG_WORK2, REG_WORK2, 6);
	write_jmp_target(low_ok, (uintptr)get_target());

	/* cflg = (newv & 0x3f0) > 0x90; if (cflg) newv += 0x60 */
	UBFX_wwii(REG_WORK1, REG_WORK2, 4, 6);
	MOV_wi(REG_WORK3, 0);
	CMP_wi(REG_WORK1, 9);
	uae_u32 *carry_clear = (uae_u32 *)get_target();
	BLS_i(0);
	ADD_wwi(REG_WORK2, REG_WORK2, 0x60);
	MOV_wi(REG_WORK3, 1);
	write_jmp_target(carry_clear, (uintptr)get_target());
}

STATIC_INLINE void emit_sbcd_b(int d, int s, int x)
{
	/* Keep the unadjusted byte subtraction for both correction predicates. */
	UBFX_wwii(REG_WORK1, d, 0, 8);
	UBFX_wwii(REG_WORK2, s, 0, 8);
	SUB_www(REG_WORK3, REG_WORK1, REG_WORK2);
	SUB_www(REG_WORK3, REG_WORK3, x); /* raw dst - src - X */

	/* newv_lo = low(dst) - low(src) - X */
	UBFX_wwii(REG_WORK1, d, 0, 4);
	UBFX_wwii(REG_WORK2, s, 0, 4);
	SUB_www(REG_WORK1, REG_WORK1, REG_WORK2);
	SUB_www(REG_WORK1, REG_WORK1, x);

	/* newv = high(dst) - high(src) + newv_lo */
	UBFX_wwii(REG_WORK2, d, 4, 4);
	UBFX_wwii(x, s, 4, 4); /* incoming X has already been consumed */
	SUB_www(REG_WORK2, REG_WORK2, x);
	LSL_wwi(REG_WORK2, REG_WORK2, 4);
	ADD_www(REG_WORK2, REG_WORK2, REG_WORK1);

	/* if (newv_lo & 0xf0) { newv -= 6; bcd = 6; } */
	MOV_wi(x, 0); /* bcd */
	UBFX_wwii(REG_WORK1, REG_WORK1, 4, 4);
	uae_u32 *low_ok = (uae_u32 *)get_target();
	CBZ_wi(REG_WORK1, 0);
	SUB_wwi(REG_WORK2, REG_WORK2, 6);
	MOV_wi(x, 6);
	write_jmp_target(low_ok, (uintptr)get_target());

	/* if ((raw subtraction & 0x100) != 0) newv -= 0x60 */
	uae_u32 *high_ok = (uae_u32 *)get_target();
	TBZ_wii(REG_WORK3, 8, 0);
	SUB_wwi(REG_WORK2, REG_WORK2, 0x60);
	write_jmp_target(high_ok, (uintptr)get_target());

	/* cflg = (((raw subtraction - bcd) & 0x300) != 0) */
	SUB_www(REG_WORK1, REG_WORK3, x);
	UBFX_wwii(REG_WORK1, REG_WORK1, 8, 2);
	MOV_wi(REG_WORK3, 0);
	uae_u32 *borrow_clear = (uae_u32 *)get_target();
	CBZ_wi(REG_WORK1, 0);
	MOV_wi(REG_WORK3, 1);
	write_jmp_target(borrow_clear, (uintptr)get_target());
}

STATIC_INLINE void emit_nbcd_b(int d, int x)
{
	/* newv_lo = -low(src) - X */
	UBFX_wwii(REG_WORK1, d, 0, 4);
	MOV_wi(REG_WORK2, 0);
	SUB_www(REG_WORK1, REG_WORK2, REG_WORK1);
	SUB_www(REG_WORK1, REG_WORK1, x);

	/* newv_hi = -high(src) */
	UBFX_wwii(REG_WORK2, d, 4, 4);
	LSL_wwi(REG_WORK2, REG_WORK2, 4);
	MOV_wi(REG_WORK3, 0);
	SUB_www(REG_WORK2, REG_WORK3, REG_WORK2);

	/* The interpreter compares the unsigned 16-bit underflow against nine. */
	CMP_wi(REG_WORK1, 9);
	uae_u32 *low_ok = (uae_u32 *)get_target();
	BLS_i(0);
	SUB_wwi(REG_WORK1, REG_WORK1, 6);
	write_jmp_target(low_ok, (uintptr)get_target());

	ADD_www(REG_WORK2, REG_WORK2, REG_WORK1);

	/* cflg = (newv & 0x1f0) > 0x90; if (cflg) newv -= 0x60 */
	UBFX_wwii(REG_WORK1, REG_WORK2, 4, 5);
	MOV_wi(REG_WORK3, 0);
	CMP_wi(REG_WORK1, 9);
	uae_u32 *borrow_clear = (uae_u32 *)get_target();
	BLS_i(0);
	SUB_wwi(REG_WORK2, REG_WORK2, 0x60);
	MOV_wi(REG_WORK3, 1);
	write_jmp_target(borrow_clear, (uintptr)get_target());
}

MIDFUNC(2,jff_ABCD_b,(RW1 d, RR1 s))
{
	INIT_REGS_b(d, s);
	int x = rmw(FLAGX);
	MRS_NZCV_x(REG_WORK4);
	emit_abcd_b(d, s, x);
	BFI_wwii(d, REG_WORK2, 0, 8);
	emit_bcd_flags(REG_WORK2, REG_WORK3);
	MOV_ww(x, REG_WORK3);
	unlock2(x);
	EXIT_REGS(d, s);
}
MENDFUNC(2,jff_ABCD_b,(RW1 d, RR1 s))

MIDFUNC(2,jff_SBCD_b,(RW1 d, RR1 s))
{
	INIT_REGS_b(d, s);
	int x = rmw(FLAGX);
	MRS_NZCV_x(REG_WORK4);
	emit_sbcd_b(d, s, x);
	BFI_wwii(d, REG_WORK2, 0, 8);
	emit_bcd_flags(REG_WORK2, REG_WORK3);
	MOV_ww(x, REG_WORK3);
	unlock2(x);
	EXIT_REGS(d, s);
}
MENDFUNC(2,jff_SBCD_b,(RW1 d, RR1 s))

MIDFUNC(1,jff_NBCD_b,(RW1 d))
{
	d = rmw(d);
	int x = rmw(FLAGX);
	MRS_NZCV_x(REG_WORK4);
	emit_nbcd_b(d, x);
	BFI_wwii(d, REG_WORK2, 0, 8);
	emit_bcd_flags(REG_WORK2, REG_WORK3);
	MOV_ww(x, REG_WORK3);
	unlock2(x);
	unlock2(d);
}
MENDFUNC(1,jff_NBCD_b,(RW1 d))

/*
 * CHK — Check Register Against Bounds
 *
 * CHK changes only N, and only on a trapping comparison.  The generator saves
 * the incoming NZCV before entering here.  Encode the selected N value in the
 * deferred request; execute_exception publishes that one bit immediately before
 * Exception(6), while plain vector-6 requests such as CHK2 remain untouched.
 */
STATIC_INLINE void emit_chk_trap(int negative, uintptr exception_idx)
{
	const uae_u32 request = 6 | JIT_EXCEPTION_OLDPC_VALID |
		JIT_EXCEPTION_CHK_N_VALID |
		(negative ? JIT_EXCEPTION_CHK_N_SET : 0);
	LOAD_U32(REG_WORK3, request);
	STR_wXi(REG_WORK3, R_REGSTRUCT, exception_idx);
}

MIDFUNC(2,jnf_CHK_w,(RR2 d, RR2 s))
{
	d = readreg(d);
	s = readreg(s);

	const uintptr exception_idx = (uintptr)(&regs.jit_exception) - (uintptr)(&regs);
	MOV_wi(REG_WORK3, 0);
	STR_wXi(REG_WORK3, R_REGSTRUCT, exception_idx);

	SXTH_ww(REG_WORK1, d);
	SXTH_ww(REG_WORK2, s);

	CMP_wi(REG_WORK1, 0);
	uae_u32 *nonnegative = (uae_u32 *)get_target();
	BGE_i(0);
	emit_chk_trap(1, exception_idx);
	uae_u32 *done = (uae_u32 *)get_target();
	B_i(0);

	write_jmp_target(nonnegative, (uintptr)get_target());
	CMP_ww(REG_WORK1, REG_WORK2);
	uae_u32 *in_range = (uae_u32 *)get_target();
	BLE_i(0);
	emit_chk_trap(0, exception_idx);

	write_jmp_target(done, (uintptr)get_target());
	write_jmp_target(in_range, (uintptr)get_target());
	register_possible_exception();
	unlock2(s);
	unlock2(d);
}
MENDFUNC(2,jnf_CHK_w,(RR2 d, RR2 s))

MIDFUNC(2,jnf_CHK_l,(RR4 d, RR4 s))
{
	d = readreg(d);
	s = readreg(s);

	const uintptr exception_idx = (uintptr)(&regs.jit_exception) - (uintptr)(&regs);
	MOV_wi(REG_WORK3, 0);
	STR_wXi(REG_WORK3, R_REGSTRUCT, exception_idx);

	CMP_wi(d, 0);
	uae_u32 *nonnegative = (uae_u32 *)get_target();
	BGE_i(0);
	emit_chk_trap(1, exception_idx);
	uae_u32 *done = (uae_u32 *)get_target();
	B_i(0);

	write_jmp_target(nonnegative, (uintptr)get_target());
	CMP_ww(d, s);
	uae_u32 *in_range = (uae_u32 *)get_target();
	BLE_i(0);
	emit_chk_trap(0, exception_idx);

	write_jmp_target(done, (uintptr)get_target());
	write_jmp_target(in_range, (uintptr)get_target());
	register_possible_exception();
	unlock2(s);
	unlock2(d);
}
MENDFUNC(2,jnf_CHK_l,(RR4 d, RR4 s))
/*
 * SWAP
 * Operand Syntax: Dn
 *
 *  Operand Size: 16
 *
 * X Not affected.
 * N Set if the most significant bit of the 32-bit result is set. Cleared otherwise.
 * Z Set if the 32-bit result is zero. Cleared otherwise.
 * V Always cleared.
 * C Always cleared.
 *
 */
MIDFUNC(1,jnf_SWAP,(RW4 d))
{
	if (isconst(d)) {
		live.state[d].val = (live.state[d].val >> 16) | (live.state[d].val << 16);
		return;
	}

	d = rmw(d);

	ROR_wwi(d, d, 16);

	unlock2(d);
}
MENDFUNC(1,jnf_SWAP,(RW4 d))

MIDFUNC(1,jff_SWAP,(RW4 d))
{
	if(isconst(d)) {
		live.state[d].val = (live.state[d].val >> 16) | (live.state[d].val << 16);
		uae_u32 f = 0;
		if((uae_s32)live.state[d].val == 0)
			f |= (ARM_Z_FLAG >> 16);
		if((uae_s32)live.state[d].val < 0)
			f |= (ARM_N_FLAG >> 16);
		MOV_xish(REG_WORK1, f, 16);
		MSR_NZCV_x(REG_WORK1);
		flags_carry_inverted = false;
		return;
	}

	d = rmw(d);

	ROR_wwi(d, d, 16);
	TST_ww(d, d);

	flags_carry_inverted = false;
	unlock2(d);
}
MENDFUNC(1,jff_SWAP,(RW4 d))

/*
 * TST
 * Operand Syntax: <ea>
 *
 *  Operand Size: 8,16,32
 *
 * X Not affected.
 * N Set if the operand is negative. Cleared otherwise.
 * Z Set if the operand is zero. Cleared otherwise.
 * V Always cleared.
 * C Always cleared.
 *
 */
MIDFUNC(1,jff_TST_b_imm,(IM8 v))
{
	SIGNED8_IMM_2_REG(REG_WORK1, (uae_u8)v);
	TST_ww(REG_WORK1, REG_WORK1);
	flags_carry_inverted = false;
}
MENDFUNC(1,jff_TST_b_imm,(IM8 v))

MIDFUNC(1,jff_TST_b,(RR1 s))
{
	if (isconst(s)) {
		COMPCALL(jff_TST_b_imm)(live.state[s].val);
		return;
	}

	s = readreg(s);
	SIGNED8_REG_2_REG(REG_WORK1, s);
	unlock2(s);

	TST_ww(REG_WORK1, REG_WORK1);
	flags_carry_inverted = false;
}
MENDFUNC(1,jff_TST_b,(RR1 s))

MIDFUNC(1,jff_TST_w_imm,(IM16 v))
{
	SIGNED16_IMM_2_REG(REG_WORK1, (uae_u16)v);
	TST_ww(REG_WORK1, REG_WORK1);
	flags_carry_inverted = false;
}
MENDFUNC(1,jff_TST_w_imm,(IM16 v))

MIDFUNC(1,jff_TST_w,(RR2 s))
{
	if (isconst(s)) {
		COMPCALL(jff_TST_w_imm)(live.state[s].val);
		return;
	}

	s = readreg(s);
	SIGNED16_REG_2_REG(REG_WORK1, s);
	unlock2(s);

	TST_ww(REG_WORK1, REG_WORK1);
	flags_carry_inverted = false;
}
MENDFUNC(1,jff_TST_w,(RR2 s))

MIDFUNC(1,jff_TST_l_imm,(IM32 v))
{
	LOAD_U32(REG_WORK1, v);
	TST_ww(REG_WORK1, REG_WORK1);
	flags_carry_inverted = false;
}
MENDFUNC(1,jff_TST_l_imm,(IM32 v))

MIDFUNC(1,jff_TST_l,(RR4 s))
{
	if(isconst(s)) {
		COMPCALL(jff_TST_l_imm)(live.state[s].val);
		return;
	}

	s = readreg(s);
	TST_ww(s, s);
	unlock2(s);
	flags_carry_inverted = false;
}
MENDFUNC(1,jff_TST_l,(RR4 s))

/*
 * Memory access functions
 *
 * Two versions: full address range and 24 bit address range
 *
 */

/* Guest low-NuBus addresses can overlap the host JIT cache reservation.  Emit
   one shared write-side guard so no direct store can modify native code.  The
   returned branch is patched after the caller's ordinary store path. */
STATIC_INLINE uae_u32 *emit_low_nubus_gap_write_skip(RR4 adr)
{
	if (RAMSize > 0x08000000u)
		return NULL;

	LOAD_U32(REG_WORK1, LOW_NUBUS_OPEN_BUS_START);
	CMP_ww(adr, REG_WORK1);
	uae_u32 *normal_low = (uae_u32 *)get_target();
	BCC_i(0);
	LOAD_U32(REG_WORK1, LOW_NUBUS_OPEN_BUS_END);
	CMP_ww(adr, REG_WORK1);
	uae_u32 *normal_high = (uae_u32 *)get_target();
	BCS_i(0);
	uae_u32 *skip = (uae_u32 *)get_target();
	B_i(0);

	write_jmp_target(normal_low, (uintptr)get_target());
	write_jmp_target(normal_high, (uintptr)get_target());
	return skip;
}

STATIC_INLINE uae_u32 *emit_low_nubus_gap_read_value(RR4 adr, W4 d, uae_u32 value)
{
	if (RAMSize > 0x08000000u)
		return NULL;

	LOAD_U32(REG_WORK1, LOW_NUBUS_OPEN_BUS_START);
	CMP_ww(adr, REG_WORK1);
	uae_u32 *normal_low = (uae_u32 *)get_target();
	BCC_i(0);
	LOAD_U32(REG_WORK1, LOW_NUBUS_OPEN_BUS_END);
	CMP_ww(adr, REG_WORK1);
	uae_u32 *normal_high = (uae_u32 *)get_target();
	BCS_i(0);
	LOAD_U32(d, value);
	uae_u32 *skip = (uae_u32 *)get_target();
	B_i(0);

	write_jmp_target(normal_low, (uintptr)get_target());
	write_jmp_target(normal_high, (uintptr)get_target());
	return skip;
}

STATIC_INLINE void finish_low_nubus_gap_skip(uae_u32 *skip)
{
	if (skip)
		write_jmp_target(skip, (uintptr)get_target());
}

MIDFUNC(2,jnf_MEM_WRITE_OFF_b,(RR4 adr, RR4 b))
{
	adr = readreg(adr);
	b = readreg(b);

	/* Match memory.h::put_byte exactly: scanner-data writes are ignored;
	   every other direct byte write stores the architectural source byte
	   unchanged.  The guard CMP is emitter plumbing, not guest arithmetic,
	   so preserve the incoming NZCV across it. */
	MRS_NZCV_x(REG_WORK4);
	uae_u32 *gap_done = emit_low_nubus_gap_write_skip(adr);
	LOAD_U32(REG_WORK1, 0xff001fff);
	AND_www(REG_WORK1, adr, REG_WORK1);
	LOAD_U32(REG_WORK3, 0x50000006);
	CMP_ww(REG_WORK1, REG_WORK3);
	BEQ_i(2);
	STRB_wXx(b, adr, R_MEMSTART);
	finish_low_nubus_gap_skip(gap_done);
	emit_strict_cache_disabled_write_barrier(adr, 1);
	MSR_NZCV_x(REG_WORK4);

	unlock2(b);
	unlock2(adr);
}
MENDFUNC(2,jnf_MEM_WRITE_OFF_b,(RR4 adr, RR4 b))

MIDFUNC(2,jnf_MEM_WRITE_OFF_w,(RR4 adr, RR4 w))
{
	adr = readreg(adr);
	w = readreg(w);

	MRS_NZCV_x(REG_WORK4);
	uae_u32 *gap_done = emit_low_nubus_gap_write_skip(adr);
	REV16_ww(REG_WORK1, w);
	STRH_wXx(REG_WORK1, adr, R_MEMSTART);
	finish_low_nubus_gap_skip(gap_done);
	emit_strict_cache_disabled_write_barrier(adr, 2);
	MSR_NZCV_x(REG_WORK4);

	unlock2(w);
	unlock2(adr);
}
MENDFUNC(2,jnf_MEM_WRITE_OFF_w,(RR4 adr, RR4 w))

MIDFUNC(2,jnf_MEM_WRITE_OFF_l,(RR4 adr, RR4 l))
{
	adr = readreg(adr);
	l = readreg(l);

	/* The 0x5ffffffc guard CMP clobbers host NZCV holding just-computed guest
	   flags (e.g. MOVE.L/CLR.L). Preserve them as the read paths do. */
	MRS_NZCV_x(REG_WORK4);
	uae_u32 *gap_done = emit_low_nubus_gap_write_skip(adr);
	/* Machine config register at 0x5ffffffc is stable hardware; ROM probes
	   write test patterns here and expects the original value to remain. */
	LOAD_U32(REG_WORK1, 0x5ffffffc);
	CMP_ww(adr, REG_WORK1);
	BEQ_i(3);
	REV_ww(REG_WORK1, l);
	STR_wXx(REG_WORK1, adr, R_MEMSTART);
	finish_low_nubus_gap_skip(gap_done);
	emit_strict_cache_disabled_write_barrier(adr, 4);
	MSR_NZCV_x(REG_WORK4);

	unlock2(l);
	unlock2(adr);
}
MENDFUNC(2,jnf_MEM_WRITE_OFF_l,(RR4 adr, RR4 l))


MIDFUNC(2,jnf_MEM_READ_OFF_b,(W4 d, RR4 adr))
{
	adr = readreg(adr);
	d = writereg(d);
	MRS_NZCV_x(REG_WORK4);

	/* Low NuBus mirror gap aliases the host JIT cache. memory.h and the
	   emitted direct path share one all-ones open-bus contract. */
	uae_u32 *gap_done = emit_low_nubus_gap_read_value(adr, d, 0xffu);
	LDRB_wXx(d, adr, R_MEMSTART);
	LOAD_U32(REG_WORK1, 0xff001fff);
	AND_www(REG_WORK1, adr, REG_WORK1);
	LOAD_U32(REG_WORK3, 0x50000002);
	CMP_ww(REG_WORK1, REG_WORK3);
	BNE_i(3);
	MOV_wi(REG_WORK1, 0);
	STRB_wXx(REG_WORK1, adr, R_MEMSTART);
	finish_low_nubus_gap_skip(gap_done);
	MSR_NZCV_x(REG_WORK4);

	unlock2(d);
	unlock2(adr);
}
MENDFUNC(2,jnf_MEM_READ_OFF_b,(W4 d, RR4 adr))

MIDFUNC(2,jnf_MEM_READ_OFF_w,(W4 d, RR4 adr))
{
	adr = readreg(adr);
	d = writereg(d);
	MRS_NZCV_x(REG_WORK4);

	uae_u32 *gap_done = emit_low_nubus_gap_read_value(adr, d, 0xffffu);
	LDRH_wXx(REG_WORK1, adr, R_MEMSTART);
	REV16_ww(d, REG_WORK1);
	finish_low_nubus_gap_skip(gap_done);
	MSR_NZCV_x(REG_WORK4);

	unlock2(d);
	unlock2(adr);
}
MENDFUNC(2,jnf_MEM_READ_OFF_w,(W4 d, RR4 adr))

MIDFUNC(2,jnf_MEM_READ_OFF_l,(W4 d, RR4 adr))
{
	adr = readreg(adr);
	d = writereg(d);
	MRS_NZCV_x(REG_WORK4);

	uae_u32 *gap_done = emit_low_nubus_gap_read_value(adr, d, 0xffffffffu);
	LDR_wXx(REG_WORK1, adr, R_MEMSTART);
	REV_ww(d, REG_WORK1);
	finish_low_nubus_gap_skip(gap_done);
	MSR_NZCV_x(REG_WORK4);

	unlock2(d);
	unlock2(adr);
}
MENDFUNC(2,jnf_MEM_READ_OFF_l,(W4 d, RR4 adr))


MIDFUNC(2,jnf_MEM_WRITE24_OFF_b,(RR4 adr, RR4 b))
{
	adr = readreg(adr);
	b = readreg(b);

	/* CMP guards below clobber guest NZCV; preserve like the read paths. */
	MRS_NZCV_x(REG_WORK4);
	/* 0x50xxxxxx is probed as hardware by the Quadra ROM.  Its byte
	   test expects a transformed readback rather than ordinary RAM. */
	LOAD_U32(REG_WORK1, 0xff000000);
	AND_www(REG_WORK1, adr, REG_WORK1);
	LOAD_U32(REG_WORK3, 0x50000000);
	CMP_ww(REG_WORK1, REG_WORK3);
	LSL_wwi(REG_WORK3, b, 1);
	NEG_ww(REG_WORK3, REG_WORK3);
	CSEL_wwwc(REG_WORK3, REG_WORK3, b, NATIVE_CC_EQ);
	LOAD_U32(REG_WORK1, 0x1fff);
	AND_www(REG_WORK1, adr, REG_WORK1);
	CMP_wi(REG_WORK1, 2);
	CSEL_wwwc(REG_WORK3, b, REG_WORK3, NATIVE_CC_EQ);
	CMP_wi(REG_WORK1, 6);
	BEQ_i(3);
	UBFIZ_xxii(REG_WORK1, adr, 0, 24);
	STRB_wXx(REG_WORK3, REG_WORK1, R_MEMSTART);
	/* Coherency follows the effective 24-bit bus address, not the unmasked
	   logical register value: high-byte aliases must invalidate the RAM block
	   that the store actually modified. */
	emit_strict_cache_disabled_write_barrier(REG_WORK1, 1);
	MSR_NZCV_x(REG_WORK4);

	unlock2(b);
	unlock2(adr);
}
MENDFUNC(2,jnf_MEM_WRITE24_OFF_b,(RR4 adr, RR4 b))

MIDFUNC(2,jnf_MEM_WRITE24_OFF_w,(RR4 adr, RR4 w))
{
	adr = readreg(adr);
	w = readreg(w);

	UBFIZ_xxii(REG_WORK1, adr, 0, 24);
	REV16_ww(REG_WORK3, w);
	STRH_wXx(REG_WORK3, REG_WORK1, R_MEMSTART);
	emit_strict_cache_disabled_write_barrier(REG_WORK1, 2);

	unlock2(w);
	unlock2(adr);
}
MENDFUNC(2,jnf_MEM_WRITE24_OFF_w,(RR4 adr, RR4 w))

MIDFUNC(2,jnf_MEM_WRITE24_OFF_l,(RR4 adr, RR4 l))
{
	adr = readreg(adr);
	l = readreg(l);

	/* CMP guard below clobbers guest NZCV; preserve like the read paths. */
	MRS_NZCV_x(REG_WORK4);
	/* Machine config register aliases to 0x00fffffc in 24-bit direct mode;
	   ROM probes write test patterns here and expects the original value to remain. */
	UBFIZ_xxii(REG_WORK1, adr, 0, 24);
	LOAD_U32(REG_WORK3, 0x00fffffc);
	CMP_ww(REG_WORK1, REG_WORK3);
	BEQ_i(3);
	REV_ww(REG_WORK3, l);
	STR_wXx(REG_WORK3, REG_WORK1, R_MEMSTART);
	emit_strict_cache_disabled_write_barrier(REG_WORK1, 4);
	MSR_NZCV_x(REG_WORK4);

	unlock2(l);
	unlock2(adr);
}
MENDFUNC(2,jnf_MEM_WRITE24_OFF_l,(RR4 adr, RR4 l))


MIDFUNC(2,jnf_MEM_READ24_OFF_b,(W4 d, RR4 adr))
{
	adr = readreg(adr);
	d = writereg(d);

	/* The scanner-status comparison is an addressing implementation detail,
	   not a 68k flag-producing operation. Preserve live guest NZCV exactly as
	   the 32-bit direct read path does. */
	MRS_NZCV_x(REG_WORK4);
	UBFIZ_xxii(REG_WORK1, adr, 0, 24);
	LDRB_wXx(d, REG_WORK1, R_MEMSTART);
	LOAD_U32(REG_WORK3, 0x00ffff);
	AND_www(REG_WORK3, adr, REG_WORK3);
	CMP_wi(REG_WORK3, 2);
	BNE_i(3);
	MOV_wi(REG_WORK3, 0);
	STRB_wXx(REG_WORK3, REG_WORK1, R_MEMSTART);
	MSR_NZCV_x(REG_WORK4);

	unlock2(d);
	unlock2(adr);
}
MENDFUNC(2,jnf_MEM_READ24_OFF_b,(W4 d, RR4 adr))

MIDFUNC(2,jnf_MEM_READ24_OFF_w,(W4 d, RR4 adr))
{
	adr = readreg(adr);
	d = writereg(d);

	UBFIZ_xxii(REG_WORK1, adr, 0, 24);
	LDRH_wXx(REG_WORK1, REG_WORK1, R_MEMSTART);
	REV16_ww(d, REG_WORK1);

	unlock2(d);
	unlock2(adr);
}
MENDFUNC(2,jnf_MEM_READ24_OFF_w,(W4 d, RR4 adr))

MIDFUNC(2,jnf_MEM_READ24_OFF_l,(W4 d, RR4 adr))
{
	adr = readreg(adr);
	d = writereg(d);

	UBFIZ_xxii(REG_WORK1, adr, 0, 24);
	LDR_wXx(d, REG_WORK1, R_MEMSTART);
	REV_ww(d, d);

	unlock2(d);
	unlock2(adr);
}
MENDFUNC(2,jnf_MEM_READ24_OFF_l,(W4 d, RR4 adr))


MIDFUNC(2,jnf_MEM_GETADR_OFF,(W4 d, RR4 adr))
{
	adr = readreg(adr);
	d = writereg(d);

	ADD_xxwEX(d, R_MEMSTART, adr, EX_UXTW);

	unlock2(d);
	unlock2(adr);
}
MENDFUNC(2,jnf_MEM_GETADR_OFF,(W4 d, RR4 adr))

MIDFUNC(2,jnf_MEM_GETADR24_OFF,(W4 d, RR4 adr))
{
	adr = readreg(adr);
	d = writereg(d);

	UBFIZ_xxii(REG_WORK1, adr, 0, 24);
	ADD_xxwEX(d, R_MEMSTART, REG_WORK1, EX_UXTW);

	unlock2(d);
	unlock2(adr);
}
MENDFUNC(2,jnf_MEM_GETADR24_OFF,(W4 d, RR4 adr))

MIDFUNC(2,jnf_MEM_GETADR_JMP_OFF,(W4 d, RR4 adr))
{
	adr = readreg(adr);
	d = writereg(d);

	LOAD_U64(REG_WORK2, (uintptr)baseaddr);
	LSR_wwi(REG_WORK1, adr, 16);
	LDR_xXxLSLi(REG_WORK3, REG_WORK2, REG_WORK1, 1); // 1 means shift by 3
	ADD_xxwEX(d, REG_WORK3, adr, EX_UXTW);
	LOAD_U64(REG_WORK1, ~1ULL);
	AND_xxx(d, d, REG_WORK1);

	unlock2(d);
	unlock2(adr);
}
MENDFUNC(2,jnf_MEM_GETADR_JMP_OFF,(W4 d, RR4 adr))


MIDFUNC(3,jnf_MEM_READMEMBANK,(W4 dest, RR4 adr, IM8 offset))
{
	clobber_flags();
	if (dest != adr) {
		COMPCALL(forget_about)(dest);
	}

	adr = readreg_specific(adr, REG_PAR1);
	prepare_for_call_1();
	unlock2(adr);
	prepare_for_call_2();

	uintptr idx = (uintptr)(&regs.mem_banks) - (uintptr)(&regs);
	LDR_xXi(REG_WORK2, R_REGSTRUCT, idx);
	LSR_wwi(REG_WORK1, adr, 16);
	LDR_xXxLSLi(REG_WORK3, REG_WORK2, REG_WORK1, 1); // 1 means shift by 3
	LDR_xXi(REG_WORK3, REG_WORK3, offset);

	compemu_raw_call_r(REG_WORK3);
	// Most bank callbacks return 32-bit values and need upper-bit cleanup.
	// xlateaddr callback (offset=6*sizeof(void*)) returns a host pointer.
	if (offset != SIZEOF_VOID_P * 6)
		MOV_ww(REG_RESULT, REG_RESULT);

	live.nat[REG_RESULT].holds[0] = dest;
	live.nat[REG_RESULT].nholds = 1;
	live.nat[REG_RESULT].touched = touchcnt++;

	live.state[dest].realreg = REG_RESULT;
	live.state[dest].realind = 0;
	live.state[dest].val = 0;
	set_status(dest, DIRTY);
}
MENDFUNC(3,jnf_MEM_READMEMBANK,(W4 dest, RR4 adr, IM8 offset))


MIDFUNC(3,jnf_MEM_WRITEMEMBANK,(RR4 adr, RR4 source, IM8 offset))
{
	clobber_flags();

	adr = readreg_specific(adr, REG_PAR1);
	source = readreg_specific(source, REG_PAR2);
	prepare_for_call_1();
	unlock2(adr);
	unlock2(source);
	prepare_for_call_2();

	uintptr idx = (uintptr)(&regs.mem_banks) - (uintptr)(&regs);
	LDR_xXi(REG_WORK2, R_REGSTRUCT, idx);
	LSR_wwi(REG_WORK1, adr, 16);
	LDR_xXxLSLi(REG_WORK3, REG_WORK2, REG_WORK1, 1); // 1 means shift by 3
	LDR_xXi(REG_WORK3, REG_WORK3, offset);

	compemu_raw_call_r(REG_WORK3);
}
MENDFUNC(3,jnf_MEM_WRITEMEMBANK,(RR4 adr, RR4 source, IM8 offset))

/*
 * TAS
 * Test byte and set bit 7.
 *
 * X Not affected.
 * N Set if the most significant bit of the operand is set. Cleared otherwise.
 * Z Set if the operand is zero. Cleared otherwise.
 * V Always cleared.
 * C Always cleared.
 */
MIDFUNC(1,jnf_TAS,(RW1 d))
{
	d = rmw(d);
	MOV_wi(REG_WORK1, 0x80);
	ORR_www(d, d, REG_WORK1);
	unlock2(d);
}
MENDFUNC(1,jnf_TAS,(RW1 d))

MIDFUNC(1,jff_TAS,(RW1 d))
{
	d = rmw(d);
	/* Test the byte value first (before setting bit 7) */
	SIGNED8_REG_2_REG(REG_WORK1, d);
	TST_ww(REG_WORK1, REG_WORK1);
	/* Now set bit 7 */
	MOV_wi(REG_WORK2, 0x80);
	ORR_www(d, d, REG_WORK2);
	flags_carry_inverted = false;
	unlock2(d);
}
MENDFUNC(1,jff_TAS,(RW1 d))

/*
 * TRAPV: Trap on overflow (V flag set)
 * If V flag is set in NZCV, signal exception 7 via jit_exception.
 */
MIDFUNC(0,jnf_TRAPV,(void))
{
	const uintptr exception_idx = (uintptr)(&regs.jit_exception) - (uintptr)(&regs);
	prepare_arithmetic_exception(exception_idx);
	/* MRS does not alter NZCV. Test V without normalising carry in a temporary:
	 * TRAPV preserves the complete incoming CCR in its exception frame and on
	 * its non-trapping successor. */
	MRS_NZCV_x(REG_WORK1);
	TBZ_xii(REG_WORK1, 28, 4);   /* if V=0, skip the tagged request */
	emit_arithmetic_exception(7, exception_idx);
}
MENDFUNC(0,jnf_TRAPV,(void))

/*
 * ROXLW: Rotate left through extend, word, memory (shift by 1)
 * bit_out = MSB; result = (val << 1) | X; X = C = bit_out
 * N set from MSB of result, Z from result==0, V cleared
 */
MIDFUNC(1,jff_ROXLW,(RW2 d))
{
	d = rmw(d);
	int x = rmw(FLAGX);

	UNSIGNED16_REG_2_REG(REG_WORK1, d);
	/* Shift left by 1, insert old X into bit 0 */
	LSL_wwi(REG_WORK2, REG_WORK1, 1);
	/* Insert X flag (bit 0 of FLAGX) into bit 0 of result */
	BFI_wwii(REG_WORK2, x, 0, 1);
	/* Extract old MSB (bit 15 of original) for new X/C */
	UBFX_wwii(REG_WORK3, REG_WORK1, 15, 1);

	/* Store result back into low 16 bits */
	BFI_wwii(d, REG_WORK2, 0, 16);

	/* Set X flag = old MSB.  The RMW binding records exactly one write and
	 * remains owned until the single unlock below. */
	MOV_ww(x, REG_WORK3);

	/* Set N, Z flags from result (16-bit) */
	SIGNED16_REG_2_REG(REG_WORK1, REG_WORK2);
	TST_ww(REG_WORK1, REG_WORK1);

	PUBLISH_CARRY_FROM_BIT(REG_WORK3, 0, REG_WORK1);

	flags_carry_inverted = false;

	unlock2(x);
	unlock2(d);
}
MENDFUNC(1,jff_ROXLW,(RW2 d))

/*
 * ROXRW: Rotate right through extend, word, memory (shift by 1)
 * bit_out = LSB; result = (val >> 1) | (X << 15); X = C = bit_out
 */
MIDFUNC(1,jff_ROXRW,(RW2 d))
{
	d = rmw(d);
	int x = rmw(FLAGX);

	UNSIGNED16_REG_2_REG(REG_WORK1, d);
	/* Extract LSB for new X/C */
	MOV_wi(REG_WORK3, 1);
	AND_www(REG_WORK3, REG_WORK1, REG_WORK3);
	/* Shift right by 1 */
	LSR_wwi(REG_WORK2, REG_WORK1, 1);
	/* Insert old X into bit 15 */
	BFI_wwii(REG_WORK2, x, 15, 1);

	/* Store result back */
	BFI_wwii(d, REG_WORK2, 0, 16);

	/* Set X flag = old LSB.  The RMW binding records exactly one write and
	 * remains owned until the single unlock below. */
	MOV_ww(x, REG_WORK3);

	/* Set N, Z from result */
	SIGNED16_REG_2_REG(REG_WORK1, REG_WORK2);
	TST_ww(REG_WORK1, REG_WORK1);

	PUBLISH_CARRY_FROM_BIT(REG_WORK3, 0, REG_WORK1);

	flags_carry_inverted = false;

	unlock2(x);
	unlock2(d);
}
MENDFUNC(1,jff_ROXRW,(RW2 d))

/*
 * MV2SCCR: Move to CCR (byte → condition codes)
 * Maps M68K XNZVC bits to ARM64 NZCV + FLAGX
 */
MIDFUNC(1,jff_MV2SCCR,(RR4 s))
{
	s = readreg(s);
	int x = writereg(FLAGX);

	/* Extract X flag (bit 4) */
	UBFX_wwii(x, s, 4, 1);

	/* Build ARM NZCV from M68K NZVC:
	   M68K: bit3=N, bit2=Z, bit1=V, bit0=C
	   ARM:  bit31=N, bit30=Z, bit29=C, bit28=V
	   Remap: N stays at top, Z shifts, C and V swap positions */
	MOV_xi(REG_WORK1, 0);

	/* N flag: M68K bit 3 → ARM bit 31 */
	UBFX_wwii(REG_WORK2, s, 3, 1);
	LSL_xxi(REG_WORK2, REG_WORK2, 31);
	ORR_xxx(REG_WORK1, REG_WORK1, REG_WORK2);

	/* Z flag: M68K bit 2 → ARM bit 30 */
	UBFX_wwii(REG_WORK2, s, 2, 1);
	LSL_xxi(REG_WORK2, REG_WORK2, 30);
	ORR_xxx(REG_WORK1, REG_WORK1, REG_WORK2);

	/* C flag: M68K bit 0 → ARM bit 29 */
	UBFX_wwii(REG_WORK2, s, 0, 1);
	LSL_xxi(REG_WORK2, REG_WORK2, 29);
	ORR_xxx(REG_WORK1, REG_WORK1, REG_WORK2);

	/* V flag: M68K bit 1 → ARM bit 28 */
	UBFX_wwii(REG_WORK2, s, 1, 1);
	LSL_xxi(REG_WORK2, REG_WORK2, 28);
	ORR_xxx(REG_WORK1, REG_WORK1, REG_WORK2);

	MSR_NZCV_x(REG_WORK1);
	flags_carry_inverted = false;

	unlock2(x);
	unlock2(s);
}
MENDFUNC(1,jff_MV2SCCR,(RR4 s))

/*
 * Inline MakeFromSR: decompose regs.sr into individual fields and swap stacks.
 * Called after regs.sr has been updated with the new value.
 * Emits ARM64 code that does what the C function MakeFromSR() does.
 *
 * REG_WORK1 = new sr value
 * REG_WORK2, REG_WORK3, REG_WORK4 = scratch
 */
static void inline_MakeFromSR(int sr_reg)
{
	/* Copy sr to REG_WORK1 so we don't clobber sr_reg */
	if (sr_reg != REG_WORK1)
		MOV_ww(REG_WORK1, sr_reg);

	/* Save old s and m for stack-swap detection */
	LDRB_wXi(REG_WORK3, R_REGSTRUCT, 80);  /* old_s */
	LDRB_wXi(REG_WORK4, R_REGSTRUCT, 81);  /* old_m */

	/* Store new sr */
	STRH_wXi(REG_WORK1, R_REGSTRUCT, 76);

	/* Decompose upper bits using REG_WORK2 as scratch */
	UBFX_wwii(REG_WORK2, REG_WORK1, 15, 1);
	STRB_wXi(REG_WORK2, R_REGSTRUCT, 78);   /* t1 */
	UBFX_wwii(REG_WORK2, REG_WORK1, 14, 1);
	STRB_wXi(REG_WORK2, R_REGSTRUCT, 79);   /* t0 */
	UBFX_wwii(REG_WORK2, REG_WORK1, 13, 1);
	STRB_wXi(REG_WORK2, R_REGSTRUCT, 80);   /* s */
	UBFX_wwii(REG_WORK2, REG_WORK1, 12, 1);
	STRB_wXi(REG_WORK2, R_REGSTRUCT, 81);   /* m */
	UBFX_wwii(REG_WORK2, REG_WORK1, 8, 3);
	STR_wXi(REG_WORK2, R_REGSTRUCT, 84);    /* intmask */

	/* Stack swap: old_s (REG_WORK3) vs new_s (bit 13) */
	UBFX_wwii(REG_WORK2, REG_WORK1, 13, 1);
	CMP_ww(REG_WORK3, REG_WORK2);
	uae_u32 *skip_swap = (uae_u32 *)get_target();
	BEQ_i(0);

	/* S changed */
	LDR_wXi(REG_WORK2, R_REGSTRUCT, 60);    /* current A7 */

	TBZ_wii(REG_WORK3, 0, 0);
	uae_u32 *was_user = (uae_u32 *)get_target() - 1;

	/* Was supervisor: save A7 to ISP/MSP based on old_m, load USP */
	TBZ_wii(REG_WORK4, 0, 2);
	STR_wXi(REG_WORK2, R_REGSTRUCT, 72);    /* msp = A7 */
	uae_u32 *s1_done = (uae_u32 *)get_target();
	B_i(0);
	STR_wXi(REG_WORK2, R_REGSTRUCT, 68);    /* isp = A7 */
	write_jmp_target(s1_done, (uintptr)get_target());
	LDR_wXi(REG_WORK2, R_REGSTRUCT, 64);    /* USP */
	STR_wXi(REG_WORK2, R_REGSTRUCT, 60);    /* A7 = USP */
	uae_u32 *swap_done = (uae_u32 *)get_target();
	B_i(0);

	/* Was user: save A7 to USP, load ISP/MSP based on new_m */
	write_jmp_target(was_user, (uintptr)get_target());
	STR_wXi(REG_WORK2, R_REGSTRUCT, 64);    /* USP = A7 */
	LDRB_wXi(REG_WORK2, R_REGSTRUCT, 81);   /* new_m */
	TBZ_wii(REG_WORK2, 0, 2);
	LDR_wXi(REG_WORK2, R_REGSTRUCT, 72);    /* MSP */
	uae_u32 *s0_done = (uae_u32 *)get_target();
	B_i(0);
	LDR_wXi(REG_WORK2, R_REGSTRUCT, 68);    /* ISP */
	write_jmp_target(s0_done, (uintptr)get_target());
	STR_wXi(REG_WORK2, R_REGSTRUCT, 60);    /* A7 = ISP/MSP */

	write_jmp_target(swap_done, (uintptr)get_target());
	write_jmp_target(skip_swap, (uintptr)get_target());

	/* Now safe to clobber REG_WORK3/4 — set flags from REG_WORK1 (sr) */

	/* X flag (bit 4) → FLAGX */
	int x = writereg(FLAGX);
	UBFX_wwii(x, REG_WORK1, 4, 1);
	unlock2(x);

	/* NZVC → ARM NZCV */
	MOV_xi(REG_WORK2, 0);
	UBFX_xxii(REG_WORK3, REG_WORK1, 3, 1);  /* N→31 */
	LSL_xxi(REG_WORK3, REG_WORK3, 31);
	ORR_xxx(REG_WORK2, REG_WORK2, REG_WORK3);
	UBFX_xxii(REG_WORK3, REG_WORK1, 2, 1);  /* Z→30 */
	LSL_xxi(REG_WORK3, REG_WORK3, 30);
	ORR_xxx(REG_WORK2, REG_WORK2, REG_WORK3);
	UBFX_xxii(REG_WORK3, REG_WORK1, 0, 1);  /* C→29 */
	LSL_xxi(REG_WORK3, REG_WORK3, 29);
	ORR_xxx(REG_WORK2, REG_WORK2, REG_WORK3);
	UBFX_xxii(REG_WORK3, REG_WORK1, 1, 1);  /* V→28 */
	LSL_xxi(REG_WORK3, REG_WORK3, 28);
	ORR_xxx(REG_WORK2, REG_WORK2, REG_WORK3);
	MSR_NZCV_x(REG_WORK2);
	flags_carry_inverted = false;
}

/*
 * MV2SR_w: MOVE to SR (word) — fully inline, no helper call.
 * src register contains the new 16-bit SR value.
 */
MIDFUNC(1,jnf_MV2SR_w,(RR4 s))
{
	s = readreg(s);
	inline_MakeFromSR(s);
	unlock2(s);
}
MENDFUNC(1,jnf_MV2SR_w,(RR4 s))

/*
 * ORSR_w: ORI to SR (word) — inline OR + MakeFromSR
 */
MIDFUNC(1,jnf_ORSR_w,(RR4 imm_reg))
{
	/* Load current sr, OR with immediate, then MakeFromSR */
	LDRH_wXi(REG_WORK1, R_REGSTRUCT, 76);   /* regs.sr */
	/* Need to MakeSR first to get current flags into regs.sr */
	/* Actually regs.sr may be stale — flags are in NZCV. We need to
	   compose current flags into sr first, then OR, then decompose.
	   This is complex. For SR word ops, use a simpler approach:
	   flush flags to regs.sr, then modify, then decompose. */

	/* Build current CCR from NZCV + FLAGX */
	MRS_NZCV_x(REG_WORK2);
	if (flags_carry_inverted) {
		EOR_xxCflag(REG_WORK2, REG_WORK2);
		flags_carry_inverted = false;
	}
	/* Extract N,Z,C,V from NZCV register */
	MOV_wi(REG_WORK3, 0);
	/* N (bit31→bit3) */
	UBFX_xxii(REG_WORK4, REG_WORK2, 31, 1);
	BFI_wwii(REG_WORK3, REG_WORK4, 3, 1);
	/* Z (bit30→bit2) */
	UBFX_xxii(REG_WORK4, REG_WORK2, 30, 1);
	BFI_wwii(REG_WORK3, REG_WORK4, 2, 1);
	/* C (bit29→bit0) */
	UBFX_xxii(REG_WORK4, REG_WORK2, 29, 1);
	BFI_wwii(REG_WORK3, REG_WORK4, 0, 1);
	/* V (bit28→bit1) */
	UBFX_xxii(REG_WORK4, REG_WORK2, 28, 1);
	BFI_wwii(REG_WORK3, REG_WORK4, 1, 1);
	/* X (FLAGX→bit4) */
	int fx = readreg(FLAGX);
	BFI_wwii(REG_WORK3, fx, 4, 1);
	unlock2(fx);

	/* Merge CCR into sr (replace low byte) */
	BFI_wwii(REG_WORK1, REG_WORK3, 0, 8);

	/* OR with register value */
	imm_reg = readreg(imm_reg);
	ORR_www(REG_WORK1, REG_WORK1, imm_reg);
	unlock2(imm_reg);

	inline_MakeFromSR(REG_WORK1);
}
MENDFUNC(1,jnf_ORSR_w,(RR4 imm_reg))

MIDFUNC(1,jnf_ANDSR_w,(RR4 imm_reg))
{
	LDRH_wXi(REG_WORK1, R_REGSTRUCT, 76);
	MRS_NZCV_x(REG_WORK2);
	if (flags_carry_inverted) {
		EOR_xxCflag(REG_WORK2, REG_WORK2);
		flags_carry_inverted = false;
	}
	MOV_wi(REG_WORK3, 0);
	UBFX_xxii(REG_WORK4, REG_WORK2, 31, 1); BFI_wwii(REG_WORK3, REG_WORK4, 3, 1);
	UBFX_xxii(REG_WORK4, REG_WORK2, 30, 1); BFI_wwii(REG_WORK3, REG_WORK4, 2, 1);
	UBFX_xxii(REG_WORK4, REG_WORK2, 29, 1); BFI_wwii(REG_WORK3, REG_WORK4, 0, 1);
	UBFX_xxii(REG_WORK4, REG_WORK2, 28, 1); BFI_wwii(REG_WORK3, REG_WORK4, 1, 1);
	int fx = readreg(FLAGX); BFI_wwii(REG_WORK3, fx, 4, 1); unlock2(fx);
	BFI_wwii(REG_WORK1, REG_WORK3, 0, 8);

	/* AND with register value */
	imm_reg = readreg(imm_reg);
	AND_www(REG_WORK1, REG_WORK1, imm_reg);
	unlock2(imm_reg);

	inline_MakeFromSR(REG_WORK1);
}
MENDFUNC(1,jnf_ANDSR_w,(RR4 imm_reg))

MIDFUNC(1,jnf_EORSR_w,(RR4 imm_reg))
{
	LDRH_wXi(REG_WORK1, R_REGSTRUCT, 76);
	MRS_NZCV_x(REG_WORK2);
	if (flags_carry_inverted) {
		EOR_xxCflag(REG_WORK2, REG_WORK2);
		flags_carry_inverted = false;
	}
	MOV_wi(REG_WORK3, 0);
	UBFX_xxii(REG_WORK4, REG_WORK2, 31, 1); BFI_wwii(REG_WORK3, REG_WORK4, 3, 1);
	UBFX_xxii(REG_WORK4, REG_WORK2, 30, 1); BFI_wwii(REG_WORK3, REG_WORK4, 2, 1);
	UBFX_xxii(REG_WORK4, REG_WORK2, 29, 1); BFI_wwii(REG_WORK3, REG_WORK4, 0, 1);
	UBFX_xxii(REG_WORK4, REG_WORK2, 28, 1); BFI_wwii(REG_WORK3, REG_WORK4, 1, 1);
	int fx = readreg(FLAGX); BFI_wwii(REG_WORK3, fx, 4, 1); unlock2(fx);
	BFI_wwii(REG_WORK1, REG_WORK3, 0, 8);

	/* EOR with register value */
	imm_reg = readreg(imm_reg);
	EOR_www(REG_WORK1, REG_WORK1, imm_reg);
	unlock2(imm_reg);

	inline_MakeFromSR(REG_WORK1);
}
MENDFUNC(1,jnf_EORSR_w,(RR4 imm_reg))
