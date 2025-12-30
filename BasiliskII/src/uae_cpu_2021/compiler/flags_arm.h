/*
 *  compiler/flags_arm.h - Native flags definitions for ARM
 *
 * Copyright (c) 2013 Jens Heitmann of ARAnyM dev team (see AUTHORS)
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
 *  Ported from ARAnyM to BasiliskII/macemu - December 2025
 */

#ifndef NATIVE_FLAGS_ARM_H
#define NATIVE_FLAGS_ARM_H

/* Native integer code conditions */
enum {
	NATIVE_CC_EQ = 0,   /* Equal (Z=1) */
	NATIVE_CC_NE = 1,   /* Not Equal (Z=0) */
	NATIVE_CC_CS = 2,   /* Carry Set / Unsigned Higher or Same (C=1) */
	NATIVE_CC_CC = 3,   /* Carry Clear / Unsigned Lower (C=0) */
	NATIVE_CC_MI = 4,   /* Minus / Negative (N=1) */
	NATIVE_CC_PL = 5,   /* Plus / Positive or Zero (N=0) */
	NATIVE_CC_VS = 6,   /* Overflow Set (V=1) */
	NATIVE_CC_VC = 7,   /* Overflow Clear (V=0) */
	NATIVE_CC_HI = 8,   /* Unsigned Higher (C=1 && Z=0) */
	NATIVE_CC_LS = 9,   /* Unsigned Lower or Same (C=0 || Z=1) */
	NATIVE_CC_GE = 10,  /* Signed Greater Than or Equal (N==V) */
	NATIVE_CC_LT = 11,  /* Signed Less Than (N!=V) */
	NATIVE_CC_GT = 12,  /* Signed Greater Than (Z=0 && N==V) */
	NATIVE_CC_LE = 13,  /* Signed Less Than or Equal (Z=1 || N!=V) */
	NATIVE_CC_AL = 14   /* Always (unconditional) */
};

#endif /* NATIVE_FLAGS_ARM_H */
