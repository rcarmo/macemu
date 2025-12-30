/*
 * memory.cpp - Memory access shim for Unicorn CPU backend
 *
 * Basilisk II (C) Christian Bauer
 * Unicorn backend (C) 2025
 *
 * This provides the same memory access interface expected by other parts
 * of BasiliskII, delegating to the functions in cpu_emulation.h
 */

#include "sysdeps.h"
#include "cpu_emulation.h"

/*
 * Memory access functions compatible with UAE CPU interface
 * These are used by emul_op.cpp and other files
 */

// These are defined inline in cpu_emulation.h for Unicorn backend
// This file exists for API compatibility

// For compatibility with code that includes memory.h directly
#ifndef MEMORY_H
#define MEMORY_H
#endif
