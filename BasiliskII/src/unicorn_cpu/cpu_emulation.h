/*
 * cpu_emulation.h - CPU interface for Unicorn-based 68k emulation
 *
 * Basilisk II (C) Christian Bauer
 * Unicorn backend (C) 2025
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#ifndef CPU_EMULATION_H
#define CPU_EMULATION_H

#include "sysdeps.h"

/*
 *  Memory system
 */

// RAM and ROM pointers (allocated and set by main_*.cpp)
extern uint32 RAMBaseMac;           // RAM base (Mac address space)
extern uint8 *RAMBaseHost;          // RAM base (host address space)
extern uint32 RAMSize;              // Size of RAM

extern uint32 ROMBaseMac;           // ROM base (Mac address space)
extern uint8 *ROMBaseHost;          // ROM base (host address space)
extern uint32 ROMSize;              // Size of ROM

// Direct addressing offset (Mac address + MEMBaseDiff = host address)
#if DIRECT_ADDRESSING
extern uintptr MEMBaseDiff;
#endif

#if !REAL_ADDRESSING
// If we are not using real addressing, the Mac frame buffer gets mapped here
const uint32 MacFrameBaseMac = 0xa0000000;
extern uint8 *MacFrameBaseHost;     // Frame buffer base (host address space)
extern uint32 MacFrameSize;         // Size of frame buffer
extern int MacFrameLayout;          // Frame buffer layout (see defines below)
#endif

// Possible frame buffer layouts
enum {
    FLAYOUT_NONE,                   // No frame buffer
    FLAYOUT_DIRECT,                 // Frame buffer is in MacOS layout, no conversion needed
    FLAYOUT_HOST_555,               // 16 bit, RGB 555, host byte order
    FLAYOUT_HOST_565,               // 16 bit, RGB 565, host byte order
    FLAYOUT_HOST_888                // 32 bit, RGB 888, host byte order
};

/*
 * Mac memory access functions
 * These directly access host memory with address translation
 */

#if DIRECT_ADDRESSING
// With direct addressing, conversion is simple offset arithmetic
static inline uint8 *Mac2HostAddr(uint32 addr)
{
    return (uint8 *)(MEMBaseDiff + addr);
}

static inline uint32 Host2MacAddr(uint8 *addr)
{
    return (uint32)((uintptr)addr - MEMBaseDiff);
}

#else
// Without direct addressing, use region-based translation

// Convert Mac address to host pointer
static inline uint8 *Mac2HostAddr(uint32 addr)
{
    // Address translation for different memory regions
    if (addr < RAMSize) {
        return RAMBaseHost + addr;
    } else if (addr >= ROMBaseMac && addr < ROMBaseMac + ROMSize) {
        return ROMBaseHost + (addr - ROMBaseMac);
    }
#if !REAL_ADDRESSING
    else if (addr >= MacFrameBaseMac && addr < MacFrameBaseMac + MacFrameSize) {
        return MacFrameBaseHost + (addr - MacFrameBaseMac);
    }
#endif
    // Fall back to RAM for unmapped regions (may cause issues)
    return RAMBaseHost + (addr & (RAMSize - 1));
}

// Convert host pointer to Mac address
static inline uint32 Host2MacAddr(uint8 *addr)
{
    if (addr >= RAMBaseHost && addr < RAMBaseHost + RAMSize) {
        return (uint32)(addr - RAMBaseHost);
    } else if (addr >= ROMBaseHost && addr < ROMBaseHost + ROMSize) {
        return ROMBaseMac + (uint32)(addr - ROMBaseHost);
    }
#if !REAL_ADDRESSING
    else if (addr >= MacFrameBaseHost && addr < MacFrameBaseHost + MacFrameSize) {
        return MacFrameBaseMac + (uint32)(addr - MacFrameBaseHost);
    }
#endif
    return 0;
}
#endif

// Read Mac memory (big-endian)
static inline uint32 ReadMacInt32(uint32 addr)
{
    uint8 *p = Mac2HostAddr(addr);
    return ((uint32)p[0] << 24) | ((uint32)p[1] << 16) | ((uint32)p[2] << 8) | p[3];
}

static inline uint16 ReadMacInt16(uint32 addr)
{
    uint8 *p = Mac2HostAddr(addr);
    return ((uint16)p[0] << 8) | p[1];
}

static inline uint8 ReadMacInt8(uint32 addr)
{
    return *Mac2HostAddr(addr);
}

// Write Mac memory (big-endian)
static inline void WriteMacInt32(uint32 addr, uint32 l)
{
    uint8 *p = Mac2HostAddr(addr);
    p[0] = l >> 24;
    p[1] = l >> 16;
    p[2] = l >> 8;
    p[3] = l;
}

static inline void WriteMacInt16(uint32 addr, uint32 w)
{
    uint8 *p = Mac2HostAddr(addr);
    p[0] = w >> 8;
    p[1] = w;
}

static inline void WriteMacInt8(uint32 addr, uint32 b)
{
    *Mac2HostAddr(addr) = b;
}

// Memory operations
static inline void *Mac_memset(uint32 addr, int c, size_t n)
{
    return memset(Mac2HostAddr(addr), c, n);
}

static inline void *Mac2Host_memcpy(void *dest, uint32 src, size_t n)
{
    return memcpy(dest, Mac2HostAddr(src), n);
}

static inline void *Host2Mac_memcpy(uint32 dest, const void *src, size_t n)
{
    return memcpy(Mac2HostAddr(dest), src, n);
}

static inline void *Mac2Mac_memcpy(uint32 dest, uint32 src, size_t n)
{
    return memcpy(Mac2HostAddr(dest), Mac2HostAddr(src), n);
}

/*
 *  680x0 emulation
 */

// 68k register structure (for Execute68k())
struct M68kRegisters;

// Initialization
extern bool Init680x0(void);
extern void Exit680x0(void);

// 680x0 emulation functions
extern void Start680x0(void);       // Reset and start 680x0

extern "C" void Execute68k(uint32 addr, struct M68kRegisters *r);       // Execute 68k code from EMUL_OP routine
extern "C" void Execute68kTrap(uint16 trap, struct M68kRegisters *r);   // Execute MacOS 68k trap from EMUL_OP routine

// Interrupt functions
extern void TriggerInterrupt(void); // Trigger interrupt level 1
extern void TriggerNMI(void);       // Trigger interrupt level 7

// Note: InterruptFlags is declared in main.h, don't redeclare here

// CPU looping handlers
extern int intlev(void);

// These are no-ops for Unicorn backend but needed for API compatibility
extern int quit_program;
extern int exit_val;

// Dummy for compatibility
static inline void AtariReset(void) {}

#endif /* CPU_EMULATION_H */
