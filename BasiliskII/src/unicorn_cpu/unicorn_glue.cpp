/*
 * unicorn_glue.cpp - Unicorn Engine based 68k emulation for Basilisk II
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
 *
 * This file implements the BasiliskII CPU interface using the Unicorn Engine
 * (https://www.unicorn-engine.org/), which provides a portable CPU emulation
 * framework based on QEMU's TCG (Tiny Code Generator).
 *
 * Unicorn provides JIT-accelerated emulation on all supported host architectures
 * (x86, x64, ARM, ARM64, MIPS, etc.) making this a portable high-performance
 * solution for 68k emulation.
 */

#include "sysdeps.h"
#include "cpu_emulation.h"
#include "main.h"
#include "emul_op.h"
#include "prefs.h"

#include <unicorn/unicorn.h>

#define DEBUG 0
#include "debug.h"

/*
 * 68k Exception Vector Numbers
 */
#define M68K_EXCEPTION_RESET_SSP       0
#define M68K_EXCEPTION_RESET_PC        1
#define M68K_EXCEPTION_BUS_ERROR       2
#define M68K_EXCEPTION_ADDRESS_ERROR   3
#define M68K_EXCEPTION_ILLEGAL         4
#define M68K_EXCEPTION_ZERO_DIVIDE     5
#define M68K_EXCEPTION_CHK             6
#define M68K_EXCEPTION_TRAPV           7
#define M68K_EXCEPTION_PRIVILEGE       8
#define M68K_EXCEPTION_TRACE           9
#define M68K_EXCEPTION_LINEA          10  // A-line trap (0xAxxx)
#define M68K_EXCEPTION_LINEF          11  // F-line trap (0xFxxx) - FPU
#define M68K_EXCEPTION_FORMAT_ERROR   14
#define M68K_EXCEPTION_UNINITIALIZED  15
#define M68K_EXCEPTION_SPURIOUS       24
#define M68K_EXCEPTION_AUTOVECTOR_1   25
#define M68K_EXCEPTION_AUTOVECTOR_2   26
#define M68K_EXCEPTION_AUTOVECTOR_3   27
#define M68K_EXCEPTION_AUTOVECTOR_4   28
#define M68K_EXCEPTION_AUTOVECTOR_5   29
#define M68K_EXCEPTION_AUTOVECTOR_6   30
#define M68K_EXCEPTION_AUTOVECTOR_7   31
#define M68K_EXCEPTION_TRAP_BASE      32  // TRAP #0-15 are vectors 32-47

/*
 * Global state
 */

// Unicorn engine instance
static uc_engine *uc = NULL;

// Note: InterruptFlags is defined in main_unix.cpp, declared in main.h

// RAM and ROM pointers (normally in main_unix.cpp when !EMULATED_68K)
uint32 RAMBaseMac;          // RAM base (Mac address space)
uint8 *RAMBaseHost;         // RAM base (host address space)
uint32 RAMSize;             // Size of RAM
uint32 ROMBaseMac;          // ROM base (Mac address space)
uint8 *ROMBaseHost;         // ROM base (host address space)
uint32 ROMSize;             // Size of ROM

#if !REAL_ADDRESSING
uint8 *MacFrameBaseHost;    // Frame buffer base (host address space)
uint32 MacFrameSize;        // Size of frame buffer
int MacFrameLayout;         // Frame buffer layout
#endif

// Direct addressing offset
#if DIRECT_ADDRESSING
uintptr MEMBaseDiff;
#endif

// Pending interrupt level (0 = none, 1-7 = interrupt level)
static volatile int pending_interrupt = 0;

// Quit control (normally from uae_cpu/newcpu.cpp, we define here)
int quit_program = 0;
int exit_val = 0;

// Memory region tracking
static bool ram_mapped = false;
static bool rom_mapped = false;
static bool frame_mapped = false;

// For nested Execute68k calls
static int execute_depth = 0;

// Return address marker for Execute68k
static const uint32 EXEC_RETURN_ADDR = 0xFFFFFFFC;

// Vector Base Register (68010+) - usually 0 for Mac
static uint32_t vbr = 0;

/*
 * Helper: Get current registers into M68kRegisters structure
 */
static void get_regs(M68kRegisters *r)
{
    uint32_t d[8], a[8], sr;
    
    uc_reg_read(uc, UC_M68K_REG_D0, &d[0]);
    uc_reg_read(uc, UC_M68K_REG_D1, &d[1]);
    uc_reg_read(uc, UC_M68K_REG_D2, &d[2]);
    uc_reg_read(uc, UC_M68K_REG_D3, &d[3]);
    uc_reg_read(uc, UC_M68K_REG_D4, &d[4]);
    uc_reg_read(uc, UC_M68K_REG_D5, &d[5]);
    uc_reg_read(uc, UC_M68K_REG_D6, &d[6]);
    uc_reg_read(uc, UC_M68K_REG_D7, &d[7]);
    
    uc_reg_read(uc, UC_M68K_REG_A0, &a[0]);
    uc_reg_read(uc, UC_M68K_REG_A1, &a[1]);
    uc_reg_read(uc, UC_M68K_REG_A2, &a[2]);
    uc_reg_read(uc, UC_M68K_REG_A3, &a[3]);
    uc_reg_read(uc, UC_M68K_REG_A4, &a[4]);
    uc_reg_read(uc, UC_M68K_REG_A5, &a[5]);
    uc_reg_read(uc, UC_M68K_REG_A6, &a[6]);
    uc_reg_read(uc, UC_M68K_REG_A7, &a[7]);
    
    uc_reg_read(uc, UC_M68K_REG_SR, &sr);
    
    for (int i = 0; i < 8; i++) {
        r->d[i] = d[i];
        r->a[i] = a[i];
    }
    r->sr = (uint16_t)sr;
}

/*
 * Helper: Set registers from M68kRegisters structure
 */
static void set_regs(const M68kRegisters *r)
{
    uint32_t d[8], a[8];
    
    for (int i = 0; i < 8; i++) {
        d[i] = r->d[i];
        a[i] = r->a[i];
    }
    
    uc_reg_write(uc, UC_M68K_REG_D0, &d[0]);
    uc_reg_write(uc, UC_M68K_REG_D1, &d[1]);
    uc_reg_write(uc, UC_M68K_REG_D2, &d[2]);
    uc_reg_write(uc, UC_M68K_REG_D3, &d[3]);
    uc_reg_write(uc, UC_M68K_REG_D4, &d[4]);
    uc_reg_write(uc, UC_M68K_REG_D5, &d[5]);
    uc_reg_write(uc, UC_M68K_REG_D6, &d[6]);
    uc_reg_write(uc, UC_M68K_REG_D7, &d[7]);
    
    uc_reg_write(uc, UC_M68K_REG_A0, &a[0]);
    uc_reg_write(uc, UC_M68K_REG_A1, &a[1]);
    uc_reg_write(uc, UC_M68K_REG_A2, &a[2]);
    uc_reg_write(uc, UC_M68K_REG_A3, &a[3]);
    uc_reg_write(uc, UC_M68K_REG_A4, &a[4]);
    uc_reg_write(uc, UC_M68K_REG_A5, &a[5]);
    uc_reg_write(uc, UC_M68K_REG_A6, &a[6]);
    uc_reg_write(uc, UC_M68K_REG_A7, &a[7]);
}

/*
 * Helper: Build 68k exception stack frame and jump to handler
 * This emulates what the 68k does when taking an exception
 */
static void take_exception(int vector, uint32_t fault_pc)
{
    uint32_t sr, sp, handler_addr;
    
    // Read current SR and SP
    uc_reg_read(uc, UC_M68K_REG_SR, &sr);
    uc_reg_read(uc, UC_M68K_REG_A7, &sp);
    
    // Get exception handler address from vector table
    handler_addr = ReadMacInt32(vbr + vector * 4);
    
    D(bug("Unicorn: Exception %d at PC=0x%08x, handler=0x%08x\n", 
          vector, fault_pc, handler_addr));
    
    // Build stack frame (format 0 - basic 4-word frame)
    // Push PC
    sp -= 4;
    WriteMacInt32(sp, fault_pc);
    
    // Push SR
    sp -= 2;
    WriteMacInt16(sp, sr);
    
    // Update SR: set supervisor mode, clear trace
    sr |= 0x2000;   // Set S bit (supervisor mode)
    sr &= ~0x8000;  // Clear T bit (trace)
    
    // Write back new SR and SP
    uc_reg_write(uc, UC_M68K_REG_SR, &sr);
    uc_reg_write(uc, UC_M68K_REG_A7, &sp);
    
    // Jump to handler
    uc_reg_write(uc, UC_M68K_REG_PC, &handler_addr);
}

/*
 * Memory callbacks for Unicorn
 *
 * Unicorn normally maps host memory directly, but we use callbacks
 * for unmapped regions to handle hardware I/O and special addresses.
 */

// Hook for unmapped memory accesses (I/O, etc.)
static void hook_mem_unmapped(uc_engine *uc, uc_mem_type type,
                               uint64_t address, int size, int64_t value,
                               void *user_data)
{
    D(bug("Unicorn: Unmapped memory access at 0x%08llx, type=%d, size=%d\n",
          (unsigned long long)address, type, size));
    
    // For now, just ignore unmapped accesses
    // In future, this would handle I/O regions
}

/*
 * Instruction hook for A-line and F-line trap detection
 *
 * Mac OS uses A-line traps (opcodes 0xAXXX) for system calls.
 * We also need to detect our special EMUL_OP opcodes (0x71XX).
 */

static int hook_call_count = 0;
static uint64_t last_pc = 0;
static int same_pc_count = 0;

static void hook_code(uc_engine *uc, uint64_t address, uint32_t size, void *user_data)
{
    // Detect stuck loops
    if (address == last_pc) {
        same_pc_count++;
        if (same_pc_count == 100) {
            uint32_t a7, sr;
            uc_reg_read(uc, UC_M68K_REG_A7, &a7);
            uc_reg_read(uc, UC_M68K_REG_SR, &sr);
            printf("Unicorn: STUCK at PC=0x%08llx (100 iterations), A7=0x%08x, SR=0x%04x\n",
                   (unsigned long long)address, a7, sr);
            printf("Unicorn: Stopping emulation due to infinite loop\n");
            fflush(stdout);
            uc_emu_stop(uc);
            return;
        }
    } else {
        same_pc_count = 0;
        last_pc = address;
    }
    
    // Diagnostic output for first 50 instructions
    if (hook_call_count < 50) {
        uint16_t opcode;
        if (uc_mem_read(uc, address, &opcode, 2) == UC_ERR_OK) {
            opcode = (opcode >> 8) | (opcode << 8);  // big-endian swap
            uint32_t a7;
            uc_reg_read(uc, UC_M68K_REG_A7, &a7);
            printf("Unicorn: [%d] PC=0x%08llx opcode=0x%04x A7=0x%08x\n", 
                   hook_call_count, (unsigned long long)address, opcode, a7);
            fflush(stdout);
        }
        hook_call_count++;
    }
    
    // Check for EXEC_RETURN marker
    if (address == EXEC_RETURN_ADDR) {
        D(bug("Unicorn: EXEC_RETURN hit, stopping execution\n"));
        uc_emu_stop(uc);
        return;
    }
    
    // Check for pending interrupts
    if (pending_interrupt > 0 && execute_depth == 0) {
        uint32_t sr;
        uc_reg_read(uc, UC_M68K_REG_SR, &sr);
        int current_ipl = (sr >> 8) & 7;
        
        if (pending_interrupt > current_ipl || pending_interrupt == 7) {
            // Take the interrupt
            int vector = M68K_EXCEPTION_AUTOVECTOR_1 + pending_interrupt - 1;
            D(bug("Unicorn: Taking interrupt level %d\n", pending_interrupt));
            
            // Update interrupt mask in SR
            sr = (sr & ~0x0700) | ((pending_interrupt & 7) << 8);
            uc_reg_write(uc, UC_M68K_REG_SR, &sr);
            
            take_exception(vector, (uint32_t)address);
            pending_interrupt = 0;
            InterruptFlags = 0;
            return;
        }
    }
    
    // Read the instruction
    uint16_t opcode;
    if (uc_mem_read(uc, address, &opcode, 2) != UC_ERR_OK) {
        return;
    }
    
    // Convert from big-endian
    opcode = (opcode >> 8) | (opcode << 8);
    
    // Check for EMUL_OP opcodes (0x71XX range - illegal moveq form)
    if ((opcode & 0xFF00) == 0x7100) {
        D(bug("Unicorn: EMUL_OP 0x%04x at 0x%08llx\n", opcode, (unsigned long long)address));
        
        // Get current registers
        M68kRegisters r;
        get_regs(&r);
        
        // Handle the EMUL_OP
        EmulOp(opcode, &r);
        
        // Write registers back
        set_regs(&r);
        
        // Skip past the EMUL_OP instruction
        uint32_t pc = (uint32_t)address + 2;
        uc_reg_write(uc, UC_M68K_REG_PC, &pc);
        
        // Check if we should quit
        if (quit_program) {
            uc_emu_stop(uc);
        }
        return;
    }
    
    // Check for A-line traps (0xAXXX) - Mac OS toolbox calls
    if ((opcode & 0xF000) == 0xA000) {
        D(bug("Unicorn: A-line trap 0x%04x at 0x%08llx\n", opcode, (unsigned long long)address));
        
        // Take Line-A exception - this will jump to the trap dispatcher in ROM
        // The Mac OS trap dispatcher reads the trap word from PC-2 to determine
        // which toolbox/OS routine to call
        take_exception(M68K_EXCEPTION_LINEA, (uint32_t)address + 2);
        return;
    }
    
    // Check for F-line traps (0xFXXX) - typically FPU instructions
    // Unicorn's 68k core should handle native FPU instructions if enabled,
    // but unimplemented FPU ops will trigger this
    if ((opcode & 0xF000) == 0xF000) {
        D(bug("Unicorn: F-line trap 0x%04x at 0x%08llx\n", opcode, (unsigned long long)address));
        
        // Take Line-F exception
        take_exception(M68K_EXCEPTION_LINEF, (uint32_t)address + 2);
        return;
    }
}

/*
 * Hook for CPU interrupts/exceptions from Unicorn
 * 
 * Unicorn triggers this when the emulated CPU takes an exception.
 * For M68K, intno is the exception vector number.
 */

static void hook_intr(uc_engine *uc, uint32_t intno, void *user_data)
{
    uint32_t pc, a7, sr;
    uc_reg_read(uc, UC_M68K_REG_PC, &pc);
    uc_reg_read(uc, UC_M68K_REG_A7, &a7);
    uc_reg_read(uc, UC_M68K_REG_SR, &sr);
    
    printf("Unicorn: EXCEPTION %d at PC=0x%08x A7=0x%08x SR=0x%04x\n", intno, pc, a7, sr);
    fflush(stdout);
    
    switch (intno) {
        case 2:  // Bus error
            printf("Unicorn: Bus Error!\n");
            uc_emu_stop(uc);
            return;
            
        case 3:  // Address error
            printf("Unicorn: Address Error!\n");
            uc_emu_stop(uc);
            return;
            
        case M68K_EXCEPTION_LINEA:
            // A-line trap - already handled in hook_code, but Unicorn may also trigger this
            printf("Unicorn: A-line exception at PC=0x%08x\n", pc);
            break;
            
        case M68K_EXCEPTION_LINEF:
            // F-line trap (FPU) - may need software FPU emulation
            printf("Unicorn: F-line exception at PC=0x%08x\n", pc);
            break;
            
        case M68K_EXCEPTION_ILLEGAL:
            printf("Unicorn: Illegal instruction at PC=0x%08x\n", pc);
            uc_emu_stop(uc);
            return;
            
        case M68K_EXCEPTION_PRIVILEGE:
            printf("Unicorn: Privilege violation at PC=0x%08x\n", pc);
            break;
            
        default:
            if (intno >= M68K_EXCEPTION_TRAP_BASE && intno < M68K_EXCEPTION_TRAP_BASE + 16) {
                printf("Unicorn: TRAP #%d at PC=0x%08x\n", intno - M68K_EXCEPTION_TRAP_BASE, pc);
            }
            break;
    }
}

/*
 * Initialize 680x0 emulation
 */

bool Init680x0(void)
{
    D(bug("Unicorn: Init680x0\n"));
    
    // Create Unicorn instance for 68040 (most compatible)
    uc_err err = uc_open(UC_ARCH_M68K, UC_MODE_BIG_ENDIAN, &uc);
    if (err != UC_ERR_OK) {
        printf("Unicorn: Failed to create engine: %s\n", uc_strerror(err));
        return false;
    }
    
    // Configure TCG translation cache size (64MB for better JIT caching)
    // This helps performance by caching more translated code blocks
    // Note: uc_ctl_set_tcg_buffer_size is only available in Unicorn 2.0.2+
#ifdef UC_CTL_TCG_BUFFER_SIZE
    const size_t tcg_cache_size = 64 * 1024 * 1024;  // 64MB
    err = uc_ctl_set_tcg_buffer_size(uc, tcg_cache_size);
    if (err == UC_ERR_OK) {
        D(bug("Unicorn: TCG cache size set to %zu MB\n", tcg_cache_size / (1024*1024)));
    } else {
        D(bug("Unicorn: Warning: Could not set TCG cache size: %s (using default)\n", uc_strerror(err)));
    }
#else
    D(bug("Unicorn: TCG cache size API not available (using default)\n"));
#endif
    
    // Map RAM
    // Unicorn requires page-aligned addresses and sizes (4KB alignment)
    printf("Unicorn: RAMSize=0x%08x RAMBaseHost=%p\n", RAMSize, RAMBaseHost);
    printf("Unicorn: ROMBaseMac=0x%08x ROMSize=0x%08x ROMBaseHost=%p\n", ROMBaseMac, ROMSize, ROMBaseHost);
    
    if (RAMSize == 0 || RAMBaseHost == NULL) {
        printf("Unicorn: ERROR: RAM not initialized (RAMSize=%u, RAMBaseHost=%p)\n", RAMSize, RAMBaseHost);
        printf("Unicorn: Init680x0() may have been called before memory setup\n");
        uc_close(uc);
        uc = NULL;
        return false;
    }
    
    size_t ram_size_aligned = (RAMSize + 0xFFF) & ~0xFFF;
    err = uc_mem_map_ptr(uc, 0, ram_size_aligned, UC_PROT_ALL, RAMBaseHost);
    if (err != UC_ERR_OK) {
        printf("Unicorn: Failed to map RAM: %s\n", uc_strerror(err));
        uc_close(uc);
        uc = NULL;
        return false;
    }
    ram_mapped = true;
    printf("Unicorn: Mapped RAM at 0x00000000, size 0x%08zx\n", ram_size_aligned);
    
    // Map ROM
    if (ROMSize == 0 || ROMBaseHost == NULL) {
        printf("Unicorn: Warning: ROM not initialized, skipping ROM mapping\n");
    } else {
        // ROM address must not overlap with RAM
        size_t rom_size_aligned = (ROMSize + 0xFFF) & ~0xFFF;
        uint32_t rom_base_aligned = ROMBaseMac & ~0xFFF;
        
        printf("Unicorn: ROM base 0x%08x (aligned: 0x%08x), size 0x%08x (aligned: 0x%08zx)\n",
              ROMBaseMac, rom_base_aligned, ROMSize, rom_size_aligned);
        
        // Check for overlap with RAM
        if (rom_base_aligned < ram_size_aligned) {
            printf("Unicorn: Warning: ROM (0x%08x) overlaps with RAM (0-0x%08zx)\n",
                   rom_base_aligned, ram_size_aligned);
            // ROM immediately follows RAM in host memory, so just adjust the base
            rom_base_aligned = ram_size_aligned;
            printf("Unicorn: Adjusted ROM base to 0x%08x\n", rom_base_aligned);
        }
        
        err = uc_mem_map_ptr(uc, rom_base_aligned, rom_size_aligned, UC_PROT_READ | UC_PROT_EXEC, ROMBaseHost);
        if (err != UC_ERR_OK) {
            printf("Unicorn: Failed to map ROM at 0x%08x: %s\n", rom_base_aligned, uc_strerror(err));
            uc_close(uc);
            uc = NULL;
            return false;
        }
        rom_mapped = true;
        printf("Unicorn: Mapped ROM at 0x%08x, size 0x%08zx\n", rom_base_aligned, rom_size_aligned);
    }
    
#if !REAL_ADDRESSING
    // Map frame buffer if present
    if (MacFrameBaseHost && MacFrameSize > 0) {
        size_t frame_size_aligned = (MacFrameSize + 0xFFF) & ~0xFFF;
        err = uc_mem_map_ptr(uc, MacFrameBaseMac, frame_size_aligned, UC_PROT_ALL, MacFrameBaseHost);
        if (err != UC_ERR_OK) {
            printf("Unicorn: Warning: Failed to map frame buffer: %s\n", uc_strerror(err));
        } else {
            frame_mapped = true;
            D(bug("Unicorn: Mapped frame buffer at 0x%08x, size 0x%08x\n", 
                  MacFrameBaseMac, (unsigned)frame_size_aligned));
        }
    }
#endif
    
    // Map a page for the EXEC_RETURN marker
    err = uc_mem_map(uc, EXEC_RETURN_ADDR & ~0xFFF, 0x1000, UC_PROT_READ | UC_PROT_EXEC);
    if (err != UC_ERR_OK) {
        D(bug("Unicorn: Warning: Failed to map EXEC_RETURN page: %s\n", uc_strerror(err)));
    }
    
    // Add code hook for EMUL_OP detection
    uc_hook hh_code;
    err = uc_hook_add(uc, &hh_code, UC_HOOK_CODE, (void *)hook_code, NULL, 1, 0);
    if (err != UC_ERR_OK) {
        printf("Unicorn: Failed to add code hook: %s\n", uc_strerror(err));
    }
    
    // Add interrupt hook for A-line traps
    uc_hook hh_intr;
    err = uc_hook_add(uc, &hh_intr, UC_HOOK_INTR, (void *)hook_intr, NULL, 1, 0);
    if (err != UC_ERR_OK) {
        D(bug("Unicorn: Warning: Failed to add interrupt hook: %s\n", uc_strerror(err)));
    }
    
    // Add hook for unmapped memory
    uc_hook hh_mem;
    err = uc_hook_add(uc, &hh_mem, UC_HOOK_MEM_UNMAPPED, (void *)hook_mem_unmapped, NULL, 1, 0);
    if (err != UC_ERR_OK) {
        D(bug("Unicorn: Warning: Failed to add memory hook: %s\n", uc_strerror(err)));
    }
    
    printf("Unicorn: 68k emulation initialized successfully\n");
    return true;
}

/*
 * Deinitialize 680x0 emulation
 */

void Exit680x0(void)
{
    D(bug("Unicorn: Exit680x0\n"));
    
    if (uc) {
        uc_close(uc);
        uc = NULL;
    }
    
    ram_mapped = false;
    rom_mapped = false;
    frame_mapped = false;
}

/*
 * Reset and start 680x0 emulation
 */

void Start680x0(void)
{
    printf("Unicorn: Start680x0\n");
    
    if (!uc) {
        printf("Unicorn: Engine not initialized!\n");
        return;
    }
    
    // Mac ROM entry point is NOT at reset vectors (0, 4)
    // BasiliskII uses fixed values (see uae_cpu/newcpu.cpp m68k_reset):
    // - SP = 0x2000 (low RAM)
    // - PC = ROMBaseMac + 0x2a (entry point in ROM)
    uint32_t initial_sp = 0x2000;
    uint32_t initial_pc = ROMBaseMac + 0x2a;
    
    printf("Unicorn: Initial SP=0x%08x, PC=0x%08x (ROM+0x2a)\n", initial_sp, initial_pc);
    
    // Set initial registers
    uc_err err;
    err = uc_reg_write(uc, UC_M68K_REG_A7, &initial_sp);
    if (err != UC_ERR_OK) {
        printf("Unicorn: Failed to set A7: %s\n", uc_strerror(err));
    }
    err = uc_reg_write(uc, UC_M68K_REG_PC, &initial_pc);
    if (err != UC_ERR_OK) {
        printf("Unicorn: Failed to set PC: %s\n", uc_strerror(err));
    }
    
    // Set supervisor mode
    uint32_t sr = 0x2700;  // Supervisor mode, interrupts disabled
    err = uc_reg_write(uc, UC_M68K_REG_SR, &sr);
    if (err != UC_ERR_OK) {
        printf("Unicorn: Failed to set SR: %s\n", uc_strerror(err));
    }
    
    // Verify registers were set
    uint32_t verify_a7, verify_pc, verify_sr;
    uc_reg_read(uc, UC_M68K_REG_A7, &verify_a7);
    uc_reg_read(uc, UC_M68K_REG_PC, &verify_pc);
    uc_reg_read(uc, UC_M68K_REG_SR, &verify_sr);
    printf("Unicorn: Verified - A7=0x%08x, PC=0x%08x, SR=0x%04x\n", verify_a7, verify_pc, verify_sr);
    
    // Clear data registers
    uint32_t zero = 0;
    for (int i = 0; i < 8; i++) {
        uc_reg_write(uc, UC_M68K_REG_D0 + i, &zero);
    }
    
    // Clear address registers (except A7)
    for (int i = 0; i < 7; i++) {
        uc_reg_write(uc, UC_M68K_REG_A0 + i, &zero);
    }
    
    quit_program = 0;
    
    // Start emulation
    printf("Unicorn: Starting emulation at PC=0x%08x\n", initial_pc);
    fflush(stdout);
    
    uc_err err = uc_emu_start(uc, initial_pc, 0, 0, 0);
    if (err != UC_ERR_OK && !quit_program) {
        uint32_t pc;
        uc_reg_read(uc, UC_M68K_REG_PC, &pc);
        printf("Unicorn: Emulation error: %s (PC=0x%08x)\n", uc_strerror(err), pc);
    }
    
    printf("Unicorn: Emulation ended\n");
}

/*
 * Execute 68k subroutine
 * The executed routine must reside in emulated memory.
 */

void Execute68k(uint32 addr, M68kRegisters *r)
{
    D(bug("Unicorn: Execute68k at 0x%08x\n", addr));
    
    if (!uc) {
        return;
    }
    
    execute_depth++;
    
    // Save current PC
    uint32_t old_pc;
    uc_reg_read(uc, UC_M68K_REG_PC, &old_pc);
    
    // Set registers from M68kRegisters
    set_regs(r);
    
    // Push return address on stack
    uint32_t sp;
    uc_reg_read(uc, UC_M68K_REG_A7, &sp);
    sp -= 4;
    WriteMacInt32(sp, EXEC_RETURN_ADDR);
    uc_reg_write(uc, UC_M68K_REG_A7, &sp);
    
    // Execute until we hit EXEC_RETURN_ADDR
    int saved_quit = quit_program;
    quit_program = 0;
    
    uc_err err = uc_emu_start(uc, addr, EXEC_RETURN_ADDR, 0, 0);
    if (err != UC_ERR_OK && err != UC_ERR_FETCH_UNMAPPED) {
        D(bug("Unicorn: Execute68k error: %s\n", uc_strerror(err)));
    }
    
    quit_program = saved_quit;
    
    // Pop return address from stack
    uc_reg_read(uc, UC_M68K_REG_A7, &sp);
    sp += 4;
    uc_reg_write(uc, UC_M68K_REG_A7, &sp);
    
    // Get registers back
    get_regs(r);
    
    // Restore PC
    uc_reg_write(uc, UC_M68K_REG_PC, &old_pc);
    
    execute_depth--;
}

/*
 * Execute MacOS 68k trap from EMUL_OP routine
 */

void Execute68kTrap(uint16 trap, M68kRegisters *r)
{
    D(bug("Unicorn: Execute68kTrap 0x%04x\n", trap));
    
    if (!uc) {
        return;
    }
    
    // Push trap word and return address on stack
    uint32_t sp;
    uc_reg_read(uc, UC_M68K_REG_A7, &sp);
    
    // Push EXEC_RETURN address
    sp -= 4;
    WriteMacInt32(sp, EXEC_RETURN_ADDR);
    
    // Push trap word
    sp -= 2;
    WriteMacInt16(sp, trap);
    
    uc_reg_write(uc, UC_M68K_REG_A7, &sp);
    
    // Execute starting at stack (the trap word)
    // The 68k will execute the trap instruction and then return to EXEC_RETURN
    Execute68k(sp, r);
    
    // Clean up stack
    uc_reg_read(uc, UC_M68K_REG_A7, &sp);
    sp += 2;  // Pop trap word (EXEC_RETURN already popped by Execute68k)
    uc_reg_write(uc, UC_M68K_REG_A7, &sp);
}

/*
 * Trigger interrupt level 1
 * 
 * This sets the pending interrupt flag. The interrupt will be taken
 * at the next instruction boundary if the interrupt priority level (IPL)
 * in SR allows it (i.e., pending_interrupt > current IPL).
 */

void TriggerInterrupt(void)
{
    InterruptFlags |= 1;
    pending_interrupt = 1;  // Level 1 interrupt (VIA)
    
    D(bug("Unicorn: TriggerInterrupt - pending level 1\n"));
    
    // If we're in the main emulation loop (not nested Execute68k),
    // we could stop emulation to check the interrupt sooner
    if (uc && execute_depth == 0) {
        // Optionally stop to process interrupt faster
        // uc_emu_stop(uc);
    }
}

/*
 * Trigger NMI (level 7)
 * 
 * NMI (Non-Maskable Interrupt) is level 7 and cannot be masked.
 */

void TriggerNMI(void)
{
    InterruptFlags |= 0x80;
    pending_interrupt = 7;  // Level 7 - NMI
    
    D(bug("Unicorn: TriggerNMI - pending level 7\n"));
    
    // NMI should be processed ASAP
    if (uc && execute_depth == 0) {
        uc_emu_stop(uc);
    }
}

/*
 * Get interrupt level
 */

int intlev(void)
{
    return InterruptFlags ? 1 : 0;
}

/*
 * Dump CPU state (for debugging/crash dumps)
 * Called from main_unix.cpp sigsegv handler
 */

void m68k_dumpstate(uint32 *nextpc)
{
    if (!uc) {
        printf("Unicorn: CPU not initialized\n");
        return;
    }
    
    uint32_t regs[16];
    uint32_t pc, sr;
    
    // Read data registers
    uc_reg_read(uc, UC_M68K_REG_D0, &regs[0]);
    uc_reg_read(uc, UC_M68K_REG_D1, &regs[1]);
    uc_reg_read(uc, UC_M68K_REG_D2, &regs[2]);
    uc_reg_read(uc, UC_M68K_REG_D3, &regs[3]);
    uc_reg_read(uc, UC_M68K_REG_D4, &regs[4]);
    uc_reg_read(uc, UC_M68K_REG_D5, &regs[5]);
    uc_reg_read(uc, UC_M68K_REG_D6, &regs[6]);
    uc_reg_read(uc, UC_M68K_REG_D7, &regs[7]);
    
    // Read address registers
    uc_reg_read(uc, UC_M68K_REG_A0, &regs[8]);
    uc_reg_read(uc, UC_M68K_REG_A1, &regs[9]);
    uc_reg_read(uc, UC_M68K_REG_A2, &regs[10]);
    uc_reg_read(uc, UC_M68K_REG_A3, &regs[11]);
    uc_reg_read(uc, UC_M68K_REG_A4, &regs[12]);
    uc_reg_read(uc, UC_M68K_REG_A5, &regs[13]);
    uc_reg_read(uc, UC_M68K_REG_A6, &regs[14]);
    uc_reg_read(uc, UC_M68K_REG_A7, &regs[15]);
    
    uc_reg_read(uc, UC_M68K_REG_PC, &pc);
    uc_reg_read(uc, UC_M68K_REG_SR, &sr);
    
    printf("D0: %08x D1: %08x D2: %08x D3: %08x\n", regs[0], regs[1], regs[2], regs[3]);
    printf("D4: %08x D5: %08x D6: %08x D7: %08x\n", regs[4], regs[5], regs[6], regs[7]);
    printf("A0: %08x A1: %08x A2: %08x A3: %08x\n", regs[8], regs[9], regs[10], regs[11]);
    printf("A4: %08x A5: %08x A6: %08x A7: %08x\n", regs[12], regs[13], regs[14], regs[15]);
    printf("PC: %08x SR: %04x\n", pc, sr);
    
    if (nextpc)
        *nextpc = pc + 2;  // Approximate next PC
}
