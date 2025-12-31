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
 * HIGH-PERFORMANCE DESIGN:
 * ========================
 * This implementation uses NO per-instruction hooks (which kill JIT performance).
 * Instead:
 * - Exception hooks catch EMUL_OP (0x71xx), A-line, F-line traps
 * - Chunked execution (100K instructions) with periodic timer/interrupt checks
 * - Unicorn's JIT runs at full speed between exception points
 *
 * This achieves performance comparable to native JIT backends while being
 * fully portable across ARM64, x86_64, and other architectures.
 */

#include "sysdeps.h"
#include "cpu_emulation.h"
#include "main.h"
#include "emul_op.h"
#include "prefs.h"
#include "rom_patches.h"

#include <unicorn/unicorn.h>
#include <sys/time.h>

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
#define M68K_EXCEPTION_LINEA          10
#define M68K_EXCEPTION_LINEF          11
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
#define M68K_EXCEPTION_TRAP_BASE      32

/*
 * Global state
 */

static uc_engine *uc = NULL;

// Memory pointers - these replace the definitions in uae_cpu/basilisk_glue.cpp
// main_unix.cpp uses these when !EMULATED_68K, but we define them here for unicorn backend
uint32 RAMBaseMac;
uint8 *RAMBaseHost;
uint32 RAMSize;
uint32 ROMBaseMac;
uint8 *ROMBaseHost;
uint32 ROMSize;

#if !REAL_ADDRESSING
uint8 *MacFrameBaseHost;
uint32 MacFrameSize;
int MacFrameLayout;
#endif

#if DIRECT_ADDRESSING
uintptr MEMBaseDiff;  // Global offset: Mac address + MEMBaseDiff = host address
#endif

// Interrupt handling
static volatile int pending_interrupt = 0;

// Quit control
int quit_program = 0;
int exit_val = 0;

// Memory mapping state
static bool ram_mapped = false;
static bool rom_mapped = false;
static bool frame_mapped = false;

// Execution state
static int execute_depth = 0;
static const uint32 EXEC_RETURN_ADDR = 0xFFFFFFFC;
static uint32_t vbr = 0;
static volatile bool stop_execution = false;

// Statistics
static uint64_t total_chunks = 0;
static uint64_t total_exceptions = 0;

// Timing
static uint64_t last_tick_time = 0;
static const uint64_t TICK_INTERVAL_US = 16667;  // ~60Hz

static uint64_t get_time_us(void) {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (uint64_t)tv.tv_sec * 1000000 + tv.tv_usec;
}

/*
 * Register helpers
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
 * Exception stack frame builder (68010+ Format 0)
 */
static void take_exception(int vector, uint32_t fault_pc, int new_ipl = 0)
{
    uint32_t sr, sp, handler_addr;
    
    uc_reg_read(uc, UC_M68K_REG_SR, &sr);
    uc_reg_read(uc, UC_M68K_REG_A7, &sp);
    
    handler_addr = ReadMacInt32(vbr + vector * 4);
    
    // Validate handler address - must be in RAM or ROM
    if (handler_addr >= RAMSize + ROMSize && handler_addr < ROMBaseMac) {
        printf("Unicorn: Bad exception %d handler 0x%08x (vector at 0x%08x)\n", 
               vector, handler_addr, vbr + vector * 4);
        printf("Unicorn: SP=0x%08x fault_pc=0x%08x\n", sp, fault_pc);
        stop_execution = true;
        return;
    }
    
    D(bug("Unicorn: Exception %d at PC=0x%08x, handler=0x%08x\n", 
          vector, fault_pc, handler_addr));
    
    // Format 0 stack frame: format/vector, PC, SR
    sp -= 2;
    WriteMacInt16(sp, (0 << 12) | (vector * 4));
    sp -= 4;
    WriteMacInt32(sp, fault_pc);
    sp -= 2;
    WriteMacInt16(sp, sr);
    
    // Update SR
    sr |= 0x2000;   // Supervisor mode
    sr &= ~0x8000;  // Clear trace
    if (new_ipl > 0) {
        sr = (sr & ~0x0700) | ((new_ipl & 7) << 8);
    }
    
    uc_reg_write(uc, UC_M68K_REG_SR, &sr);
    uc_reg_write(uc, UC_M68K_REG_A7, &sp);
    uc_reg_write(uc, UC_M68K_REG_PC, &handler_addr);
}

/*
 * EMUL_OP handler - called when we hit 0x71xx opcodes
 */
static bool handle_emul_op(uint32_t pc, uint16_t opcode)
{
    if (opcode != 0x7104) {  // Skip CLKNOMEM spam
        D(bug("Unicorn: EMUL_OP 0x%04x at PC=0x%08x\n", opcode, pc));
    }
    
    M68kRegisters r;
    get_regs(&r);
    EmulOp(opcode, &r);
    set_regs(&r);
    
    uint32_t new_pc = pc + 2;
    uc_reg_write(uc, UC_M68K_REG_PC, &new_pc);
    
    if (quit_program) {
        stop_execution = true;
    }
    
    return true;
}

/*
 * Memory error hook - mimics UAE's dummy_bank behavior
 * Returns true to allow the access to proceed (like UAE's dummy_bank returns 0)
 * This prevents crashes on unmapped memory access
 */
static bool hook_mem_invalid(uc_engine *uc, uc_mem_type type,
                             uint64_t address, int size, int64_t value,
                             void *user_data)
{
    static int error_count = 0;
    static int mapped_pages = 0;
    error_count++;
    
    uint32_t pc, sp;
    uc_reg_read(uc, UC_M68K_REG_PC, &pc);
    uc_reg_read(uc, UC_M68K_REG_A7, &sp);
    
    // For unmapped reads/writes, try to map dummy memory dynamically
    // This is like UAE's dummy_bank - allow access to proceed
    if (type == UC_MEM_READ_UNMAPPED || type == UC_MEM_WRITE_UNMAPPED) {
        // Map a 64KB region at the faulting address (aligned to 64KB)
        // Using 64KB because Mac often accesses contiguous regions
        uint64_t region_addr = address & ~0xFFFFULL;
        
        // Limit total dummy mappings to prevent memory exhaustion
        if (mapped_pages < 256) {  // Max 16MB of dummy memory
            uc_err err = uc_mem_map(uc, region_addr, 0x10000, UC_PROT_ALL);
            if (err == UC_ERR_OK) {
                mapped_pages++;
                if (error_count <= 20) {
                    printf("Unicorn: Mapped dummy region at 0x%08llx for %s (PC=0x%08x) [%d regions]\n",
                           (unsigned long long)region_addr,
                           type == UC_MEM_READ_UNMAPPED ? "read" : "write", pc, mapped_pages);
                }
                return true;  // Retry the access
            }
        }
        // If mapping failed (e.g., overlaps), just log and continue
        if (error_count <= 20) {
            printf("Unicorn: %s at unmapped 0x%08llx (PC=0x%08x SP=0x%08x) - can't map\n",
                   type == UC_MEM_READ_UNMAPPED ? "Read" : "Write",
                   (unsigned long long)address, pc, sp);
        }
        return false;  // Can't fix this one
    }
    
    // For fetch unmapped - this is more serious, likely a bad PC
    if (type == UC_MEM_FETCH_UNMAPPED) {
        if (error_count <= 20) {
            printf("Unicorn: Fetch from unmapped 0x%08llx (PC=0x%08x SP=0x%08x)\n",
                   (unsigned long long)address, pc, sp);
        }
        // Stop on fetch errors - can't continue
        stop_execution = true;
        uc_emu_stop(uc);
        return false;
    }
    
    // Protection errors - just log
    if (error_count <= 20) {
        const char *type_str = "UNKNOWN";
        switch (type) {
            case UC_MEM_READ_PROT: type_str = "READ_PROT"; break;
            case UC_MEM_WRITE_PROT: type_str = "WRITE_PROT"; break;
            case UC_MEM_FETCH_PROT: type_str = "FETCH_PROT"; break;
            default: break;
        }
        printf("Unicorn: Memory error %s at 0x%08llx (PC=0x%08x SP=0x%08x)\n",
               type_str, (unsigned long long)address, pc, sp);
    }
    
    // Stop after too many errors to prevent runaway
    if (error_count >= 500) {
        printf("Unicorn: Too many memory errors (%d), stopping execution\n", error_count);
        stop_execution = true;
        uc_emu_stop(uc);
    }
    
    return false;
}

/*
 * Exception/interrupt hook - THE MAIN HANDLER
 * This catches EMUL_OPs, A-line traps, etc. without per-instruction overhead
 */
static void hook_intr(uc_engine *uc, uint32_t intno, void *user_data)
{
    uint32_t pc, sr;
    uc_reg_read(uc, UC_M68K_REG_PC, &pc);
    uc_reg_read(uc, UC_M68K_REG_SR, &sr);
    
    total_exceptions++;
    
    switch (intno) {
        case M68K_EXCEPTION_ILLEGAL: {
            uint16_t opcode;
            if (uc_mem_read(uc, pc, &opcode, 2) != UC_ERR_OK) {
                printf("Unicorn: Failed to read opcode at PC=0x%08x\n", pc);
                stop_execution = true;
                uc_emu_stop(uc);
                return;
            }
            opcode = (opcode >> 8) | (opcode << 8);
            
            // EMUL_OP (0x71xx)
            if ((opcode & 0xFF00) == 0x7100) {
                handle_emul_op(pc, opcode);
                return;
            }
            
            printf("Unicorn: Illegal instruction 0x%04x at PC=0x%08x\n", opcode, pc);
            stop_execution = true;
            uc_emu_stop(uc);
            return;
        }
        
        case M68K_EXCEPTION_LINEA:
            // A-line trap - let ROM dispatcher handle it
            take_exception(M68K_EXCEPTION_LINEA, pc);
            uc_emu_stop(uc);  // Must stop so main loop continues from handler
            return;
            
        case M68K_EXCEPTION_LINEF:
            take_exception(M68K_EXCEPTION_LINEF, pc);
            uc_emu_stop(uc);  // Must stop so main loop continues from handler
            return;
            
        case M68K_EXCEPTION_BUS_ERROR:
        case M68K_EXCEPTION_ADDRESS_ERROR:
            printf("Unicorn: %s at PC=0x%08x\n", 
                   intno == 2 ? "Bus Error" : "Address Error", pc);
            stop_execution = true;
            uc_emu_stop(uc);
            return;
            
        case M68K_EXCEPTION_PRIVILEGE:
            printf("Unicorn: Privilege Violation at PC=0x%08x\n", pc);
            stop_execution = true;
            uc_emu_stop(uc);
            return;
            
        default:
            if (intno >= M68K_EXCEPTION_TRAP_BASE && intno < M68K_EXCEPTION_TRAP_BASE + 16) {
                take_exception(intno, pc + 2);
                uc_emu_stop(uc);  // Must stop so main loop continues from handler
                return;
            }
            D(bug("Unicorn: Exception %d at PC=0x%08x\n", intno, pc));
            break;
    }
}

// External declarations
extern void cpu_do_check_ticks(void);
extern void VideoRefresh(void);
extern void SDL_PumpEventsFromMainThread(void);

/*
 * Periodic task handler - called between execution chunks
 */
static void do_periodic_tasks(void)
{
    uint64_t now = get_time_us();
    
    if (now - last_tick_time >= TICK_INTERVAL_US) {
        last_tick_time = now;
        
        SDL_PumpEventsFromMainThread();
        VideoRefresh();
        cpu_do_check_ticks();
        
        uint32_t warm_start = ReadMacInt32(0xcfc);
        bool mac_started = (warm_start == 0x574C5343);
        
        if (ROMVersion != ROM_VERSION_CLASSIC || mac_started) {
            SetInterruptFlag(INTFLAG_60HZ);
            pending_interrupt = 1;
        }
    }
}

/*
 * Deliver pending interrupt
 */
static void deliver_interrupt(void)
{
    if (pending_interrupt > 0 && execute_depth == 0) {
        uint32_t sr, pc;
        uc_reg_read(uc, UC_M68K_REG_SR, &sr);
        uc_reg_read(uc, UC_M68K_REG_PC, &pc);
        int current_ipl = (sr >> 8) & 7;
        
        if (pending_interrupt > current_ipl || pending_interrupt == 7) {
            int vector = M68K_EXCEPTION_AUTOVECTOR_1 + pending_interrupt - 1;
            D(bug("Unicorn: Interrupt level %d\n", pending_interrupt));
            take_exception(vector, pc, pending_interrupt);
            pending_interrupt = 0;
            InterruptFlags = 0;
        }
    }
}

/*
 * Initialize 680x0 emulation
 */
bool Init680x0(void)
{
    D(bug("Unicorn: Init680x0\n"));
    
    uc_err err = uc_open(UC_ARCH_M68K, UC_MODE_BIG_ENDIAN, &uc);
    if (err != UC_ERR_OK) {
        printf("Unicorn: Failed to create engine: %s\n", uc_strerror(err));
        return false;
    }
    
    // Set CPU model to M68040
#ifdef UC_CPU_M68K_M68040
    err = uc_ctl_set_cpu_model(uc, UC_CPU_M68K_M68040);
#else
    err = uc_ctl_set_cpu_model(uc, 3);  // M68040 = 3
#endif
    if (err == UC_ERR_OK) {
        printf("Unicorn: CPU model set to M68040\n");
    } else {
        printf("Unicorn: Warning: Could not set CPU model: %s\n", uc_strerror(err));
    }
    
    printf("Unicorn: RAM=0x%08x ROM=0x%08x@0x%08x\n", RAMSize, ROMSize, ROMBaseMac);
    
    if (RAMSize == 0 || RAMBaseHost == NULL) {
        printf("Unicorn: ERROR: RAM not initialized\n");
        uc_close(uc);
        uc = NULL;
        return false;
    }
    
    // Map RAM
    size_t ram_size_aligned = (RAMSize + 0xFFF) & ~0xFFF;
    err = uc_mem_map_ptr(uc, 0, ram_size_aligned, UC_PROT_ALL, RAMBaseHost);
    if (err != UC_ERR_OK) {
        printf("Unicorn: Failed to map RAM: %s\n", uc_strerror(err));
        uc_close(uc);
        uc = NULL;
        return false;
    }
    ram_mapped = true;
    printf("Unicorn: Mapped RAM 0x00000000-0x%08zx\n", ram_size_aligned);
    
    // Map ROM
    if (ROMSize > 0 && ROMBaseHost != NULL) {
        size_t rom_size_aligned = (ROMSize + 0xFFF) & ~0xFFF;
        uint32_t rom_base = ROMBaseMac & ~0xFFF;
        if (rom_base < ram_size_aligned) {
            rom_base = ram_size_aligned;
        }
        
        // ROM needs write permission for ROM patches and self-modifying code
        // Map extra space after ROM for scratch memory (64KB after ROM_MAX_SIZE)
        const size_t ROM_MAX_SIZE = 0x100000;
        const size_t SCRATCH_MEM_SIZE = 0x10000;
        size_t rom_total_size = ROM_MAX_SIZE + SCRATCH_MEM_SIZE;
        size_t rom_total_aligned = (rom_total_size + 0xFFF) & ~0xFFF;
        
        err = uc_mem_map_ptr(uc, rom_base, rom_total_aligned, UC_PROT_ALL, ROMBaseHost);
        if (err != UC_ERR_OK) {
            printf("Unicorn: Failed to map ROM: %s\n", uc_strerror(err));
            uc_close(uc);
            uc = NULL;
            return false;
        }
        rom_mapped = true;
        printf("Unicorn: Mapped ROM+scratch 0x%08x-0x%08x\n", rom_base, (unsigned)(rom_base + rom_total_aligned));
    }
    
#if !REAL_ADDRESSING
    if (MacFrameBaseHost && MacFrameSize > 0) {
        size_t frame_size_aligned = (MacFrameSize + 0xFFF) & ~0xFFF;
        err = uc_mem_map_ptr(uc, MacFrameBaseMac, frame_size_aligned, UC_PROT_ALL, MacFrameBaseHost);
        if (err == UC_ERR_OK) {
            frame_mapped = true;
            printf("Unicorn: Mapped framebuffer at 0x%08x\n", MacFrameBaseMac);
        }
    }
#endif
    
    // Map dummy I/O space for Mac II hardware (VIA, SCC, ASC, SCSI at 0x50Fxxxxx)
    // This prevents crashes when ROM code tries to access hardware before patches redirect it
    static uint8 dummy_io[0x20000];  // 128KB for I/O space
    memset(dummy_io, 0xFF, sizeof(dummy_io));  // Default to 0xFF (typical for unmapped I/O)
    err = uc_mem_map_ptr(uc, 0x50F00000, sizeof(dummy_io), UC_PROT_ALL, dummy_io);
    if (err == UC_ERR_OK) {
        printf("Unicorn: Mapped dummy I/O space 0x50F00000-0x50F1FFFF\n");
    }
    
    // Map high memory region for system stack and EXEC_RETURN
    // Quadra 800 ROM sets supervisor SP to 0xFFFF0000, and stack grows DOWN
    // ROM uses extensive stack during initialization (RAM test, etc.)
    // Map 16MB at 0xFF000000-0xFFFFFFFF to give plenty of stack room
    static uint8 high_mem[0x1000000];  // 16MB
    memset(high_mem, 0, sizeof(high_mem));
    err = uc_mem_map_ptr(uc, 0xFF000000, sizeof(high_mem), UC_PROT_ALL, high_mem);
    if (err == UC_ERR_OK) {
        printf("Unicorn: Mapped high memory 0xFF000000-0xFFFFFFFF (16MB system stack)\n");
    } else {
        printf("Unicorn: Warning: Could not map high memory: %s\n", uc_strerror(err));
    }
    
    // Add exception hook - THE KEY TO PERFORMANCE
    uc_hook hh_intr;
    err = uc_hook_add(uc, &hh_intr, UC_HOOK_INTR, (void *)hook_intr, NULL, 1, 0);
    if (err != UC_ERR_OK) {
        printf("Unicorn: Failed to add interrupt hook: %s\n", uc_strerror(err));
    }
    
    // Add memory error hook
    uc_hook hh_mem;
    uc_hook_add(uc, &hh_mem, 
                UC_HOOK_MEM_READ_UNMAPPED | UC_HOOK_MEM_WRITE_UNMAPPED | 
                UC_HOOK_MEM_FETCH_UNMAPPED | UC_HOOK_MEM_READ_PROT |
                UC_HOOK_MEM_WRITE_PROT | UC_HOOK_MEM_FETCH_PROT,
                (void *)hook_mem_invalid, NULL, 1, 0);
    
    printf("Unicorn: Initialized (high-performance mode - no per-instruction hooks)\n");
    return true;
}

void Exit680x0(void)
{
    D(bug("Unicorn: Exit680x0\n"));
    if (uc) {
        uc_close(uc);
        uc = NULL;
    }
    ram_mapped = rom_mapped = frame_mapped = false;
}

/*
 * Main execution loop - chunked for performance
 */
void Start680x0(void)
{
    printf("Unicorn: Start680x0 (chunked execution)\n");
    
    if (!uc) {
        printf("Unicorn: Engine not initialized!\n");
        return;
    }
    
    // Set initial state
    uint32_t initial_sp = 0x2000;
    uint32_t initial_pc = ROMBaseMac + 0x2a;
    uint32_t sr = 0x2700;
    uint32_t zero = 0;
    
    uc_reg_write(uc, UC_M68K_REG_A7, &initial_sp);
    uc_reg_write(uc, UC_M68K_REG_PC, &initial_pc);
    uc_reg_write(uc, UC_M68K_REG_SR, &sr);
    
    for (int i = 0; i < 8; i++) {
        uc_reg_write(uc, UC_M68K_REG_D0 + i, &zero);
    }
    for (int i = 0; i < 7; i++) {
        uc_reg_write(uc, UC_M68K_REG_A0 + i, &zero);
    }
    
    printf("Unicorn: SP=0x%08x PC=0x%08x\n", initial_sp, initial_pc);
    
    quit_program = 0;
    stop_execution = false;
    last_tick_time = get_time_us();
    
    // Chunked execution - run 100K instructions per chunk
    // This allows JIT to run efficiently while still checking timers/interrupts
    const size_t CHUNK_SIZE = 100000;
    int status_counter = 0;
    
    while (!quit_program && !stop_execution) {
        uint32_t pc;
        uc_reg_read(uc, UC_M68K_REG_PC, &pc);
        
        deliver_interrupt();
        
        uc_err err = uc_emu_start(uc, pc, EXEC_RETURN_ADDR, 0, CHUNK_SIZE);
        total_chunks++;
        
        if (err != UC_ERR_OK) {
            uc_reg_read(uc, UC_M68K_REG_PC, &pc);
            if (pc == EXEC_RETURN_ADDR || 
                (err == UC_ERR_FETCH_UNMAPPED && pc == EXEC_RETURN_ADDR)) {
                break;
            }
            printf("Unicorn: Error: %s at PC=0x%08x\n", uc_strerror(err), pc);
            break;
        }
        
        do_periodic_tasks();
        
        // Status every ~1 second
        if (++status_counter >= 60) {
            status_counter = 0;
            uint32_t sr;
            uc_reg_read(uc, UC_M68K_REG_PC, &pc);
            uc_reg_read(uc, UC_M68K_REG_SR, &sr);
            printf("Unicorn: chunks=%llu PC=0x%08x SR=0x%04x\n",
                   (unsigned long long)total_chunks, pc, sr);
            fflush(stdout);
        }
    }
    
    uint32_t final_pc, final_sr;
    uc_reg_read(uc, UC_M68K_REG_PC, &final_pc);
    uc_reg_read(uc, UC_M68K_REG_SR, &final_sr);
    printf("Unicorn: Done - PC=0x%08x chunks=%llu exceptions=%llu\n",
           final_pc, (unsigned long long)total_chunks, (unsigned long long)total_exceptions);
}

void Execute68k(uint32 addr, M68kRegisters *r)
{
    D(bug("Unicorn: Execute68k 0x%08x\n", addr));
    if (!uc) return;
    
    execute_depth++;
    
    uint32_t old_pc;
    uc_reg_read(uc, UC_M68K_REG_PC, &old_pc);
    
    set_regs(r);
    
    uint32_t sp;
    uc_reg_read(uc, UC_M68K_REG_A7, &sp);
    sp -= 4;
    WriteMacInt32(sp, EXEC_RETURN_ADDR);
    uc_reg_write(uc, UC_M68K_REG_A7, &sp);
    
    int saved_quit = quit_program;
    quit_program = 0;
    
    uc_emu_start(uc, addr, EXEC_RETURN_ADDR, 0, 0);
    
    quit_program = saved_quit;
    
    uc_reg_read(uc, UC_M68K_REG_A7, &sp);
    sp += 4;
    uc_reg_write(uc, UC_M68K_REG_A7, &sp);
    
    get_regs(r);
    uc_reg_write(uc, UC_M68K_REG_PC, &old_pc);
    
    execute_depth--;
}

void Execute68kTrap(uint16 trap, M68kRegisters *r)
{
    D(bug("Unicorn: Execute68kTrap 0x%04x\n", trap));
    if (!uc) return;
    
    uint32_t sp;
    uc_reg_read(uc, UC_M68K_REG_A7, &sp);
    sp -= 4;
    WriteMacInt32(sp, EXEC_RETURN_ADDR);
    sp -= 2;
    WriteMacInt16(sp, trap);
    uc_reg_write(uc, UC_M68K_REG_A7, &sp);
    
    Execute68k(sp, r);
    
    uc_reg_read(uc, UC_M68K_REG_A7, &sp);
    sp += 2;
    uc_reg_write(uc, UC_M68K_REG_A7, &sp);
}

void TriggerInterrupt(void)
{
    pending_interrupt = 1;
}

void TriggerNMI(void)
{
    pending_interrupt = 7;
}

int intlev(void)
{
    return InterruptFlags ? 1 : 0;
}

// Note: QuitEmulator() is defined in main_unix.cpp

void Dump68kRegs(void)
{
    if (!uc) return;
    
    uint32_t d[8], a[8], pc, sr;
    for (int i = 0; i < 8; i++) {
        uc_reg_read(uc, UC_M68K_REG_D0 + i, &d[i]);
        uc_reg_read(uc, UC_M68K_REG_A0 + i, &a[i]);
    }
    uc_reg_read(uc, UC_M68K_REG_PC, &pc);
    uc_reg_read(uc, UC_M68K_REG_SR, &sr);
    
    printf("D0-D3: %08x %08x %08x %08x\n", d[0], d[1], d[2], d[3]);
    printf("D4-D7: %08x %08x %08x %08x\n", d[4], d[5], d[6], d[7]);
    printf("A0-A3: %08x %08x %08x %08x\n", a[0], a[1], a[2], a[3]);
    printf("A4-A7: %08x %08x %08x %08x\n", a[4], a[5], a[6], a[7]);
    printf("PC=%08x SR=%04x\n", pc, sr);
}

/*
 * m68k_dumpstate - called by main_unix.cpp sigsegv_dump_state
 * Two overloads to match UAE CPU interface
 */
void m68k_dumpstate(uaecptr *nextpc)
{
    if (!uc) {
        fprintf(stderr, "m68k_dumpstate: Unicorn not initialized\n");
        if (nextpc) *nextpc = 0;
        return;
    }
    
    Dump68kRegs();
    
    if (nextpc) {
        uint32_t pc;
        uc_reg_read(uc, UC_M68K_REG_PC, &pc);
        *nextpc = pc;
    }
}

void m68k_dumpstate(FILE *out, uaecptr *nextpc)
{
    (void)out;  // We always print to stderr via Dump68kRegs
    m68k_dumpstate(nextpc);
}
