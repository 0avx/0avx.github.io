# Yet Another DBVM Detection

I reverse engineered this detection technique from a user-mode anti-cheat for a popular game many months ago with a friend. I'll keep the anti-cheat name hidden for privacy reasons. I thought this particular detection was an interesting abuse of a logic flaw in [DBVM's (Dark Byte Virtual Machine)](https://github.com/cheat-engine/cheat-engine/tree/master/dbvm) code and wanted to share the concept for anybody who might come across it while reversing, or for those generally interested in hypervisor detection techniques.

User-mode anti-cheats have it quite a bit harder than their kernel-mode counterparts. Without unrestricted access to the CPU and hardware, they are limited in terms of detecting hypervisors. Even so, some legitimate hypervisors fail generic detections that cheating hypervisors also fail. Because their detection possibilities are already limited, user-mode anti-cheats need ways to detect specific cheating hypervisor implementations.

There are also additional interesting detection opportunities in DBVM's [`handleInterruptProtectedMode`](https://github.com/cheat-engine/cheat-engine/blob/master/dbvm/vmm/vmeventhandler.c#L3346) function, but I'll leave those as an exercise for the reader. Some generic hypervisor detections, possible from user-mode, that this particular anti-cheat also does, include legacy 32-bit wraparound behavior, proper (branch) trap flag handling, and proper interruptability state handling. DBVM is detected by some of these techniques as well.

## Debug Exceptions and the DR6 Register

When a [debug exception (#DB, interrupt vector 1)](https://wiki.osdev.org/Exceptions#Debug) fires, the CPU populates the DR6 register with information about what triggered it. The [Intel® 64 and IA-32 Architectures Software Developer's Manual Combined Volumes 3A, 3B, 3C, and 3D: System Programming Guide (Intel SDM)](https://cdrdv2.intel.com/v1/dl/getContent/671447) describes these fields as follows:

> "B0 through B3 (breakpoint condition detected) flags (bits 0 through 3) — Indicates (when set) that its associated breakpoint condition was met when a debug exception was generated. These flags are set if the condition described for each breakpoint by the LENn, and R/Wn flags in debug control register DR7 is true."

> "BS (single step) flag (bit 14) — Indicates (when set) that the debug exception was triggered by the single-
step execution mode (enabled with the TF flag in the EFLAGS register). The single-step mode is the highest-
priority debug exception. When the BS flag is set, any of the other debug status bits also may be set."

This means that multiple conditions can accumulate in DR6. If both a hardware breakpoint fires and a single-step trap occurs, both B0 (or whichever breakpoint) and BS should be set simultaneously.

The `MOV SS` instruction has special semantics related to interrupt and exception blocking. The Intel SDM ("Table 26-3. Format of Interruptibility State") describes this behavior:

> "Execution of a MOV to SS or a POP to SS blocks or suppresses certain debug exceptions as well as interrupts (maskable and nonmaskable) on the instruction boundary following its execution. Setting this bit indicates that this blocking is in effect."

This is critical. When you execute `MOV SS`, the CPU defers any pending debug exceptions until after the _next_ instruction completes, which was designed for atomic stack switching.

## The Detection Technique

Here's the insight: if we set up both a hardware data breakpoint (via DR0-DR3) on a memory location and the trap flag (TF) for single-stepping, then execute `MOV SS` that reads from the breakpoint address followed by an instruction that causes a VM exit (`CPUID`), we can observe how the hypervisor handles the pending debug exceptions.

On real hardware, the sequence works as follows. First, `MOV SS, [address]` triggers B0 (data breakpoint), but it's blocked by `MOV SS` semantics. Then `CPUID` executes, and finally the debug exception fires with both B0=1 and BS=1.

On DBVM, things go differently. First, `MOV SS, [address]` triggers the B0 condition. Then `CPUID` causes a VM exit before the debug exception can fire. DBVM's `CPUID` handler sees TF=1 and manually sets `pending_debug_exceptions = 0x4000` (only BS). Finally, the debug exception fires with only BS=1, and B0=0.

Looking at DBVM's [`handleCPUID`](https://github.com/cheat-engine/cheat-engine/blob/master/dbvm/vmm/vmeventhandler.c#L1928-L1934) function in [`vmeventhandler.c`](https://github.com/cheat-engine/cheat-engine/blob/master/dbvm/vmm/vmeventhandler.c):

```c
int handleCPUID(VMRegisters *vmregisters)
{
	// .....

  RFLAGS flags;
  flags.value=vmread(vm_guest_rflags);

  if (flags.TF==1)
  {
    vmwrite(vm_pending_debug_exceptions,0x4000);
  }
  
	// .....
}
```

The value `0x4000` corresponds to just bit 14 (BS). DBVM completely ignores any pending hardware breakpoint conditions that may have been triggered during the `MOV SS` instruction.

The choice of instructions is deliberate. The `MOV SS` instruction creates the blocking window where debug exceptions are deferred. Reading from a watchpoint address triggers the B0 condition during the blocked period. The `CPUID` instruction unconditionally causes a VM exit, interrupting the normal flow before the blocked debug exception can be delivered.

Without `CPUID` (or another VM-exiting instruction), the debug exception fires naturally through the CPU's own logic, and DR6 is populated correctly. The bug only occurs when DBVM has to manually handle the re-injection.

## Proof of Concept

Here's the complete detection code:

```c
#include <windows.h>
#include <stdio.h>
#include <stdint.h>

/* Generated by Claude Code. */
/* DR6 status register. */
typedef union {
    DWORD64 raw;
    struct {
        DWORD64 b0  : 1;  /* Breakpoint 0 condition detected. */
        DWORD64 b1  : 1;  /* Breakpoint 1 condition detected. */
        DWORD64 b2  : 1;  /* Breakpoint 2 condition detected. */
        DWORD64 b3  : 1;  /* Breakpoint 3 condition detected. */
        DWORD64 _r0 : 9;  /* Reserved.                        */
        DWORD64 bd  : 1;  /* Debug register access detected.  */
        DWORD64 bs  : 1;  /* Single-step trap.                */
        DWORD64 bt  : 1;  /* Task switch.                     */
        DWORD64 _r1 : 48; /* Reserved.                        */
    };
} Dr6;

/* Generated by Claude Code. */
/* DR7 control register. */
typedef union {
    DWORD64 raw;
    struct {
        DWORD64 l0   : 1;  /* Local enable DR0.           */
        DWORD64 g0   : 1;  /* Global enable DR0.          */
        DWORD64 l1   : 1;  /* Local enable DR1.           */
        DWORD64 g1   : 1;  /* Global enable DR1.          */
        DWORD64 l2   : 1;  /* Local enable DR2.           */
        DWORD64 g2   : 1;  /* Global enable DR2.          */
        DWORD64 l3   : 1;  /* Local enable DR3.           */
        DWORD64 g3   : 1;  /* Global enable DR3.          */
        DWORD64 le   : 1;  /* Local exact (obsolete).     */
        DWORD64 ge   : 1;  /* Global exact (obsolete).    */
        DWORD64 _r0  : 1;  /* Reserved (1).               */
        DWORD64 rtm  : 1;  /* RTM.                        */
        DWORD64 _r1  : 1;  /* Reserved (0).               */
        DWORD64 gd   : 1;  /* General detect.             */
        DWORD64 _r2  : 2;  /* Reserved (0).               */
        DWORD64 rw0  : 2;  /* Condition DR0.              */
        DWORD64 len0 : 2;  /* Length DR0.                 */
        DWORD64 rw1  : 2;  /* Condition DR1.              */
        DWORD64 len1 : 2;  /* Length DR1.                 */
        DWORD64 rw2  : 2;  /* Condition DR2.              */
        DWORD64 len2 : 2;  /* Length DR2.                 */
        DWORD64 rw3  : 2;  /* Condition DR3.              */
        DWORD64 len3 : 2;  /* Length DR3.                 */
        DWORD64 _r3  : 32; /* Reserved.                   */
    };
} Dr7;

/* Generated by Claude Code. */
/* DR7 RW field values. */
typedef enum {
    DR7_RW_EXEC  = 0,  /* Break on execution.  */
    DR7_RW_WRITE = 1,  /* Break on write.      */
    DR7_RW_IO    = 2,  /* Break on I/O.        */
    DR7_RW_RW    = 3,  /* Break on read/write. */
} Dr7Rw;

/* Generated by Claude Code. */
/* DR7 LEN field values. */
typedef enum {
    DR7_LEN_1 = 0,  /* 1-byte length.          */
    DR7_LEN_2 = 1,  /* 2-byte length.          */
    DR7_LEN_8 = 2,  /* 8-byte length (64-bit). */
    DR7_LEN_4 = 3,  /* 4-byte length.          */
} Dr7Len;

/* Generated by Claude Code. */
/* EFLAGS bits. */
#define EFLAGS_TF    (1 << 8)  /* Trap flag (single-step). */

/* Global variables. */
static Dr6 g_dr6 = {0};
static WORD g_ss = 0;

LONG WINAPI veh(EXCEPTION_POINTERS *info) {
    if (info->ExceptionRecord->ExceptionCode != EXCEPTION_SINGLE_STEP)
        return EXCEPTION_CONTINUE_SEARCH;

    PCONTEXT ctx = info->ContextRecord;
    g_dr6.raw = ctx->Dr6;

    ctx->EFlags &= ~EFLAGS_TF;
    ctx->Dr0 = 0;
    ctx->Dr6 = 0;
    ctx->Dr7 = 0;

    return EXCEPTION_CONTINUE_EXECUTION;
}

void print_dr6(Dr6 dr6) {
    printf("    DR6: 0x%llX\n", dr6.raw);
    printf("        B0 (HWBP 0):      %lld\n", dr6.b0);
    printf("        B1 (HWBP 1):      %lld\n", dr6.b1);
    printf("        B2 (HWBP 2):      %lld\n", dr6.b2);
    printf("        B3 (HWBP 3):      %lld\n", dr6.b3);
    printf("        BD (DR access):   %lld\n", dr6.bd);
    printf("        BS (single-step): %lld\n", dr6.bs);
    printf("        BT (task switch): %lld\n", dr6.bt);
}

int main(void) {
    AddVectoredExceptionHandler(1, veh);

    __asm__ volatile (".intel_syntax noprefix; mov %0, ss; .att_syntax prefix" : "=r"(g_ss));

    CONTEXT ctx = { .ContextFlags = CONTEXT_DEBUG_REGISTERS };
    GetThreadContext(GetCurrentThread(), &ctx);

    Dr7 dr7 = {0};
    dr7.l0   = 1;
    dr7.g0   = 1;
    dr7.rw0  = DR7_RW_RW;
    dr7.len0 = DR7_LEN_2;
    ctx.Dr0 = (DWORD64)&g_ss;
    ctx.Dr7 = dr7.raw;
    SetThreadContext(GetCurrentThread(), &ctx);

    __asm__ volatile (
        ".intel_syntax noprefix\n"
        "push rbx\n"
        "pushfq\n"
        "or dword ptr [rsp], %c[tf]\n"
        "popfq\n"
        "mov ss, word ptr [%0]\n"
        "cpuid\n"
        "pop rbx\n"
        ".att_syntax prefix\n"
        :: "r"(&g_ss), [tf] "i"(EFLAGS_TF) : "rax", "rcx", "rdx", "memory"
    );

    int detected = !(g_dr6.bs && g_dr6.b0);
    printf("    DBVM Detected: %s\n", detected ? "true" : "false");
    print_dr6(g_dr6);

    return 0;
}
```

On DBVM (Windows 10, Intel i7-8700):

```
C:\Users\win10\Desktop>dbvm-dtc.exe
    DBVM Detected: true
    DR6: 0xFFFF4FF0
        B0 (HWBP 0):      0
        B1 (HWBP 1):      0
        B2 (HWBP 2):      0
        B3 (HWBP 3):      0
        BD (DR access):   0
        BS (single-step): 1
        BT (task switch): 0
```

On bare metal (Windows 10, Intel i7-8700):

```
C:\Users\win10\Desktop>dbvm-dtc.exe
    DBVM Detected: false
    DR6: 0xFFFF4FF1
        B0 (HWBP 0):      1
        B1 (HWBP 1):      0
        B2 (HWBP 2):      0
        B3 (HWBP 3):      0
        BD (DR access):   0
        BS (single-step): 1
        BT (task switch): 0
```

## Conclusion

I hope you enjoyed this article. In hindsight, the detection is rather intuitive, and similar techniques exploiting blocking semantics have been documented for years. Yet despite its simplicity, I was surprised by how many people struggled to understand how this particular detection worked when reversing the anti-cheat. These are exactly the kinds of detections that user-mode anti-cheats are limited to. In the future, I plan to release more novel kernel detection methods that I have yet seen any anti-cheat to implement.
