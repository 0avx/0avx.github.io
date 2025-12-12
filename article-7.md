# Yet Another Wine Detection

There are virtually infinite ways to detect Wine from user-mode; from checking for Wine-specific registry keys and DLLs, to probing undocumented Windows internals that Wine hasn't implemented. This article presents another method, this time abusing a lesser-known feature of the Windows kernel: automatic SSE alignment fault fixup.

## How Wine Works

Wine ("Wine Is Not an Emulator") is a compatibility layer that allows Windows applications to run on Linux and other POSIX-compliant operating systems. Rather than emulating the entire Windows operating system, Wine implements the Windows API on top of the host OS. When a Windows executable calls `CreateFile` for example, Wine translates that into the appropriate Linux syscall (`open`). This technique allows for pretty optimal performance and compatibility.

This approach works remarkably well for most applications. However, Wine cannot replicate every quirk and behavior of the Windows kernel. The deeper you dig into Windows internals, the more nuances you'll find, which is exactly what we're exploiting here.

## MOVAPS and Alignment Requirements

The [`MOVAPS`](https://c9x.me/x86/html/file_module_x86_id_180.html) instruction (Move Aligned Packed Single-Precision Floating-Point Values) is an SSE instruction that moves 128 bits of data between XMM registers and memory. Critically, it requires the memory operand to be aligned to a 16-byte boundary. From the [Intel 64 and IA-32 Architectures Software Developer's Manual](https://c9x.me/x86/html/file_module_x86_id_180.html):

> When the source or destination operand is a memory operand, the operand must be aligned on a 16-byte boundary or a general-protection exception (#GP) is generated.

On most operating systems, this #GP would propagate to user-mode as an access violation, crashing your program, but Windows does something clever.

## Windows Kernel Alignment Fixup: KiOp_MOVAPS

Windows provides [`SetErrorMode(SEM_NOALIGNMENTFAULTEXCEPT)`](https://learn.microsoft.com/en-us/windows/win32/winprog64/fault-alignments) which, when set, causes the kernel to transparently handle alignment faults on SSE instructions. When a #GP occurs due to a misaligned `MOVAPS`, the kernel intercepts the fault and patches the instruction in-place, changing `MOVAPS` (opcode `0F 28`) to [`MOVUPS`](https://c9x.me/x86/html/file_module_x86_id_208.html) (opcode `0F 10`). The instruction then re-executes successfully.

The kernel function responsible for this is [`KiOp_MOVAPS`](https://github.com/mic101/windows/blob/master/WRK-v1.2/base/ntos/ke/amd64/decode.c#L299). It takes a [`PDECODE_CONTEXT`](https://github.com/mic101/windows/blob/master/WRK-v1.2/base/ntos/ke/amd64/decode.c#L153)—a structure containing the decoded instruction state, exception information, and processor mode (The code below is rewritten from decompilation of the Windows kernel):

```c
NTSTATUS
KiOpPatchCode(
    IN PDECODE_CONTEXT DecodeContext,
    OUT PUCHAR Destination,
    IN UCHAR Replacement
);

NTSTATUS
KiOp_MOVAPS(
    IN PDECODE_CONTEXT DecodeContext
)
{
    // Only handle from user-mode.
    if (DecodeContext->PreviousMode != UserMode) {
        return STATUS_SUCCESS;
    }

    // Check thread-level AutoAlignment flag.
    if (KeGetCurrentThread()->ThreadFlags & 4) {
        goto PatchInstruction;
    }

    // Check process-level AutoAlignment flag.
    if ((KeGetCurrentProcess()->ProcessFlags & 1) == 0) {
        return STATUS_SUCCESS;
    }

PatchInstruction:
    //
    // Replace MOVAPS with MOVUPS to avoid alignment fault.
    NTSTATUS Status = KiOpPatchCode(
        DecodeContext,
        DecodeContext->OpCodeLocation,
        (DecodeContext->OpCode != 0x28) ? 0x11 : 0x10
    );

    if (!NT_SUCCESS(Status) && Status != STATUS_RETRY) {
        return Status;
    }

    DecodeContext->Retry = TRUE;

    return STATUS_SUCCESS;
}
```

The function first validates that the fault came from user-mode (`PreviousMode == UserMode`). It then checks whether alignment fixup is permitted for the current thread, and if that flag isn't set, it then checks if it's permitted for the current process.

If fixup is allowed, the kernel calls [`KiOpPatchCode`](https://github.com/mic101/windows/blob/master/WRK-v1.2/base/ntos/ke/amd64/decode.c#L377) to modify the instruction bytes directly in the user's code. After patching, the kernel sets [`DecodeContext->Retry = TRUE`](https://github.com/mic101/windows/blob/master/WRK-v1.2/base/ntos/ke/amd64/decode.c#L202), signaling that execution should resume at the now-corrected instruction.

The key insight here is that Windows rewrites your code at runtime. The original `0F 28` bytes are replaced with `0F 10`, and execution continues as if nothing happened. Wine, running on top of Linux, has no such behavior, and thus the fault simply propagates to the application.

## The Detection Technique

Our proof of concept exploits this behavioral difference:

1. **Create a raw MOVAPS instruction stub** — We place the bytes `0F 28 01 C3` (MOVAPS + RET) directly in the `.text` section. This ensures we have executable bytes we can observe.

2. **Enable alignment fault fixup** — Call `SetErrorMode(SEM_NOALIGNMENTFAULTEXCEPT)` to activate the kernel's automatic patching behavior.

3. **Create a misaligned pointer** — Allocate a 16-byte aligned buffer, then add 1 to deliberately misalign it.

4. **Execute and observe** — Call our stub with the misaligned pointer. On Windows, the kernel patches `0F 28` to `0F 10` and execution succeeds. On Wine, we catch an access violation exception.

5. **Check the bytes** — After execution, inspect whether the instruction bytes changed. On Windows: `0F 28` → `0F 10`. On Wine: bytes unchanged, exception thrown.

## Results

On Windows 10 22H2:

```
C:\Users\user\source\repos\WinePoC\x64\Release>WinePoC.exe

  MOVAPS Alignment Fault Detection
  =================================

  Before: 0F 28 01 C3
  After : 0F 10 01 C3

  [+] Result: Native Windows
      Kernel patched MOVAPS -> MOVUPS
```

The bytes changed from `0F 28` (MOVAPS) to `0F 10` (MOVUPS). The kernel silently rewrote our code.

On Fedora 43:

```
⬢ [user@toolbx ~]$ wine WinePoC.exe 

  MOVAPS Alignment Fault Detection
  =================================

  Before: 0F 28 01 C3
  After : 0F 28 01 C3

  [!] Result: Wine Detected
      Exception 0xC0000005 not handled by kernel
```

The bytes remain unchanged, and we caught an access violation. Wine has no logic to intercept the fault, and fix it up.

## Complete Source Code

```c
#include <windows.h>
#include <stdio.h>

#pragma section(".text")
__declspec(allocate(".text"))
static unsigned char movaps_stub[] =
{
    0x0F, 0x28, 0x01,       /* movaps xmm0, XMMWORD PTR [rcx] */
    0xC3                    /* ret                            */
};

typedef void (*movaps_fn)(void*);

static void print_hex(const char* label, const unsigned char* code, int count)
{
    printf("  %s:", label);
    for (int i = 0; i < count; i++)
        printf(" %02X", code[i]);
    printf("\n");
}

int main(void)
{
    SetErrorMode(SEM_NOALIGNMENTFAULTEXCEPT);

    __declspec(align(16)) unsigned char buffer[32] = { 0 };
    void* misaligned = buffer + 1;

    printf("\n");
    printf("  MOVAPS Alignment Fault Detection\n");
    printf("  =================================\n\n");

    print_hex("Before", movaps_stub, sizeof(movaps_stub));

    __try
    {
        ((movaps_fn)movaps_stub)(misaligned);

        print_hex("After ", movaps_stub, sizeof(movaps_stub));
        printf("\n");
        printf("  [+] Result: Native Windows\n");
        printf("      Kernel patched MOVAPS -> MOVUPS\n");
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        print_hex("After ", movaps_stub, sizeof(movaps_stub));
        printf("\n");
        printf("  [!] Result: Wine Detected\n");
        printf("      Exception 0x%08lX not handled by kernel\n",
            (unsigned long)GetExceptionCode());
    }

    printf("\n");
    return 0;
}
```

## Conclusion

This approach shows a fundamental limitation of Wine's architecture. No matter how complete Wine's API implementation becomes, it cannot replicate every single behavior, because while many are documented, they are still unknown to the vast majority of developers. This approach, like many others, while not really worthwhile for kernel-mode anti-cheats, can be leveraged by user-mode anti-cheats.
