# Vanguard's Page Fault Hooking

## Introduction

Vanguard hooks page faults at the kernel level and uses the execute disable bit to detect manually mapped drivers. When code attempts to execute from a page table entry marked with the execute disable bit, the CPU throws a page fault exception. Vanguard intercepts this exception, captures the offending page, and logs what happened.

This demonstrates how Vanguard's page fault interception mechanism works by directly reading its own kernel structures to retrieve captured driver data, allowing you to see if your driver is captured.

## How Page Fault Interception Works

Manually mapped drivers exist outside the normal driver loading pipeline—no registry entry, no official record, and so Vanguard finds them by watching what the CPU tries to execute.

The mechanism: set the execute disable bit on monitored page table entries (code cannot execute), the CPU throws a page fault exception when execution is attempted, Vanguard's hook intercepts the exception, captures the page if it's unauthorized execution, and either handles it or jumps to the real `KiPageFault` handler.

Vanguard places a hook on `KiPageFault`, as well as other routines responsible for handling Kernel Patch Protection.

The logic employed by Vanguard is similar to [Can Boluk's Kernel Patch Protection Bypass](https://blog.can.ac/2024/06/28/pgc-garbage-collecting-patchguard/).

## Finding the Hook

The first step is locating the function inside `vgk.sys` that manages page fault data via signature scanning:

```cpp
const auto vgk = nt::driver::get("vgk.sys");
if (!vgk)
    return 0ull;

const auto get_illegal_page_fault = utils::scan_signature(vgk->base, vgk->size, 
    "\x48\x83\xEC\x28\x45\x33\xC0\x44");

if (!get_illegal_page_fault)
    return 0ull;
```

Once located, extract the relative offset to find the data structure containing captured page fault information:

```cpp
const auto relative = nt::intel::get().read<std::int32_t>(get_illegal_page_fault + 0xA);
if (!relative)
    return 0ull;

return get_illegal_page_fault + *relative + 0xE;
```

## The Data Structure

This is where Vanguard stores captured page fault information (other fields have been redacted for simplicity):

```cpp
struct illegal_page_fault
{
    bool finished;                      // Did the scan finish?
    std::uint8_t _;                     // Padding.
    std::uint8_t page[4096];            // The 4KB page of captured code.
};
```

When Vanguard catches a page fault from unauthorized code execution, it writes the offending page here and sets `finished` to `true`.

## Activation and Capture

Signal Vanguard to begin monitoring, then poll until a page fault is captured:

```cpp
// Get the data struct, and clear the finished flag so that we start fresh.
const auto illegal_page_fault = vgk::illegal_page_fault::get<std::uintptr_t>();
if (!nt::intel::get().write(*illegal_page_fault, false))
    return 1;

while (true)
{
    const auto finished = nt::intel::get().read<bool>(*illegal_page_fault);
    if (!finished)
        return 1;

    // Wait until it's captured something.
    if (!*finished)
    {
        std::this_thread::sleep_for(1s);
        continue;
    }

    // Retrieve captured page.
    const auto illegal_page_fault = vgk::illegal_page_fault::get();

    // Ensure that Vanguard caught something useful.
    if (!illegal_page_fault || std::all_of(illegal_page_fault->page, 
        illegal_page_fault->page + 4096, 
        [](const auto byte) { return !byte; }))
        return 1;

    // Save to disk.
    std::ofstream("illegal-page-fault.bin", std::ios::binary)
        .write((char*)illegal_page_fault->page, 4096);

    break;
}
```

## Kernel Patch Protection

Another critical point to state is that Kernel Patch Protection, if not handled, would also be captured by Vanguard's hook, and thus logged, which is not ideal. 

So, Vanguard detects if execution is within a Kernel Patch Protection context, and if so, unhooks everything, then allows it to execute normally:

```
vgk.sys+0x1867BF <-- Return from the unhook routine.
vgk.sys+0x18619C
vgk.sys+0x1884CE
vgk.sys+0x7394C
ExpCenturyDpcRoutine$fin$0+0x26D <-- Return from the KPP context.
``` 

## Conclusion

This approach is effective because it operates at the CPU level. Any code attempting to execute from a marked page will trigger an exception before execution occurs, which allows Vanguard to log the page and execution offset, and resume execution normally.

For security researchers, this is a concrete example of how modern anti-cheat operates at the kernel level through hardware-enforced mechanisms, not just software signatures or behavior detection, and as cheats become more advanced, so must anti-cheat strategies.
