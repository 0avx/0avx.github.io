# EasyAntiCheat’s EProcess Emulation

## Disclaimer
The information provided in this document is intended solely for educational and informational purposes. It is not meant to belittle EasyAntiCheat or any individuals involved in its development or implementation. Rather, it aims to shed light on the internal workings of EasyAntiCheat so that consumers can better understand what happens behind the scenes when playing their favorite games. Any opinions expressed herein do not necessarily reflect those of EasyAntiCheat or any other parties mentioned. This document is provided “as is” without warranty of any kind, either express or implied, including but not limited to the implied warranties of merchantability and fitness for a particular purpose. I shall not be liable for any damages whatsoever arising out of or in connection with the use of this document.

## Introduction
In a world where virtual battlegrounds have become the arena for fierce competition, cheaters threaten to undermine the very foundations of fair play. But what if the key to safeguarding the integrity of online gaming lies in an elusive strategy, cleverly concealed from prying eyes? Enter EasyAntiCheat, the silent sentinel dedicated to preserving the sanctity of gaming realms.

As we dive into the depths of this captivating tale, we uncover a hidden gem that unfolds like a thrilling detective novel. Beneath the surface of EasyAntiCheat’s armor, a remarkable methodology emerges—one that involves the cunning emulation of `NtCreateUserProcess`, subtly controlling the very essence of construction within the gaming universe.

## Before We Dive In: Getting the Basics Right
To proceed with the remaining part of the article, I recommend first addressing these topics:
- [EasyAntiCheat’s CR3 Protection](https://github.com/0AVX/0AVX.github.io/blob/main/article-3.md)
- [Virtualization-Based Obfuscators](https://www.youtube.com/watch?v=DRH0oRFwFiM)
- [Windows Kernel Opaque Structures](https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/eprocess)

## The Problem
In the past, it was possible to register a process creation callback and obtain the game’s real `CR3` before EasyAntiCheat modified it. However, little did we know that a significant change was about to take place.

As I was going about my daily routine, a message from my friend popped up on Discord, stating that his cheat was no longer functional. The reason behind this sudden disruption? Registering a process creation callback now yielded an incorrect `CR3`.

Naturally, I couldn’t let this revelation pass without verifying it firsthand. Intrigued and determined, I embarked on a mission to uncover the truth.

![](https://i.imgur.com/db1KvTC.png)

Before diving deep, and to get a rough idea of what they were doing, I installed a hook on `PspInsertProcess` to see if the `CR3` had been altered. To my surprise, it had been!

This was quite odd because there were no easy hook points in `PspAllocateProcess` without installing a hook that was local to the game’s launcher process, which required doing trickery with the `PFN`, and is rather a versatile approach.

But, more importantly, what does this change mean? Well, it simply means that either scanning for the `CR3` or decrypting it is now required.

## The Interrogation: Who Dares Touch the EProcess?
To initiate my reversing process, I needed to obtain access to the `EProcess` allocation before EasyAntiCheat made any modifications to it.

During my investigation of the `PspAllocateProcess` function in search of a convenient hook point, I stumbled upon the `PspInitializeProcessLock` function, which proved to be relatively simple to re-implement.

![](https://i.imgur.com/hYcJUxw.png)

> While I could’ve hooked another function, this function didn’t require using a trampoline.

If we delve deeper into the allocation function, we encounter a function named `MmCreateProcessAddressSpace`, which is responsible for writing to the process’ `CR3`.

![](https://i.imgur.com/RMy5hRd.png)

So, by understanding where the `CR3` is written, we can determine if it is intercepted by EasyAntiCheat, and not written by the original location.

To accomplish this, I decided to utilize my hypervisor and set an `EPT` breakpoint on the page that contained the `EProcess`.

Considering that the function was likely to be called from within the launcher’s context, I simply compared the name to the launcher’s name for verification.

![](https://i.imgur.com/63FIn9n.png)

Since the `EProcess` might not be allocated on a page boundary, I saved the address and checked if the violation occurred within the specified range.

![](https://i.imgur.com/KXGFD5c.png)

```json
{ "Rva":"0x58233A", "Rbp": "0x4000000853FFF000", ...Other Registers... }
```

Now, as you can clearly observe, this is precisely where EasyAntiCheat is writing their manipulated `CR3` value to the `EProcess`.

![](https://i.imgur.com/Mjh781a.png)

Unfortunately, but not surprisingly, the routine responsible for writing the `CR3` is virtualized.

Instead of investing time and effort into tracing and lifting the VM, an alternative approach would be to search for other sections of code that are not virtualized.

However, it’s crucial to remember and keep track of the mentioned piece of code, as it holds significance for future stages.

## The Interrogation: The Search Party
As we are aware from the previous section, EasyAntiCheat is somehow intercepting the `PspAllocateProcess` function and modifying the `CR3` very early on in the process.

Considering this information, it is not far-fetched to speculate that they may also be writing to the other components? To confirm this, I removed the offset check, and logged every write to the `EProcess`.

```json
{ "Rva":"0x42106", "Offset":"0x5E8" }
{ "Rva":"0x42106", "Offset":"0x5E0" }
{ "Rva":"0x42106", "Offset":"0x8A8" }
{ "Rva":"0x42106", "Offset":"0x8A0" }
{ "Rva":"0x42106", "Offset":"0x998" }
{ "Rva":"0x42106", "Offset":"0x990" }

```
> This log was quite a big bigger, but I stripped it down for clarity’s sake.

After following the Rva, I was introduced with a wonderful looking switch case.

![](https://i.imgur.com/GmyyqmN.png)

Now, when examining this, what does it appear to be? Well, to me, it resembles some kind of function for writing to registers.

To further validate my suspicions, I logged the return address and proceeded to track its path.

![](https://i.imgur.com/PSzWLFJ.png)
![](https://i.imgur.com/o8kkNha.png)

Well, this turned out to be a highly successful endeavor, as upon further exploration of the function, it became apparent that it was in fact a CPU emulator!

![](https://i.imgur.com/TZ6Hi7Z.png)
![](https://i.imgur.com/GjZfcxD.png)

Indeed, now everything falls into place. It appears that they were emulating the `EProcess` construction process and manipulating the `CR3` write through their emulation engine. This explains how EasyAntiCheat was able to intercept and modify the `CR3` value at such an early stage.


## The Interrogation: The Operator
Driven by my curiosity, I persisted in tracing the return stack as I was eager to uncover the exact workings of this emulation engine, and who dared to operate it.

![](https://i.imgur.com/f77zXwi.png)
![](https://i.imgur.com/STyhKlO.png)

I understand that the code may appear obfuscated, but rest assured, it holds valuable significance for our investigation.

As you may have already deduced, this is, in fact, a handler within their VM, which I have identified as `BRANCHCALL`.

Let’s begin by tracing the branch that is executed when the emulation succeeds, which has the offset `0xFFFFFFFFF844BC37`.

![](https://i.imgur.com/Uku8hDb.png)
> This is known as the dispatcher, which the handler uses to dispatch control flow.

It seems relatively straightforward. By adding both constants together, we obtain another branch, which leads to an `EXIT` handler.

![](https://i.imgur.com/O6tVajD.png)

In the other branch, which is executed when the emulation is not completed, the code continues the loop and proceeds with further emulation.


## The Interrogation: Stealing the Flow
To determine the starting and ending points of the emulation process, I referred to my reliable hypervisor and hooked the `BRANCHCALL` handler.

![](https://i.imgur.com/Rs2MYmc.png)

> These offsets were gathered by inspecting the assembly in the handler, and are relative to the VM.

```json
{ "vRip":"0xFFFFF80681274376" }
{ "vRip":"0xFFFFF80681274379" }
{ "vRip":"0xFFFFF8068127437E" }
{ "vRip":"0xFFFFF80681274385" }
{ "vRip":"0xFFFFF80681274387" }
{ "vRip":"0xFFFFF80681274389" }
{ "vRip":"0xFFFFF8068127438B" } 
{ "vRip":"0xFFFFF8068127438D" }
{ "vRip":"0xFFFFF8068127438E" }
{ "vRip":"0xFFFFF8068127438F" }
{ "vRip":"0xFFFFF80681274390" }
{ "vRip":"0xFFFFF80681274391" }
{ "vRip":"0x0000000000000000" }
```
> This log was quite a big bigger, but I stripped it down for clarity’s sake.

They were actually emulating even further back than I initially suspected. From analyzing my log, it became apparent that they were emulating `NtCreateUserProcess`!

To halt the emulation engine at the end of the function, they set the return address to `NULL`, effectively stopping the emulation process.

## The Interrogation: The Backbone
Remember those random function pointers in the emulator’s context? Well, they’re not so random afterall, and are actually the backbone of this entire process.

Let’s start with analyzing this one, which lives at the top of the emulator’s function.

![](https://i.imgur.com/sLuAswx.png)
![](https://i.imgur.com/kveRWUS.png)

Well, isn’t that something! Now the puzzle is starting to come together, as that particular `QWORD` is actually the address of the instruction responsible for writing the `CR3` value, which we found in `MmCreateProcessAddressSpace`.

To add the final touch, that function is even the virtualized function that performed the write operation on the `CR3`, which we traced in the previous sections.

Even after all of this, the question still remains: are they truly emulating every single call within `NtCreateUserProcess`?

After looking at the rest of the emulator’s code, I discovered the section that handles the execution or emulation of subroutines.

![](https://i.imgur.com/0DabId3.png)
![](https://i.imgur.com/3isRzQ3.png)

The callback itself is quite straightforward and simply emulates the code if the function leads to `MmCreateProcessAddressSpace`.

![](https://i.imgur.com/C8tfwM9.png)

Conclusion

In conclusion, EasyAntiCheat has opened up a Pandora’s box that they cannot close. They have revealed their capabilities, and there is so much more they can unleash.

I eagerly am waiting to document any future developments that EasyAntiCheat introduces.

Until the next revelation!
