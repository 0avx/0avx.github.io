# EasyAntiCheat’s CR3 Protection

## Disclaimer
The information provided in this document is intended solely for educational and informational purposes. It is not meant to belittle EasyAntiCheat or any individuals involved in its development or implementation. Rather, it aims to shed light on the internal workings of EasyAntiCheat so that consumers can better understand what happens behind the scenes when playing their favorite games. Any opinions expressed herein do not necessarily reflect those of EasyAntiCheat or any other parties mentioned. This document is provided “as is” without warranty of any kind, either express or implied, including but not limited to the implied warranties of merchantability and fitness for a particular purpose. I shall not be liable for any damages whatsoever arising out of or in connection with the use of this document.

## Introduction
The world of online gaming has long been plagued by the scourge of cheaters, whose insidious machinations threaten to undermine the very foundations upon which fair play and competition are built. But fear not, for there is a shining beacon of hope in this dark and murky landscape - EasyAntiCheat. Employed by some of the most popular titles on the market today, this cutting-edge software represents a formidable bulwark against those who would seek to gain an unfair advantage through illicit means. But just how does it work? What makes it so effective? And can it truly stand up to the ever-evolving tactics of the cheating underworld? Join us as we delve deep into the heart of this technological marvel and uncover the secrets that make it a force to be reckoned with.

## Before We Dive In: Getting the Basics Right

To proceed with the remaining part of the article, I recommend first addressing these topics:
- [IA-32e Hardware Paging](https://www.triplefault.io/2017/07/introduction-to-ia-32e-hardware-paging.html)
- [Windows Virtual Memory Management](https://www.triplefault.io/2017/08/exploring-windows-virtual-memory.html)
- [Process Isolation](https://en.wikipedia.org/wiki/Process_isolation)

## Identifying the Problem
As any individual who has engaged in cheating will attest, accessing memory is a pivotal aspect of the process. However, with anti-cheat measures operating at the kernel level, cheaters have had to resort to executing at this elevated level as well; the highest level under `SMM` and `VT-X/AMD-V`.

As anti-cheats have evolved, they have adopted increasingly sophisticated strategies that delve deep into the intricacies of the Windows kernel. Take, for instance, Vanguard, the anti-cheat system used in Valorant. It safeguards critical game regions by utilizing a technique to hook context swaps and creating a whitelist of specific threads that are authorized to access their cloned `CR3`; which allows for seamless, yet secure, access to the protected memory.

Such measures have proven especially effective in thwarting DMA cheats, which leverage an external device to translate virtual memory to its corresponding physical memory mappings and extract data.

```cpp
VOID VgkHooks::PostSwapContext( PVOID Thread )
{
	UINT64 ThreadIndex = 0;
	BOOLEAN AllowCr3Write = FALSE;

	//
	// I have simplified it here, this routine actually decrypts the obfuscated import.
	//
	const auto PsGetThreadProcess = Vgk::Imports::PsGetThreadProcess;

	//
	// Ensure that we are swapping a thread associated with Valorant.
	//
	if ( __readcr3( ) == GuardedRegion.GameCr3 )
	{
		if ( PsGetThreadProcess( Thread ) == VgkData::ValorantProcess )
		{
			_disable( );

			//
			// Update the pml4s, Windows may have changed it.
			//
			Vgk::Setup( GuardedRegion.OriginalPml4s );
			memcpy( GuardedRegion.ClonedPml4s, GuardedRegion.OriginalPml4s, PAGE_SIZE );

			//
			// As the pml4 table has been overwritten, it is necessary for us to reset our pml4e.
			//
			GuardedRegion.ClonedPml4s[ GuardedRegion.AvailablePml4Index ] = GuardedRegion.NewPml4e;

			//
			// Has the game surpassed the maximum allowable whitelisted thread count as permitted by VGK?
			//
			if ( ThreadData.Count != VGK_MAX_THREADS )
			{
				if ( !ThreadData.Count )
				{
				WriteCr3:
					if ( AllowCr3Write )
						__writecr3( GuardedRegion.NewCr3 );

					if ( ShouldFlushTlb )
						FlushTlb( );

					_enable( );
					return;
				}

				//
				// If not, enumerate through each whitelisted thread.
				//
				while ( Thread != ThreadData.List[ ThreadIndex ] )
				{
					if ( ThreadIndex++ >= ThreadData.Count )
						goto WriteCr3;
				}
			}

			AllowWriteCr3 = TRUE;
			goto WriteCr3;
		}
 	}
}
```
> The code that is not relevant to this article has been redacted, and the remaining code has been formatted for improved readability.

While this is certainly fascinating, the question remains: how does all of this relate to EasyAntiCheat? As it turns out, EasyAntiCheat is also quite adept at detecting and thwarting cheat attempts. In fact, it employs a technique that is similar to the aforementioned Vanguard anti-cheat, albeit one that is more complex in nature.

However, unlike Vanguard, which utilizes two legitimate address spaces, EasyAntiCheat opts for a different approach - one that involves concealing its original `CR3` from any prying eyes. This is an involved and intricate technique, but one that has proven to be quite effective in deterring cheaters.
> It’s worth noting that Rust, the game detailed in this article, incorporates EasyAntiCheat_EOS. As far as my observation goes, no other EOS-protected game has implemented this particular approach.

## Explaining the Problem
In order to provide additional support for the claims we have made, we’ll translate Rust’s base address to its corresponding physical mapping using the `CR3` located in the `EProcess::DirectoryTableBase` field. This will provide us with concrete evidence to support our claim, which is a critical step because if the `CR3` value is truly invalid, the translation process would fail as it would not be pointing to any legitimate `PML4` table.

To further validate our findings, we’ll compare the results obtained through this process with the actual game’s fixed `CR3`.

To simplify this task, and make the process more efficient, we’ll utilize the well-known and widely-used [Cheat Engine](https://www.cheatengine.org/) Lua scripting interface.
> -I decided to use Cheat Engine because it offers scripting capabilities that can be quickly accessed and modified, rather than having to create a driver for every minor alteration.

```lua
local RustProcess = dbk_getPEProcess( RustPid );

local RustSectionBaseAddress = readQword( RustProcess + 0x520 );
local RustDirectoryTableBase = readQword( RustProcess + 0x28 );

print( string.format( "RustSectionBaseAddress -> %X", RustSectionBaseAddress ) );
print( string.format( "RustDirectoryTableBase -> %X", RustDirectoryTableBase ) );

local RustPhysicalBaseAddress = getPhysicalAddressCR3( RustDirectoryTableBase, RustSectionBaseAddress );
if not RustPhysicalBaseAddress then
  	print( "Error -> 0" );
else
   	print( string.format( "Success -> %X", RustPhysicalBaseAddress ) );
end

--[[
	RustSectionBaseAddress -> 7FF7B4600000 
	RustDirectoryTableBase -> 4000000853DFF000 
	Error -> 0 
--]]
```

Now, for the corresponding counterpart:

```lua
local RustProcess = dbk_getPEProcess( RustPid );

local RustSectionBaseAddress = readQword( RustProcess + 0x520 );
local RustDirectoryTableBase = dbk_getCR3( );

print( string.format( "RustSectionBaseAddress -> %X", RustSectionBaseAddress ) );
print( string.format( "RustDirectoryTableBase -> %X", RustDirectoryTableBase ) );

local RustPhysicalBaseAddress = getPhysicalAddressCR3( RustDirectoryTableBase, RustSectionBaseAddress );
if not RustPhysicalBaseAddress then
  	print( "Error -> 0" );
else
   	print( string.format( "Success -> %X", RustPhysicalBaseAddress ) );
end

--[[
	RustSectionBaseAddress -> 7FF7B4600000 
	RustDirectoryTableBase -> 197198000 
	Success -> 199CFE000 
--]]
```

As you can see, the `CR3` value `4000000853DFF000` appears quite peculiar at first glance. It’s pretty obvious that something is amiss even before consulting the manual. To get a better understanding, let’s use the programmer’s calculator on Windows to examine the toggled bits in the 64-bit integer.

![](https://i.imgur.com/nzYfRgr.png)

As observed from the calculator’s output, the 63rd bit is set. Armed with this knowledge, we can now refer to the manual to determine if this is a reserved bit that would trigger any sort of exception.
- If an attempt is made to change `CR4.PCIDE` from 0 to 1 while `CR3[11:0] ≠ 000H`.
- If an attempt is made to clear `CR0.PG[bit 31]`.
- If an attempt is made to write a 1 to any reserved bit in `CR4`.
- If an attempt is made to write a 1 to any reserved bit in `CR8`.
- If an attempt is made to write a 1 to any reserved bit in `CR3[63:MAXPHYADDR]`.
- If an attempt is made to leave IA-32e mode by clearing `CR4.PAE[bit 5]`.

Since our focus is on a particular control register, namely the third one, we can narrow down the scope of the search to indicate that triggering a `#GP(0)` exception would occur only if one tries to write a value of 1 to any reserved bit within `CR3[63:MAXPHYADDR]`, which is exactly what we’re looking for!

At this point, you might be wondering why it’s not possible to unset those bits to make the `CR3` valid. However, the `CR3` that’s saved within Rust’s process is solely intended to trigger an exception and doesn’t refer to any `PML4s` (without proper decryption). This approach from EasyAntiCheat is quite clever as it compels reverse engineers, such as ourselves, to reverse their driver.

## Connecting the Dots: The Thread Scheduler
Now that we have obtained the prerequisite knowledge on the issue at hand, we can start connecting the dots to understand how EasyAntiCheat is exploiting the vulnerability.

As we already know, EasyAntiCheat forces an exception when the `EProcess::DirectoryTableBase` is being written to the `CR3` of any active processor. However, this raises the question: how exactly are they are abusing this?

To answer this question, let’s take a closer look at the `ntoskrnl!SwapContext` routine, which is responsible for swapping the current core’s context to a new thread.

```cpp
//
// The impact of their hook extends beyond this specific routine and encompasses any kernel routine that involves CR3 swapping, such as KiAttachProcess.
//

UINT64 ProcessCr3 = Process->DirectoryTableBase;

if ( ( HvlEnlightenments & 1 ) != 0 )
{
	//
	// If HyperV is present, it'll handle swapping the current core's CR3.
	//
	HvlSwitchVirtualAddressSpace( ProcessCr3 );
}
else
{
	__writecr3( ProcessCr3 );

	if ( ShouldFlushTlb )
	{
		//
		// If possible, flushes the TLB for the current core. 
		//
		auto Cr4 = __readcr4( );
  		Cr4 ^= 0x80;
		__writecr4( Cr4 );
		__writecr4( Cr4 ^ 0x80 );
	}
}
```
> The code that is not relevant to this article has been redacted, and the remaining code has been formatted for improved readability.

By analyzing the code within this routine, we can see that the function proceeds to update the `CR3` register to the `EProcess::DirectoryTableBase` field using the `__writecr3` intrinsic. It is at this point where EasyAntiCheat is able to exploit the vulnerability. By forcing an exception, and catching it, EasyAntiCheat is able to instrument when a thread is being swapped, and thereby obtain complete and utter control over their game’s context-switches (and other whitelisted regions).

## Connecting the Dots: Wresling the Exception
Following the reverse engineering process, the next step is to locate the location where EasyAntiCheat writes the updated `CR3`. Based on our previous findings, this will be found within their exception hook.

Although there are multiple methods to achieve this, the steps I will take include:
- Utilizing my `VT-X` hypervisor to virtualize all logical processors.
- Installing an image load callback.
- Upon the loading of the `EasyAntiCheat_EOS.sys` driver, preserving the driver’s details.
- Deferring a task to the subsequent `CR3` write, if an attempt is made to write a 1 to any reserved bit in `CR3[63:MAXPHYADDR]`.
- Recording the `RVA` using EasyAntiCheat’s stored driver information.

Upon completion of the aforementioned steps, and removing duplicates for clarity, the outcomes obtained are:

```json
{"Type":"Invalid","RVA":"ntoskrnl.exe+0x40028F"}
{"Type":"Valid","RVA":"EasyAntiCheat_EOS.sys+0x19A20"}

{"Type":"Invalid","RVA":"ntoskrnl.exe+0x20C130"}
{"Type":"Valid","RVA":"EasyAntiCheat_EOS.sys+0x19A20"}
```

Although it may appear daunting initially, it is not something we have not previously discussed. Let’s review it together.

First, let us direct our attention towards the `Invalid` outcomes, which occur when the kernel writes EasyAntiCheat’s exception-forced `CR3`.

```asm
.text:000000000040028F      0F 22 D9      mov cr3, rcx ; SwapContext
```

```asm
.text:000000000020C130      0F 22 DF      mov cr3, rdi ; KiAttachProcess
```

As you can observe, we have previously covered this, it’s where the kernel writes Rust’s `CR3`. Let’s now shift our focus towards the juicy Valid outcomes, where EasyAntiCheat writes the genuine `CR3`.

```cpp
BOOLEAN EacHooks::HandleException( ExceptonData* Exception, PCONTEXT Context )
{
#define GetFixedCr3( Key ) ((__ROR8__(_byteswap_uint64(Key), 31) & 0xFFFFFFFFF) << 12)

	if ( Exception->Code == STATUS_PRIVILEGED_INSTRUCTION  )
	{
		//
		// --> "mov cr3", ??
		//
		if ( *( WORD* )Context->Rip == 0x220F )
		{
			//
			// mov cr3, "??" <--
			//
			BYTE Operand = *( BYTE* )( Context->Rip + 2 );

			//
			// Converts the operand to an offset in the context structure, beginning from RAX.
			//
			Operand &= 7;

			//
			// Retrieve the CR3 that was being written from its register.
			//
			UINT64* Registers = &Context->Rax;
			UINT64 AttemptedCr3 = Registers[ Operand ];

			//
			// This is always computes to the same value, which is the base of their structure's allocation.
			//
			UINT64 DataOffset = InterlockedExchangeAdd64( EAC::InitialDataOffset, 0x1000000000 );
			DataOffset += 0x1000000000;
			DataOffset &= 0xFFFFFFFFF;
			DataOffset <<= 12;

			//
			// In their actual code, this uses an address in the stack to perform their calculation against.
			//
			EAC::EacData* Data = ( EAC::EacData* )( ( 0xFFFFull << 48 ) + DataOffset );

			//
			// Nothing complicated here, just gets the current process.
			//
			PEPROCESS CurrentProcess = *( PEPROCESS* )( UINT64( KeGetCurrentThread( ) ) + EAC::ProcessOffset );

			//
			// This isn't exactly what's done here, I've simplified it.
			//
			if ( CurrentProcess != Data->Process )
			{
				if ( AttemptedCr3 != Data->Cr3 )
				{
					InterlockedIncrement( Data->Counter );
					return FALSE;
				}
				
				__writecr3( __readcr3( ) );
				Context->Rip += 3;

				InterlockedIncrement( Data->Counter );
				return TRUE;
			}

			if ( Context->Rip >= EAC::WhitelistStart && Context->Rip < EAC::WhitelistEnd )
			{
				//
				// This removes the reserved bits, and fixes the CR3.
				// The decryption changes per update, so don't expect this to remain.
				//
				UINT64 FixedCr3 = AttemptedCr3 & 0xBFFF000000000FFF;	
				FixedCr3 |= GetFixedCr3( Data->Key );

				__writecr3( FixedCr3 );
				Context->Rip += 3;				

				InterlockedIncrement( Data->Counter );
				return TRUE;
			}
		}
	}

	return FALSE;
}
```
> The code that is not relevant to this article has been redacted, and the remaining code has been formatted for improved readability.

Although I have improved the code’s readability by symbolizing and cleaning it, I will still provide a summary of its behavior:
- Verify that the exception resulted from a `mov cr3, ??` instruction.
- Extract the instruction’s operand and convert it to an index beginning from `ZERO/RAX`.
- Retrieve the value of the `CR3` register from the the context structure.
- Compute the address by calculating the offset to the hook’s data structure.
- Verify that the exception occurred in Rust’s process and check the validity of the `CR3`.
- Verify that the exception occurred within a designated region inside `ntoskrnl.exe`.
- If all of the above conditions are met, update `CR3` and `RIP` accordingly.

Awesome! You know the drill by now, let’s confirm our reversal by comparing Rust’s process with the structure.

```lua
local InitialDataOffset = readQword( EacBase + EacInitialDataOffset );
local DataOffset = bAnd( InitialDataOffset, 0xFFFFFFFFF );
DataOffset = bShl( DataOffset, 12 );

local Data = bOr( bShl( 0xFFFF, 48 ), DataOffset );
if ( readQword( Data + 0xC ) == dbk_getPEProcess( RustPid ) ) then
	print( "Valid Structure" );
else
	print( "Invalid Structure" );
end

--[[
	Valid Structure
--]]
```

## Connecting the Dots: Hal to the Rescue!
Up until now, we have discovered that EasyAntiCheat is somehow able to intercept any exception generated, but we don’t know how. So, let’s find out!

While there are multiple approaches to this problem, such as recursing and reversing through every function from the interrupt’s routine. I opted for a more suitable method, which involved tracking the return stack directly to the function.

To achieve this, I set a software breakpoint, `INT3`, on their exception dispatcher routine and read the guest’s `RSP` from the `VMCS`. Then, I walked the stack and checked if the code was within a kernel code section.

After tracing where it led me, I came to the conclusion that EasyAntiCheat was hooking `Hal` pointers, as the return address led to the return of a call to a `Hal` callback.

```cpp
InternalData = HalpTimerGetInternalData( Timer );
Rax = ( *( __int64 ( __fastcall ** )( __int64 ) )( Timer + 0x70 ) )( InternalData );
```

This can be easily verified this by running this script and observing that all pointers point to EasyAntiCheat’s `Hal` dispatcher:

```lua
local Timer = readPointer( HalpRegisteredTimers );
while Timer ~= HalpRegisteredTimers do
      print( string.format( "Timer %X points to Function %X", Timer, readPointer( Timer + 0x70 ) ) );
      Timer = readPointer( Timer );
end
```

Congratulations on making it this far, that’s really impressive!

Now, I have a little brain-teaser for you. Based on the information I’ve given you previously, try to figure out how EasyAntiCheat manages its `Hal` hooks by reversing their dispatcher.

## Building the Puzzle: Breaking the Wall
I hope this article has been helpful in showing how anticheats can exploit the kernel to their advantage. However, this is just the beginning, as it’s likely that EasyAntiCheat will eventually start hooking syscalls from their driver - Vanguard has been doing it for a while already.

Furthermore, with EasyAntiCheat’s full control of context swaps, they can even implement per-thread hooks that are invisible to external threads. Alternatively, they can create hidden code regions that change on a per-thread basis.

```cpp
//
// This changes per update, it's very simple to copy.
//
#define DecryptCr3( Cr3 )

//
// We don't need to increment it, it's useless.
//
UINT64 DataOffset = ( InitialDataOffset & 0xFFFFFFFFF ) << 12;
UINT64 Data = *( UINT64* )( ( 0xFFFFull << 48 ) + DataOffset );
DbgPrint( "[Eac] Data -> %llx\n", Data );

PEPROCESS RustProcess;
PsLookupProcessByProcessId( RustPid, &RustProcess );

UINT64 FakeCr3 = *( UINT64* )( UINT64( RustProcess ) + 0x28 );
UINT64 FixedCr3 = DecryptCr3( FakeCr3 & 0xBFFF000000000FFF );
DbgPrint( "[Eac] FixedCr3 -> %llx\n", FixedCr3 );

//
// We don't want to leak any memory.
//
ObDereferenceObject( RustProcess );
```
