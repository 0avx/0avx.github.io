# EasyAntiCheat’s Import Protection

## Disclaimer
The information provided in this document is intended solely for educational and informational purposes. It is not meant to belittle EasyAntiCheat or any individuals involved in its development or implementation. Rather, it aims to shed light on the internal workings of EasyAntiCheat so that consumers can better understand what happens behind the scenes when playing their favorite games. Any opinions expressed herein do not necessarily reflect those of EasyAntiCheat or any other parties mentioned. This document is provided “as is” without warranty of any kind, either express or implied, including but not limited to the implied warranties of merchantability and fitness for a particular purpose. I shall not be liable for any damages whatsoever arising out of or in connection with the use of this document.

# Introduction
In the ever-evolving virtual battlegrounds, where the quest for fair play clashes with cunning cheaters, an enigmatic sentinel, EasyAntiCheat, reigns supreme, concealing its guarded export resolving strategies. This gripping journey takes us deep into the heart of its jungle-like defenses, as we endeavor to dethrone the Jungle King, exposing the hidden mechanisms, unlocking the secrets of their superior technology.

Armed with inquisitiveness and technical prowess, we embark on an enthralling expedition to shed light on the protected imports, unraveling the captivating tale of EasyAntiCheat’s silent prowess in safeguarding the integrity of online gaming.

# Before We Dive In: Getting the Basics Right
To proceed with the remaining part of the article, I recommend first addressing these topics:
- [Virtualization-Based Obfuscators](https://www.youtube.com/watch?v=DRH0oRFwFiM)
- [Understanding the Import Address Table](http://sandsprite.com/CodeStuff/Understanding_imports.html)
- [Exploring the Export Table](https://dev.to/wireless90/exploring-the-export-table-windows-pe-internals-4l47)

# The Problem
Dynamic analysis plays a crucial role in understanding the behavior of code, especially when dealing with reverse engineering. Anticheats, such as EasyAntiCheat, have recognized the importance of this approach and actively develop methods to mitigate against such attacks.

One of the primary methods for understanding behavior is by observing calls to imported functions. Typically, these functions can be found in the application’s IAT, which is resolved during the application’s construction phase.

However, relying on the IAT for security products is considered quite an insecure design. To address this issue, one can reproduce the behavior by manually parsing the EAT and resolving imports themselves, which eliminates the need for using the IAT.

In the case of EasyAntiCheat, they have implemented this solution by employing a safeguarded virtualized routine, which attempts to securely resolve their needed exports, and also inlining decryption for the callers of the `DecryptImport` function.

Furthermore, on top of the inlined decryption, they are also employing encryption that utilizes a public and private key, with the private key being discarded at runtime.

With the use of this method, it becomes nearly impossible to recover the aforementioned private key or to overwrite the import with another value.

# Spying on the King: Real World Examples
To kick things off, and before approaching the Jungle, let’s examine some examples which are used in other applications.

```cpp
void* VgkExports::ExEnumHandleTable(void* a1)
{
  v17.m128i_i64[1] = 0x3DC8C9558A64BA8Ai64;
  v18.m128i_i64[0] = 0xD6EBDD7A0CEE792Bui64;
  v19.m128i_i64[1] = 0x3DC8C9558A64BA8Ai64;
  v18.m128i_i64[1] = 0xD6C6BCCF590828A8ui64;
  v1 = _mm_load_si128(&v18);
  v19.m128i_i64[0] = 0xC7884760EDC680EDui64;
  v16.m128i_i64[0] = 0xB7A3B00F62AB016Eui64;
  v16.m128i_i64[1] = 0xBAA4DD9B3C644CC6ui64;
  v17.m128i_i64[0] = 0xC7884760EDC68088ui64;
  v2 = *(__int64 **)a1;
  v17 = _mm_xor_si128(v17, v19);
  v16 = _mm_xor_si128(v1, v16);
  Export = FindExport(*v2, v16.m128i_i8, 0i64, 0i64);
  /* redacted code */
  return Export;
}
```

If you’ve ever worked with VGK before, then you’ll immediately notice these stubs spread throughout their binary.

The process is relatively straightforward:
- They start by constructing the string on the stack, applying XOR to obfuscate it, and calling `FindExport`.
- `FindExport` then takes the provided base address as the first argument and locates the EAT from that address.
- Lastly, `FindExport` iterates through the EAT and compares the provided name with the names of exports to find a match.

If you need further clarification on this technique, then I recommend exploring Justas Masiulis’ [Lazy Importer](https://github.com/JustasMasiulis/lazy_importer), which expands on the concept by employing a hash instead of a decryptable string, which improves the level of obfuscation and security.

# Approaching the Jungle: The Inlined Decryption
As we know, EasyAntiCheat takes great pride in protecting against reverse engineering attempts, as can be seen from their new obfuscator.

So, instead of applying just one layer of encryption to the import addresses, they have opted to add another layer, known as their inlined decryption.

```cpp
v16 = DecryptImport(qword_125B00);
((void (__fastcall *)(__int64))(__ROL8__(v16, 29) ^ 0x3A505A07B9BA3B9Ei64))(v15);
```

Just as the name suggests, each caller to the `DecryptImport` function decrypts the second layer.

This is quite a play on their part as it makes it rather difficult to hook imports without knowing the decryption algorithm.

Of course, one can simply just employ an assembly disassembler and automatically resolve the constants used for decryption.

While this method certainly performs well in most scenarios, it proves to be a great challenge in functions that leverage obfuscation.

Another feasible approach would be to capture the context after returning to the obfuscated code from `DecryptImport` and emulate until the decryption has completed.

However, where’s the fun in doing that?

# Approaching the Jungle: The Main Decryption
```cpp
uint64_t DecryptImport( uint64_t* PublicKeys )
{
    uint64_t First  = DecryptFirst( PublicKeys[ 0 ] );
    uint64_t Second = DecryptSecond( PublicKeys[ 1 ] ) << 32;

    return First | Second;
}
```

Based on both of these reversed snippets, I can infer what the encryption process may look like:
- Iterate and find the export in a driver’s EAT.
- Apply the inlined encryption to the result.
- Apply the main encryption to the result.
- Write both public keys to the designated region.

# Entering the Jungle: Setting the Traps
With that out of the way, I started my analysis by setting a write trap on the public keys of a random encrypted import in the `.data` section.

This enabled me to see what I was dealing with and continue reversing from there.

```cpp
AddEptHook_Range( EacBase + 0x125B00, EacBase + 0x125B08, HvDebugger::HvAccess::Write, 
    +[ ]( HvDebugger::HvContext* Context, uint64_t Address, uint64_t& Pfn ) 
{
    WriteLog( "WriteTrap", TraceLoggingHexUInt64( EAC_BASE( Context->Rip ), "RipRva" ), TraceLoggingHexUInt64( EAC_BASE( Address ), "AddrRva" ) );

    return false;
} );
```

```json
{ "RipRva":"0x91FB7E", "AddrRva":"0x125B00" }
{ "RipRva":"0xD1C721", "AddrRva":"0x125B08" }
```

There were two other writes, but these are used (and read) before the export is found, so I didn’t mention them here.

After looking at these addresses, it’s pretty obvious that it’s coming from a virtualized function, which was my initial anticipation.

# Entering the Jungle: Following the River
Since I was now analyzing a virtualized routine, specifically a `VMWRITE` handler, I figured that I’d take a look at the stack as interesting stuff that could be useful to our investigation may be present on it.

```cpp
uint64_t* Stack = ( uint64_t* )Context->Rsp;

for ( size_t Idx = 0; Idx < 200; Idx++ )
{
    uint64_t Value = Stack[ Idx ];
    if ( Value && IN_EAC( Value ) )
        WriteLog( "StackDump", TraceLoggingHexUInt64( Idx ), TraceLoggingHexUInt64( EAC_BASE( Value ), "Rva" ) );
}
```

```json
{ "Idx":"0x0",  "Rva":"0x125B00" } <-- Trap Location
{ "Idx":"0x23", "Rva":"0x6F4E4"  }
{ "Idx":"0x24", "Rva":"0x6F4E4"  }
{ "Idx":"0x25", "Rva":"0x6F598"  }
{ "Idx":"0x4B", "Rva":"0x66698C" }
{ "Idx":"0x4D", "Rva":"0x125B00" } <-- Trap Location
{ "Idx":"0x52", "Rva":"0x18F9E4" } <-- DriverEntry
{ "Idx":"0x63", "Rva":"0x18FAC0" }
{ "Idx":"0x65", "Rva":"0x18FA80" }
{ "Idx":"0x6D", "Rva":"0x74F8E2" }
```

After quickly looking at the results, I noticed that `0x18F9E4` was the `DriverEntry` function, and so everything after that could be easily disregarded.

Another thing that can be disregarded is `0x125B00`, which is the address that I set the trap to in the first place.

After removing duplicates, I was left with the following results:

```json
{ "Idx":"0x23", "Rva":"0x6F4E4"  }
{ "Idx":"0x25", "Rva":"0x6F598"  }
{ "Idx":"0x4B", "Rva":"0x66698C" }
```

```cpp
__int64 __fastcall sub_6F4E4(unsigned __int64 a1, unsigned __int64 a2, unsigned int a3)
{
  unsigned __int64 v3; // r9
  __int64 i; // r8

  v3 = a3;
  for ( i = 1i64; a1; v3 = v3 * (unsigned __int128)v3 % a2 )
  {
    if ( (a1 & 1) != 0 )
      i = (unsigned __int64)i * (unsigned __int128)v3 % a2;
    a1 >>= 1;
  }
  return i;
}
```

Just from looking at the general structure of this function, it reminded me of the initial `DecryptImport` routine which we went over earlier.

However, it was quite odd that they’d be decrypting the imports before they were even written.

So, judging by the arguments, and after setting a breakpoint and dumping the registers, it became obvious that this routine is actually used to apply the main encryption to each respective import.

```json
{ "Rcx":"0x35375306D545459",  "Rdx":"0x12D8ED6858CD15B7", "R8":"0xA588E17A" }
{ "Rcx":"0x1D34200DE5B033A1", "Rdx":"0x237626ED2C9C28F3", "R8":"0x20FAECB8" }
{ "Rcx":"0x35375306D545459",  "Rdx":"0x12D8ED6858CD15B7", "R8":"0x63558ACF" }
{ "Rcx":"0x1D34200DE5B033A1", "Rdx":"0x237626ED2C9C28F3", "R8":"0xAD8C5A8"  }
{ "Rcx":"0x35375306D545459",  "Rdx":"0x12D8ED6858CD15B7", "R8":"0x30696C03" }
{ "Rcx":"0x1D34200DE5B033A1", "Rdx":"0x237626ED2C9C28F3", "R8":"0x46D4F31E" }
{ "Rcx":"0x35375306D545459",  "Rdx":"0x12D8ED6858CD15B7", "R8":"0xCFBFE39F" }
{ "Rcx":"0x1D34200DE5B033A1", "Rdx":"0x237626ED2C9C28F3", "R8":"0xBB301A01" }
{ "Rcx":"0x35375306D545459",  "Rdx":"0x12D8ED6858CD15B7", "R8":"0xD4D49738" }
```

Yet again, this reminded me of the initial `DecryptImport` function, as `RDX`, which represents the public key, was exactly the same.

This function is being called twice, with each public and private key, on the inline encrypted values, which is represented using `R8`.

The next function on the list, namely `0x6F598`, had also piqued my interest during the investigation.

Much like the previous function, I also dumped the registers and noticed something rather interesting about the registers at hand.

When I looked at the registers, `RCX` was the only interesting one, as it pointed to `0x1861D0`, which was an empty region in the `.data` section.

I decided to continue searching for anything else that was interesting and kept this address in mind.

Lastly, I was left with a `VMCALL` handler, which after some quick analysis, didn’t turn out useful.

# Entering the Jungle: The King’s Den
To gather some more information and determine how they were comparing the names, I decided to set a read trap on `NtGlobalFlag`’s name in `ntoskrnl.exe`’s EAT, as I already knew that they’re using this import.

```cpp
AddEptHook( Utils::GetExportName( "NtGlobalFlag" ), HvDebugger::HvAccess::Read, 
    +[ ]( HvDebugger::HvContext* Context, uint64_t Address, uint64_t& Pfn ) 
{
    WriteLog( "ReadTrap", TraceLoggingHexUInt64( EAC_BASE( Context->Rip ), "Rva" ) );

    uint64_t* Stack = ( uint64_t* )Context->Rsp;

    for ( size_t Idx = 0; Idx < 200; Idx++ )
    {
        uint64_t Value = Stack[ Idx ];
        if ( Value && IN_EAC( Value ) )
            WriteLog( "StackDump", TraceLoggingHexUInt64( Idx ), TraceLoggingHexUInt64( EAC_BASE( Value ), "Rva" ) );
    }

    return false;
} );
```

```json
{ "Rva":"0x2FE234"               } <-- Read Handler
{ "Rva":"0x4637B"                } <-- SHA1 Read
{ "Idx":"0xF",  "Rva":"0x6B09A5" } <-- SHA1 Caller
{ "Idx":"0x13", "Rva":"0x463AC"  } <-- SHA1 Function
{ "Idx":"0x1E", "Rva":"0x125600" } <-- Export Keys
{ "Idx":"0x1F", "Rva":"0x6F584"  } <-- Placeholder Function
{ "Idx":"0x3A", "Rva":"0x1861D0" } <-- Chunk in .data
{ "Idx":"0x3D", "Rva":"0x924C56" }
{ "Idx":"0x67", "Rva":"0x66698C" } <-- Useless Function
{ "Idx":"0x69", "Rva":"0x1260F8" } <-- Random Export
{ "Idx":"0x6E", "Rva":"0x18F9E4" } <-- DriverEntry
{ "Idx":"0x7F", "Rva":"0x18FAC0" }
{ "Idx":"0x81", "Rva":"0x18FA80" }
{ "Idx":"0x89", "Rva":"0x74F8E2" }
```

That’s exciting to see! They were still relying on their SHA1 algorithm to read and compare the names of exports, which I noticed from the distinct constants that are used in the SHA1 context.

Since the SHA1 routine was provided with the length, and the initial reading handlers were reading all of the bytes in the name, I came to the conclusion that it was an inlined `strlen`, which was virtualized.

Just like before, I removed the useless entries that are labeled, which left me with a single entry: `0x924C56`.

It’s also important to note that, yet again, `0x1861D0` appears, so I deemed it quite important.

Now, given that the entry was a `VMCALL` instruction, I dumped the destination and registers alike.

```cpp
AddEptHook( EacBase + 0x924C52, HvDebugger::HvAccess::Execute, 
    +[ ]( HvDebugger::HvContext* Context, uint64_t Address, uint64_t& Pfn ) 
{
    /*
      seg007:0000000000924C4B add rsp, 110h
      seg007:0000000000924C52 call qword ptr [rsp+8]
      seg007:0000000000924C56 sub rsp, 110h
    */
    uint64_t Function = *( uint64_t* )( Context->Rsp + 8 );
    WriteLog( "Vmcall", TraceLoggingHexUInt64( EAC_BASE( Function ), "Function" ) );

    HvDebugger::DumpRegisters( Context );

    return false;
} );
```

```json
{ "Function":"0x72E98"                       }
{ "Name":"RCX", "Value":"0xFFFF8E8BAE7255E0" }
{ "Name":"RDX", "Value":"0xFFFFF80706E00000" } <-- Ntoskrnl Base Address
{ "Name":"R8",  "Value":"0xFFFF8E8BAE7256C0" }
```

Awesome, this was exactly the function that I was looking for, which I deemed as `InitializeImports`!

This function, in fact, was called for every module that EasyAntiCheat wanted to initialize protected imports for, and was provided with the base address.

After further analysis, the function’s parameters are as follows:
- `RCX`: A pointer to both public keys.
- `RDX`: The module’s base address.
- `R8`: A pointer to an integer that was written the number of resolved imports, which was determinated by logging writes, and observing the integer increasing when an import was resolved.

While this is definitely all useful information, I still had the question: how did they know which imports to find?

As I mentioned previously, none of the registers contained anything that held this information.

But then I thought of something: what if they were writing it to `0x1861D0`?

```cpp
AddEptHook( EacBase + 0x1861D0, HvDebugger::HvAccess::Read,
    +[ ]( HvDebugger::HvContext* Context, uint64_t Address, uint64_t& Pfn )
{
		WriteLog( "ReadTrap", TraceLoggingString( Symbolize( Context->Rip ), "Name" ) );

		return false;	
} );
```

```json
{ "Name":"EasyAntiCheat_EOS.sys+0x73228"  } <-- Sorting Function
{ "Name":"ntoskrnl.exe+0x3D0A9A"          } <-- qsort
{ "Name":"ntoskrnl.exe+0x3D0AD3"          } <-- qsort
{ "Name":"EasyAntiCheat_EOS.sys+0x7322B"  } <-- Sorting Function
{ "Name":"ntoskrnl.exe+0x3D0A23"          } <-- qsort
{ "Name":"EasyAntiCheat_EOS.sys+0x21F118" } <-- Reading Handler
{ "Name":"EasyAntiCheat_EOS.sys+0x855527" } <-- Reading Handler
{ "Name":"EasyAntiCheat_EOS.sys+0x425042" } <-- Reading Handler
{ "Name":"EasyAntiCheat_EOS.sys+0x86D2BC" } <-- Reading Handler
{ "Name":"EasyAntiCheat_EOS.sys+0x425042" } <-- Reading Handler
```

This was quite interesting, as sorting them is definitely smart on their end, as it allows for faster iteration later on.

```cpp
AddEptHook( Utils::GetExport( "qsort" ), HvDebugger::HvAccess::Execute,
    +[ ]( HvDebugger::HvContext* Context, uintptr_t Address, uint64_t& Pfn )
{
    uint64_t ReturnAddress = *( uint64_t* )Context->Rsp;  
    if ( !IN_EAC( ReturnAddress ) )
      return false;

    Utils::DumpArray( &FormatElements, Context->Gpr->rcx /* Base of Elements */, Context->Gpr->rdx /* Number of Elements */, Context->Gpr->r8 /* Size of Elements */ );

    return false;	
} );
```

```json
{ "Sort":"0x6556BC1D6053223C", "InlinedKey":"0x65091738C0592277", "Export":"0x1263E8", "Default":"0x6F584" }
{ "Sort":"0x386399B9B0FD723E", "InlinedKey":"0xF26FB57ABCF6FADF", "Export":"0x126408", "Default":"0x6F584" }
```

```cpp
struct ProtectedImportData
{
    uint64_t Sort;
    uint64_t InlinedKey;

    uint64_t* PublicKeys;
    uint64_t Default;
}
```
> This dump was much larger, but I condensed it for readability.

My suspicions were correct, as EasyAntiCheat is indeed temporarily storing the import data here, and wiping it after they’ve encrypted their imports.

Another interesting thing is that, if the import couldn’t be resolved, they resort to using default values instead, which I noticed after looking at the default values in IDA.

On a final note, EasyAntiCheat also uses `RtlPcToFileHeader`, on itself, to locate the base address for `ntoskrnl.exe`. The base address is then encrypted, and stored, within the `.data` section, with a boolean to say that it was found.

# Leaving the Jungle: Winning the Battle
In conclusion, EasyAntiCheat has opted for quite an effective method in dealing with hardening against reverse engineering attempts.

However, like with anything in this field, it is subject to being analyzed.

As per usual, I have left an exercise for the reader, which you will quickly notice when attempting to generate decryption stubs for the imports.

Until next time!
