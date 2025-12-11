# Hyperion Integrity Bypass

## Introduction

Hyperion is Roblox's anti-tamper system. It computes hashes of critical code sections and verifies them at runtime. The fundamental problem with software-based integrity checking in an untrusted environment is that the attacker shares the same execution context as the verifier.

This demonstrates three approaches to circumventing Hyperion's integrity checks, each exposing different vulnerabilities in the integrity verification model.

Hyperion's approach is to compute BLAKE3 hashes of critical code, store them, verify at runtime. If hashes match, code is trusted.

## Method 1: Early Precomputation

Pre-compute hashes of unmodified code, then intercept the verification function to return precomputed values instead of allowing Hyperion to compute them at runtime.

```cpp
const auto GetEarlyDigests = (std::uint64_t(*)(std::uintptr_t, std::size_t, 
    const std::uint32_t*, std::uint64_t, std::uint64_t, void*))(Hyperion + 0x1C29060);

// Precompute hashes before modification.
if constexpr (Method == 1)
{
	for (auto Page = CodeStart; Page < CodeStart + CodeSize; Page += PAGE_SIZE)
	{
		const auto Rva = Page - CodeStart;
		GetEarlyDigests(Page, PAGE_SIZE, iv, 0, CMP_MASK, &EarlyDigests[PFN(Rva)]);
	}
}

// Overwrite with breakpoint to capture execution.
*(std::uint8_t*)GetEarlyDigests = 0xCC;
```

When Hyperion calls `GetEarlyDigests`, the CPU hits the breakpoint and raises an exception. The exception handler intercepts it:

```cpp
if (Context->Rip == (std::uintptr_t)GetEarlyDigests)
{
	const auto EarlyDigest = *(void**)(Context->Rsp + 0x30);
	std::memcpy(EarlyDigest, &EarlyDigests[PFN(Rva)], sizeof(Digest));
}
```

From Hyperion's perspective, the function executed normally and returned valid hashes. The limitation is version dependency—any change to the hash format or function location breaks this approach.

## Method 2: Memory Cloning

Maintain a pristine copy of the entire code section and redirect hash computations to that copy instead of the modified code.

```cpp
CodeClone = VirtualAlloc(nullptr, CodeSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
if (!CodeClone)
	return;

std::memcpy(CodeClone, (void*)CodeStart, CodeSize);
```

The exception handler redirects the first argument to point to the unmodified clone:

```cpp
else if constexpr (Method == 2)
	Context->Rcx = (std::uintptr_t)CodeClone + Rva;
```

Hyperion hashes the unmodified copy and the verification passes. The tradeoff is ~13MB of extra memory.

## Method 3: Direct Hash Manipulation

Hyperion encrypts the list pointing to each hash, but not the individual hashes themselves. They exist as raw data in heap memory.

```cpp
template <class T>
void PatchCode(const std::uintptr_t Address, const T& Value)
{
	// For this PoC, we won't support patches that exceed a page boundary.
	if (PAGE_ALIGN(Address) != PAGE_ALIGN(Address + sizeof(T)))
		return;

	const auto HashBlock = [](const void* Data, const std::size_t Size, std::uint8_t* Hash)
	{
		blake3 Hasher;
		blake3_init(&Hasher);

		blake3_update(&Hasher, Data, Size);
		blake3_out(&Hasher, Hash, 32);
	};

	std::uint8_t OriginalHash[32];
	HashBlock((const void*)PAGE_ALIGN(Address), PAGE_SIZE, OriginalHash);

	std::memcpy((void*)Address, &Value, sizeof(T));

	std::uint8_t NewHash[32];
	HashBlock((const void*)PAGE_ALIGN(Address), PAGE_SIZE, NewHash);

	PROCESS_HEAP_ENTRY Entry;
	Entry.lpData = nullptr;

	// While the list pointing to each hash allocation is encrypted, each hash is not.
	// This allows us to simply iterate over the heap, find the hash, and replace it.
	while (HeapWalk(GetProcessHeap(), &Entry))
	{
		if (Entry.wFlags & PROCESS_HEAP_ENTRY_BUSY)
		{
			if (!Entry.lpData)
				continue;

			if (std::memcmp(Entry.lpData, OriginalHash, sizeof(OriginalHash)) == 0)
				std::memcpy(Entry.lpData, NewHash, sizeof(NewHash));
		}
	}
}
```

This code computes the original hash, modifies the code, computes the new hash, finds the old hash on the heap, and replaces it with the new one. When Hyperion verifies, the stored hash matches the modified code. No interception required—the verification runs normally, just with inconsistent data.

## Verifying

Each method was injected alongside a mid-function hook on Hyperion's encrypt packet routine, for multiple minutes, ensuring that the integrity was successfully bypassed.

```cpp
const auto EncryptPacket = Hyperion + 0x12336B0;

// Overwrite with breakpoint to capture execution.
*(std::uint8_t*)EncryptPacket = 0xCC;
```

Then, when the CPU executed the code with the breakpoint, our exception handler was ran:

```cpp
// This code is within the exception handler.
else if (Context->Rip == EncryptPacket)
{
	// XOR RAX, [R12+0x20]
	Context->Rip += 5;
	Context->Rax ^= *(std::uint64_t*)(Context->R12 + 0x20);

	Utils::Logger::Log("Time: %x", *(std::uint64_t*)(Context->R12 + 0x20));
	Utils::Logger::Log("Violations: %x", *(std::uint32_t*)(Context->R12 + 0x34));

	return EXCEPTION_CONTINUE_EXECUTION;
}
```

## Conclusion

These three methods represent different attack angles on runtime integrity verification in Hyperion. Method 1 and 2 intercept or misdirect verification. Method 3 lets verification run but ensures the data remains consistent, which is a more novel technique, and exploits an actual logic vulnerability in Hyperion.

For injection, another logic vulnerability in Hyperion was abused, which allowed any unsigned DLL to be injected if the name matched that of a user-mode GPU driver.
The injector was responsible for handling Hyperion page permissions.

These methods were submitted to Roblox's HackerOne program, and thus were patched accordingly.
