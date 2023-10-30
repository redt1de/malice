# TODO
 - [ ] darklib: needs PEB linking
 - [ ] moonwalk: random issue with go stack protections. sometimes if other routines are running we get a panic SPWRITE at line 101 of the asm.
 - [ ] sysid lookup by exception
 - [ ] hwsyscall,moonwalk need cleaned up, add error/nil value checks, do testing
 - [ ] moonwalk needs a little more work, its a bit messy but functional
 - [ ] figure out the moonwalk SPWRITE issue
 - [ ] finish get SSN from exception table, pe package was modified with some support for exception table
 - [ ] ntd and darklib are using sycall.Syscall() for Call(). need to implement asm func to avoid suspicious syscall import


## Functionality:
 - [X] direct syscalls
 - [X] indirect syscalls
 - [X] HWsyscall - sets VEH/breakpoint on NT call, indirect syscalls it, spoofs return to look like its from kernel32
 - [X] proxycalls - custom call stack via proxied Nt calls (proxycall through TpAllocWork)
 - [X] custom no WINAPI GetProcAddress (darklib)
 - [X] custom loadlibrary (darklib)
 - [X] instrumentation callbacks (inst)
 - [X] hardware breakpoint/VEH hooks
 - [X] call stack spoofing, spoofed indirect syscalls via silentmoonwalk desync (moonwalk)
 - [ ] PPID spoofing
 - [ ] checks for detection mechs, i.e. if user-hook -> mod.IsHooked()
 - [ ] Shellcode encryption -> add encoders pkg
 - [ ] Reducing entropy -> ?????
 - [ ] Escaping the (local) AV sandbox -> prime sleep
 - [ ] Disabling Event Tracing for Windows (ETW) -> patching, veh hooks
 - [ ] Evading common malicious API call patterns -> drip loader style calls
 - [ ] Removing hooks in ntdll.dll
 - [ ] In-memory encryption/sleep obfuscation

# pkgs
## callz
### darklib
 - GetModuleHandle + GetProcAddress replacement, no WINAPI calls
 - DarkLoadLibrary, partial implementation. still need to link the module to PEB.

### ntd
- essentially just darklib but focused on ntdll. needed for some of the syscall packages.

### direct
- direct syscalls
- sysid lookup via in mem or on disk (hellsgate), exception lookup coming soon
- halos gate fallback (if proc is hooked, try and get sysid from an unhooked neighbor)
- supports API hashing

#### indirect
- indirect syscalls
- sysid lookup via in mem or on disk (hellsgate), exception lookup coming soon
- halos gate fallback (if proc is hooked, try and get sysid from an unhooked neighbor)
- supports API hashing

#### _hwsyscall
 - hwsyscalls implementation
 - sets VEH and HWBP on the NT call, then tweaks the context to perform an indirect syscall + spoofed return address so call stack isnt KERNEL -> MALCODE

#### moonwalk
 - silentmoonwalk desync call stack spoofing on indirect syscalls.
 - slighly sketchy, go is not meant for this kind of thing,GC and stack protections make it rough, still needs some work.

#### proxycall
- uses undocumented Nt callbacks to create a call stack that appears legitimate. Note, no return values are provided so r1,r2,err will always be empty.

#### hashers
- Djb2 hashing algo

## check

## dbg

## enc
- encoders for payloads
- gzip -> XOR -> gzip encoder

## inst
- set or clear an instrumentation callback

## mem
- some util functions for direct memory access

## pe
- modified fork of github.com/Binject/debug/pe
- added support for NewFileFromMemory

## peb
- util functions for working with PEB
- mainly used to walk exports for sysids and functions
- had issues with the PE package on SentinelOne systems, so this works better.

## _synth
- messing with alternative call stack spoofing methods

## util

## veh
- functions for manipulate vectored exception handlers and hardware breakpoints


#### all the callz follow a similar pattern for modularity (sliver builders caugh) except ntd and darklib
```go
    // you can pretty much replace [package] with direct/indirect/moonwalk/hwsyscall/proxycall and they all work the same way. 
    /* for opts:
     [package].New(
        New(
            callz.WithResolver(callz.SSN_MEM), // pick SSN_MEM, SSN_DISK, SSN_REMOTE, SSN_EXCEPT although some are not finished yet
            callz.WithHasher(hash.Djb2)  // define custom hashing func too, func(string) string{}
        )

        then for hashing just do:
            m.NewProc("WhateverHASHEDstring")
        */

	m := [package].New()
	ntac := m.NewProc("NtAllocateVirtualMemory")

	allocatedAddress := uintptr(0)
	allocatedsize := uintptr(0x8181)

	fmt.Printf("[!] calling NtAllocateVirtualMemory...\n")
	e, _, _ := ntac.Call(
		uintptr(0xffffffffffffffff),                //ProcessHandle
		uintptr(unsafe.Pointer(&allocatedAddress)), //*BaseAddress
		uintptr(0),                              //ZeroBits
		uintptr(unsafe.Pointer(&allocatedsize)), //RegionSize
		uintptr(0x00001000|0x00002000),          //AllocationType
		windows.PAGE_READWRITE,
	)
	fmt.Printf("ret code: 0x%x\n", e)
	fmt.Printf("addr: 0x%x\n", allocatedAddress)
```

## refs
https://vanmieghem.io/blueprint-for-evading-edr-in-2022/

https://github.com/VirtualAlllocEx/DEFCON-31-Syscalls-Workshop

https://labs.en1gma.co/malwaredevelopment/evasion/security/2023/08/14/syscalls.html

https://github.com/ShorSec/HWSyscalls

https://github.com/timwhitez

https://github.com/C-Sto/BananaPhone

https://github.com/f1zm0/acheron

https://github.com/klezVirus/SilentMoonwalk
