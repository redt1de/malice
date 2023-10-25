

## TODO:
 - hwsyscall,moonwalk need cleaned up, add error/nil value checks, do testing
 - moonwalk needs a little more work, its a bit messy but functional
 - implement the various resolvers in each call type, mem/disk/remote
 - finish darklib, add PEB linking
 - finish get SSN from exception table, pe package was modified with some support for exception table
 - ntd and darklib are using sycall.Syscall() for Call(). need to implement asm func to avoid suspicious syscall import


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


## pkgs

#### callz/direct:
    - direct syscalls
    - sysid lookup via in mem or on disk (hellsgate)
    - halos gate fallback (if proc is hooked, try and get sysid from an unhooked neighbor)
    - supports API hashing


#### callz/indirect:
    - indirect syscalls (basically direct syscall but uses a "syscall;ret; trampoline)
    - sysid lookup via in mem or on disk (hellsgate)
    - halos gate fallback (if proc is hooked, try and get sysid from an unhooked neighbor)
    - supports API hashing

#### callz/proxycall:
    - uses undocumented Nt callbacks to create a call stack that appears legitimate. Note, no return values are provided so r1,r2,err will always be empty.

#### callz/darklib:
    - darkloadlibrary'ish. still need to implement PEB linking, currently its more of a reflective dll load.
    - mimics windows.NewLazyDLL(), NewProc() etc but without the use of LoadLibrary() and GetProcAddress() since these may be monitored. This works by extracting Ldr data from PEB and parsing the Dll in mem to get exports. 
    - supports API hashing

#### callz/moonwalk:
    - silentmoonwalk desync call stack spoofing on indirect syscalls.

#### callz/hwsyscall:
    - hwsyscalls implementation

#### callz:
    - util functions for DLLs/Nt calls
    - handles ssn resolution,finding gadgets etc.

#### inst:
    - set or clear an instrumentation callback

#### veh:
    - functions for manipulate vectored exception handlers and hardware breakpoints
    - hooks a Dll call using hardware breakpoints and vectored exception handlers.


#### all the callz follow a similar pattern for modularity (sliver builders caugh)
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
