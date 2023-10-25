package main

import (
	"fmt"
	"unsafe"

	"github.com/redt1de/malice/pkg/callz/direct"
	"golang.org/x/sys/windows"
)

func main() {
	// windows.LoadLibrary("win32u.dll")
	// windows.LoadLibrary("dbghelp.dll")
	// windows.LoadLibrary("./syscall-detect.dll")
	windows.LoadLibrary("./manual-syscall-detect.dll")

	allocatedsize := uintptr(0x8181)

	// ////////////// notlazy
	// NotLazyntAlloc1 := notlazy.NotLazyDLL("ntdll.dll").NewProc("NtAllocateVirtualMemory")
	// NotLazyntAlloc2 := notlazy.NotLazyDLL("377d2b522d3b5ed").NewProc("5bb3894b6793c34c")

	// NotLazyAllocAddr := uintptr(0)

	// NotLazyntAlloc1.Call(
	// 	uintptr(0xffffffffffffffff),                //ProcessHandle
	// 	uintptr(unsafe.Pointer(&NotLazyAllocAddr)), //*BaseAddress
	// 	uintptr(0),                              //ZeroBits
	// 	uintptr(unsafe.Pointer(&allocatedsize)), //RegionSize
	// 	uintptr(0x00001000|0x00002000),          //AllocationType
	// 	windows.PAGE_EXECUTE_READWRITE,          //Protect
	// )

	// fmt.Printf("NotLazy Addr: 0x%x\n", NotLazyAllocAddr)

	// NotLazyAllocAddr2 := uintptr(0)
	// NotLazyntAlloc2.Call(
	// 	uintptr(0xffffffffffffffff),                 //ProcessHandle
	// 	uintptr(unsafe.Pointer(&NotLazyAllocAddr2)), //*BaseAddress
	// 	uintptr(0),                              //ZeroBits
	// 	uintptr(unsafe.Pointer(&allocatedsize)), //RegionSize
	// 	uintptr(0x00001000|0x00002000),          //AllocationType
	// 	windows.PAGE_EXECUTE_READWRITE,          //Protect
	// )

	// fmt.Printf("NotLazy (hashed) Addr: 0x%x\n", NotLazyAllocAddr2)
	// println()

	////////////// direct
	DirectntAlloc1 := direct.New("NtAllocateVirtualMemory", 0)
	DirectntAlloc2 := direct.New("5bb3894b6793c34c", 0)

	DirectAllocAddr := uintptr(0)
	DirectntAlloc1.Call(
		uintptr(0xffffffffffffffff),               //ProcessHandle
		uintptr(unsafe.Pointer(&DirectAllocAddr)), //*BaseAddress
		uintptr(0),                              //ZeroBits
		uintptr(unsafe.Pointer(&allocatedsize)), //RegionSize
		uintptr(0x00001000|0x00002000),          //AllocationType
		windows.PAGE_EXECUTE_READWRITE,          //Protect
	)

	fmt.Printf("Direct Addr: 0x%x\n", DirectAllocAddr)

	DirectAllocAddr2 := uintptr(0)
	DirectntAlloc2.Call(
		uintptr(0xffffffffffffffff),                //ProcessHandle
		uintptr(unsafe.Pointer(&DirectAllocAddr2)), //*BaseAddress
		uintptr(0),                              //ZeroBits
		uintptr(unsafe.Pointer(&allocatedsize)), //RegionSize
		uintptr(0x00001000|0x00002000),          //AllocationType
		windows.PAGE_EXECUTE_READWRITE,          //Protect
	)

	fmt.Printf("Direct (hashed) Addr: 0x%x\n", DirectAllocAddr2)
	println()

	// ////////////// indirect
	// IndirectntAlloc1 := indirect.New("NtAllocateVirtualMemory", 0)
	// IndirectntAlloc2 := indirect.New("5bb3894b6793c34c", 0)

	// IndirectAllocAddr := uintptr(0)
	// IndirectntAlloc1.Call(
	// 	uintptr(0xffffffffffffffff),                 //ProcessHandle
	// 	uintptr(unsafe.Pointer(&IndirectAllocAddr)), //*BaseAddress
	// 	uintptr(0),                              //ZeroBits
	// 	uintptr(unsafe.Pointer(&allocatedsize)), //RegionSize
	// 	uintptr(0x00001000|0x00002000),          //AllocationType
	// 	windows.PAGE_EXECUTE_READWRITE,          //Protect
	// )

	// fmt.Printf("Indirect Addr: 0x%x\n", IndirectAllocAddr)

	// IndirectAllocAddr2 := uintptr(0)
	// IndirectntAlloc2.Call(
	// 	uintptr(0xffffffffffffffff),                  //ProcessHandle
	// 	uintptr(unsafe.Pointer(&IndirectAllocAddr2)), //*BaseAddress
	// 	uintptr(0),                              //ZeroBits
	// 	uintptr(unsafe.Pointer(&allocatedsize)), //RegionSize
	// 	uintptr(0x00001000|0x00002000),          //AllocationType
	// 	windows.PAGE_EXECUTE_READWRITE,          //Protect
	// )

	// fmt.Printf("Indirect (hashed) Addr: 0x%x\n", IndirectAllocAddr2)
	// println()
	// ////////////// proxycall
	// ProxycallntAlloc1 := proxycall.New("NtAllocateVirtualMemory")
	// ProxycallntAlloc2 := proxycall.New("5bb3894b6793c34c")

	// ProxycallAllocAddr := uintptr(0)
	// ProxycallntAlloc1.Call(
	// 	uintptr(0xffffffffffffffff),                  //ProcessHandle
	// 	uintptr(unsafe.Pointer(&ProxycallAllocAddr)), //*BaseAddress
	// 	uintptr(0),                              //ZeroBits
	// 	uintptr(unsafe.Pointer(&allocatedsize)), //RegionSize
	// 	uintptr(0x00001000|0x00002000),          //AllocationType
	// 	windows.PAGE_EXECUTE_READWRITE,          //Protect
	// )

	// fmt.Printf("Proxycall Addr: 0x%x\n", ProxycallAllocAddr)

	// ProxycallAllocAddr2 := uintptr(0)
	// ProxycallntAlloc2.Call(
	// 	uintptr(0xffffffffffffffff),                   //ProcessHandle
	// 	uintptr(unsafe.Pointer(&ProxycallAllocAddr2)), //*BaseAddress
	// 	uintptr(0),                              //ZeroBits
	// 	uintptr(unsafe.Pointer(&allocatedsize)), //RegionSize
	// 	uintptr(0x00001000|0x00002000),          //AllocationType
	// 	windows.PAGE_EXECUTE_READWRITE,          //Protect
	// )

	// fmt.Printf("Proxycall (hashed) Addr: 0x%x\n", ProxycallAllocAddr2)
	// println()
	// ///////////////// hwsyscall
	// HwSyscallntAlloc1 := hwsyscall.New("NtAllocateVirtualMemory")
	// HwSyscallntAlloc2 := hwsyscall.New("5bb3894b6793c34c")

	// HwSyscallAllocAddr := uintptr(0)
	// HwSyscallntAlloc1.Call(
	// 	uintptr(0xffffffffffffffff),                  //ProcessHandle
	// 	uintptr(unsafe.Pointer(&HwSyscallAllocAddr)), //*BaseAddress
	// 	uintptr(0),                              //ZeroBits
	// 	uintptr(unsafe.Pointer(&allocatedsize)), //RegionSize
	// 	uintptr(0x00001000|0x00002000),          //AllocationType
	// 	windows.PAGE_EXECUTE_READWRITE,          //Protect
	// )

	// fmt.Printf("HwSyscall Addr: 0x%x\n", HwSyscallAllocAddr)

	// HwSyscallAllocAddr2 := uintptr(0)
	// HwSyscallntAlloc2.Call(
	// 	uintptr(0xffffffffffffffff),                   //ProcessHandle
	// 	uintptr(unsafe.Pointer(&HwSyscallAllocAddr2)), //*BaseAddress
	// 	uintptr(0),                              //ZeroBits
	// 	uintptr(unsafe.Pointer(&allocatedsize)), //RegionSize
	// 	uintptr(0x00001000|0x00002000),          //AllocationType
	// 	windows.PAGE_EXECUTE_READWRITE,          //Protect
	// )

	// fmt.Printf("HwSyscall (hashed) Addr: 0x%x\n", HwSyscallAllocAddr2)

}
