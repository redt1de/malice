package main

import (
	"fmt"
	"unsafe"

	"github.com/redt1de/malice/pkg/callz"
	"github.com/redt1de/malice/pkg/callz/darklib"
	"github.com/redt1de/malice/pkg/callz/direct"
	"github.com/redt1de/malice/pkg/callz/hashers"
	"github.com/redt1de/malice/pkg/callz/indirect"
	"github.com/redt1de/malice/pkg/callz/moonwalk"
	"github.com/redt1de/malice/pkg/callz/ntd"
	"github.com/redt1de/malice/pkg/callz/proxycall"
	"golang.org/x/sys/windows"
)

func main() {
	daFunc := "NtAllocateVirtualMemory"
	daHashedFunc := "5bb3894b6793c34c"
	println("Testing with function: "+daFunc, "("+daHashedFunc+")")

	test_darklib(daFunc)
	test_darklib_hashed(daHashedFunc)
	test_ntd(daFunc)
	test_ntd_hashed(daHashedFunc)
	test_direct(daFunc)
	test_direct_hashed(daHashedFunc)
	test_indirect(daFunc)
	test_indirect_hashed(daHashedFunc)
	test_proxycall(daFunc)
	test_proxycall_hashed(daHashedFunc)
	test_moonwalk(daFunc)
	test_moonwalk_hashed(daHashedFunc)

}

func test_darklib(daFunc string) {
	var AllocSize, AllocAddr uintptr
	AllocSize = uintptr(0x8181)
	dllname := "ntdll.dll"

	a1 := darklib.New()
	a1Ntdll := a1.NewDarkDll(dllname)
	a1Ntavm := a1Ntdll.NewProc(daFunc)

	AllocAddr = uintptr(0)
	r1, r2, err := a1Ntavm.Call(
		uintptr(0xffffffffffffffff),         //ProcessHandle
		uintptr(unsafe.Pointer(&AllocAddr)), //*BaseAddress
		uintptr(0),                          //ZeroBits
		uintptr(unsafe.Pointer(&AllocSize)), //RegionSize
		uintptr(0x00001000|0x00002000),      //AllocationType
		windows.PAGE_EXECUTE_READWRITE,      //Protect
	)
	fmt.Printf("[DARKLIB] [NOT HASHED]: R1: 0x%x, R2: 0x%x, Err: %v  -> Addr: 0x%x\n", r1, r2, err, AllocAddr)
}

func test_darklib_hashed(daHashedFunc string) {
	var AllocSize, AllocAddr uintptr
	AllocSize = uintptr(0x8181)
	hashedDllname := "377d2b522d3b5ed"

	a2 := darklib.New(callz.WithHasher(hashers.Djb2))
	a2Ntdll := a2.NewDarkDll(hashedDllname)
	a2Ntavm := a2Ntdll.NewProc(daHashedFunc)

	AllocAddr = uintptr(0)
	r1, r2, err := a2Ntavm.Call(
		uintptr(0xffffffffffffffff),         //ProcessHandle
		uintptr(unsafe.Pointer(&AllocAddr)), //*BaseAddress
		uintptr(0),                          //ZeroBits
		uintptr(unsafe.Pointer(&AllocSize)), //RegionSize
		uintptr(0x00001000|0x00002000),      //AllocationType
		windows.PAGE_EXECUTE_READWRITE,      //Protect
	)
	fmt.Printf("[DARKLIB] [HASHED]: R1: 0x%x, R2: 0x%x, Err: %v  -> Addr: 0x%x\n", r1, r2, err, AllocAddr)
}

func test_ntd(daFunc string) {
	var AllocSize, AllocAddr uintptr
	AllocSize = uintptr(0x8181)

	b1 := ntd.NewNtDll()
	b1Ntavm := b1.NewProc(daFunc)

	AllocAddr = uintptr(0)
	r1, r2, err := b1Ntavm.Call(
		uintptr(0xffffffffffffffff),         //ProcessHandle
		uintptr(unsafe.Pointer(&AllocAddr)), //*BaseAddress
		uintptr(0),                          //ZeroBits
		uintptr(unsafe.Pointer(&AllocSize)), //RegionSize
		uintptr(0x00001000|0x00002000),      //AllocationType
		windows.PAGE_EXECUTE_READWRITE,      //Protect
	)
	fmt.Printf("[NTD] [NOT HASHED]: R1: 0x%x, R2: 0x%x, Err: %v  -> Addr: 0x%x\n", r1, r2, err, AllocAddr)
}

func test_ntd_hashed(daHashedFunc string) {
	var AllocSize, AllocAddr uintptr
	AllocSize = uintptr(0x8181)

	b2 := ntd.NewNtDll(callz.WithHasher(hashers.Djb2))
	b2Ntavm := b2.NewProc(daHashedFunc)

	AllocAddr = uintptr(0)
	r1, r2, err := b2Ntavm.Call(
		uintptr(0xffffffffffffffff),         //ProcessHandle
		uintptr(unsafe.Pointer(&AllocAddr)), //*BaseAddress
		uintptr(0),                          //ZeroBits
		uintptr(unsafe.Pointer(&AllocSize)), //RegionSize
		uintptr(0x00001000|0x00002000),      //AllocationType
		windows.PAGE_EXECUTE_READWRITE,      //Protect
	)
	fmt.Printf("[NTD] [HASHED]: R1: 0x%x, R2: 0x%x, Err: %v  -> Addr: 0x%x\n", r1, r2, err, AllocAddr)
}

func test_direct(daFunc string) {
	var AllocSize, AllocAddr uintptr
	AllocSize = uintptr(0x8181)

	c1 := direct.New()
	c1Ntavm := c1.NewProc(daFunc)

	AllocAddr = uintptr(0)
	r1, r2, err := c1Ntavm.Call(
		uintptr(0xffffffffffffffff),         //ProcessHandle
		uintptr(unsafe.Pointer(&AllocAddr)), //*BaseAddress
		uintptr(0),                          //ZeroBits
		uintptr(unsafe.Pointer(&AllocSize)), //RegionSize
		uintptr(0x00001000|0x00002000),      //AllocationType
		windows.PAGE_EXECUTE_READWRITE,      //Protect
	)
	fmt.Printf("[DIRECT] [NOT HASHED]: R1: 0x%x, R2: 0x%x, Err: %v  -> Addr: 0x%x\n", r1, r2, err, AllocAddr)
}

func test_direct_hashed(daHashedFunc string) {
	var AllocSize, AllocAddr uintptr
	AllocSize = uintptr(0x8181)

	c2 := direct.New(callz.WithHasher(hashers.Djb2))
	c2Ntavm := c2.NewProc(daHashedFunc)

	AllocAddr = uintptr(0)
	r1, r2, err := c2Ntavm.Call(
		uintptr(0xffffffffffffffff),         //ProcessHandle
		uintptr(unsafe.Pointer(&AllocAddr)), //*BaseAddress
		uintptr(0),                          //ZeroBits
		uintptr(unsafe.Pointer(&AllocSize)), //RegionSize
		uintptr(0x00001000|0x00002000),      //AllocationType
		windows.PAGE_EXECUTE_READWRITE,      //Protect
	)
	fmt.Printf("[DIRECT] [HASHED]: R1: 0x%x, R2: 0x%x, Err: %v  -> Addr: 0x%x\n", r1, r2, err, AllocAddr)
}

func test_indirect(daFunc string) {
	var AllocSize, AllocAddr uintptr
	AllocSize = uintptr(0x8181)

	d1 := indirect.New()
	d1Ntavm := d1.NewProc(daFunc)

	AllocAddr = uintptr(0)
	r1, r2, err := d1Ntavm.Call(
		uintptr(0xffffffffffffffff),         //ProcessHandle
		uintptr(unsafe.Pointer(&AllocAddr)), //*BaseAddress
		uintptr(0),                          //ZeroBits
		uintptr(unsafe.Pointer(&AllocSize)), //RegionSize
		uintptr(0x00001000|0x00002000),      //AllocationType
		windows.PAGE_EXECUTE_READWRITE,      //Protect
	)
	fmt.Printf("[INDIRECT] [NOT HASHED]: R1: 0x%x, R2: 0x%x, Err: %v  -> Addr: 0x%x\n", r1, r2, err, AllocAddr)
}

func test_indirect_hashed(daHashedFunc string) {
	var AllocSize, AllocAddr uintptr
	AllocSize = uintptr(0x8181)

	d2 := indirect.New(callz.WithHasher(hashers.Djb2))
	d2Ntavm := d2.NewProc(daHashedFunc)

	AllocAddr = uintptr(0)
	r1, r2, err := d2Ntavm.Call(
		uintptr(0xffffffffffffffff),         //ProcessHandle
		uintptr(unsafe.Pointer(&AllocAddr)), //*BaseAddress
		uintptr(0),                          //ZeroBits
		uintptr(unsafe.Pointer(&AllocSize)), //RegionSize
		uintptr(0x00001000|0x00002000),      //AllocationType
		windows.PAGE_EXECUTE_READWRITE,      //Protect
	)
	fmt.Printf("[INDIRECT] [HASHED]: R1: 0x%x, R2: 0x%x, Err: %v  -> Addr: 0x%x\n", r1, r2, err, AllocAddr)
}

func test_proxycall(daFunc string) {
	var AllocSize, AllocAddr uintptr
	AllocSize = uintptr(0x8181)

	e1 := proxycall.New()
	e1Ntavm := e1.NewProc(daFunc)

	AllocAddr = uintptr(0)
	r1, r2, err := e1Ntavm.Call(
		uintptr(0xffffffffffffffff),         //ProcessHandle
		uintptr(unsafe.Pointer(&AllocAddr)), //*BaseAddress
		uintptr(0),                          //ZeroBits
		uintptr(unsafe.Pointer(&AllocSize)), //RegionSize
		uintptr(0x00001000|0x00002000),      //AllocationType
		windows.PAGE_EXECUTE_READWRITE,      //Protect
	)
	fmt.Printf("[PROXYCALL] [NOT HASHED]: R1: 0x%x, R2: 0x%x, Err: %v  -> Addr: 0x%x\n", r1, r2, err, AllocAddr)
}

func test_proxycall_hashed(daHashedFunc string) {
	var AllocSize, AllocAddr uintptr
	AllocSize = uintptr(0x8181)

	e2 := proxycall.New(callz.WithHasher(hashers.Djb2))
	e2Ntavm := e2.NewProc(daHashedFunc)

	AllocAddr = uintptr(0)
	r1, r2, err := e2Ntavm.Call(
		uintptr(0xffffffffffffffff),         //ProcessHandle
		uintptr(unsafe.Pointer(&AllocAddr)), //*BaseAddress
		uintptr(0),                          //ZeroBits
		uintptr(unsafe.Pointer(&AllocSize)), //RegionSize
		uintptr(0x00001000|0x00002000),      //AllocationType
		windows.PAGE_EXECUTE_READWRITE,      //Protect
	)
	fmt.Printf("[PROXYCALL] [HASHED]: R1: 0x%x, R2: 0x%x, Err: %v  -> Addr: 0x%x\n", r1, r2, err, AllocAddr)
}

func test_moonwalk(daFunc string) {
	var AllocSize, AllocAddr uintptr
	AllocSize = uintptr(0x8181)

	f1 := moonwalk.New()
	f1Ntavm := f1.NewProc(daFunc)

	AllocAddr = uintptr(0)
	r1, r2, err := f1Ntavm.Call(
		uintptr(0xffffffffffffffff),         //ProcessHandle
		uintptr(unsafe.Pointer(&AllocAddr)), //*BaseAddress
		uintptr(0),                          //ZeroBits
		uintptr(unsafe.Pointer(&AllocSize)), //RegionSize
		uintptr(0x00001000|0x00002000),      //AllocationType
		windows.PAGE_EXECUTE_READWRITE,      //Protect
	)
	fmt.Printf("[MOONWALK] [NOT HASHED]: R1: 0x%x, R2: 0x%x, Err: %v  -> Addr: 0x%x\n", r1, r2, err, AllocAddr)
}

func test_moonwalk_hashed(daHashedFunc string) {
	var AllocSize, AllocAddr uintptr
	AllocSize = uintptr(0x8181)

	f2 := moonwalk.New(callz.WithHasher(hashers.Djb2))
	f2Ntavm := f2.NewProc(daHashedFunc)

	AllocAddr = uintptr(0)
	r1, r2, err := f2Ntavm.Call(
		uintptr(0xffffffffffffffff),         //ProcessHandle
		uintptr(unsafe.Pointer(&AllocAddr)), //*BaseAddress
		uintptr(0),                          //ZeroBits
		uintptr(unsafe.Pointer(&AllocSize)), //RegionSize
		uintptr(0x00001000|0x00002000),      //AllocationType
		windows.PAGE_EXECUTE_READWRITE,      //Protect
	)
	fmt.Printf("[MOONWALK] [HASHED]: R1: 0x%x, R2: 0x%x, Err: %v  -> Addr: 0x%x\n", r1, r2, err, AllocAddr)
}
