package main

import (
	"fmt"
	"unsafe"

	"github.com/redt1de/malice/pkg/callz/darklib"
	"golang.org/x/sys/windows"
)

// GOPRIVATE=* GOOS=windows GOARCH=amd64 CGO_ENABLED=1 CC=x86_64-w64-mingw32-gcc CXX=x86_64-w64-mingw32-g++ GOFLAGS=-ldflags=-s GOFLAGS=-ldflags=-w go build -a -trimpath -ldflags="-extldflags=-w -s -buildid=" -o LicensingDiagSpp.dll -buildmode=c-shared
// GOPRIVATE=* GOOS=windows GOARCH=amd64 CGO_ENABLED=1 CC=x86_64-w64-mingw32-gcc CXX=x86_64-w64-mingw32-g++ GOFLAGS=-ldflags=-s GOFLAGS=-ldflags=-w garble -tiny -debugdir=/tmp/LicenseDiag/ build -a -trimpath -ldflags="-extldflags=-w -s -buildid=" -o GARBLE-LicensingDiagSpp.dll -buildmode=c-shared

func main() {
	allocatedAddress := uintptr(0)
	allocatedsize := uintptr(0x8181)

	cl := darklib.New()
	nt := cl.NewDarkDll("ntdll.dll")
	ntavm := nt.NewProc("NtAllocateVirtualMemory")

	fmt.Printf("[!] Calling NtAvM...\n")
	e, _, _ := ntavm.Call(
		uintptr(0xffffffffffffffff),                //ProcessHandle
		uintptr(unsafe.Pointer(&allocatedAddress)), //*BaseAddress
		uintptr(0),                              //ZeroBits
		uintptr(unsafe.Pointer(&allocatedsize)), //RegionSize
		uintptr(0x00001000|0x00002000),          //AllocationType
		windows.PAGE_READWRITE,
	)
	fmt.Printf("ret code: 0x%x\n", e)
	fmt.Printf("addr: 0x%x\n", allocatedAddress)

}
