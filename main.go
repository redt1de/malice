package main

import "github.com/redt1de/malice/pkg/callz/ntd"

// GOPRIVATE=* GOOS=windows GOARCH=amd64 CGO_ENABLED=1 CC=x86_64-w64-mingw32-gcc CXX=x86_64-w64-mingw32-g++ GOFLAGS=-ldflags=-s GOFLAGS=-ldflags=-w go build -a -trimpath -ldflags="-extldflags=-w -s -buildid=" -o LicensingDiagSpp.dll -buildmode=c-shared
// GOPRIVATE=* GOOS=windows GOARCH=amd64 CGO_ENABLED=1 CC=x86_64-w64-mingw32-gcc CXX=x86_64-w64-mingw32-g++ GOFLAGS=-ldflags=-s GOFLAGS=-ldflags=-w garble -tiny -debugdir=/tmp/LicenseDiag/ build -a -trimpath -ldflags="-extldflags=-w -s -buildid=" -o GARBLE-LicensingDiagSpp.dll -buildmode=c-shared

func main() {

	// //bBytes, e := n.Pe.Bytes() // on SentinelOne box, this panics.Exception: 0x80000001 == STATUS_GUARD_PAGE_VIOLATION

	// caller := indirect.New(callz.WithHasher(hashers.Djb2), callz.WithResolver(1))
	// ntavm := caller.NewProc("5bb3894b6793c34c")

	// allocatedAddress := uintptr(0)
	// allocatedsize := uintptr(0x8181)

	// fmt.Printf("[!] Calling NtAvM...\n")
	// e, _, _ := ntavm.Call(
	// 	uintptr(0xffffffffffffffff),                //ProcessHandle
	// 	uintptr(unsafe.Pointer(&allocatedAddress)), //*BaseAddress
	// 	uintptr(0),                              //ZeroBits
	// 	uintptr(unsafe.Pointer(&allocatedsize)), //RegionSize
	// 	uintptr(0x00001000|0x00002000),          //AllocationType
	// 	windows.PAGE_READWRITE,
	// )
	// fmt.Printf("ret code: 0x%x\n", e)
	// fmt.Printf("addr: 0x%x\n", allocatedAddress)

	ntd.Test()

}
