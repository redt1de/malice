package veh

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

// References:
// https://gist.github.com/susMdT/360c64c842583f8732cc1c98a60bfd9e
// notlazy.NotLazyDLL("377d2b522d3b5ed").NewProc("")
var (
	TargetAddr uintptr
	// Thread     windows.Handle
	ch = windows.NewLazyDLL("ntdll.dll").NewProc("RtlAddVectoredContinueHandler")
	// ch = darklib.New(callz.WithHasher(hash.Djb2)).NotLazyDLL("377d2b522d3b5ed").NewProc("27799dac7f7a9a1f")
	eh = windows.NewLazyDLL("ntdll.dll").NewProc("RtlAddVectoredExceptionHandler")
	// eh = darklib.New(callz.WithHasher(hash.Djb2)).NotLazyDLL("377d2b522d3b5ed").NewProc("b236009c554bafa9")
	rch = windows.NewLazyDLL("ntdll.dll").NewProc("RtlRemoveVectoredContinueHandler")
	// rch = darklib.New(callz.WithHasher(hash.Djb2)).NotLazyDLL("377d2b522d3b5ed").NewProc("216250feaf8ff2e4")
	reh = windows.NewLazyDLL("ntdll.dll").NewProc("RtlRemoveVectoredExceptionHandler")
	// reh = darklib.New(callz.WithHasher(hash.Djb2)).NotLazyDLL("377d2b522d3b5ed").NewProc("e9351e34880c210e")
	gtc = windows.NewLazySystemDLL("kernel32.dll").NewProc("GetThreadContext")
	// gtc = darklib.New(callz.WithHasher(hash.Djb2)).NotLazyDLL("d537e9367040ee75").NewProc("62e49c1eba2cfc2")
	stc = windows.NewLazySystemDLL("kernel32.dll").NewProc("SetThreadContext")
	// stc = darklib.New(callz.WithHasher(hash.Djb2)).NotLazyDLL("d537e9367040ee75").NewProc("95c916a67e20964e")
)

type VHandler struct {
	contH      uintptr
	exH        uintptr
	targetAddr uintptr
	threads    []windows.Handle
	threadids  []uint32
}

func New(handler uintptr) (*VHandler, error) {
	chand, _, _ := ch.Call(1, windows.NewCallback(continueHandler))
	if chand == 0 {
		return nil, fmt.Errorf("failed to add vectored continue handler")
	}

	ehand, _, _ := eh.Call(uintptr(1), handler)
	if ehand == 0 {
		return nil, fmt.Errorf("failed to add vectored exception handler")
	}
	return &VHandler{
		contH: chand,
		exH:   ehand,
	}, nil
}

// SetBPLocal sets a breakpoint on the target address for the current thread, Dr7 local enable
func (vh *VHandler) SetBPLocal(targetFunc uintptr, t windows.Handle) error {
	// t := windows.CurrentThread()
	vh.targetAddr = targetFunc
	TargetAddr = targetFunc
	vh.threads = append(vh.threads, t)

	ctx := CONTEXT{}
	ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS

	// TODO: implement error checking, some syscall types may not provide return values, like proxycall
	r1, _, err := gtc.Call(uintptr(t), uintptr(unsafe.Pointer(&ctx)))
	if r1 == 0 {
		return fmt.Errorf("failed to get thread context: %v", err)
	}

	SetHWBP(&ctx, targetFunc, 0, true) //<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<

	// TODO: implement error checking, some syscall types may not provide return values, like proxycall
	r1, _, err = stc.Call(uintptr(t), uintptr(unsafe.Pointer(&ctx)))
	if r1 == 0 {
		return fmt.Errorf("failed to set thread context: %v", err)
	}
	return nil
}

const THREAD_ALL_ACCESS = 0x001F03FF

// SetBPGlobal sets a breakpoint on the target address for all accessible threads, Dr7 enable global
func (vh *VHandler) SetBPGlobal(targetFunc uintptr) error {
	vh.targetAddr = targetFunc
	TargetAddr = targetFunc
	curProc := windows.GetCurrentProcessId()
	snaphand, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPTHREAD, 0)
	if err != nil {
		return fmt.Errorf("CreateToolhelp32Snapshot failed: %v", err)
	}
	defer windows.CloseHandle(snaphand)
	var entry windows.ThreadEntry32
	entry.Size = uint32(unsafe.Sizeof(entry))
	windows.Thread32First(snaphand, &entry)

	if entry.OwnerProcessID == curProc {
		vh.a(entry)
	}
	for {
		if err := windows.Thread32Next(snaphand, &entry); err != nil {
			break
		}
		if entry.OwnerProcessID == curProc {
			vh.a(entry)
		}

	}
	return nil

}

func (vh *VHandler) a(entry windows.ThreadEntry32) {
	for _, id := range vh.threadids {
		if entry.ThreadID == id {
			return
		}
	}
	h, err := windows.OpenThread(THREAD_ALL_ACCESS, false, entry.ThreadID)
	if err != nil {
		fmt.Printf("process: %d, thread: %d, err: %v\n", entry.OwnerProcessID, entry.ThreadID, err)
		return
		// continue
	}

	vh.threads = append(vh.threads, h)
	vh.threadids = append(vh.threadids, entry.ThreadID)

	ctx := CONTEXT{}
	ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS

	// TODO: implement error checking, some syscall types may not provide return values, like proxycall
	r1, _, err := gtc.Call(uintptr(h), uintptr(unsafe.Pointer(&ctx)))
	if r1 == 0 {
		// continue
		// return fmt.Errorf("failed to get thread context: %v", err)
		fmt.Printf("failed to get thread context: %v", err)
		return
	}

	SetHWBP(&ctx, vh.targetAddr, 0, true)

	// TODO: implement error checking, some syscall types may not provide return values, like proxycall
	r1, _, err = stc.Call(uintptr(h), uintptr(unsafe.Pointer(&ctx)))
	if r1 == 0 {
		// continue
		// return fmt.Errorf("failed to set thread context: %v", err)
		fmt.Printf("failed to set thread context: %v", err)
		return
	}
	fmt.Printf("Set on proc: %d, thread: %d\n", entry.OwnerProcessID, entry.ThreadID)
}
func (vh *VHandler) Kill() error {
	chand, _, _ := rch.Call(vh.contH)
	if chand == 0 {
		return fmt.Errorf("failed to remove vectored continue handler")
	}

	ehand, _, _ := reh.Call(vh.exH)
	if ehand == 0 {
		return fmt.Errorf("failed to remove vectored exception handler")
	}

	return nil
}

/////////////////////////////////////

// var chand, ehand uintptr

// func AddVeh(handler uintptr) error {
// 	chand, _, _ = ch.Call(1, windows.NewCallback(continueHandler))
// 	if chand == 0 {
// 		return fmt.Errorf("failed to add vectored continue handler")
// 	}

// 	ehand, _, _ = eh.Call(uintptr(1), handler)
// 	if ehand == 0 {
// 		return fmt.Errorf("failed to add vectored exception handler")
// 	}

// 	return nil
// }

// func RemoveVeh() error {
// 	chand, _, _ = rch.Call(chand)
// 	if chand == 0 {
// 		return fmt.Errorf("failed to remove vectored continue handler")
// 	}

// 	ehand, _, _ = reh.Call(ehand)
// 	if ehand == 0 {
// 		return fmt.Errorf("failed to remove vectored exception handler")
// 	}

// 	return nil
// }

// func EnableBreakpoint(targetFunc uintptr, thread windows.Handle) error {
// 	TargetAddr = targetFunc
// 	ctx := CONTEXT{}
// 	ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS

// 	// TODO: implement error checking, some syscall types may not provide return values, like proxycall
// 	r1, _, err := gtc.Call(uintptr(thread), uintptr(unsafe.Pointer(&ctx)))
// 	if r1 == 0 {
// 		return fmt.Errorf("failed to get thread context: %v", err)
// 	}

// 	SetHWBP(&ctx, targetFunc, 0, false)

// 	// TODO: implement error checking, some syscall types may not provide return values, like proxycall
// 	r1, _, err = stc.Call(uintptr(thread), uintptr(unsafe.Pointer(&ctx)))
// 	if r1 == 0 {
// 		return fmt.Errorf("failed to set thread context: %v", err)
// 	}
// 	return nil
// }

func SetHWBP(ctx *CONTEXT, address uintptr, index int, global bool) {
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
	if global {
		ctx.Dr7 = SetBits(ctx.Dr7, (index * 2), 1, 1)
	} else {
		ctx.Dr7 = SetBits(ctx.Dr7, (index*2)+1, 1, 1)

	}

	ctx.Dr6 = 0
}

func SetBits(dw uint64, lowBit int, bits int, newValue uint64) uint64 {
	mask := (1 << bits) - 1
	dw = (dw & ^(uint64(mask) << lowBit)) | (newValue << lowBit)
	return dw
}

func Func2Ptr(f interface{}) uintptr {
	return *(*[2]*uintptr)(unsafe.Pointer(&f))[1]
}

func Func2Ptr2(f interface{}) uintptr {
	a := (*[2]unsafe.Pointer)(unsafe.Pointer(&f))
	return *(*uintptr)(unsafe.Pointer(a[1]))
}

// continue handler is needed since go uses VEH, and will default to panic without it.
//
//go:nosplit
func continueHandler(e *EXCEPTION_POINTERS) uintptr {
	return 0xffffffff // just return EXCEPTION_CONTINUE_EXECUTION
}
