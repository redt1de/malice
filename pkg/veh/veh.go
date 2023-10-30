package veh

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

// References:
// https://gist.github.com/susMdT/360c64c842583f8732cc1c98a60bfd9e
var (
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

type VHandleFunc func(*CONTEXT) uintptr

type VHandler struct {
	contH      uintptr
	exH        uintptr
	targetAddr uintptr
	// threads    []windows.Handle
	// threadids  []uint32
	handleFunc VHandleFunc
}

func New(addr uintptr, handler VHandleFunc) (*VHandler, error) {
	ret := VHandler{}
	chand, _, _ := ch.Call(1, windows.NewCallback(continueHandler))
	if chand == 0 {
		return nil, fmt.Errorf("failed to add vectored continue handler")
	}
	ret.contH = chand

	ehand, _, _ := eh.Call(uintptr(1), windows.NewCallback(ret.intHandler))
	if ehand == 0 {
		return nil, fmt.Errorf("failed to add vectored exception handler")
	}
	ret.targetAddr = addr
	ret.handleFunc = handler
	ret.exH = ehand
	return &ret, nil
}

// // SetBPLocal sets a breakpoint on the target address for the current thread, Dr7 local enable
// func (vh *VHandler) EnableLocal() error {
// 	t := windows.CurrentThread()
// 	vh.threads = append(vh.threads, t)

// 	ctx := CONTEXT{}
// 	ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS

// 	// TODO: implement error checking, some syscall types may not provide return values, like proxycall
// 	r1, _, err := gtc.Call(uintptr(t), uintptr(unsafe.Pointer(&ctx)))
// 	if r1 == 0 {
// 		return fmt.Errorf("failed to get thread context: %v", err)
// 	}

// 	SetHWBP(&ctx, vh.targetAddr, 0, true) //<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<

// 	// TODO: implement error checking, some syscall types may not provide return values, like proxycall
// 	r1, _, err = stc.Call(uintptr(t), uintptr(unsafe.Pointer(&ctx)))
// 	if r1 == 0 {
// 		return fmt.Errorf("failed to set thread context: %v", err)
// 	}
// 	return nil
// }

const THREAD_ALL_ACCESS = 0x001F03FF

// // SetBPGlobal sets a breakpoint on the target address for all accessible threads, Dr7 enable global
// func (vh *VHandler) EnableGlobal() error {
// 	curProc := windows.GetCurrentProcessId()
// 	snaphand, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPTHREAD, 0)
// 	if err != nil {
// 		return fmt.Errorf("CreateToolhelp32Snapshot failed: %v", err)
// 	}
// 	defer windows.CloseHandle(snaphand)
// 	var entry windows.ThreadEntry32
// 	entry.Size = uint32(unsafe.Sizeof(entry))
// 	windows.Thread32First(snaphand, &entry)

// 	if entry.OwnerProcessID == curProc {
// 		vh.EnableForThread(entry.ThreadID)
// 	}
// 	for {
// 		if err := windows.Thread32Next(snaphand, &entry); err != nil {
// 			break
// 		}
// 		if entry.OwnerProcessID == curProc {
// 			vh.EnableForThread(entry.ThreadID)
// 		}

// 	}
// 	return nil

// }

func (vh *VHandler) SetThread(tid uint32) error {
	h, err := windows.OpenThread(THREAD_ALL_ACCESS, false, tid)
	if err != nil {
		return fmt.Errorf("OpenThread failed -> thread: %d, err: %v\n", tid, err)
	}

	ctx := CONTEXT{}
	ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS

	r1, _, err := gtc.Call(uintptr(h), uintptr(unsafe.Pointer(&ctx)))
	if r1 == 0 {
		return fmt.Errorf("GetThreadContext failed -> thread: %d, err: %v\n", tid, err)
	}

	set_on := SetHWBP(&ctx, vh.targetAddr)
	if set_on == -1 {
		return fmt.Errorf("no available breakpoint slots -> thread: %d, err: %v\n", tid, err)
	}
	if set_on == -2 {
		return fmt.Errorf("breakpoint already set -> thread: %d, err: %v\n", tid, err)
	}

	r1, _, err = stc.Call(uintptr(h), uintptr(unsafe.Pointer(&ctx)))
	if r1 == 0 {
		return fmt.Errorf("SetThreadContext failed -> thread: %d, err: %v\n", tid, err)
	}
	fmt.Printf("[+] Breakpoint set on thread: %d, via DR%d\n", tid, set_on)
	return nil
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

func SetHWBP(ctx *CONTEXT, address uintptr) int {
	var index int
	if ctx.Dr0 == uint64(address) || ctx.Dr1 == uint64(address) || ctx.Dr2 == uint64(address) || ctx.Dr3 == uint64(address) {
		return -2
	}

	switch {
	case ctx.Dr0 == 0:
		ctx.Dr0 = uint64(address)
		index = 0
	case ctx.Dr1 == 0:
		ctx.Dr1 = uint64(address)
		index = 1
	case ctx.Dr2 == 0:
		ctx.Dr2 = uint64(address)
		index = 2
	case ctx.Dr3 == 0:
		ctx.Dr3 = uint64(address)
		index = 3
	default:
		return -1
	}

	ctx.Dr7 = SetBits(ctx.Dr7, 16, 16, 0)
	ctx.Dr7 = SetBits(ctx.Dr7, (index * 2), 1, 1)
	ctx.Dr7 = SetBits(ctx.Dr7, (index*2)+1, 1, 1)
	ctx.Dr6 = 0
	return index
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

func (vh *VHandler) intHandler(e *EXCEPTION_POINTERS) uintptr {
	if e.ExceptionRecord.ExceptionCode == EXCEPTION_SINGLE_STEP && e.ExceptionRecord.ExceptionAddress == vh.targetAddr {
		r := vh.handleFunc(e.ContextRecord)
		if r == 0 {
		} // force intHandler to wait for return from handler.
		return uintptr(UEXCEPTION_CONTINUE_EXECUTION)
	}
	return uintptr(EXCEPTION_CONTINUE_SEARCH)
}
