package synth

import (
	"encoding/hex"
	"fmt"
	"reflect"
	"unsafe"

	"github.com/redt1de/malice/pkg/callz/darklib"
)

var (
	dl                      = darklib.New()
	k32                     = dl.NotLazyDLL("kernel32.dll")
	ntd                     = dl.NotLazyDLL("ntdll.dll")
	pRtlLookupFunctionEntry = k32.NewProc("RtlLookupFunctionEntry")
)

type Nasty struct {
	SSN        uintptr
	Trampoline uintptr
}

func doTest(strct *Nasty, argh ...uintptr) uint32
func Spoof(a uintptr, argh ...uintptr)

func printf(f string, a ...interface{}) {
	fmt.Printf(f, a...)
}

func Dump(addr unsafe.Pointer, size int) {
	fmt.Printf("Dumping %d bytes at 0x%x\n", size, uintptr(addr))
	println(hex.Dump(*(*[]byte)(unsafe.Pointer(&reflect.SliceHeader{
		Data: uintptr(addr),
		Len:  size,
		Cap:  size,
	}))))
}

func Test() {

	dl := darklib.New()
	// k32 := dl.NotLazyDLL("kernel32.dll")
	// k32.PE.Blah(pBaseThreadInitThunk)
	// rtBaseThreadInitThunk := k32.PE.RTFindFunctionByAddress(pBaseThreadInitThunk)
	// rtRtlUserThreadStart := ntdll.PE.RTFindFunctionByAddress(pRtlUserThreadStart)

	kbase := dl.NotLazyDLL("kernelbase.dll")
	var stackSize, rtSaveIndex, skip_prolog_frame, skip_pop_rsp_frame, stackOffsetWhereRbpIsPushed uint32
	var rtTargetOffset uint64
	FindProlog(kbase.PE, &stackSize, &rtSaveIndex, &skip_prolog_frame, &rtTargetOffset)
	stackOffsetWhereRbpIsPushed = FindPushRbp(kbase.PE, &stackSize, &rtSaveIndex, &skip_pop_rsp_frame, &rtTargetOffset)
	printf("stackOffsetWhereRbpIsPushed: 0x%x\n", stackOffsetWhereRbpIsPushed)

	println("junk", skip_pop_rsp_frame, stackOffsetWhereRbpIsPushed)
	return

	/////////////////////////////////////////////////////////////////////
	// uw := GetUnwindInfo(pRuntimeFunction)
	// fmt.Printf("UnwindInfo.Version: 0x%x\n", uw.Version)
	// fmt.Printf("UnwindInfo.Flags: 0x%x\n", uw.Flags)
	// fmt.Printf("UnwindInfo.SizeOfProlog: 0x%x\n", uw.SizeOfProlog)
	// fmt.Printf("UnwindInfo.CountOfCodes: 0x%x\n", uw.CountOfCodes)
	// fmt.Printf("UnwindInfo.FrameRegister: 0x%x\n", uw.FrameRegister)
	// fmt.Printf("UnwindInfo.FrameOffset: 0x%x\n", uw.FrameOffset)

	// a := Nasty{
	// 	SSN:        0x18,
	// 	Trampoline: callz.FindInModule("kernel32.dll", callz.GADGET_JMP_RBX),
	// }

	// b := doTest(&a, 0xdeadbeef, 0xdeadbeef, 0xdeadbeef, 0xdeadbeef)
	// fmt.Printf("b: 0x%x\n", b)

	// // var p PRM
	// // aBaseThreadInitThunk := k32.NewProc("BaseThreadInitThunk").Addr() + 0x14
	// // aRtlUserThreadStart := ntd.NewProc("RtlUserThreadStart").Addr() + 0x21
	// // // aTpReleaseCleanupGroupMembers := ntd.NewProc("TpReleaseCleanupGroupMembers").Addr() + 0x747

	// // p.Trampoline = callz.FindInModule("kernel32.dll", callz.GADGET_JMP_RBX)
	// // fmt.Printf("[+] Gadget is at 0x%llx\n", p.Trampoline)

	// // p.BTITSS = uintptr(CalculateFunctionStackSizeWrapper(aBaseThreadInitThunk))
	// // p.BTITRetaddr = aBaseThreadInitThunk

	// // p.RUTSSS = uintptr(CalculateFunctionStackSizeWrapper(aRtlUserThreadStart))
	// // p.RUTSRetaddr = aRtlUserThreadStart

	// // p.GadgetSS = uintptr(CalculateFunctionStackSizeWrapper(p.Trampoline))
	// // p.SSN = 0x18
	// // syscallRet := callz.FindInModule("ntdll.dll", callz.GADGET_SYSCALL_RET)

	// // fmt.Println(syscallRet)

}
