package dbg

import (
	"encoding/hex"
	"fmt"
	"unsafe"

	"github.com/redt1de/malice/pkg/veh"
)

var Debug bool

func Printf(fm string, a ...any) {
	if !Debug {
		return
	}
	fmt.Printf(fm, a...)
}

func Println(a ...any) {
	if !Debug {
		return
	}
	fmt.Println(a...)
}

func Pausef(fm string, a ...any) {
	if !Debug {
		return
	}
	fmt.Printf(fm, a...)
	fmt.Printf("  Press Enter to continue...")
	fmt.Scanln()
}

func Pauseln(a ...any) {
	if !Debug {
		return
	}
	fmt.Println(a...)
	fmt.Printf("  Press Enter to continue...")
	fmt.Scanln()
}

func Pause() {
	if !Debug {
		return
	}
	fmt.Printf("  Press Enter to continue...")
	fmt.Scanln()
}

func DumpRIP(ctx *veh.CONTEXT) {
	fmt.Printf("RIP: 0x%x\n", ctx.Rip)
}

func DumpRegs(c *veh.CONTEXT) {
	fmt.Println("Context:")
	fmt.Printf("	RAX: 0x%x\n", c.Rax)
	fmt.Printf("	RBX: 0x%x\n", c.Rbx)
	fmt.Printf("	RCX: 0x%x\n", c.Rcx)
	fmt.Printf("	RDX: 0x%x\n", c.Rdx)
	fmt.Printf("	RDI: 0x%x\n", c.Rdi)
	fmt.Printf("	RSI: 0x%x\n", c.Rsi)
	fmt.Printf("	RSP: 0x%x\n", c.Rsp)
	fmt.Printf("	RBP: 0x%x\n", c.Rbp)
	fmt.Printf("	RIP: 0x%x\n", c.Rip)
	fmt.Printf("	R8: 0x%x\n", c.R8)
	fmt.Printf("	R9: 0x%x\n", c.R9)
	fmt.Printf("	R10: 0x%x\n", c.R10)
	fmt.Printf("	R11: 0x%x\n", c.R11)
	fmt.Printf("	R12: 0x%x\n", c.R12)
	fmt.Printf("	R13: 0x%x\n", c.R13)
	fmt.Printf("	R14: 0x%x\n", c.R14)
	fmt.Printf("	R15: 0x%x\n", c.R15)
	fmt.Printf("	ContextFlags: 0x%x\n", c.ContextFlags)
	fmt.Printf("	EFLAGS: 0x%x\n", c.EFlags)
	fmt.Printf("	DR0: 0x%x\n", c.Dr0)
	fmt.Printf("	DR1: 0x%x\n", c.Dr1)
	fmt.Printf("	DR2: 0x%x\n", c.Dr2)
	fmt.Printf("	DR3: 0x%x\n", c.Dr3)
	fmt.Printf("	DR6: 0x%x\n", c.Dr6)
	fmt.Printf("	DR7: 0x%x\n", c.Dr7)
	// fmt.Printf("    LastBranchToRip: 0x%x\n", c.LastBranchToRip)
	// fmt.Printf("    LastBranchFromRip: 0x%x\n", c.LastBranchFromRip)
	// fmt.Printf("    LastExceptionToRip: 0x%x\n", c.LastExceptionToRip)
	// fmt.Printf("    LastExceptionFromRip: 0x%x\n", c.LastExceptionFromRip)

}

func DumpStack(rsp uint64, size int) {
	fmt.Println("Stack:")
	stack := ReadMemory(uintptr(rsp), size)
	fmt.Println(hex.Dump(stack))
}

func ReadMemory(addr uintptr, readLen int) []byte {
	readmem := unsafe.Slice((*byte)(unsafe.Pointer(addr)), readLen)
	return readmem
}

// func  GetContext(thread windows.Handle) *veh.CONTEXT {
// 	ctx := veh.CONTEXT{}
// 	ctx.ContextFlags = veh.CONTEXT_ALL
// 	ct := windows.CurrentThread()
// 	err := veh.GetThreadContext(ct, &ctx)
// 	if err != nil {
// 		log.Fatal(err)
// 	}
// 	return &ctx
// }

func Break()
