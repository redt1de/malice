package cmd

import "fmt"

type Context struct {
	RAX uint64
	RBX uint64
	RCX uint64
	RDX uint64
	RSP uint64
	RBP uint64
	RDI uint64
	RSI uint64
	R8  uint64
	R9  uint64
	R10 uint64
	R11 uint64
	R12 uint64
	R13 uint64
	R14 uint64
	R15 uint64
}

func outRegs() string {
	return fmt.Sprintf("\nRAX: %016X RBX: %016X RCX: %016X RDX: %016X\nRSP: %016X RBP: %016X RDI: %016X RSI: %016X\n R8: %016X  R9: %016X R10: %016X R11: %016X\nR12: %016X R13: %016X R14: %016X R15: %016X", Proj.CTX.RAX, Proj.CTX.RBX, Proj.CTX.RCX, Proj.CTX.RDX, Proj.CTX.RSP, Proj.CTX.RBP, Proj.CTX.RDI, Proj.CTX.RSI, Proj.CTX.R8, Proj.CTX.R9, Proj.CTX.R10, Proj.CTX.R11, Proj.CTX.R12, Proj.CTX.R13, Proj.CTX.R14, Proj.CTX.R15)
}
