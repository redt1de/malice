package synth

const (
	UNWIND_HISTORY_TABLE_SIZE   = 12
	UNWIND_HISTORY_TABLE_NONE   = 0
	UNWIND_HISTORY_TABLE_GLOBAL = 1
	UNWIND_HISTORY_TABLE_LOCAL  = 2
	STATUS_INVALID_PARAMETER    = 0xC000000D
	UNW_FLAG_CHAININFO          = 0x4
)

// type UNWIND_CODE_OPS int

const (
	UWOP_PUSH_NONVOL     uint8 = iota // 0
	UWOP_ALLOC_LARGE                  // 1
	UWOP_ALLOC_SMALL                  // 2
	UWOP_SET_FPREG                    // 3
	UWOP_SAVE_NONVOL                  // 4
	UWOP_SAVE_NONVOL_BIG              // 5
	UWOP_EPILOG                       // 6
	UWOP_SPARE_CODE                   // 7
	UWOP_SAVE_XMM128                  // 8
	UWOP_SAVE_XMM128BIG               // 9
	UWOP_PUSH_MACH_FRAME              // 10
)

const (
	RAX uint8 = iota // 0
	RCX              // 1
	RDX              // 2
	RBX              // 3
	RSP              // 4
	RBP              // 5
	RSI              // 6
	RDI              // 7
	R8               // 8
	R9               // 9
	R10              // 10
	R11              // 11
	R12              // 12
	R13              // 13
	R14              // 14
	R15              // 15
)

type UNWIND_HISTORY_TABLE struct {
	Count       uint32
	Search      uint8
	LowAddress  uint64
	HighAddress uint64
	Entry       [UNWIND_HISTORY_TABLE_SIZE]UNWIND_HISTORY_TABLE_ENTRY
}

type UNWIND_HISTORY_TABLE_ENTRY struct {
	ImageBase     uint64
	FunctionEntry *IMAGE_RUNTIME_FUNCTION_ENTRY
}

/*

RUNTIME_FUNCTION
	BeginAddress uint32
	EndAddress   uint32
	UnwindData   uint32 > UNWIND_INFO
		Version       uint8
		Flags         uint8
		SizeOfProlog  uint8
		CountOfCodes  uint8
		FrameRegister uint8
		FrameOffset   uint8
		UnwindCode    []UNWIND_CODE
							CodeOffset  uint8  // BYTE
							UnwindOp    uint8  // Extract from BYTE using bitwise operations
							OpInfo      uint8  // Extract from BYTE using bitwise operations
							FrameOffset uint16 // USHORT
*/

type GRUNTIME_FUNCTION struct {
	BeginAddress uint32
	EndAddress   uint32
	UnwindInfo   struct {
		Version       uint8
		Flags         uint8
		SizeOfProlog  uint8
		CountOfCodes  uint8
		FrameRegister uint8
		FrameOffset   uint8
		UnwindCodes   []UNWIND_CODE
	}
}

type RUNTIME_FUNCTION = IMAGE_RUNTIME_FUNCTION_ENTRY
type IMAGE_RUNTIME_FUNCTION_ENTRY struct {
	BeginAddress uint32
	EndAddress   uint32
	UnwindData   uint32
}

type _UNWIND_INFO struct {
	VersionAndFlags             byte
	SizeOfProlog                byte
	CountOfCodes                byte
	FrameRegisterAndFrameOffset byte
	UnwindCode                  [255]uint16
}

type UNWIND_INFO struct {
	Version       uint8
	Flags         uint8
	SizeOfProlog  uint8
	CountOfCodes  uint8
	FrameRegister uint8
	FrameOffset   uint8
	UnwindCode    []UNWIND_CODE
}

type _UNWIND_CODE struct {
	CodeOffset        byte // BYTE
	UnwindOpAndOpInfo byte // BYTE
	// FrameOffset       uint16 // USHORT
}

type UNWIND_CODE struct {
	CodeOffset  uint8  // BYTE
	UnwindOp    uint8  // Extract from BYTE using bitwise operations
	OpInfo      uint8  // Extract from BYTE using bitwise operations
	FrameOffset uint16 // USHORT
}

// //////////////////////////////////////////////////////////////////////////////////////////////
type PRM struct {
	Fixup       uintptr
	OGRetaddr   uintptr
	RBX         uintptr
	RDI         uintptr
	BTITSS      uintptr
	BTITRetaddr uintptr
	GadgetSS    uintptr
	RUTSSS      uintptr
	RUTSRetaddr uintptr
	SSN         uintptr
	Trampoline  uintptr
	RSI         uintptr
	R12         uintptr
	R13         uintptr
	R14         uintptr
	R15         uintptr
}

type StackFrame struct {
	DllPath             *uint16 // LPCWSTR is equivalent to *uint16 in Go
	Offset              uint32
	TotalStackSize      uint32
	RequiresLoadLibrary bool
	SetsFramePointer    bool
	ReturnAddress       uintptr // PVOID is equivalent to uintptr in Go
	PushRbp             bool
	CountOfCodes        uint32
	PushRbpIndex        uint32 //bool: why is this a bool in LoudSunRun
}

type MIN_CTX struct {
	Rax       uint64
	Rcx       uint64
	Rdx       uint64
	Rbx       uint64
	Rsp       uint64
	Rbp       uint64
	Rsi       uint64
	Rdi       uint64
	R8        uint64
	R9        uint64
	R10       uint64
	R11       uint64
	R12       uint64
	R13       uint64
	R14       uint64
	R15       uint64
	Rip       uint64
	Reserved  uint64
	StackSize uint64
}
