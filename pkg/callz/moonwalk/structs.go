package moonwalk

const (
	UNWIND_HISTORY_TABLE_SIZE   = 12
	UNWIND_HISTORY_TABLE_NONE   = 0
	UNWIND_HISTORY_TABLE_GLOBAL = 1
	UNWIND_HISTORY_TABLE_LOCAL  = 2
	STATUS_INVALID_PARAMETER    = 0xC000000D
	UNW_FLAG_CHAININFO          = 0x4
)

const MAX_FRAMES = 154

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

func BitVal(data, y uint8) uint8    { return (data >> y) & 1 }
func BitChainInfo(data uint8) uint8 { return BitVal(data, 2) }
func BitUHandler(data uint8) uint8  { return BitVal(data, 1) }
func BitEHandler(data uint8) uint8  { return BitVal(data, 0) }

type SPOOFER struct {
	RtlUserThreadStartAddress    uintptr
	RtlUserThreadStartFrameSize  uintptr
	BaseThreadInitThunkAddress   uintptr
	BaseThreadInitThunkFrameSize uintptr
	FirstFrameFunctionPointer    uintptr
	FirstFrameSize               uintptr
	FirstFrameRandomOffset       uintptr
	SecondFrameFunctionPointer   uintptr
	SecondFrameSize              uintptr
	SecondFrameRandomOffset      uintptr
	JmpRbxGadget                 uintptr
	JmpRbxGadgetFrameSize        uintptr
	JmpRbxGadgetRef              uintptr
	AddRspXGadget                uintptr
	AddRspXGadgetFrameSize       uintptr
	StackOffsetWhereRbpIsPushed  uintptr
	Ssn                          uintptr
	SpoofFunctionPointer         uintptr
	OgRet                        uintptr
	OgRSP                        uintptr
	OgRBP                        uintptr
}
