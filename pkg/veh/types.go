package veh

const (
	CONTEXT_AMD64 = 0x100000

	CONTEXT_CONTROL         = (CONTEXT_AMD64 | 0x1)
	CONTEXT_INTEGER         = (CONTEXT_AMD64 | 0x2)
	CONTEXT_SEGMENTS        = (CONTEXT_AMD64 | 0x4)
	CONTEXT_FLOATING_POINT  = (CONTEXT_AMD64 | 0x8)
	CONTEXT_DEBUG_REGISTERS = (CONTEXT_AMD64 | 0x10)

	CONTEXT_FULL = (CONTEXT_CONTROL | CONTEXT_INTEGER | CONTEXT_FLOATING_POINT)
	CONTEXT_ALL  = (CONTEXT_CONTROL | CONTEXT_INTEGER | CONTEXT_SEGMENTS | CONTEXT_FLOATING_POINT | CONTEXT_DEBUG_REGISTERS)

	CONTEXT_EXCEPTION_ACTIVE    = 0x8000000
	CONTEXT_SERVICE_ACTIVE      = 0x10000000
	CONTEXT_EXCEPTION_REQUEST   = 0x40000000
	CONTEXT_EXCEPTION_REPORTING = 0x80000000

	CONTEXT64_AMD64           = 0x100000
	CONTEXT64_CONTROL         = CONTEXT64_AMD64 | 0x01
	CONTEXT64_INTEGER         = CONTEXT64_AMD64 | 0x02
	CONTEXT64_SEGMENTS        = CONTEXT64_AMD64 | 0x04
	CONTEXT64_FLOATING_POINT  = CONTEXT64_AMD64 | 0x08
	CONTEXT64_DEBUG_REGISTERS = CONTEXT64_AMD64 | 0x10
	CONTEXT64_FULL            = CONTEXT64_CONTROL | CONTEXT64_INTEGER | CONTEXT64_FLOATING_POINT
	CONTEXT64_ALL             = CONTEXT64_CONTROL | CONTEXT64_INTEGER | CONTEXT64_SEGMENTS | CONTEXT64_FLOATING_POINT | CONTEXT64_DEBUG_REGISTERS

	// EXCEPTION_CONTINUE_EXECUTION = uint32(0xffffffff)
	EXCEPTION_CONTINUE_EXECUTION  = -1
	EXCEPTION_CONTINUE_SEARCH     = 0
	EXCEPTION_EXECUTE_HANDLER     = 1
	UEXCEPTION_CONTINUE_EXECUTION = 0xffffffff

	EXCEPTION_ACCESS_VIOLATION      = uint32(0xC0000005)
	EXCEPTION_BREAKPOINT            = uint32(0x80000003)
	EXCEPTION_DATATYPE_MISALIGNMENT = uint32(0x80000002)
	EXCEPTION_SINGLE_STEP           = uint32(0x80000004)
	EXCEPTION_ARRAY_BOUNDS_EXCEEDED = uint32(0xC000008C)
	EXCEPTION_INT_DIVIDE_BY_ZERO    = uint32(0xC0000094)

	// exception flags
	EXCEPTION_NONCONTINUABLE  = 0x0001
	EXCEPTION_UNWINDING       = 0x0002
	EXCEPTION_EXIT_UNWIND     = 0x0004
	EXCEPTION_STACK_INVALID   = 0x0008
	EXCEPTION_NESTED_CALL     = 0x0010
	EXCEPTION_TARGET_UNWIND   = 0x0020
	EXCEPTION_COLLIDED_UNWIND = 0x0040
	EXCEPTION_UNWIND          = 0x0066
)

// //////////////////////// EXCEPTION_POINTERS
type EXCEPTION_POINTERS _EXCEPTION_POINTERS
type PEXCEPTION_POINTERS *EXCEPTION_POINTERS
type _EXCEPTION_POINTERS struct {
	ExceptionRecord PEXCEPTION_RECORD
	ContextRecord   PCONTEXT
}

// //////////////////////// EXCEPTION_RECORD
const EXCEPTION_MAXIMUM_PARAMETERS = 15 // Placeholder value, replace with actual value if known
type PEXCEPTION_RECORD *EXCEPTION_RECORD
type EXCEPTION_RECORD struct {
	ExceptionCode        uint32
	ExceptionFlags       uint32
	ExceptionRecord      *EXCEPTION_RECORD
	ExceptionAddress     uintptr
	NumberParameters     uint32
	ExceptionInformation [EXCEPTION_MAXIMUM_PARAMETERS]uintptr
}

type M128A struct {
	Low  uint64
	High uint64
}

type XMM_SAVE_AREA32 struct {
	Controluint16  uint16
	Statusuint16   uint16
	Taguint16      byte
	Reserved1      byte
	ErrorOpcode    uint16
	ErrorOffset    uint32
	ErrorSelector  uint16
	Reserved2      uint16
	DataOffset     uint32
	DataSelector   uint16
	Reserved3      uint16
	MxCsr          uint32
	MxCsr_Mask     uint32
	FloatRegisters [8]M128A
	XmmRegisters   [16]M128A
	Reserved4      [96]byte
}

type PCONTEXT *CONTEXT
type LPCONTEXT PCONTEXT
type CONTEXT struct {
	P1Home uint64
	P2Home uint64
	P3Home uint64
	P4Home uint64
	P5Home uint64
	P6Home uint64

	ContextFlags         uint32
	MxCsr                uint32
	SegCs                uint16
	SegDs                uint16
	SegEs                uint16
	SegFs                uint16
	SegGs                uint16
	SegSs                uint16
	EFlags               uint32
	Dr0                  uint64
	Dr1                  uint64
	Dr2                  uint64
	Dr3                  uint64
	Dr6                  uint64
	Dr7                  uint64
	Rax                  uint64
	Rcx                  uint64
	Rdx                  uint64
	Rbx                  uint64
	Rsp                  uint64
	Rbp                  uint64
	Rsi                  uint64
	Rdi                  uint64
	R8                   uint64
	R9                   uint64
	R10                  uint64
	R11                  uint64
	R12                  uint64
	R13                  uint64
	R14                  uint64
	R15                  uint64
	Rip                  uint64
	FloatSave            XMM_SAVE_AREA32
	VectorRegister       [26]M128A
	VectorControl        uint64
	DebugControl         uint64
	LastBranchToRip      uint64
	LastBranchFromRip    uint64
	LastExceptionToRip   uint64
	LastExceptionFromRip uint64
}
