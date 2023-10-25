package darklib

import "golang.org/x/sys/windows"

const (
	MEM_COMMIT             = 0x001000
	MEM_RESERVE            = 0x002000
	IDX                    = 32
	LDR_HASH_TABLE_ENTRIES = 32
)

type (
	DWORD     uint32
	ULONGLONG uint64
	WORD      uint16
	BYTE      uint8
	LONG      uint32
)

const (
	IMAGE_NUMBEROF_DIRECTORY_ENTRIES = 16
)

type _IMAGE_FILE_HEADER struct {
	Machine              WORD
	NumberOfSections     WORD
	TimeDateStamp        DWORD
	PointerToSymbolTable DWORD
	NumberOfSymbols      DWORD
	SizeOfOptionalHeader WORD
	Characteristics      WORD
}

type IMAGE_FILE_HEADER _IMAGE_FILE_HEADER

type IMAGE_OPTIONAL_HEADER64 _IMAGE_OPTIONAL_HEADER64
type IMAGE_OPTIONAL_HEADER IMAGE_OPTIONAL_HEADER64

type _IMAGE_OPTIONAL_HEADER64 struct {
	Magic                       WORD
	MajorLinkerVersion          BYTE
	MinorLinkerVersion          BYTE
	SizeOfCode                  DWORD
	SizeOfInitializedData       DWORD
	SizeOfUninitializedData     DWORD
	AddressOfEntryPoint         DWORD
	BaseOfCode                  DWORD
	ImageBase                   ULONGLONG
	SectionAlignment            DWORD
	FileAlignment               DWORD
	MajorOperatingSystemVersion WORD
	MinorOperatingSystemVersion WORD
	MajorImageVersion           WORD
	MinorImageVersion           WORD
	MajorSubsystemVersion       WORD
	MinorSubsystemVersion       WORD
	Win32VersionValue           DWORD
	SizeOfImage                 DWORD
	SizeOfHeaders               DWORD
	CheckSum                    DWORD
	Subsystem                   WORD
	DllCharacteristics          WORD
	SizeOfStackReserve          ULONGLONG
	SizeOfStackCommit           ULONGLONG
	SizeOfHeapReserve           ULONGLONG
	SizeOfHeapCommit            ULONGLONG
	LoaderFlags                 DWORD
	NumberOfRvaAndSizes         DWORD
	DataDirectory               [IMAGE_NUMBEROF_DIRECTORY_ENTRIES]IMAGE_DATA_DIRECTORY
}
type _IMAGE_DATA_DIRECTORY struct {
	VirtualAddress DWORD
	Size           DWORD
}
type IMAGE_DATA_DIRECTORY _IMAGE_DATA_DIRECTORY

type _IMAGE_NT_HEADERS64 struct {
	Signature      DWORD
	FileHeader     IMAGE_FILE_HEADER
	OptionalHeader IMAGE_OPTIONAL_HEADER
}
type IMAGE_NT_HEADERS64 _IMAGE_NT_HEADERS64
type IMAGE_NT_HEADERS IMAGE_NT_HEADERS64
type _IMAGE_DOS_HEADER struct { // DOS .EXE header
	E_magic    WORD     // Magic number
	E_cblp     WORD     // Bytes on last page of file
	E_cp       WORD     // Pages in file
	E_crlc     WORD     // Relocations
	E_cparhdr  WORD     // Size of header in paragraphs
	E_minalloc WORD     // Minimum extra paragraphs needed
	E_maxalloc WORD     // Maximum extra paragraphs needed
	E_ss       WORD     // Initial (relative) SS value
	E_sp       WORD     // Initial SP value
	E_csum     WORD     // Checksum
	E_ip       WORD     // Initial IP value
	E_cs       WORD     // Initial (relative) CS value
	E_lfarlc   WORD     // File address of relocation table
	E_ovno     WORD     // Overlay number
	E_res      [4]WORD  // Reserved words
	E_oemid    WORD     // OEM identifier (for E_oeminfo)
	E_oeminfo  WORD     // OEM information; E_oemid specific
	E_res2     [10]WORD // Reserved words
	E_lfanew   LONG     // File address of new exe header
}

type IMAGE_DOS_HEADER _IMAGE_DOS_HEADER

type LIST_ENTRY struct {
	Flink *LIST_ENTRY
	Blink *LIST_ENTRY
}

type SINGLE_LIST_ENTRY struct {
	Next *SINGLE_LIST_ENTRY
}

type LIST_ENTRY32 struct {
	Flink uint32
	Blink uint32
}

type LIST_ENTRY64 struct {
	Flink uint64
	Blink uint64
}

type UNICODE_STRING struct {
	Length        uint16
	MaximumLength uint16
	Buffer        *uint16
}

func NewUnicodeString(s string) UNICODE_STRING {
	ws, _ := windows.UTF16PtrFromString(s)
	len := uint16(len(s) * 2) // 2 bytes per character in UTF-16
	return UNICODE_STRING{
		Length:        len,
		MaximumLength: len,
		Buffer:        ws,
	}
}
func (u UNICODE_STRING) String() string {
	return windows.UTF16PtrToString(u.Buffer)
}

type PRLIST_ENTRY *LIST_ENTRY
type PSINGLE_LIST_ENTRY *SINGLE_LIST_ENTRY
type PLIST_ENTRY32 *LIST_ENTRY32
type PLIST_ENTRY64 *LIST_ENTRY64

type PLDR_INIT_ROUTINE func(DllHandle uintptr, Reason uint32, Context uintptr) bool //uint32???
// typedef BOOLEAN (NTAPI *PLDR_INIT_ROUTINE)(
//
//	_In_ PVOID DllHandle,
//	_In_ ULONG Reason,
//	_In_opt_ PVOID Context
//
// );
type LDR_DATA_TABLE_ENTRY2 struct {
	InLoadOrderLinks            LIST_ENTRY
	InMemoryOrderLinks          LIST_ENTRY
	InInitializationOrderLinks  LIST_ENTRY // Union, chose one member
	DllBase                     uintptr
	EntryPoint                  PLDR_INIT_ROUTINE
	SizeOfImage                 uint32
	FullDllName                 UNICODE_STRING
	BaseDllName                 UNICODE_STRING
	Flags                       uint32 // I'm representing the entire union with this single field
	ObsoleteLoadCount           uint16
	TlsIndex                    uint16
	HashLinks                   LIST_ENTRY
	TimeDateStamp               uint32
	EntryPointActivationContext uintptr //*ACTIVATION_CONTEXT
	Lock                        uintptr
	DdagNode                    uintptr //*LDR_DDAG_NODE
	NodeModuleLink              LIST_ENTRY
	LoadContext                 uintptr //*LDRP_LOAD_CONTEXT
	ParentDllBase               uintptr
	SwitchBackContext           uintptr
	BaseAddressIndexNode        RTL_BALANCED_NODE
	MappingInfoIndexNode        RTL_BALANCED_NODE
	OriginalBase                uintptr
	LoadTime                    int64 // LARGE_INTEGER is typically a 64-bit signed integer
	BaseNameHashValue           uint32
	LoadReason                  LDR_DLL_LOAD_REASON
	ImplicitPathOptions         uint32
	ReferenceCount              uint32
	DependentLoadFlags          uint32
	SigningLevel                byte
}

type RTL_BALANCED_NODE struct {
	Children    [2]*RTL_BALANCED_NODE // Choosing Children array to represent the space
	ParentValue uintptr               // Choosing ParentValue to represent the space
}

type LDR_DLL_LOAD_REASON uint32

const (
	LoadReasonStaticDependency LDR_DLL_LOAD_REASON = iota
	LoadReasonStaticForwarderDependency
	LoadReasonDynamicForwarderDependency
	LoadReasonDelayloadDependency
	LoadReasonDynamicLoad
	LoadReasonAsImageLoad
	LoadReasonAsDataLoad
	LoadReasonEnclavePrimary
	LoadReasonEnclaveDependency
)

// const LoadReasonUnknown LDR_DLL_LOAD_REASON = -1
