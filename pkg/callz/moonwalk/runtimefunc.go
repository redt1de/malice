package moonwalk

import (
	"unsafe"

	"github.com/redt1de/malice/pkg/pe"
)

// C compatible structs
type PRUNTIME_FUNCTION *RUNTIME_FUNCTION
type RUNTIME_FUNCTION struct {
	BeginAddress uint32
	EndAddress   uint32
	UnwindData   uint32
}

type PUNWIND_INFO *UNWIND_INFO
type UNWIND_INFO struct {
	versionAndFlags             byte
	SizeOfProlog                byte
	CountOfCodes                byte
	frameRegisterAndFrameOffset byte
	UnwindCode                  [1]UNWIND_CODE
	// UnwindCode uintptr
}

type PUNWIND_CODE *UNWIND_CODE
type UNWIND_CODE struct {
	CodeOffset        uint8 // BYTE
	unwindOpAndOpInfo uint8 // BYTE
	// FrameOffset       uint16 // USHORT
}

func (u *UNWIND_INFO) Version() uint8 {
	return u.versionAndFlags & 0x07
}

func (u *UNWIND_INFO) Flags() uint8 {
	return (u.versionAndFlags >> 3) & 0x1F
}
func (u *UNWIND_INFO) FrameRegister() uint8 {
	return u.frameRegisterAndFrameOffset & 0x0F
}

func (u *UNWIND_INFO) FrameOffset() uint8 {
	return (u.frameRegisterAndFrameOffset >> 4) & 0x0F
}

func (u *UNWIND_CODE) UnwindOp() uint8 {
	return u.unwindOpAndOpInfo & 0x0F
}

func (u *UNWIND_CODE) OpInfo() uint8 {
	return (u.unwindOpAndOpInfo >> 4) & 0x0F
}

func (u *UNWIND_CODE) FrameOffset() uint16 {
	frameOffset := *(*uint16)(unsafe.Pointer(u))
	return frameOffset
}

func GetRuntimeTableAddr(hmod *pe.File) (uintptr, uint32) {
	if hmod.ImageBase == 0 || hmod.ImageSize == 0 {
		panic("RuntimeTable: File not loaded in memory")
	}

	var edd pe.DataDirectory
	pe64 := hmod.Machine == pe.IMAGE_FILE_MACHINE_AMD64
	if pe64 {
		edd = hmod.OptionalHeader.(*pe.OptionalHeader64).DataDirectory[pe.IMAGE_DIRECTORY_ENTRY_EXCEPTION]
	} else {
		edd = hmod.OptionalHeader.(*pe.OptionalHeader32).DataDirectory[pe.IMAGE_DIRECTORY_ENTRY_EXCEPTION]
	}
	count := edd.Size / uint32(unsafe.Sizeof(RUNTIME_FUNCTION{}))
	eddAddr := hmod.ImageBase + uintptr(edd.VirtualAddress)

	return eddAddr, count
}

func RTFindFunctionByAddress(hmod *pe.File, searchAddr uintptr) *RUNTIME_FUNCTION {
	rttaddr, count := GetRuntimeTableAddr(hmod)
	for i := 0; i < int(count); i++ {
		rf := (*RUNTIME_FUNCTION)(unsafe.Pointer(rttaddr + uintptr(i)*unsafe.Sizeof(RUNTIME_FUNCTION{})))
		if uintptr(rf.BeginAddress)+hmod.ImageBase == searchAddr {
			return rf
		}
	}
	return nil
}
