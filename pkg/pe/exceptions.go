package pe

import (
	"encoding/hex"
	"fmt"
	"reflect"
	"unsafe"
)

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

// C compatible structs
type C_RUNTIME_FUNCTION struct {
	BeginAddress                       uint32
	EndAddress                         uint32
	UNION_UnwindInfoAddress_UnwindData uint32
}

type C_UNWIND_INFO struct {
	VersionAndFlags             byte
	SizeOfProlog                byte
	CountOfCodes                byte
	FrameRegisterAndFrameOffset byte
	UnwindCode                  [255]uint16
}

type C_UNWIND_CODE struct {
	CodeOffset        byte // BYTE
	UnwindOpAndOpInfo byte // BYTE
	// FrameOffset       uint16 // USHORT
}

// go structs
type RUNTIME_FUNCTION struct {
	BeginAddress uint32
	EndAddress   uint32
	UnwindInfo   UNWIND_INFO
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

func (u *C_UNWIND_INFO) Version() uint8 {
	return u.VersionAndFlags & 0x07
}

func (u *C_UNWIND_INFO) Flags() uint8 {
	return (u.VersionAndFlags >> 3) & 0x1F
}
func (u *C_UNWIND_INFO) FrameRegister() uint8 {
	return u.FrameRegisterAndFrameOffset & 0x0F
}

func (u *C_UNWIND_INFO) FrameOffset() uint8 {
	return (u.FrameRegisterAndFrameOffset >> 4) & 0x0F
}

type UNWIND_CODE struct {
	CodeOffset  uint8
	UnwindOp    uint8
	OpInfo      uint8
	FrameOffset uint16
}

func (u *C_UNWIND_CODE) UnwindOp() uint8 {
	return u.UnwindOpAndOpInfo & 0x0F
}

func (u *C_UNWIND_CODE) OpInfo() uint8 {
	return (u.UnwindOpAndOpInfo >> 4) & 0x0F
}

func (u *C_UNWIND_CODE) FrameOffset() uint16 {
	return *(*uint16)(unsafe.Pointer(&u))
}

// GetRuntimeTableAddr returns the address of the runtime exception table and the number of entries
func (f *File) GetRuntimeTableAddr() (uintptr, uint32) {
	if f.ImageBase == 0 || f.ImageSize == 0 {
		panic("RuntimeTable: File not loaded in memory")
	}

	var edd DataDirectory
	pe64 := f.Machine == IMAGE_FILE_MACHINE_AMD64
	if pe64 {
		edd = f.OptionalHeader.(*OptionalHeader64).DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION]
	} else {
		edd = f.OptionalHeader.(*OptionalHeader32).DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION]
	}
	count := edd.Size / uint32(unsafe.Sizeof(C_RUNTIME_FUNCTION{}))
	eddAddr := f.ImageBase + uintptr(edd.VirtualAddress)

	return eddAddr, count
}

// ParseCRuntimeFunction parses the C compatible _RUNTIME_FUNCTION struct, and returns a the go struct RUNTIME_FUNCTION
func ParseCRuntimeFunction(rf *C_RUNTIME_FUNCTION, imgBase uintptr) RUNTIME_FUNCTION {
	var ret RUNTIME_FUNCTION
	ret.BeginAddress = rf.BeginAddress
	ret.EndAddress = rf.EndAddress
	ret.UnwindInfo = UNWIND_INFO{}

	tmpUnwindInfo := (*C_UNWIND_INFO)(unsafe.Pointer(uintptr(rf.UNION_UnwindInfoAddress_UnwindData) + imgBase))
	Version := tmpUnwindInfo.VersionAndFlags & 0x07
	Flags := (tmpUnwindInfo.VersionAndFlags >> 3) & 0x1F
	SizeOfProlog := tmpUnwindInfo.SizeOfProlog
	CountOfCodes := tmpUnwindInfo.CountOfCodes
	FrameRegister := tmpUnwindInfo.FrameRegisterAndFrameOffset & 0x0F
	FrameOffset := (tmpUnwindInfo.FrameRegisterAndFrameOffset >> 4) & 0x0F

	ret.UnwindInfo.Version = Version
	ret.UnwindInfo.Flags = Flags
	ret.UnwindInfo.SizeOfProlog = SizeOfProlog
	ret.UnwindInfo.CountOfCodes = CountOfCodes
	ret.UnwindInfo.FrameRegister = FrameRegister
	ret.UnwindInfo.FrameOffset = FrameOffset

	index := 0
	for {
		if index >= int(tmpUnwindInfo.CountOfCodes) {
			break
		}

		u := *(*uint16)(unsafe.Pointer(&tmpUnwindInfo.UnwindCode[index]))
		tmp3 := (*C_UNWIND_CODE)(unsafe.Pointer(&u))

		unwindOperation := tmp3.UnwindOpAndOpInfo & 0x0F
		operationInfo := (tmp3.UnwindOpAndOpInfo >> 4) & 0x0F
		frameOffset := *(*uint16)(unsafe.Pointer(&u))
		ret.UnwindInfo.UnwindCode = append(ret.UnwindInfo.UnwindCode, UNWIND_CODE{
			CodeOffset:  tmp3.CodeOffset,
			UnwindOp:    unwindOperation,
			OpInfo:      operationInfo,
			FrameOffset: frameOffset,
		})

		index++

	}
	return ret
}

// RTFindFunctionByAddress returns the RUNTIME_FUNCTION struct for the given address
func (f *File) RTFindFunctionByAddress(searchAddr uintptr) *RUNTIME_FUNCTION {
	rttaddr, count := f.GetRuntimeTableAddr()
	for i := 0; i < int(count); i++ {
		rf := (*C_RUNTIME_FUNCTION)(unsafe.Pointer(rttaddr + uintptr(i)*unsafe.Sizeof(C_RUNTIME_FUNCTION{})))
		if uintptr(rf.BeginAddress)+f.ImageBase == searchAddr {
			ret := ParseCRuntimeFunction(rf, f.ImageBase)
			return &ret
		}
	}
	return nil
}

func (f *File) Blah(searchAddr uintptr) {
	rttaddr, count := f.GetRuntimeTableAddr()
	printf("RuntimeTable Addr: 0x%x\n", rttaddr)
	for i := 0; i < int(count); i++ {
		rf := (*C_RUNTIME_FUNCTION)(unsafe.Pointer(rttaddr + uintptr(i)*unsafe.Sizeof(C_RUNTIME_FUNCTION{})))
		if uintptr(rf.BeginAddress)+f.ImageBase == searchAddr {
			printf("BeginAddress: 0x%x\n", rf.BeginAddress)
			printf("EndAddress: 0x%x\n", rf.EndAddress)
			printf("UnwindInfoAddress: 0x%x\n", rf.UNION_UnwindInfoAddress_UnwindData)
			printf("ADDR: 0x%x\n", uintptr(rf.UNION_UnwindInfoAddress_UnwindData)+f.ImageBase)

			tmpUnwindInfo := (*C_UNWIND_INFO)(unsafe.Pointer(uintptr(rf.UNION_UnwindInfoAddress_UnwindData) + f.ImageBase))
			Version := tmpUnwindInfo.VersionAndFlags & 0x07
			Flags := (tmpUnwindInfo.VersionAndFlags >> 3) & 0x1F
			SizeOfProlog := tmpUnwindInfo.SizeOfProlog
			CountOfCodes := tmpUnwindInfo.CountOfCodes
			FrameRegister := tmpUnwindInfo.FrameRegisterAndFrameOffset & 0x0F
			FrameOffset := (tmpUnwindInfo.FrameRegisterAndFrameOffset >> 4) & 0x0F

			printf("  Version: 0x%x (0x%x)\n", Version, tmpUnwindInfo.VersionAndFlags)
			printf("  Flags: 0x%x\n", Flags)
			printf("  SizeOfProlog: 0x%x\n", SizeOfProlog)
			printf("  CountOfCodes: 0x%x\n", CountOfCodes)
			printf("  FrameRegister: 0x%x\n", FrameRegister)
			printf("  FrameOffset: 0x%x\n", FrameOffset)
			index := 0
			for {
				if index >= int(tmpUnwindInfo.CountOfCodes) {
					break
				}

				u := *(*uint32)(unsafe.Pointer(&tmpUnwindInfo.UnwindCode[index]))
				tmp3 := (*C_UNWIND_CODE)(unsafe.Pointer(&u))

				unwindOperation := tmp3.UnwindOpAndOpInfo & 0x0F
				operationInfo := (tmp3.UnwindOpAndOpInfo >> 4) & 0x0F
				frameOffset := *(*uint16)(unsafe.Pointer(&u))

				printf("     UnwindOperation: 0x%x\n", unwindOperation)
				printf("     OperationInfo: 0x%x\n", operationInfo)
				printf("     FrameOffset: 0x%x\n", frameOffset)

				index++

			}

			break
		}
	}
}

// ////////////////////////////////////////////////////////////////////////////////////////
