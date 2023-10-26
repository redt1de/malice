package main

import (
	"fmt"
	"reflect"
)

const EXCEPTION_MAXIMUM_PARAMETERS = 15

type _EXCEPTION_POINTERS struct {
	ExceptionRecord EXCEPTION_RECORD
	ContextRecord   CONTEXT
}
type EXCEPTION_RECORD struct {
	ExceptionCode        uint32
	ExceptionFlags       uint32
	ExceptionRecord      *EXCEPTION_RECORD
	ExceptionAddress     uintptr
	NumberParameters     uint32
	ExceptionInformation [EXCEPTION_MAXIMUM_PARAMETERS]uintptr
}
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

func printf(a string, b ...any) { fmt.Printf(a, b...) }
func main() {
	var o int
	printAll(reflect.ValueOf(CONTEXT{}), &o, "")
}

func printAll(v reflect.Value, offset *int, ident string) {
	s := v
	typeOfT := s.Type()
	for i := 0; i < s.NumField(); i++ {
		f := s.Field(i)

		if f.Kind().String() == "struct" {
			x1 := reflect.ValueOf(f.Interface())
			fmt.Printf("// struct %s (%d bytes)\n", f.Type().String(), f.Type().Size())
			printAll(x1, offset, ident+"    ")
		} else {
			// fmt.Printf("%s%s %s = %d\n", ident, typeOfT.Field(i).Name, f.Type(), f.Type().Size())
			printf("// %s%s  offset: 0x%x (%d)\n", ident, typeOfT.Field(i).Name, *offset, *offset)
			*offset += int(f.Type().Size())
		}
	}
}
