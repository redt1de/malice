#include "textflag.h"

//func GetPEB() uintptr
TEXT ·GetPEB(SB), $0-8
     MOVQ 	0x60(GS), AX
     MOVQ	AX, ret+0(FP)
     RET

//func GetModByIndex(i int) (start uintptr, size uintptr)
TEXT ·getModByIndex(SB), $0-32
	//All operations push values into AX
	//PEB
	MOVQ 0x60(GS), AX
	//PEB->LDR
	MOVQ 0x18(AX),AX

	//LDR->InMemoryOrderModuleList
	MOVQ 0x20(AX),AX

	//loop things
	XORQ R10,R10
startloop:
	CMPQ R10,i+0(FP)
	JE endloop
	//Flink (get next element)
	MOVQ (AX),AX
	INCQ R10
	JMP startloop
endloop:
	//Flink - 0x10 -> _LDR_DATA_TABLE_ENTRY
	//_LDR_DATA_TABLE_ENTRY->DllBase (offset 0x30)
	MOVQ 0x20(AX),CX
	MOVQ CX, start+8(FP)
	
	MOVQ 0x30(AX),CX
	MOVQ CX, size+16(FP)
	MOVQ AX,CX
	ADDQ $0x38,CX
	MOVQ CX, modulepath+24(FP)
	//SYSCALL
	RET 

//func GetModPtrByIndex(i int) *LdrDataTableEntry
TEXT ·GetModPtrByIndex(SB), $0-16
	//All operations push values into AX
	//PEB
	MOVQ 0x60(GS), AX
	//PEB->LDR
	MOVQ 0x18(AX),AX

	//LDR->InMemoryOrderModuleList
	MOVQ 0x20(AX),AX

	//loop things
	XORQ R10,R10
startloop:
	CMPQ R10,i+0(FP)
	JE endloop
	//Flink (get next element)
	MOVQ (AX),AX
	INCQ R10
	JMP startloop
endloop:
	MOVQ AX,CX
	SUBQ $0x10,CX
	MOVQ CX, ret+8(FP)
	
	RET 


    ///////////////////////////////////////


// func Rva2Va(moduleBase uintptr, rva uint32) uintptr
TEXT ·Rva2Va(SB),NOSPLIT,$0-16
    MOVQ moduleBase+0(FP), AX
    XORQ DI, DI

    MOVL rva+8(FP), DI
    ADDQ DI, AX

    MOVQ AX, ret+16(FP)
    RET


// func GetExportsDirAddr (moduleBase uintptr) uintptr
TEXT ·GetExportsDirAddr(SB),NOSPLIT,$0-8
    MOVQ moduleBase+0(FP), AX

    XORQ R15, R15
    XORQ R14, R14

    // AX = IMAGE_DOS_HEADER->e_lfanew offset
    MOVB 0x3C(AX), R15

    // R15 = ntdll base + R15
    ADDQ AX, R15

    // R15 = R15 + OptionalHeader + DataDirectory offset
    ADDQ $0x88, R15

    // AX = ntdll base + IMAGE_DATA_DIRECTORY.VirtualAddress
    ADDL (R15), R14
    ADDQ R14, AX

    MOVQ AX, ret+8(FP)
    RET


// func GetNumberOfNames(exportsBase uintptr) uint32
TEXT ·GetNumberOfNames(SB),NOSPLIT,$0-8
    MOVQ exportsBase+0(FP), AX

    XORQ R15, R15

    // R15 = exportsBase + IMAGE_EXPORT_DIRECTORY.NumberOfNames
    MOVL 0x18(AX), R15

    MOVL R15, ret+8(FP)
    RET


// func GetAddressOfFunctions(moduleBase,exportsBase uintptr) uintptr
TEXT ·GetAddressOfFunctions(SB),NOSPLIT,$0-16
    MOVQ moduleBase+0(FP), AX
    MOVQ exportsBase+8(FP), R8

    XORQ SI, SI

    // R15 = exportsBase + IMAGE_EXPORT_DIRECTORY.AddressOfFunctions
    MOVL 0x1c(R8), SI

    // AX = exportsBase + AddressOfFunctions offset
    ADDQ SI, AX

    MOVQ AX, ret+16(FP)
    RET


// func GetAddressOfNames(moduleBase,exportsBase uintptr) uintptr
TEXT ·GetAddressOfNames(SB),NOSPLIT,$0-16
    MOVQ moduleBase+0(FP), AX
    MOVQ exportsBase+8(FP), R8

    XORQ SI, SI

    // SI = exportsBase + IMAGE_EXPORT_DIRECTORY.AddressOfNames
    MOVL 0x20(R8), SI

    // AX = exportsBase + AddressOfNames offset
    ADDQ SI, AX

    MOVQ AX, ret+16(FP)
    RET


// func GetAddressOfNameOrdinals(moduleBase, exportsBase uintptr) uintptr
TEXT ·GetAddressOfNameOrdinals(SB),NOSPLIT,$0-16
    MOVQ moduleBase+0(FP), AX
    MOVQ exportsBase+8(FP), R8

    XORQ SI, SI

    // SI = exportsBase + IMAGE_EXPORT_DIRECTORY.AddressOfNameOrdinals
    MOVL 0x24(R8), SI

    // AX = exportsBase + AddressOfNames offset
    ADDQ SI, AX

    MOVQ AX, ret+16(FP)
    RET
