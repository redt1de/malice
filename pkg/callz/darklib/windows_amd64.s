//func GetPEB() uintptr
TEXT ·GetPEB(SB), $0-8
     MOVQ 	0x60(GS), AX
     MOVQ	AX, ret+0(FP)
     RET
/*
//func GetNtdll() uintptr
TEXT ·GetNtdll(SB), $0-16
	//All operations push values into AX
	//PEB
	MOVQ 0x60(GS), AX
	//PEB->LDR
	MOVQ 0x18(AX),AX

	//LDR->InMemoryOrderModuleList
	MOVQ 0x20(AX),AX

	//Flink (get next element)
	MOVQ (AX),AX

	//Flink - 0x10 -> _LDR_DATA_TABLE_ENTRY
	//_LDR_DATA_TABLE_ENTRY->DllBase (offset 0x30)
	MOVQ 0x20(AX),CX
	MOVQ CX, start+0(FP)
	
	MOVQ 0x30(AX),CX
	MOVQ CX, size+8(FP)
		
	RET 
*/
//func getModByIndex(i int) (start uintptr, size uintptr)
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


    