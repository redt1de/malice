#include "textflag.h"

TEXT ·getAddr(SB),NOSPLIT,$16
    XORQ AX,AX
    LEAQ ·MyBaseThreadInitThunk(SB),AX
    MOVQ AX,r+0(FP)
    RET

// SAVE: RBX, RBP, RDI, RSI, RSP, R12, R13, R14, R15 
// func MyBaseThreadInitThunk(LdrReserved uint32, lpStartAddress uintptr, lpParameter uintptr)
TEXT ·MyBaseThreadInitThunk(SB),NOSPLIT,$0
    //MOVQ AX,AX
    ADDQ $1,·Hit(SB)
    //////////////////////////
    //MOVQ AX,AX
    //LEAQ ·Blah(SB),R15
    //CALL R15
    //MOVQ AX,AX
    //////////////////////////
    MOVQ ·RealBaseThreadInitThunkAddr(SB),R15
    JMP R15
    RET


