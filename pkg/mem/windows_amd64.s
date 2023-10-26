#include "textflag.h"

// func ReadDword(start uintptr, offset uint32) uint32
TEXT ·ReadDword(SB),NOSPLIT,$0-16
    MOVQ start+0(FP), AX
    MOVL offset+8(FP), R8

    XORQ DI, DI
    ADDQ R8, AX
    MOVL (AX), DI

    MOVL DI, ret+16(FP)
    RET


// func ReadWordAtOffset(start uintptr, offset uint32) uint16
TEXT ·ReadWord(SB),NOSPLIT,$0-16
    MOVQ start+0(FP), AX
    MOVL offset+8(FP), R8

    XORQ DI, DI
    ADDQ R8, AX
    MOVW (AX), DI

    MOVW DI, ret+16(FP)
    RET


// func ReadByteAtOffset(start uintptr, offset uint32) uint8
TEXT ·ReadByte(SB),NOSPLIT,$0-16
    MOVQ start+0(FP), AX
    MOVL offset+8(FP), R8

    XORQ DI, DI
    ADDQ R8, AX
    MOVB (AX), DI

    MOVB DI, ret+16(FP)
    RET



