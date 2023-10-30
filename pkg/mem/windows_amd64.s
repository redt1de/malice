#include "textflag.h"

// func ReadQwordAtOffset(start uintptr, offset uint32) uint16
TEXT ·ReadQwordAtOffset(SB),NOSPLIT,$0-16
    MOVQ start+0(FP), AX
    MOVL offset+8(FP), R8

    XORQ DI, DI
    ADDQ R8, AX
    MOVQ (AX), DI

    MOVW DI, ret+16(FP)
    RET

// func ReadDword(start uintptr, offset uint32) uint32
TEXT ·ReadDwordAtOffset(SB),NOSPLIT,$0-16
    MOVQ start+0(FP), AX
    MOVL offset+8(FP), R8

    XORQ DI, DI
    ADDQ R8, AX
    MOVL (AX), DI

    MOVL DI, ret+16(FP)
    RET


// func ReadWordAtOffset(start uintptr, offset uint32) uint16
TEXT ·ReadWordAtOffset(SB),NOSPLIT,$0-16
    MOVQ start+0(FP), AX
    MOVL offset+8(FP), R8

    XORQ DI, DI
    ADDQ R8, AX
    MOVW (AX), DI

    MOVW DI, ret+16(FP)
    RET


// func ReadByteAtOffset(start uintptr, offset uint32) uint8
TEXT ·ReadByteAtOffset(SB),NOSPLIT,$0-16
    MOVQ start+0(FP), AX
    MOVL offset+8(FP), R8

    XORQ DI, DI
    ADDQ R8, AX
    MOVB (AX), DI

    MOVB DI, ret+16(FP)
    RET


// func ReadQword(addr uintptr) uintptr
TEXT ·ReadQword(SB),NOSPLIT,$0-16
    MOVQ addr+0(FP), AX
    XORQ DI, DI
    MOVQ (AX), DI
    MOVQ DI, ret+8(FP)
    RET

// func ReadWord(addr uintptr) uint16
TEXT ·ReadWord(SB),NOSPLIT,$0-16
    MOVQ addr+0(FP), AX
    XORQ DI, DI
    MOVW (AX), DI
    MOVW DI, ret+8(FP)
    RET

// func ReadDword(addr uintptr) uint32
TEXT ·ReadDword(SB),NOSPLIT,$0-16
    MOVQ addr+0(FP), AX
    XORQ DI, DI
    MOVL (AX), DI
    MOVL DI, ret+8(FP)
    RET

// func ReadByte(addr uintptr) uint8
TEXT ·ReadByte(SB),NOSPLIT,$0-16
    MOVQ addr+0(FP), AX
    XORQ DI, DI
    MOVB (AX), DI
    MOVB DI, ret+8(FP)
    RET

// func Jmp(addr uintptr)
TEXT ·Jmp(SB),NOSPLIT,$8
    MOVQ addr+0(FP), R12
    JMP R12
    //RET

