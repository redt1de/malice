/*
util macros and defines used by various assembly files
*/

#define maxargs 16

// Macros to circumvent Golangs stupid PUSH/POP balance requirements. pfft, safety.
#define _PUSH(val) \
	SUBQ $8,SP     \
    MOVQ val,0(SP)

#define _POP(r)	 \
	MOVQ 0(SP),r \
    ADDQ $8,SP

#define _NOP BYTE $0x90


// macro for simple junk code obfuscation. change this if signatured
// x64dbg: findasm  "mov rax,rax";bp ref.addr(0)
#define _OBF          \
    BYTE   $0x90      \
    MOVQ   AX,AX      \
    BYTE   $0x90      \
//     ADDQ   $0x36,AX \
//     CMPL   AX,$0    \
//     JE    bounce    \
// bounce:             \
//     MOVQ   BX,BX    \
//     SUBQ   $0x36,AX \