#include "textflag.h"
/*
// getTrampoline check if the export has a clean syscall;ret gadget within its 32 bytes.
// Returns the trampoline address if clean, nullptr if not.

// func getTrampoline(stubAddr uintptr) uintptr
TEXT ·getTrampoline(SB),NOSPLIT,$0-8
    MOVQ stubAddr+0(FP), AX
    MOVQ AX, R10

    // stub_length-gadget_length bytes of the stub (32-3)
    ADDQ $29, AX

loop:
    XORQ DI, DI

    // check for 0x0f05c3 byte sequence
    MOVB $0x0f, DI
    CMPB DI, 0(AX)
    JNE nope

    MOVB $0x05, DI
    CMPB DI, 1(AX)
    JNE nope

    MOVB $0xc3, DI
    CMPB DI, 2(AX)
    JNE nope

    // if we are here, we found a clean syscall;ret gadget
    MOVQ AX, ret+8(FP)
    RET

nope:
    // if AX is equal to R10, we have reached the start of the stub
    // which means we could not find a clean syscall;ret gadget
    CMPQ AX, R10
    JE not_found

    DECQ AX
    JMP loop

not_found:
    // returning nullptr
    XORQ AX, AX
    MOVQ AX, ret+8(FP)
    RET
*/


// syscalls implementation is a mix of:
// - https://golang.org/src/runtime/sys_windows_amd64.s
// - https://github.com/C-Sto/BananaPhone/blob/master/pkg/BananaPhone/asm_x64.s#L96
// with custom modifications to support indirect syscall execution 
// via a trampoline (syscall;ret instruction) in ntdll.dll

// return type is a 32-bit datatype, as per NTSTATUS definition (https://msdn.microsoft.com/en-us/library/cc704588.aspx)
// but we use an unsigned integer instead of LONG (int32), since working with uint types is easier in Go

#define maxargs 16

// func doCall(ssn uint16, syscall_ret_tramp uintptr, argh ...uintptr) uint32
TEXT ·doCall(SB),NOSPLIT, $0-40
    XORQ    AX, AX              // AX = 0 
    MOVW    ssn+0(FP), AX       // put ssn into AX
    MOVQ    syscall_ret_tramp+8(FP), R11 // put syscall;ret gadget address into R11
    PUSHQ   CX
    MOVQ    argh_base+16(FP),SI // put variadic pointer into SI
    MOVQ    argh_len+24(FP),CX  // put variadic size into CX, CX = num args
    MOVQ    0x30(GS), DI        // Get TEB
    MOVL    $0, 0x68(DI)        // TEB.SetLastError = 0
    SUBQ    $(maxargs*8), SP	// make room for args
    
    CMPL    CX, $0              // CX <= 0, no parameters, special case just call
    JLE     jumpcall
    CMPL    CX, $4              // CX <= 4, Fast version, do not store args on the stack.
    JLE	    loadregs
    CMPL    CX, $maxargs        // Check we have enough room for args. CX <= 16
    JLE	    2(PC)               // jump over the int3
    INT	    $3			        // else not enough room -> crash
    // Copy args to the stack.
    MOVQ    SP, DI
    CLD
    REP; MOVSQ
    MOVQ    SP, SI
	
loadregs:
    // Load first 4 args into correspondent registers.
    MOVQ	0(SI), CX
    MOVQ	8(SI), DX
    MOVQ	16(SI), R8
    MOVQ	24(SI), R9
    // Floating point arguments are passed in the XMM registers
    // Set them here in case any of the arguments are floating point values. 
    // For details see: https://msdn.microsoft.com/en-us/library/zthk2dkh.aspx
    MOVQ	CX, X0
    MOVQ	DX, X1
    MOVQ	R8, X2
    MOVQ	R9, X3
	
jumpcall:
    MOVQ    CX, R10 // save CX in R10
    CALL    R11   // jump to syscall;ret gadget address instead of direct syscall
    ADDQ	$((maxargs)*8), SP // restore stack pointer
    POPQ	CX  // restore CX
    MOVL	AX, errcode+40(FP) // put return value into errcode
    RET

// ssn = 0(FP)
// syscall_ret_tramp 8(FP)
// add_rsp_68_ret_tramp 16(FP)
// argh_base 24(FP)
// argh_len 32(FP)


// Janky indirect syscall with a spoofed kernel32 return address. uses "add rsp, 78; ret" gadget found in kernel32
// orignal indirect syscall code is from the ascheron project.
// func doFancyCall(ssn uint16, syscall_ret_tramp uintptr, add_rsp_78_ret_tramp uintptr, argh ...uintptr) uint32
TEXT ·doFancyCall(SB),NOSPLIT, $0-40
    XORQ    R11, R11            // R11 = 0
    XORQ    R12,R12             // R12 = 0
    XORQ    R14,R14             // R14 = 0
    XORQ    R15,R15             // R15 = 0
    MOVQ    0(SP), R13          // put return address into R14
    //PUSHQ   CX  // need to change this to a SUBQ 8, SP; MOVQ CX, 0(SP) so go doesnt bitch about unbalanced PUSH/POP
    XORQ    AX, AX              // AX = 0 
    MOVW    ssn+0(FP), AX       // put ssn into AX
    MOVQ    syscall_ret_tramp+8(FP), R11 // put syscall;ret gadget address into R11
    MOVQ    add_rsp_78_ret_tramp+16(FP), R12 // put add rsp, 68; ret gadget address into R12
    MOVQ    argh_base+24(FP),SI // put variadic pointer into SI
    MOVQ    argh_len+32(FP),CX  // put variadic size into CX, CX = num args
    //////////////////////////////////////////////////////////////// this is stupid
    SUBQ    $0x80, SP	         // make room for fake stack
    LEAQ   ·cleanup(SB), R15     // store address of cleanup() in R15
    MOVQ   R15, -8(SP)           // set the return address of the fake stack to cleanup()
    MOVQ   $0x0, 0(SP)           // PUSH 0 to stop unwinding after return
    ////////////////////////////////////////////////////////////
    MOVQ    0x30(GS), DI        // Get TEB
    MOVL    $0, 0x68(DI)        // TEB.SetLastError = 0
    SUBQ    $(maxargs*8), SP	// make room for args
    CMPL    CX, $0              // CX <= 0, no parameters, special case just call
    JLE     jumpcall
    CMPL    CX, $4              // CX <= 4, Fast version, do not store args on the stack.
    JLE	    loadregs
    CMPL    CX, $maxargs        // Check we have enough room for args. CX <= 16
    JLE	    2(PC)               // jump over the int3
    INT	    $3			        // else not enough room -> crash
    // Copy args to the stack.
    MOVQ    SP, DI
    CLD
    REP; MOVSQ
    MOVQ    SP, SI
	
loadregs:
    // Load first 4 args into correspondent registers, fill XMM registers in case there are floating point args
    MOVQ	0(SI), CX
    MOVQ	8(SI), DX
    MOVQ	16(SI), R8
    MOVQ	24(SI), R9
    MOVQ	CX, X0
    MOVQ	DX, X1
    MOVQ	R8, X2
    MOVQ	R9, X3
	
jumpcall:
    MOVQ    CX, R10               // save CX in R10
    SUBQ    $8, SP                // make room for fake return address
    MOVQ    R12, 0(SP)            // push address to "add rsp, 78; ret" gadget
    JMP    R11                    // jump to "syscall;ret" gadget

TEXT ·cleanup(SB),NOSPLIT, $0-16
    ADDQ	$((maxargs)*8), SP // restore stack pointer
    //POPQ	CX  // need to change this to a  0(SP),CX;ADDQ 8, SP so go doesnt bitch about unbalanced PUSH/POP
    MOVL	AX, errcode+40(FP) // put return value into errcode
    RET
