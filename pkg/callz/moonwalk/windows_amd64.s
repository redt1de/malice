#include "textflag.h"
#include "../asmstuff.h"

/*
NOTE: 
    To change the _OBF macro see ../asmstuff.h
    this file also contains other util macros and defines.
*/


// Offsets:
#define RtlUserThreadStartAddress 0     // 0x0
#define RtlUserThreadStartFrameSize 8   // 0x8
#define BaseThreadInitThunkAddress 16   // 0x10
#define BaseThreadInitThunkFrameSize 24 // 0x18
#define FirstFrameFunctionPointer 32    // 0x20
#define FirstFrameSize 40               // 0x28
#define FirstFrameRandomOffset 48       // 0x30
#define SecondFrameFunctionPointer 56   // 0x38
#define SecondFrameSize 64              // 0x40
#define SecondFrameRandomOffset 72      // 0x48
#define JmpRbxGadget 80                 // 0x50
#define JmpRbxGadgetFrameSize 88        // 0x58
#define JmpRbxGadgetRef 96              // 0x60
#define AddRspXGadget 104               // 0x68
#define AddRspXGadgetFrameSize 112      // 0x70
#define StackOffsetWhereRbpIsPushed 120 // 0x78
#define Ssn 128                         // 0x80
#define SpoofFunctionPointer 136        // 0x88
#define OgRet 144                       // 0x90
#define OgRSP 152                       // 0x98
#define OgRBP 160                       // 0xa0


// func doTest(strct *SPOOFER, argh ...uintptr) uint32
TEXT ·doCall(SB),NOSPLIT, $0-24 // (*struct)8 + (variadic arg base(8) + variadic arg len(8))16 = 24
    CALL runtime·morestack(SB)
    MOVQ BX,BX
    _OBF
    MOVQ    strct+0(FP), R11         // put address of struct in R11
    MOVQ    argh_base+8(FP),SI       // put variadic pointer into SI
    MOVQ    argh_len+16(FP),CX       // put variadic size into CX, CX = num args   
    MOVQ    0x30(GS), DI             // Get TEB
    MOVL    $0, 0x68(DI)             // TEB.SetLastError = 0        
    MOVQ    0(SP), R15                // store original return address in R15
    MOVQ    R15, OgRet(R11)           // backup OG return address in struct.ReturnAddress
    MOVQ    SP, OgRSP(R11)            // backup OG RSP in struct
    MOVQ    BP, OgRBP(R11)            // backup OG RBP in struct
    // ------------------------------------------------------------------------------
    // Creating a stack reference to the JMP RBX gadget
    // ------------------------------------------------------------------------------
    _OBF
    MOVQ    JmpRbxGadget(R11),BX 
    MOVQ    BX,0x18(SP)
    MOVQ    SP,BX
    ADDQ    $0x18,BX
    MOVQ    BX,JmpRbxGadgetRef(R11)
    // ------------------------------------------------------------------------------
    // Prolog
    // RBP -> Keeps track of original Stack
  	// RSP -> Desync Stack for Unwinding Info
    // ------------------------------------------------------------------------------------
    // Note: Everything between RSP and RBP is our new stack frame for unwinding 
    // ------------------------------------------------------------------------------
    _OBF
    MOVQ    SP,BP
    // ------------------------------------------------------------------------------
    // Creating stack pointer to Restore PROC
    // ------------------------------------------------------------------------------
    _OBF
    LEAQ    ·restore(SB),AX        // get address of restore() 
    PUSHQ    AX                    // push it on the stack, will be ref'd by stack pointer
    LEAQ    0(SP),BX               // Now RBX contains the stack pointer to Restore PROC  -> Will be called by the JMP [RBX] gadget
    // ------------------------------------------------------------------------------
    // Starting Frames Tampering
    // ------------------------------------------------------------------------------
    // First Frame (Fake origin)
    // ------------------------------------------------------------------------------
    _OBF
    PUSHQ   FirstFrameFunctionPointer(R11)  // \
    //MOVQ    FirstFrameRandomOffset(R11),AX  //  > this just adds the random offset to the addr, this can be done in go code 
    //ADDQ    AX,0(SP)                        // /  


    MOVQ    OgRet(R11),AX
    SUBQ    FirstFrameSize(R11),AX
    SUBQ    SecondFrameSize(R11),SP
    MOVQ    StackOffsetWhereRbpIsPushed(R11),R10 // this is empty
    MOVQ    AX, (SP)(R10*1)                                    // mov     [rsp+r10], rax
    // ------------------------------------------------------------------------------
    // ROP Frames
    // ------------------------------------------------------------------------------
    _OBF
    PUSHQ    SecondFrameFunctionPointer(R11) // \
    // MOVQ    SecondFrameRandomOffset(R11),AX  //  >  this just adds the random offset to the addr, this can be done in go code 
    // ADDQ    AX,0(SP)                         // /  
    // ------------------------------------------------------------------------------
    // 1. JMP [RBX] Gadget
    // ------------------------------------------------------------------------------
    _OBF
    MOVQ    JmpRbxGadgetFrameSize(R11),AX
    SUBQ    AX,SP
    MOVQ BX,BX
    PUSHQ   JmpRbxGadgetRef(DX) //////////////////// <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<< unexpected SPWRITE when darklib is also used
    

    MOVQ    AddRspXGadgetFrameSize(R11),AX
    SUBQ    AX,SP
    MOVQ    JmpRbxGadget(R11),R10
    MOVQ    R10,0x38(SP)
    // ------------------------------------------------------------------------------
    // 2. Stack PIVOT (To restore original Control Flow Stack)
    // ------------------------------------------------------------------------------
    _OBF
    PUSHQ    AddRspXGadget(R11)
    MOVQ    AddRspXGadgetFrameSize(R11),AX
    MOVQ    AX,0x28(BP)
    // ------------------------------------------------------------------------------
    // Set the pointer to the function to call in RAX
    // ------------------------------------------------------------------------------
    _OBF
    // MOVQ    SpoofFunctionPointer(R11),AX
    // ------------------------------------------------------------------------------
    // Setup call params
    // ------------------------------------------------------------------------------
    CMPL    CX, $0              // CX <= 0, no parameters, special case just call
    JLE     jumpcall
    CMPL    CX, $4              // CX <= 4, Fast version, do not store args on the stack.
    JLE	    loadregs
    //    CMPL    CX, $maxargs        // Check we have enough room for args. CX <= 16
    //    JLE	    2(PC)               // jump over the int3
    //    INT	    $3			        // else not enough room -> crash
    // Copy args to the stack.
    MOVQ    SP, DI
    ADDQ    $8, DI
    CLD
    REP; MOVSQ
    MOVQ    SP, SI
    ADDQ    $8, SI

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
    // ------------------------------------------------------------------------------
    // set up syscall stub
    // ------------------------------------------------------------------------------
    MOVQ  CX,R10
    MOVQ Ssn(R11),AX
    // ------------------------------------------------------------------------------
    // Execute
    // ------------------------------------------------------------------------------
    JMP SpoofFunctionPointer(R11)

    // this code should never be reached, just here to balance the push/pop so compiler doesnt complain
    POPQ R14
    POPQ R14
    POPQ R14
    POPQ R14   
    POPQ R14 
    //RET

// func restore() uint32
TEXT ·restore(SB),NOSPLIT, $0-8 // we do a "LEAQ ·CleanUp(SB),BX" and the JmpRbxGadget will land here so we can cleanup, and put ret vals where they need to go.
    MOVQ  BP,SP
    MOVL	AX, errcode+0x20(FP) // put return value into errcode
    RET

