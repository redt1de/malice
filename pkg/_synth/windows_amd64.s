#include "textflag.h"
#define maxargs 16

// func doTest(strct *Nasty, argh ...uintptr) uint32
TEXT ·doTest(SB), $0-24 // (*struct)8 + (variadic arg base(8) + variadic arg len(8))16 = 24
    XORQ    R15,R15            // just here for finding the start of the function in x64dg. REMOVE ME
    XORQ    R14,R14
    RET
