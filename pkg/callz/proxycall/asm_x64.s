
TEXT ·pC(SB), $0-16
    NOP
    NOP
    NOP
    NOP

    //EGG-Start
    BYTE $0x52
    BYTE $0x33
    BYTE $0x64
    BYTE $0x54
    BYTE $0x31
    BYTE $0x64
    BYTE $0x65
    //EGG-End

    BYTE $0x90
    BYTE $0x90
    BYTE $0x90
    BYTE $0x90
    BYTE $0x90

// this code unpacks the args passed in  RDX->*(ProxyArgs), and fills the registers as needed for passing to WINAPI

// type ProxyArgs struct {
// 	Addr    uintptr  RBX+0 -> RAX
// 	ArgsLen uintptr  RBX+8 -> used in cmp to see how many args we have
// 	Args1   uintptr  RBX+16 -> RCX
// 	Args2   uintptr  RBX+24 -> RDX
// 	Args3   uintptr  RBX+32 -> R8
// 	Args4   uintptr  RBX+40 -> R9
// 	Args5   uintptr  RBX+48 -> R10 -> stack
// 	Args6   uintptr  RBX+56 -> R10 -> stack
// 	Args7   uintptr  RBX+64 -> R10 -> stack
// 	Args8   uintptr  RBX+72 -> R10 -> stack
// 	Args9   uintptr  RBX+80 -> R10 -> stack
// 	Args10  uintptr  RBX+88 -> R10 -> stack
// }

    // ----- mov    rbx,rdx  
     BYTE $0x48
     BYTE $0x89
     BYTE $0xd3
     // ----- xor    rdx,rdx    // zero RDX
     BYTE $0x48
     BYTE $0x31
     BYTE $0xd2
     // ----- mov    rax,QWORD PTR [rbx]    // mov ProxyArgs+0 to rax, address to api we want to call
     BYTE $0x48
     BYTE $0x8b
     BYTE $0x03
     // ----- cmp    QWORD PTR [rbx+0x8],0x0 // if num args = 0, jmp to end
     BYTE $0x48
     BYTE $0x83
     BYTE $0x7b
     BYTE $0x08
     BYTE $0x00
     // ----- jbe    0x155
     BYTE $0x0f
     BYTE $0x86
     BYTE $0x41
     BYTE $0x01
     BYTE $0x00
     BYTE $0x00
     // ----- mov    rcx,QWORD PTR [rbx+0x10]  // didnt jump, so mov next arg to RCX RBX+16 ->RCX
     BYTE $0x48
     BYTE $0x8b
     BYTE $0x4b
     BYTE $0x10
     // ----- cmp    QWORD PTR [rbx+0x8],0x1 // if num args = 1 jmp
     BYTE $0x48
     BYTE $0x83
     BYTE $0x7b
     BYTE $0x08
     BYTE $0x01
     // ----- jbe    0x155
     BYTE $0x0f
     BYTE $0x86
     BYTE $0x32
     BYTE $0x01
     BYTE $0x00
     BYTE $0x00
     // ----- mov    rdx,QWORD PTR [rbx+0x18] // didnt jump, so mov next arg to RDX
     BYTE $0x48
     BYTE $0x8b
     BYTE $0x53
     BYTE $0x18
     // ----- cmp    QWORD PTR [rbx+0x8],0x2 // if num args = 2 jmp
     BYTE $0x48
     BYTE $0x83
     BYTE $0x7b
     BYTE $0x08
     BYTE $0x02
     // ----- jbe    0x155
     BYTE $0x0f
     BYTE $0x86
     BYTE $0x23
     BYTE $0x01
     BYTE $0x00
     BYTE $0x00
     // ----- mov    r8,QWORD PTR [rbx+0x20] // mov next arg to R8
     BYTE $0x4c
     BYTE $0x8b
     BYTE $0x43
     BYTE $0x20
     // ----- cmp    QWORD PTR [rbx+0x8],0x3 // if len args = 3 jmp
     BYTE $0x48
     BYTE $0x83
     BYTE $0x7b
     BYTE $0x08
     BYTE $0x03
     // ----- jbe    0x155
     BYTE $0x0f
     BYTE $0x86
     BYTE $0x14
     BYTE $0x01
     BYTE $0x00
     BYTE $0x00
     // ----- mov    r9,QWORD PTR [rbx+0x28] // mov next arg to R9
     BYTE $0x4c
     BYTE $0x8b
     BYTE $0x4b
     BYTE $0x28
     // ----- cmp    QWORD PTR [rbx+0x8],0x4  // if len args = 4 jmp
     BYTE $0x48
     BYTE $0x83
     BYTE $0x7b
     BYTE $0x08
     BYTE $0x04
     // ----- jbe    0x155
     BYTE $0x0f
     BYTE $0x86
     BYTE $0x05
     BYTE $0x01
     BYTE $0x00
     BYTE $0x00
     // ----- mov    r10,QWORD PTR [rbx+0x30]    // mov arg5 to R10
     BYTE $0x4c
     BYTE $0x8b
     BYTE $0x53
     BYTE $0x30
     // ----- mov    QWORD PTR [rsp+0x28],r10    // put R10 on stack
     BYTE $0x4c
     BYTE $0x89
     BYTE $0x54
     BYTE $0x24
     BYTE $0x28
     // ----- xor    r10,r10 // zero R10
     BYTE $0x4d
     BYTE $0x31
     BYTE $0xd2
     // ----- cmp    QWORD PTR [rbx+0x8],0x5 // if num args = 5 jmp
     BYTE $0x48
     BYTE $0x83
     BYTE $0x7b
     BYTE $0x08
     BYTE $0x05
     // ----- jbe    0x155
     BYTE $0x0f
     BYTE $0x86
     BYTE $0xee
     BYTE $0x00
     BYTE $0x00
     BYTE $0x00
     // ----- mov    r10,QWORD PTR [rbx+0x38]  // mov arg6 R10
     BYTE $0x4c
     BYTE $0x8b
     BYTE $0x53
     BYTE $0x38
     // ----- mov    QWORD PTR [rsp+0x30],r10 // put arg6 on the stack
     BYTE $0x4c
     BYTE $0x89
     BYTE $0x54
     BYTE $0x24
     BYTE $0x30
     // ----- mov    r10,QWORD PTR [rbx+0x30]
     BYTE $0x4c
     BYTE $0x8b
     BYTE $0x53
     BYTE $0x30
     // ----- mov    QWORD PTR [rsp+0x28],r10
     BYTE $0x4c
     BYTE $0x89
     BYTE $0x54
     BYTE $0x24
     BYTE $0x28
     // ----- xor    r10,r10
     BYTE $0x4d
     BYTE $0x31
     BYTE $0xd2
     // ----- cmp    QWORD PTR [rbx+0x8],0x6
     BYTE $0x48
     BYTE $0x83
     BYTE $0x7b
     BYTE $0x08
     BYTE $0x06
     // ----- jbe    0x155
     BYTE $0x0f
     BYTE $0x86
     BYTE $0xce
     BYTE $0x00
     BYTE $0x00
     BYTE $0x00
     // ----- mov    r10,QWORD PTR [rbx+0x40]
     BYTE $0x4c
     BYTE $0x8b
     BYTE $0x53
     BYTE $0x40
     // ----- mov    QWORD PTR [rsp+0x38],r10
     BYTE $0x4c
     BYTE $0x89
     BYTE $0x54
     BYTE $0x24
     BYTE $0x38
     // ----- mov    r10,QWORD PTR [rbx+0x38]
     BYTE $0x4c
     BYTE $0x8b
     BYTE $0x53
     BYTE $0x38
     // ----- mov    QWORD PTR [rsp+0x30],r10
     BYTE $0x4c
     BYTE $0x89
     BYTE $0x54
     BYTE $0x24
     BYTE $0x30
     // ----- mov    r10,QWORD PTR [rbx+0x30]
     BYTE $0x4c
     BYTE $0x8b
     BYTE $0x53
     BYTE $0x30
     // ----- mov    QWORD PTR [rsp+0x28],r10
     BYTE $0x4c
     BYTE $0x89
     BYTE $0x54
     BYTE $0x24
     BYTE $0x28
     // ----- xor    r10,r10
     BYTE $0x4d
     BYTE $0x31
     BYTE $0xd2
     // ----- cmp    QWORD PTR [rbx+0x8],0x7
     BYTE $0x48
     BYTE $0x83
     BYTE $0x7b
     BYTE $0x08
     BYTE $0x07
     // ----- jbe    0x155
     BYTE $0x0f
     BYTE $0x86
     BYTE $0xa5
     BYTE $0x00
     BYTE $0x00
     BYTE $0x00
     // ----- mov    r10,QWORD PTR [rbx+0x48]
     BYTE $0x4c
     BYTE $0x8b
     BYTE $0x53
     BYTE $0x48
     // ----- mov    QWORD PTR [rsp+0x40],r10
     BYTE $0x4c
     BYTE $0x89
     BYTE $0x54
     BYTE $0x24
     BYTE $0x40
     // ----- mov    r10,QWORD PTR [rbx+0x40]
     BYTE $0x4c
     BYTE $0x8b
     BYTE $0x53
     BYTE $0x40
     // ----- mov    QWORD PTR [rsp+0x38],r10
     BYTE $0x4c
     BYTE $0x89
     BYTE $0x54
     BYTE $0x24
     BYTE $0x38
     // ----- mov    r10,QWORD PTR [rbx+0x38]
     BYTE $0x4c
     BYTE $0x8b
     BYTE $0x53
     BYTE $0x38
     // ----- mov    QWORD PTR [rsp+0x30],r10
     BYTE $0x4c
     BYTE $0x89
     BYTE $0x54
     BYTE $0x24
     BYTE $0x30
     // ----- mov    r10,QWORD PTR [rbx+0x30]
     BYTE $0x4c
     BYTE $0x8b
     BYTE $0x53
     BYTE $0x30
     // ----- mov    QWORD PTR [rsp+0x28],r10
     BYTE $0x4c
     BYTE $0x89
     BYTE $0x54
     BYTE $0x24
     BYTE $0x28
     // ----- xor    r10,r10
     BYTE $0x4d
     BYTE $0x31
     BYTE $0xd2
     // ----- cmp    QWORD PTR [rbx+0x8],0x8
     BYTE $0x48
     BYTE $0x83
     BYTE $0x7b
     BYTE $0x08
     BYTE $0x08
     // ----- jbe    0x155
     BYTE $0x76
     BYTE $0x77
     // ----- mov    r10,QWORD PTR [rbx+0x50]
     BYTE $0x4c
     BYTE $0x8b
     BYTE $0x53
     BYTE $0x50
     // ----- mov    QWORD PTR [rsp+0x48],r10
     BYTE $0x4c
     BYTE $0x89
     BYTE $0x54
     BYTE $0x24
     BYTE $0x48
     // ----- mov    r10,QWORD PTR [rbx+0x48]
     BYTE $0x4c
     BYTE $0x8b
     BYTE $0x53
     BYTE $0x48
     // ----- mov    QWORD PTR [rsp+0x40],r10
     BYTE $0x4c
     BYTE $0x89
     BYTE $0x54
     BYTE $0x24
     BYTE $0x40
     // ----- mov    r10,QWORD PTR [rbx+0x40]
     BYTE $0x4c
     BYTE $0x8b
     BYTE $0x53
     BYTE $0x40
     // ----- mov    QWORD PTR [rsp+0x38],r10
     BYTE $0x4c
     BYTE $0x89
     BYTE $0x54
     BYTE $0x24
     BYTE $0x38
     // ----- mov    r10,QWORD PTR [rbx+0x38]
     BYTE $0x4c
     BYTE $0x8b
     BYTE $0x53
     BYTE $0x38
     // ----- mov    QWORD PTR [rsp+0x30],r10
     BYTE $0x4c
     BYTE $0x89
     BYTE $0x54
     BYTE $0x24
     BYTE $0x30
     // ----- mov    r10,QWORD PTR [rbx+0x30]
     BYTE $0x4c
     BYTE $0x8b
     BYTE $0x53
     BYTE $0x30
     // ----- mov    QWORD PTR [rsp+0x28],r10
     BYTE $0x4c
     BYTE $0x89
     BYTE $0x54
     BYTE $0x24
     BYTE $0x28
     // ----- xor    r10,r10
     BYTE $0x4d
     BYTE $0x31
     BYTE $0xd2
     // ----- cmp    QWORD PTR [rbx+0x8],0x9
     BYTE $0x48
     BYTE $0x83
     BYTE $0x7b
     BYTE $0x08
     BYTE $0x09
     // ----- jbe    0x155
     BYTE $0x76
     BYTE $0x40
     // ----- mov    r10,QWORD PTR [rbx+0x58]
     BYTE $0x4c
     BYTE $0x8b
     BYTE $0x53
     BYTE $0x58
     // ----- mov    QWORD PTR [rsp+0x50],r10
     BYTE $0x4c
     BYTE $0x89
     BYTE $0x54
     BYTE $0x24
     BYTE $0x50
     // ----- mov    r10,QWORD PTR [rbx+0x50] ///////////////
     BYTE $0x4c
     BYTE $0x8b
     BYTE $0x53
     BYTE $0x50
     // ----- mov    QWORD PTR [rsp+0x48],r10
     BYTE $0x4c
     BYTE $0x89
     BYTE $0x54
     BYTE $0x24
     BYTE $0x48
     // ----- mov    r10,QWORD PTR [rbx+0x48]
     BYTE $0x4c
     BYTE $0x8b
     BYTE $0x53
     BYTE $0x48
     // ----- mov    QWORD PTR [rsp+0x40],r10
     BYTE $0x4c
     BYTE $0x89
     BYTE $0x54
     BYTE $0x24
     BYTE $0x40
     // ----- mov    r10,QWORD PTR [rbx+0x40]
     BYTE $0x4c
     BYTE $0x8b
     BYTE $0x53
     BYTE $0x40
     // ----- mov    QWORD PTR [rsp+0x38],r10
     BYTE $0x4c
     BYTE $0x89
     BYTE $0x54
     BYTE $0x24
     BYTE $0x38
     // ----- mov    r10,QWORD PTR [rbx+0x38]
     BYTE $0x4c
     BYTE $0x8b
     BYTE $0x53
     BYTE $0x38
     // ----- mov    QWORD PTR [rsp+0x30],r10
     BYTE $0x4c
     BYTE $0x89
     BYTE $0x54
     BYTE $0x24
     BYTE $0x30
     // ----- mov    r10,QWORD PTR [rbx+0x30]
     BYTE $0x4c
     BYTE $0x8b
     BYTE $0x53
     BYTE $0x30
     // ----- mov    QWORD PTR [rsp+0x28],r10
     BYTE $0x4c
     BYTE $0x89
     BYTE $0x54
     BYTE $0x24
     BYTE $0x28
     // ----- xor    r10,r10
     BYTE $0x4d
     BYTE $0x31
     BYTE $0xd2
     // ----- cmp    QWORD PTR [rbx+0x8],0xa
     BYTE $0x48
     BYTE $0x83
     BYTE $0x7b
     BYTE $0x08
     BYTE $0x0a
     // ----- jbe    0x155
     BYTE $0x76
     BYTE $0x00
     // ----- jmp    rax
     BYTE $0xff
     BYTE $0xe0
    //Func-End

    NOP
    NOP
    NOP
    NOP



    