option casemap:none

EXTERN PrepareLdrLoadDllBootstrap:PROC
EXTERN LDR_LOAD_DLL_BOOTSTRAP_CHAIN:QWORD

.code

PUBLIC LdrLoadDllBootstrapDetours
LdrLoadDllBootstrapDetours PROC FRAME
    sub rsp, 0C8h
    .allocstack 0C8h
    .endprolog

    mov qword ptr [rsp + 020h], rax
    mov qword ptr [rsp + 028h], rcx
    mov qword ptr [rsp + 030h], rdx
    mov qword ptr [rsp + 038h], r8
    mov qword ptr [rsp + 040h], r9
    mov qword ptr [rsp + 048h], r10
    mov qword ptr [rsp + 050h], r11
    movdqu xmmword ptr [rsp + 060h], xmm0
    movdqu xmmword ptr [rsp + 070h], xmm1
    movdqu xmmword ptr [rsp + 080h], xmm2
    movdqu xmmword ptr [rsp + 090h], xmm3
    movdqu xmmword ptr [rsp + 0A0h], xmm4
    movdqu xmmword ptr [rsp + 0B0h], xmm5

    call PrepareLdrLoadDllBootstrap

    movdqu xmm0, xmmword ptr [rsp + 060h]
    movdqu xmm1, xmmword ptr [rsp + 070h]
    movdqu xmm2, xmmword ptr [rsp + 080h]
    movdqu xmm3, xmmword ptr [rsp + 090h]
    movdqu xmm4, xmmword ptr [rsp + 0A0h]
    movdqu xmm5, xmmword ptr [rsp + 0B0h]
    mov r11, qword ptr [rsp + 050h]
    mov r10, qword ptr [rsp + 048h]
    mov r9, qword ptr [rsp + 040h]
    mov r8, qword ptr [rsp + 038h]
    mov rdx, qword ptr [rsp + 030h]
    mov rcx, qword ptr [rsp + 028h]
    mov rax, qword ptr [rsp + 020h]
    add rsp, 0C8h

    jmp qword ptr [LDR_LOAD_DLL_BOOTSTRAP_CHAIN]
LdrLoadDllBootstrapDetours ENDP

END
