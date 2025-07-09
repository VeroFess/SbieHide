PUBLIC _invoke_systemcall_internal_asm

.code
_invoke_systemcall_internal_asm PROC
    mov r10, rcx
    pop rcx
    pop rax
    mov QWORD PTR [rsp], rcx
    mov eax, [rsp + 24]
    syscall
    sub rsp, 8
    jmp QWORD PTR [rsp + 8]
_invoke_systemcall_internal_asm ENDP
END