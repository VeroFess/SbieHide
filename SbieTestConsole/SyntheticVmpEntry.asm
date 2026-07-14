option casemap:none

EXTERN wmainCRTStartup:PROC

.code

PUBLIC SyntheticVmpEntryPoint
SyntheticVmpEntryPoint PROC
    db 16 dup (090h)
    jmp wmainCRTStartup
SyntheticVmpEntryPoint ENDP

END
