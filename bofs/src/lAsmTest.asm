format ELF64

public go
extrn 'BeaconPrintf' as BeaconPrintf:qword

section '.text' executable

align 8
go:
    push rbp
    mov eax, 12345

    mov edi, 0
    lea rsi, [msg]
    mov edx, eax
    call BeaconPrintf

    xor eax, eax
    pop rbp
    ret

align 8
msg db "Hello from asm BOF on Linux! eax is %d", 0xa, 0
