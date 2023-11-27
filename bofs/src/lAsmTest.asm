format ELF64

public go

section '.text' executable

align 8
go:
    xor eax, eax
    ret

section '.data' writeable

;msg db "Elves are coming!",0xA,0
