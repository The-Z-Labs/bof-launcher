format ELF64

section '.text' executable

public go
go:
    xor eax, eax

section '.data' writeable

;msg db "Elves are coming!",0xA,0
