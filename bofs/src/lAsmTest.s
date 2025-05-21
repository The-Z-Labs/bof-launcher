.text

msg:
.ascii "Hello from asm BOF on Linux! eax is %d\12\0"

.global go
go:
    push %rbp
    mov $12345, %eax

    mov $0, %edi
    mov $msg, %rsi
    mov %eax, %edx
    call BeaconPrintf

    xor %eax, %eax
    pop %rbp
    ret
