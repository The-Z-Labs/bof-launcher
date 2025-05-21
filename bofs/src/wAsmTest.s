.text

.global go
go:
    sub $40, %rsp
    mov $12345, %eax

    mov $0, %ecx
    lea msg(%rip), %rdx
    mov %eax, %r8d
    call BeaconPrintf

    add $40, %rsp
    xor %eax, %eax
    ret

.data

msg:
.ascii "Hello from asm BOF on Windows! eax is %d\12\0"
