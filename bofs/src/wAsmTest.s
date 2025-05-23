.text

.global go
go:
    sub $40, %rsp
    mov $12345, %eax    ; Value to print

    ; void BeaconPrintf(int type, char * fmt, ...)
    mov $0, %ecx        ; arg 1: `type`
    lea msg(%rip), %rdx ; arg 2: `fmt`
    mov %eax, %r8d      ; arg 3: `...`
    call BeaconPrintf

    add $40, %rsp
    xor %eax, %eax      ; BOF exit code
    ret

.data

msg:
.ascii "Hello from asm BOF on Windows! eax is %d\12\0"
