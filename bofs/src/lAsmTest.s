.text

.global go
go:
    sub $40, %rsp
    mov $12345, %eax    ; Value to print

    ; void BeaconPrintf(int type, char * fmt, ...)
    mov $0, %edi        ; arg 1: `type`
    lea msg(%rip), %rsi ; arg 2: `fmt`
    mov %eax, %edx      ; arg 3: `...`
    call BeaconPrintf

    add $40, %rsp
    xor %eax, %eax      ; BOF exit code
    ret

.data

msg:
.ascii "Hello from asm BOF on Linux! eax is %d\12\0"
