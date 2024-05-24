format MS64 COFF

public go
extrn 'BeaconDataParse' as BeaconDataParse:qword
extrn 'BeaconDataExtract' as BeaconDataExtract:qword

section '.text' code readable executable align 8

align 8
go:
    push rbp
    mov rbp, rsp
    sub	rsp, 256

    mov r8d, edx ; int size
    mov rdx, rcx ; char* buffer
    lea rcx, [rbp-16] ; datap* parser (sizeof(datap) == 24)
    call BeaconDataParse

    lea rcx, [rbp-16] ; datap* parser
    xor edx, edx ; int* size
    call BeaconDataExtract

    mov rax, [rax]
    mov [rbp-40], rax ; State*

    mov rcx, [rax+24] ; state.process_handle
    lea rdx, [rax+32] ; state.base_address
    xor r8d, r8d ; ULONG_PTR ZeroBits
    lea r9, [rbp-48] ; SIZE_T* RegionSize
    mov dword [rsp+32], 0x1000 or 0x2000 ; MEM_COMMIT | MEM_RESERVE
    mov dword [rsp+40], 0x04 ; PAGE_READWRITE
    call nt_allocate_virtual_memory

    mov rcx, [rbp-40] ; State*
    mov [rcx+4], eax ; nt_status

    mov rsp, rbp
    pop rbp
    ret

align 8
nt_allocate_virtual_memory:
    mov rax, [gs:0x60] ; PEB address

    ; [rax+280] ULONG OSMajorVersion
    ; [rax+284] ULONG OSMinorVersion
    ; [rax+288] USHORT OSBuildNumber

    imul r10d, [rax+280], 10
    add r10d, [rax+284]

    mov eax, 21 ; Windows XP (NT 5.x)

    mov r11d, 21
    cmp r10d, 60 ; Windows Vista (NT 6.0)
    cmove eax, r11d

    mov r11d, 21
    cmp r10d, 61 ; Windows 7 (NT 6.1)
    cmove eax, r11d

    mov r11d, 22
    cmp r10d, 62 ; Windows 8 (NT 6.2)
    cmove eax, r11d

    mov r11d, 23
    cmp r10d, 63 ; Windows 8.1 (NT 6.3)
    cmove eax, r11d

    mov r11d, 24
    cmp r10d, 100 ; Windows 10+ (NT 10.0)
    cmove eax, r11d

    mov r10, rcx
    syscall
    ret
