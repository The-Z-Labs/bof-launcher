format MS64 COFF
public go

section '.text' code readable executable align 8

align 8
go:
    sub rsp, 128 ; allocate some space on the stack

    mov rax, [gs:0x60] ; PEB address
    mov rax, [rax+32] ; ProcessParameters address
    mov rax, [rax+72] ; CurrentDirectory.Handle
    mov [file_object_attributes.RootDirectory], rax

    mov rcx, file_handle
    mov edx, FILE_GENERIC_WRITE
    mov r8, file_object_attributes
    mov r9, file_status_block
    mov qword [rsp+32], 0 ; AllocationSize
    mov dword [rsp+40], FILE_ATTRIBUTE_NORMAL
    mov dword [rsp+48], 0 ; ShareAccess
    mov dword [rsp+56], FILE_OVERWRITE_IF ; CreateDisposition
    mov dword [rsp+64], FILE_SYNCHRONOUS_IO_NONALERT ; CreateOptions
    mov qword [rsp+72], 0 ; EaBuffer
    mov dword [rsp+80], 0 ; EaLength
    call nt_create_file

    add rsp, 128
    ret

; syscall numbers for Windows 10+ x64:
;   https://hfiref0x.github.io/NT10_syscalls.html
;   https://j00ru.vexillium.org/syscalls/nt/64

align 8
nt_create_file:
    mov r10, rcx ; first argument needs to be in 'r10' register
    mov eax, 85 ; NtCreateFile syscall number on Windows 10+
    syscall
    ret

section '.data' data readable writeable align 8

; https://codeverge.com/utf16-encode
; 'file.txt'
align 8
filename dw 0x0066,0x0069,0x006c,0x0065,0x002e,0x0074,0x0078,0x0074
    .SIZE = $ - filename

align 8
file_unicode_string:
    .Length dw filename.SIZE
    .MaximumLength dw filename.SIZE
    dd 0
    .ObjectName.Buffer dq filename

align 8
file_object_attributes:
    .Length dd .SIZE
    dd 0
    .RootDirectory dq 0
    .ObjectName dq file_unicode_string
    .Attributes dd 0
    dd 0
    .SecurityDescriptor dq 0
    .SecurityQualityOfService dq 0
    .SIZE = $ - file_object_attributes

align 8
file_status_block:
    virtual at $
    .Status dd ?
    end virtual
    virtual at $
    .Pointer dq ?
    end virtual
    dq 0 ; storage for the above union
    .Information dq 0

align 8
file_handle dq 0

READ_CONTROL = 0x00020000
STANDARD_RIGHTS_READ = READ_CONTROL
STANDARD_RIGHTS_WRITE = READ_CONTROL
FILE_READ_DATA = 0x0001
FILE_READ_EA = 0x0008
FILE_READ_ATTRIBUTES = 0x0080
FILE_WRITE_DATA = 0x0002
FILE_WRITE_EA = 0x0010
FILE_WRITE_ATTRIBUTES = 0x0100
FILE_APPEND_DATA = 0x0004
FILE_GENERIC_READ = STANDARD_RIGHTS_READ or\
    FILE_READ_DATA or\
    FILE_READ_ATTRIBUTES or\
    FILE_READ_EA or\
    SYNCHRONIZE
FILE_GENERIC_WRITE = STANDARD_RIGHTS_WRITE or\
    FILE_WRITE_DATA or\
    FILE_WRITE_ATTRIBUTES or\
    FILE_WRITE_EA or\
    FILE_APPEND_DATA or\
    SYNCHRONIZE
SYNCHRONIZE = 0x00100000
STANDARD_RIGHTS_REQUIRED = 0x000F0000
FILE_ATTRIBUTE_NORMAL = 0x00000080
FILE_OVERWRITE_IF = 0x00000005
FILE_SYNCHRONOUS_IO_NONALERT = 0x00000020
