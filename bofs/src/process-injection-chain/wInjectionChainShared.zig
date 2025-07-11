const windows = @import("std").os.windows;
const DWORD = windows.DWORD;
const NTSTATUS = windows.NTSTATUS;
const HANDLE = windows.HANDLE;

pub const State = extern struct {
    process_id: DWORD,
    nt_status: NTSTATUS = @enumFromInt(0xffff_ffff),
    shellcode: [*]const u8,
    shellcode_len: usize,
    process_handle: HANDLE = undefined,
    base_address: usize = 0,
};
