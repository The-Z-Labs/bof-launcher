const w32 = @import("bof_api").win32;

pub const State = extern struct {
    process_id: w32.DWORD,
    nt_status: w32.NTSTATUS = @enumFromInt(0xffff_ffff),
    shellcode: [*]const u8,
    shellcode_len: usize,
    process_handle: w32.HANDLE = undefined,
    base_address: usize = 0,
};
