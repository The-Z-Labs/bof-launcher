const w32 = @import("bof_api").win32;

pub const State = struct {
    process_id: w32.DWORD,
    shellcode: []const u8 = undefined,

    process_handle: w32.HANDLE = undefined,
    base_address: usize = 0,

    nt_status: w32.NTSTATUS = .SUCCESS,
};
