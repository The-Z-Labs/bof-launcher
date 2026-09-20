const DWORD = u32;
const NTSTATUS = u32;
const HANDLE = *anyopaque;

pub const State = extern struct {
    process_id: DWORD,
    nt_status: NTSTATUS = 0,
    shellcode: [*]const u8,
    shellcode_len: usize,
    process_handle: HANDLE = undefined,
    base_address: usize = 0,
};
