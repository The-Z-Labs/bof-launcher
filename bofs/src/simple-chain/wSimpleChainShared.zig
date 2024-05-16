const w32 = @import("bof_api").win32;

pub const State = struct {
    number: u32,
    handle: w32.HANDLE,
};
