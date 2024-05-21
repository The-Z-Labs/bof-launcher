const std = @import("std");
const w32 = @import("bof_api").win32;

pub export fn go(_: ?[*]u8, _: i32) callconv(.C) u8 {
    var process_handle: w32.HANDLE = undefined;
    var thread_handle: w32.HANDLE = undefined;
    var create_info: w32.PS_CREATE_INFO = undefined;
    @memset(std.mem.asBytes(&create_info), 0);

    const nt_status = w32.NtCreateUserProcess(
        &process_handle,
        &thread_handle,
        w32.PROCESS_ALL_ACCESS,
        w32.PROCESS_ALL_ACCESS,
        null,
        null,
        w32.PROCESS_CREATE_FLAGS_INHERIT_HANDLES,
        0,
        null,
        &create_info,
        null,
    );
    return if (nt_status == .SUCCESS) 0 else 1;
}
