const beacon = @import("bof_api").beacon;
const w32 = @import("bof_api").win32;

extern fn bofRun(
    file_data_ptr: [*]const u8,
    file_data_len: c_int,
) callconv(.C) c_int;

pub export fn go(_: ?[*]u8, _: i32) callconv(.C) u8 {
    const bof_bytes = @embedFile("helloBof.coff.x64.o");

    const res = bofRun(bof_bytes.ptr, bof_bytes.len);

    _ = beacon.printf(0, "Child BOF exit code: %d\n", res);

    return 0;
}
