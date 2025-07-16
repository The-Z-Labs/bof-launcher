const std = @import("std");
const beacon = @import("bof_api").beacon;
const w32 = @import("bof_api").win32;

pub export fn go(arg_data: ?[*]u8, arg_len: i32) callconv(.C) u8 {
    _ = beacon.printf.?(.output, "--- test_async.zig ---\n");

    var parser: beacon.datap = .{};
    beacon.dataParse.?(&parser, arg_data, arg_len);

    const id = beacon.dataInt.?(&parser);

    for (0..10) |_| {
        _ = beacon.printf.?(.output, "Async bof #%d is running...\n", id);
        std.time.sleep(10e6);
    }

    if (@import("builtin").os.tag == .windows) {
        const addr = w32.VirtualAlloc.?(
            null,
            1024,
            w32.MEM_COMMIT | w32.MEM_RESERVE,
            w32.PAGE_READWRITE,
        );
        if (addr == null) return 255;
        _ = w32.VirtualFree.?(addr, 0, w32.MEM_RELEASE);
    }

    return @intCast(id);
}
