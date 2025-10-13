const std = @import("std");
const beacon = @import("bof_api").beacon;
const w32 = @import("bof_api").win32;

pub export fn go(adata: ?[*]u8, alen: i32) callconv(.c) u8 {
    @import("bof_api").init(adata, alen, .{});

    _ = beacon.printf(.output, "--- test_async.zig ---\n");

    var parser: beacon.datap = .{};
    beacon.dataParse(&parser, adata, alen);

    const id = beacon.dataInt(&parser);

    for (0..10) |_| {
        _ = beacon.printf(.output, "Async bof #%d is running...\n", id);
        std.Thread.sleep(10e6);
    }

    if (@import("builtin").os.tag == .windows) {
        const addr = w32.VirtualAlloc(
            null,
            1024,
            w32.MEM_COMMIT | w32.MEM_RESERVE,
            w32.PAGE_READWRITE,
        );
        if (addr == null) return 255;
        _ = w32.VirtualFree(addr, 0, w32.MEM_RELEASE);
    }

    return @intCast(id);
}
