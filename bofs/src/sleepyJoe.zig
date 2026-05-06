const std = @import("std");
const beacon = @import("bof_api").beacon;
const posix = @import("bof_api").posix;


pub export fn go(adata: ?[*]u8, alen: i32) callconv(.c) u8 {
    @import("bof_api").init(adata, alen, .{});

    _ = beacon.printf(.output, "Before ...\n");
    std.posix.nanosleep(4, 0);
    _ = beacon.printf(.output, "After ...\n");

    return 0;
}
