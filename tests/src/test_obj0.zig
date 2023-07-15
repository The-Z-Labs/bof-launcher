const std = @import("std");
const beacon = @import("bofapi").beacon;

fn func(msg: []const u8) i32 {
    std.debug.print("debug: test {s}\n", .{msg});
    return 0;
}

pub export fn go(arg_data: ?[*]u8, arg_len: i32) callconv(.C) i32 {
    _ = arg_data;
    _ = arg_len;
    _ = beacon.printf(0, "--- test_obj0.zig ---\n");

    const stdout = std.io.getStdErr().writer();
    stdout.print("debug: Hello, {s}!\n", .{"go"}) catch unreachable;
    return func("it");
}
