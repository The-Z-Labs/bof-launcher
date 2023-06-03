const std = @import("std");
const beacon = @import("bofapi").beacon;

pub export fn go(arg_data: ?[*]u8, arg_len: i32) callconv(.C) u8 {
    var parser: beacon.datap = .{};
    beacon.dataParse(&parser, arg_data, arg_len);

    const id = beacon.dataInt(&parser);

    for (0..10) |_| {
        _ = beacon.printf(0, "Async bof #%d is running...\n", id);
        std.time.sleep(10e6);
    }

    return @intCast(u8, id);
}
