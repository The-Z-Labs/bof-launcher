const std = @import("std");
const beacon = @import("bof_api").beacon;

pub export fn go(_: ?[*]u8, _: i32) callconv(.c) u8 {
    if (beacon.getValue("__stdbofin__")) |stdin| {
        const stdin_data = @as(*[]const u8, @ptrCast(@alignCast(stdin))).*;
        _ = beacon.printf(.output, "%s[pipe1]%d", .{ stdin_data.ptr, stdin_data.len });
    } else {
        _ = beacon.printf(.output, "Error\n", .{});
    }

    return 0;
}
