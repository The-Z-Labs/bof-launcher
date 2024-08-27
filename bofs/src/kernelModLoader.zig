const std = @import("std");
const beacon = @import("bof_api").beacon;

pub export fn loadKernelMod(mod_name: [*:0]const u8) callconv(.C) u8 {
    debugPrint("Loading kernel module: {s}\n", .{mod_name});
    return 0;
}

fn debugPrint(comptime format: []const u8, args: anytype) void {
    if (true) std.debug.print(format, args);
}
