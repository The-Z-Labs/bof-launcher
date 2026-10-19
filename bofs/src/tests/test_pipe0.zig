const std = @import("std");
const beacon = @import("bof_api").beacon;

pub export fn go(adata: ?[*]u8, alen: i32) callconv(.c) u8 {
    var parser = beacon.datap{};
    beacon.dataParse(&parser, adata, alen);

    const str = if (beacon.dataExtract(&parser, null)) |s| std.mem.span(s) else return 0;
    const int = beacon.dataInt(&parser);

    if (beacon.getValue("__stdbofin__") != null) {
        _ = beacon.printf(.output, "%s[pipe0]%d", .{ str.ptr, int });
    } else {
        _ = beacon.printf(.output, "Error\n", .{});
    }

    return 0;
}
