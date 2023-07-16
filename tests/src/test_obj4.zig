const std = @import("std");
const fmt = std.fmt;
const beacon = @import("bofapi").beacon;

pub export fn go(arg_data: ?[*]u8, arg_len: i32) callconv(.C) u8 {
    var parser = beacon.datap{};

    _ = beacon.printf(0, "--- test_obj4.zig ---\n");

    if (arg_data == null) return 0;

    beacon.dataParse(&parser, arg_data, arg_len);
    const len = beacon.dataLength(&parser);
    const permissions = beacon.dataExtract(&parser, null);
    const path = beacon.dataExtract(&parser, null);
    const num = beacon.dataInt(&parser);
    const num_short = beacon.dataShort(&parser);
    if (arg_len > 0) {
        _ = beacon.printf(0, "arg_len (from go): %d\n", arg_len);
        _ = beacon.printf(0, "Length: (from go): %d\n", len);

        _ = beacon.printf(0, "permissions: (from go): %s\n", permissions);
        _ = beacon.printf(0, "path: (from go): %s\n", path);
        _ = beacon.printf(0, "number (int): (from go): %d\n", num);
        _ = beacon.printf(0, "number (short): (from go): %d\n", num_short);
    }

    return 0;
}
