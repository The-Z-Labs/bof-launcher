const std = @import("std");
const fmt = std.fmt;
const beacon = @import("bof_api").beacon;

pub export fn go(adata: ?[*]u8, alen: i32) callconv(.c) u8 {
    @import("bof_api").init(adata, alen, .{});

    const printf = beacon.printf;

    var parser = beacon.datap{};

    _ = printf(.output, "--- test_obj4.zig ---\n");

    if (adata == null) return 0;

    beacon.dataParse(&parser, adata, alen);
    const len = beacon.dataLength(&parser);
    const permissions = beacon.dataExtract(&parser, null);
    const path = beacon.dataExtract(&parser, null);
    const num = beacon.dataInt(&parser);
    const num_short = beacon.dataShort(&parser);
    if (alen > 0) {
        _ = printf(.output, "arg_len (from go): %d\n", alen);
        _ = printf(.output, "Length: (from go): %d\n", len);

        _ = printf(.output, "permissions: (from go): %s\n", permissions);
        _ = printf(.output, "path: (from go): %s\n", path);
        _ = printf(.output, "number (int): (from go): %d\n", num);
        _ = printf(.output, "number (short): (from go): %d\n", num_short);
    }

    return 0;
}
