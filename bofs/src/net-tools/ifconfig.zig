const std = @import("std");
const beacon = @import("bofapi").beacon;

pub export fn go(args: ?[*]u8, args_len: i32) callconv(.C) u8 {
    if (args_len == 0) {
        return 1;
    }

    var opt_size: i32 = 0;

    var parser = beacon.datap{};

    beacon.dataParse(&parser, args, args_len);
    const opt = beacon.dataExtract(&parser, &opt_size);
    const optS = opt.?[0..@as(usize, @intCast(opt_size - 1))];

    if (std.mem.eql(u8, optS, "-a")) {
        _ = beacon.printf(0, "ifconfig\n");
    }

    return 0;
}
