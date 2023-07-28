const std = @import("std");
const beacon = @import("bofapi").beacon;

pub export fn go(args: ?[*]u8, args_len: i32) callconv(.C) u8 {
    const utsn: std.os.utsname = std.os.uname();

    if (args_len == 0) {
        _ = beacon.printf(0, "%s\n", &utsn.sysname);
        return 0;
    }

    var opt_size: i32 = 0;

    var parser = beacon.datap{};

    beacon.dataParse(&parser, args, args_len);
    const opt = beacon.dataExtract(&parser, &opt_size);
    const optS = opt.?[0..@as(usize, @intCast(opt_size - 1))];
    std.debug.print("[uname] optS: {s} opt_size: {d}", .{ optS, opt_size });
    //const optS = std.mem.sliceTo(opt, 0);

    if (std.mem.eql(u8, optS, "-a")) {
        _ = beacon.printf(0, "%s %s %s %s %s\n", &utsn.sysname, &utsn.nodename, &utsn.release, &utsn.version, &utsn.machine);
    } else if (std.mem.eql(u8, optS, "-s")) {
        _ = beacon.printf(0, "%s\n", &utsn.sysname);
    } else if (std.mem.eql(u8, optS, "-n")) {
        _ = beacon.printf(0, "%s\n", &utsn.nodename);
    } else if (std.mem.eql(u8, optS, "-r")) {
        _ = beacon.printf(0, "%s\n", &utsn.release);
    } else if (std.mem.eql(u8, optS, "-v")) {
        _ = beacon.printf(0, "%s\n", &utsn.version);
    } else if (std.mem.eql(u8, optS, "-m")) {
        _ = beacon.printf(0, "%s\n", &utsn.machine);
    }

    return 0;
}
