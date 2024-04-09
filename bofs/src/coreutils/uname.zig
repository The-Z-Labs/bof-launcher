///name: uname
///description: "Print certain system information. With no FLAGS, same as -s"
///author: Z-Labs
///tags: ['host-recon']
///OS: linux
///header: ['inline', '']
///sources:
///    - 'https://raw.githubusercontent.com/The-Z-Labs/bof-launcher/main/bofs/src/coreutils/uname.zig'
///usage: '
/// uname [str:FLAGS]
///
/// Flags:
/// -a    print all information
/// -s    print the kernel name
/// -n    print the network node hostname
/// -r    print the kernel release
/// -v    print the kernel version
/// -m    print the machine hardware name
///'
///examples: '
/// uname
/// uname -a
///'
///
const std = @import("std");
const beacon = @import("bof_api").beacon;

pub export fn go(args: ?[*]u8, args_len: i32) callconv(.C) u8 {
    const utsn: std.posix.utsname = std.posix.uname();

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
