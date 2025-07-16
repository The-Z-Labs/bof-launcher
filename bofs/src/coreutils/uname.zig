///name: uname
///description: "Print system information. With no flag, same as -s"
///author: Z-Labs
///tags: ['linux','host-recon','z-labs']
///OS: linux
///sources:
///    - 'https://raw.githubusercontent.com/The-Z-Labs/bof-launcher/main/bofs/src/coreutils/uname.zig'
///examples: '
/// uname
/// uname -a
///
/// Flags:
/// -a    print all information
/// -s    print the kernel name
/// -n    print the network node hostname
/// -r    print the kernel release
/// -v    print the kernel version
/// -m    print the machine hardware name
///'
///arguments:
///- name: option
///  desc: "Print only chosen system information. Supported options: -asnrvm"
///  type: string
///  required: false
const std = @import("std");
const beacon = @import("bof_api").beacon;

pub export fn go(args: ?[*]u8, args_len: i32) callconv(.C) u8 {
    const printf = beacon.printf.?;

    const utsn: std.posix.utsname = std.posix.uname();

    if (args_len == 0) {
        _ = printf(.output, "%s\n", &utsn.sysname);
        return 0;
    }

    var opt_size: i32 = 0;

    var parser = beacon.datap{};

    beacon.dataParse.?(&parser, args, args_len);
    const opt = beacon.dataExtract.?(&parser, &opt_size);
    const optS = opt.?[0..@as(usize, @intCast(opt_size - 1))];
    std.debug.print("[uname] optS: {s} opt_size: {d}", .{ optS, opt_size });
    //const optS = std.mem.sliceTo(opt, 0);

    if (std.mem.eql(u8, optS, "-a")) {
        _ = printf(.output, "%s %s %s %s %s\n", &utsn.sysname, &utsn.nodename, &utsn.release, &utsn.version, &utsn.machine);
    } else if (std.mem.eql(u8, optS, "-s")) {
        _ = printf(.output, "%s\n", &utsn.sysname);
    } else if (std.mem.eql(u8, optS, "-n")) {
        _ = printf(.output, "%s\n", &utsn.nodename);
    } else if (std.mem.eql(u8, optS, "-r")) {
        _ = printf(.output, "%s\n", &utsn.release);
    } else if (std.mem.eql(u8, optS, "-v")) {
        _ = printf(.output, "%s\n", &utsn.version);
    } else if (std.mem.eql(u8, optS, "-m")) {
        _ = printf(.output, "%s\n", &utsn.machine);
    } else {
        return 1;
    }

    return 0;
}
