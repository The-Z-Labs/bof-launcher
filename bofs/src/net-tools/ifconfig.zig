const std = @import("std");
const posix = @import("std").posix;
const c = @import("std").c;
const beacon = @import("bof_api").beacon;

pub const ifaddrs = extern struct {
    ifa_next: ?*ifaddrs,
    ifa_name: ?[*:0]u8,
    ifa_flags: u32,
    ifa_addr: ?*posix.sockaddr,
    ifa_netmask: ?*posix.sockaddr,
    ifa_ifu: extern union {
        ifu_broadaddr: ?*posix.sockaddr,
        ifu_dstaddr: ?*posix.sockaddr,
    },
    ifa_data: ?*anyopaque,
};

//https://man7.org/linux/man-pages/man3/getifaddrs.3.html
pub extern fn getifaddrs(ifap: **ifaddrs) callconv(.C) i32;
pub extern fn freeifaddrs(ifap: *ifaddrs) callconv(.C) void;

pub export fn go(args: ?[*]u8, args_len: i32) callconv(.C) u8 {
    _ = .{ args, args_len };

    var family: i32 = undefined;
    var list: *ifaddrs = undefined;
    if (getifaddrs(&list) == -1) {
        _ = beacon.printf(0, "getifaddrs failed. Aborted.\n");
        return 1;
    }

    var iter: ?*ifaddrs = list;
    while (iter != null) : (iter = iter.?.ifa_next) {
        family = iter.?.ifa_addr.?.family;
        _ = beacon.printf(0, "if name: %s ", iter.?.ifa_name);
        if (family == std.os.linux.AF.PACKET)
            _ = beacon.printf(0, "AF_PACKET");
        if (family == std.os.linux.AF.INET)
            _ = beacon.printf(0, "AF_INET");
        if (family == std.os.linux.AF.INET6)
            _ = beacon.printf(0, "AF_INET6");

        _ = beacon.printf(0, "\n");
        //std.debug.print("{any}\n\n", .{iter.?.*});
    }

    freeifaddrs(list);

    return 0;
}
