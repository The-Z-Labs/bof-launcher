const std = @import("std");
const posix = @import("std").posix;
const c = @import("std").c;
const beacon = @import("bof_api").beacon;

pub const ifaddrs = extern struct {
    ifa_next: *ifaddrs,
    ifa_name: [*:0]u8,
    ifa_flags: u32,
    ifa_addr: *posix.sockaddr,
    ifa_netmask: *posix.sockaddr,
    pub const ifa_ifu = extern union {
        ifu_broadaddr: *posix.sockaddr,
        ifu_dstaddr: *posix.sockaddr,
    };
};

//https://man7.org/linux/man-pages/man3/getifaddrs.3.html
pub extern fn getifaddrs(ifap: *[*]ifaddrs) callconv(.C) i32;
pub extern fn freeifaddrs(ifap: [*]ifaddrs) callconv(.C) void;

pub export fn go(args: ?[*]u8, args_len: i32) callconv(.C) u8 {
    var ifap: [*]ifaddrs = undefined;

    if (args_len != 0) {
        _ = beacon.printf(0, "Interface was provided.\n");
    }

    _ = args;

    if (getifaddrs(&ifap) == -1) {
        _ = beacon.printf(0, "getifaddrs failed. Aborted.\n");
        return 1;
    }

    var ifi: ?*ifaddrs = &ifap[0];
    while (ifi != null) : (ifi = ifi.?.ifa_next) {
        _ = beacon.printf(0, "if name: %s.\n", ifi.?.ifa_name);
    }

    freeifaddrs(ifap);

    return 0;
}
