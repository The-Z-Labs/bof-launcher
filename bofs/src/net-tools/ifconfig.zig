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

    const allocator = std.heap.page_allocator;

    var family: i32 = undefined;
    var list: *ifaddrs = undefined;
    if (getifaddrs(&list) == -1) {
        _ = beacon.printf(0, "getifaddrs failed. Aborted.\n");
        return 1;
    }

    var iter: ?*ifaddrs = list;

    // add all identified interfaces (distincted by name) to the interfaces collection
    var interfaces = std.ArrayList([]const u8).init(allocator);
    defer interfaces.deinit();
    outer: while (iter != null) : (iter = iter.?.ifa_next) {
        const cur_iface_name = std.mem.sliceTo(iter.?.ifa_name.?, 0);

        // check if given interface was already added
        for (interfaces.items) |iface| {
            if(std.mem.eql(u8, iface, cur_iface_name))
                continue :outer;
        }
        else interfaces.append(cur_iface_name) catch unreachable;
    }

    // iterate over each interface name and print its statistics
    for (interfaces.items) |iface| {
        _ = beacon.printf(0, "%s: flags=\n", iface.ptr);

        iter = list;
        while (iter != null) : (iter = iter.?.ifa_next) {
	    family = iter.?.ifa_addr.?.family;
            const cur_iface_name = std.mem.sliceTo(iter.?.ifa_name.?, 0);

            if(std.mem.eql(u8, iface, cur_iface_name)) {
	        if (family == std.os.linux.AF.PACKET)
		    _ = beacon.printf(0, "ether AF_PACKET\n");
		if (family == std.os.linux.AF.INET)
		    _ = beacon.printf(0, "inet AF_INET\n");
		if (family == std.os.linux.AF.INET6)
		    _ = beacon.printf(0, "inet6 AF_INET6\n");
            }

	    //std.debug.print("{any}\n\n\n", .{iter.?.*});
        }
    }

    freeifaddrs(list);

    return 0;
}
