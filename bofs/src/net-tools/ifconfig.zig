const std = @import("std");
const posix = @import("std").posix;
const c = @import("std").c;
const beacon = @import("bof_api").beacon;

const NI_MAXHOST = 1025;
const NI_NUMERICHOST = 1;

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

// https://man7.org/linux/man-pages/man3/getifaddrs.3.html
pub extern fn getifaddrs(ifap: **ifaddrs) callconv(.C) i32;
pub extern fn freeifaddrs(ifap: *ifaddrs) callconv(.C) void;

// https://man7.org/linux/man-pages/man3/getnameinfo.3.html
pub extern fn getnameinfo(addr: *posix.sockaddr,
    addrlen: c.socklen_t,
    noalias host: ?[*]u8,
    hostlen: c.socklen_t,
    noalias serv: ?[*]u8,
    servlen: c.socklen_t,
    flags: u32,
) callconv(.C) c.EAI;

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
        _ = beacon.printf(0, "%s: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500\n", iface.ptr);

        iter = list;
        while (iter != null) : (iter = iter.?.ifa_next) {
            var host = [_]u8{0} ** NI_MAXHOST;
            var host6 = [_]u8{0} ** NI_MAXHOST;
	    family = iter.?.ifa_addr.?.family;
            const cur_iface_name = std.mem.sliceTo(iter.?.ifa_name.?, 0);

            if(std.mem.eql(u8, iface, cur_iface_name)) {
                if (family == std.os.linux.AF.INET) {
                    _ = getnameinfo(iter.?.ifa_addr.?, @sizeOf(std.posix.sockaddr.in), &host, NI_MAXHOST, null, 0, NI_NUMERICHOST);
		    _ = beacon.printf(0, "       inet %s netmask=\n", &host);
                }
                if (family == std.os.linux.AF.INET6) {
                    _ = getnameinfo(iter.?.ifa_addr.?, @sizeOf(std.posix.sockaddr.in6), &host6, NI_MAXHOST, null, 0, NI_NUMERICHOST);
		    _ = beacon.printf(0, "       inet6 %s netmask=\n", &host6);
                }
	        if (family == std.os.linux.AF.PACKET) {

	            if(iter.?.ifa_data != null) {
                        const stats = @as(*std.os.linux.rtnl_link_stats, @ptrCast(@alignCast(iter.?.ifa_data)));
		        _ = beacon.printf(0, "       RX packets %d bytes %d\n", stats.rx_packets, stats.rx_bytes);
		        _ = beacon.printf(0, "       TX packets %d bytes %d\n", stats.tx_packets, stats.tx_bytes);
                    }
                }
            }

	    //std.debug.print("{any}\n\n\n", .{iter.?.*});
        }
        _ = beacon.printf(0, "\n");
    }

    freeifaddrs(list);

    return 0;
}
