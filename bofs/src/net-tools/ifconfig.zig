///name: "ifconfig"
///description: "Displays the status of the currently active network interfaces; Manipulates current state of the device (euid = 0 or CAP_NET_ADMIN is required for state changing)."
///author: "Z-Labs"
///tags: ['host-recon']
///OS: 'linux'
///header: ['inline', 'z']
///sources:
///    - 'https://raw.githubusercontent.com/The-Z-Labs/bof-launcher/main/bofs/src/net-tools/ifconfig.zig'
///usage: '
/// ifconfig [str:interface]
///'
///examples: '
/// ifconfig
/// ifconfig eth0 down
/// ifconfig eth0 promisc
///'

// TODO:
// get MTU value
const std = @import("std");
const posix = @import("std").posix;
const c = @import("std").c;
const beacon = @import("bof_api").beacon;

pub const SIOCGIFFLAGS = 0x8913;
pub const SIOCSIFFLAGS = 0x8914;

// https://github.com/ziglang/zig/blob/a2b834e8c7152f70d71c71107db40b9182909647/lib/libc/include/generic-glibc/netdb.h
const NI_MAXHOST = 1025;
const NI_NUMERICHOST = 1;

// https://github.com/ziglang/zig/blob/a2b834e8c7152f70d71c71107db40b9182909647/lib/libc/musl/include/net/if.h
pub const IFF_UP = 0x1;
pub const IFF_BROADCAST = 0x2;
pub const IFF_DEBUG = 0x4;
pub const IFF_LOOPBACK = 0x8;
pub const IFF_POINTOPOINT = 0x10;
pub const IFF_NOTRAILERS = 0x20;
pub const IFF_RUNNING = 0x40;
pub const IFF_NOARP = 0x80;
pub const IFF_PROMISC = 0x100;
pub const IFF_ALLMULTI = 0x200;
pub const IFF_MASTER = 0x400;
pub const IFF_SLAVE = 0x800;
pub const IFF_MULTICAST = 0x1000;
pub const IFF_PORTSEL = 0x2000;
pub const IFF_AUTOMEDIA = 0x4000;
pub const IFF_DYNAMIC = 0x8000;
pub const IFF_LOWER_UP = 0x10000;
pub const IFF_DORMANT = 0x20000;
pub const IFF_ECHO = 0x40000;

// https://man7.org/linux/man-pages/man3/getifaddrs.3.html
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

// https://github.com/ziglang/zig/blob/1b90888f576b4863f4a61213a9ca32b97aa57859/lib/libc/include/generic-glibc/netpacket/packet.h#L22
// https://man7.org/linux/man-pages/man7/packet.7.html
pub const sockaddr_ll = extern struct {
    sll_family: u16,
    sll_protocol: u16,
    sll_ifindex: i32,
    sll_hatype: i16,
    sll_pkttype: u8,
    sll_halen: u8,
    sll_addr: [8]u8,
};


fn flagsDisplay(flags: u32) void {
    _ = beacon.printf(0, "flags=%u<", flags);

    if(flags & IFF_UP != 0)
        _ = beacon.printf(0, "UP");
    if(flags & IFF_BROADCAST != 0)
        _ = beacon.printf(0, ",BROADCAST");
    if(flags & IFF_LOOPBACK != 0)
        _ = beacon.printf(0, ",LOOPBACK");
    if(flags & IFF_POINTOPOINT != 0)
        _ = beacon.printf(0, ",POINT-TO-POINT");
    if(flags & IFF_RUNNING != 0)
        _ = beacon.printf(0, ",RUNNING");
    if(flags & IFF_MULTICAST != 0)
        _ = beacon.printf(0, ",MULTICAST");
    _ = beacon.printf(0, ">");
}

pub export fn go(args: ?[*]u8, args_len: i32) callconv(.C) u8 {

    const allocator = std.heap.page_allocator;

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

        iter = list;
        while (iter != null) : (iter = iter.?.ifa_next) {
            var host = [_]u8{0} ** NI_MAXHOST;
            var netmask = [_]u8{0} ** NI_MAXHOST;
            var aux = [_]u8{0} ** NI_MAXHOST;
	    const family = iter.?.ifa_addr.?.family;
            const cur_iface_name = std.mem.sliceTo(iter.?.ifa_name.?, 0);
            const flags = iter.?.ifa_flags;

            if(std.mem.eql(u8, iface, cur_iface_name)) {

                if (family == std.os.linux.AF.INET) {
                    _ = getnameinfo(iter.?.ifa_addr.?, @sizeOf(std.posix.sockaddr.in), &host, NI_MAXHOST, null, 0, NI_NUMERICHOST);
                    _ = getnameinfo(iter.?.ifa_netmask.?, @sizeOf(std.posix.sockaddr.in), &netmask, NI_MAXHOST, null, 0, NI_NUMERICHOST);

                    if(flags & IFF_BROADCAST != 0) {
                        _ = getnameinfo(iter.?.ifa_ifu.ifu_broadaddr.?, @sizeOf(std.posix.sockaddr.in), &aux, NI_MAXHOST, null, 0, NI_NUMERICHOST);
		        _ = beacon.printf(0, "\tinet %s netmask=%s broadcast=%s\n", &host, &netmask, &aux);
                    }
                    else {
                        _ = getnameinfo(iter.?.ifa_ifu.ifu_dstaddr.?, @sizeOf(std.posix.sockaddr.in), &aux, NI_MAXHOST, null, 0, NI_NUMERICHOST);
		        _ = beacon.printf(0, "\tinet %s netmask=%s point2point=%s\n", &host, &netmask, &aux);
                    }
                }
                if (family == std.os.linux.AF.INET6) {
                    _ = getnameinfo(iter.?.ifa_addr.?, @sizeOf(std.posix.sockaddr.in6), &host, NI_MAXHOST, null, 0, NI_NUMERICHOST);
                    _ = getnameinfo(iter.?.ifa_netmask.?, @sizeOf(std.posix.sockaddr.in6), &netmask, NI_MAXHOST, null, 0, NI_NUMERICHOST);
		    _ = beacon.printf(0, "\tinet %s netmask=%s\n", &host, &netmask);
                }
	        if (family == std.os.linux.AF.PACKET) {

                    _ = beacon.printf(0, "%s: ", iface.ptr);
                    flagsDisplay(flags);
                    _ = beacon.printf(0, "\n");

                    // display HW address
                    if(!std.mem.eql(u8, iface, "lo")) {
                        if(iter.?.ifa_addr) |addr| {
                            const s = @as(*sockaddr_ll, @ptrCast(@alignCast(addr)));
                            var i: u32 = 0;

                            _ = beacon.printf(0, "\tether ");
                            while (i < s.sll_halen) : (i+=1) {
                                _ = beacon.printf(0, "%x", s.sll_addr[i]);
                                if(i+1 != s.sll_halen)  { _  = beacon.printf(0, ":"); } else { _  = beacon.printf(0, "\n"); }
                            }
                        }
                    }

	            if(iter.?.ifa_data != null) {
                        const stats = @as(*std.os.linux.rtnl_link_stats, @ptrCast(@alignCast(iter.?.ifa_data)));
		        _ = beacon.printf(0, "\tRX packets %d bytes %d\n", stats.rx_packets, stats.rx_bytes);
		        _ = beacon.printf(0, "\tRX errors %d dropped %d overruns %d frame %d\n", stats.rx_errors, stats.rx_dropped, stats.rx_fifo_errors, stats.rx_frame_errors);
		        _ = beacon.printf(0, "\tTX packets %d bytes %d\n", stats.tx_packets, stats.tx_bytes);
		        _ = beacon.printf(0, "\tTX errors %d dropped %d overruns %d carrier %d collisions %d\n", stats.tx_errors, stats.tx_dropped, stats.tx_fifo_errors, stats.tx_carrier_errors, stats.collisions);
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
