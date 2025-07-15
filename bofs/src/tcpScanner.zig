///name: "tcpScanner"
///description: "TCP connect() port scanner"
///author: "Z-Labs"
///tags: ['windows', 'linux','net-recon','z-labs']
///OS: "cross"
///entrypoint: "go"
///sources:
///    - 'https://raw.githubusercontent.com/The-Z-Labs/bof-launcher/main/bofs/src/tcpScanner.zig'
///examples: '
/// Scanning selected hosts and ports:
///
///   tcpScanner str:192.168.0.1:80,22,443
///   tcpScanner str:192.168.0.1:100-200
///   tcpScanner str:102.168.1.1-128:445,81,8080-8089
///'
///arguments:
///  - name: IPSpec
///    desc: "IP addresses specification, ex: 192.168.0.1; 10.0.0-255.1-254; 192.168.0.1:161,427,10-15"
///    type: string
///    required: true
const std = @import("std");
const beacon = @import("bof_api").beacon;
const posix = @import("bof_api").posix;
const fmt = std.fmt;
const mem = std.mem;
const net = std.net;

const POLL_TIMEOUT = 300;

pub const linger = extern struct {
    l_onoff: i32,
    l_linger: i32,
};

fn extractPorts(allocator: mem.Allocator, port_spec: []const u8) ![]u16 {
    var list = std.ArrayList(u16).init(allocator);
    defer list.deinit();

    var iter = mem.tokenizeScalar(u8, port_spec, ',');

    while (iter.next()) |port_set| {
        if (mem.containsAtLeast(u8, port_set, 1, "-")) {
            // we're dealing with a port range, like: 1-3 in a set

            var iter2 = mem.tokenizeScalar(u8, port_set, '-');

            const first_port = fmt.parseInt(
                u16,
                iter2.next() orelse continue,
                10,
            ) catch continue;

            const last_port = fmt.parseInt(
                u16,
                iter2.next() orelse continue,
                10,
            ) catch continue;

            var n = first_port;
            while (n <= last_port) {
                try list.append(n);
                n += 1;
            }
        } else {
            // we're dealing with just one port number in a set
            const port = fmt.parseInt(u16, port_set, 10) catch continue;
            try list.append(port);
        }
    }

    return list.toOwnedSlice();
}

fn extractIPs(allocator: mem.Allocator, ip_spec: []const u8) ![][]const u8 {
    var list = std.ArrayList([]const u8).init(allocator);
    defer list.deinit();

    // ip_spec contains only single IP - add it to the list and return
    if (!mem.containsAtLeast(u8, ip_spec, 1, "-")) {
        try list.append(ip_spec);
        return list.toOwnedSlice();
    }

    // splitting IP to get last octet for expansion (IP specification in a form us only supported x.x.x.1-3)
    var iter = mem.splitScalar(u8, ip_spec, '.');
    var i: u32 = 0;
    var buf: [32]u8 = undefined;
    var buf_index: usize = 0;
    while (iter.next()) |ip_octet| {
        // badly formatted ip_spec, return empty list
        if (mem.eql(u8, ip_spec, ip_octet))
            return error.BadData;
        @memcpy(buf[buf_index..], ip_octet);
        buf_index += ip_octet.len;
        buf[buf_index] = '.';
        buf_index += 1;

        i += 1;
        if (i == 3) break;
    }
    const ip_last_octet = iter.next() orelse return error.BadData;

    // Expanding last octet
    if (mem.containsAtLeast(u8, ip_last_octet, 1, "-")) {
        var iter2 = mem.tokenizeScalar(u8, ip_last_octet, '-');

        const sFirst_Num = iter2.next() orelse return error.BadData;
        const first_num = fmt.parseInt(u16, sFirst_Num, 10) catch return error.BadData;

        const sLast_Num = iter2.next() orelse return error.BadData;
        const last_num = fmt.parseInt(u16, sLast_Num, 10) catch return error.BadData;

        var n = first_num;
        while (n <= last_num) {
            try list.append(try fmt.allocPrint(allocator, "{s}{d}", .{ buf[0..buf_index], n }));
            n += 1;
        }
    }

    return list.toOwnedSlice();
}

pub export fn go(args: ?[*]u8, args_len: i32) callconv(.C) u8 {
    const printf = beacon.printf.?;

    if (args_len == 0) {
        return 1; // err 1: no argument provided
    }

    var opt_len: i32 = 0;
    const allocator = std.heap.page_allocator;
    var parser = beacon.datap{};

    // parse 1st (mandatory) argument:
    beacon.dataParse.?(&parser, args, args_len);
    const targets_spec = beacon.dataExtract.?(&parser, &opt_len);
    const sTargets_spec = targets_spec.?[0..@as(usize, @intCast(opt_len - 1))];

    // spliting IP:port specification argument to IPs and ports parts
    var iter = mem.splitScalar(u8, sTargets_spec, ':');
    const sIP_spec = iter.next() orelse unreachable;
    const sPort_spec = iter.next() orelse "";

    // IPs to scan
    const sIPs = extractIPs(allocator, sIP_spec) catch return 2; // err 2: invalid IPs provided
    defer allocator.free(sIPs);

    // ports to scan
    var sPorts: []u16 = undefined;
    sPorts = extractPorts(allocator, sPort_spec) catch return 3; // err 3: invalid port range provided
    defer allocator.free(sPorts);

    if (sIPs.len == 0 or sPorts.len == 0)
        return 4; // err 4: nothing to scan

    // preparing sockaddr struct
    const family: std.posix.sa_family_t = std.posix.AF.INET;
    var sa: net.Address = undefined;
    @memset(@as([*]u8, @ptrCast(&sa))[0..@sizeOf(net.Address)], 0);
    sa.any.family = family;

    const lin = linger{
        .l_onoff = 1,
        .l_linger = 0,
    };
    //_ = lin;

    // scanning
    for (sIPs) |IP| {
        _ = printf(0, "IP: %s\n", IP.ptr);
        var dest_addr = net.Address.parseIp(IP, @as(u16, @intCast(0))) catch return 1;

        for (sPorts) |port| {
            _ = printf(0, "port: %d\n", port);
            // creating socket
            const sockfd = std.posix.socket(
                std.posix.AF.INET,
                std.posix.SOCK.STREAM | std.posix.SOCK.NONBLOCK,
                0,
            ) catch return 1;
            defer std.posix.close(sockfd);

            dest_addr.setPort(port);

            var pfd = [1]std.posix.pollfd{std.posix.pollfd{
                .fd = sockfd,
                .events = std.posix.POLL.OUT,
                .revents = 0,
            }};

            //EINPROGRESS
            //  The socket is nonblocking and the connection cannot be
            //  completed immediately.  (UNIX domain sockets failed with
            //  EAGAIN instead.)  It is possible to select(2) or poll(2)
            //  for completion by selecting the socket for writing.  After
            //  select(2) indicates writability, use getsockopt(2) to read
            //  the SO_ERROR option at level SOL_SOCKET to determine
            //  whether connect() completed successfully (SO_ERROR is
            //  zero) or unsuccessfully (SO_ERROR is one of the usual
            //  error codes listed here, explaining the reason for the
            //  failure).
            std.posix.connect(sockfd, &dest_addr.any, dest_addr.getOsSockLen()) catch {};

            std.posix.setsockopt(sockfd, std.posix.SOL.SOCKET, std.posix.SO.LINGER, std.mem.asBytes(&lin)) catch {};

            // use this on Windows: https://github.com/ziglang/zig/blob/956f53beb09c07925970453d4c178c6feb53ba70/lib/std/os/windows.zig#L1687
            const nevents = posix.poll(&pfd, POLL_TIMEOUT) catch 0;
            _ = printf(0, "nevents: %d\n", nevents);

            if ((pfd[0].revents & std.posix.POLL.OUT) != 0) {
                // use this on Windows: https://ziglang.org/documentation/master/std/#std.os.windows.ws2_32.getsockopt
                const rc = posix.getsockoptError(sockfd);
                if (rc == error.ConnectionRefused) {
                    _ = printf(0, "Port %d closed on host %s\n", port, IP.ptr);
                } else _ = printf(0, "Port %d opened on host %s\n", port, IP.ptr);
            } else {
                _ = printf(0, "Port %d filtered on host %s\n", port, IP.ptr);
            }
        }
        _ = printf(0, "\n");
    }

    return 0;
}
