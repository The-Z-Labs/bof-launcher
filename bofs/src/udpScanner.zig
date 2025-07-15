///name: "udpScanner"
///description: "Universal UDP port sweeper."
///author: "Z-Labs"
///tags: ['windows', 'linux','net-recon','z-labs']
///OS: "cross"
///entrypoint: "go"
///sources:
///    - 'https://raw.githubusercontent.com/The-Z-Labs/bof-launcher/main/bofs/src/udpScanner.zig'
///examples: '
/// Scanning provided IP range on most common UDP ports with builtin UDP probes:
///
///   udpScanner str:192.168.0.1-32
///
/// Scanning only cherry-picked ports (if no builtin UDP probe for the chosen port is available then length and content of the packet payload will be randomly generated:
///
///   udpScanner str:192.168.0.1:123,161
///   udpScanner str:102.168.1.1-128:53,427,137
///   udpScanner str:192.168.0.1:100-200
///
/// Example of running with provided UDP probes:
///
///   udpScanner str:192.168.0.1-32 int:BUF_LEN str:BUF_MEMORY_ADDRESS
///
/// UDP probe syntax (with example):
///
///   <portSpec> <probeName> <hexadecimal encoded probe data>\n
///   53,69,135,1761 dnsReq 000010000000000000000000
///
/// Example of running udpScanner using cli4bofs tool and with UDP probes provided from the file:
///
///   cli4bofs exec udpScanner 102.168.1.1-4:161,427 file:/tmp/udpPayloads
///'
///arguments:
///  - name: IPSpec
///    desc: "IP addresses specification, ex: 192.168.0.1; 10.0.0-255.1-254; 192.168.0.1:161,427,10-15"
///    type: string
///    required: true
///  - name: BufLen
///    desc: "length of UDP probes buffer"
///    type: integer
///    required: false
///  - name: BufMemoryAddress
///    desc: "memory address of UDP probes buffer"
///    type: string
///    required: false
const std = @import("std");
const beacon = @import("bof_api").beacon;
const posix = @import("bof_api").posix;
const fmt = std.fmt;
const mem = std.mem;
const net = std.net;

const Payload = struct {
    ports: []u16,
    service_name: []u8,
    data: []u8,
};

const builtin_major_ports: []const u8 = "53,161,137,427";
const builtin_payloads: []const u8 =
    \\53,69,135,1761 dnsReq 000010000000000000000000
    \\161,260,3401 snmpGetReq 3082002f02010004067075626c6963a082002002044c33a756020100020100308200103082000c06082b060102010105000500
    \\137 nbStat 80f00010000100000000000020434b4141414141414141414141414141414141414141414141414141414141410000210001
    \\427 srvLoc 0201000036200000000000010002656e00000015736572766963653a736572766963652d6167656e74000764656661756c7400000000
;

fn parseRawPayloads(allocator: mem.Allocator, payloads_buf: []const u8) ![]Payload {
    var list = std.ArrayList(Payload).init(allocator);
    defer list.deinit();

    var line_iter = mem.splitScalar(u8, mem.trimRight(u8, payloads_buf, "\n"), '\n');

    while (line_iter.next()) |p| {
        var iter = mem.splitScalar(u8, p, ' ');

        // get ports
        const ports_spec = iter.next() orelse return error.BadData;
        const ports = try extractPorts(allocator, ports_spec);
        errdefer allocator.free(ports);

        // get name
        const service_name_spec = iter.next() orelse return error.BadData;
        const service_name = try allocator.alloc(u8, service_name_spec.len);
        errdefer allocator.free(service_name);
        @memcpy(service_name, service_name_spec);

        // get data
        const data_spec = iter.next() orelse return error.BadData;
        var data = try allocator.alloc(u8, data_spec.len / 2);
        errdefer allocator.free(data);
        data = try fmt.hexToBytes(data, data_spec);

        // adding payload to the list
        try list.append(.{
            .ports = ports,
            .service_name = service_name,
            .data = data,
        });
    }

    return list.toOwnedSlice();
}

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

        //debugPrint("IP range: {d} - {d}\n", .{ first_num, last_num });

        var n = first_num;
        while (n <= last_num) {
            try list.append(try fmt.allocPrint(allocator, "{s}{d}", .{ buf[0..buf_index], n }));
            n += 1;
        }
    }

    return list.toOwnedSlice();
}

pub export fn go(args: ?[*]u8, args_len: i32) callconv(.C) u8 {
    if (args_len == 0) {
        _ = beacon.printf.?(0, "Usage: udpScanner str:IPSpec[:portSpec] [int:BUF_LEN str:BUF_MEMORY_ADDR]\n");
        return 1;
    }

    var payloads_buf: []const u8 = undefined;
    var opt_len: i32 = 0;
    const allocator = std.heap.page_allocator;
    var parser = beacon.datap{};

    debugPrint("parser: {any}\n", .{parser});

    // parse 1st (mandatory) argument:
    beacon.dataParse.?(&parser, args, args_len);
    const targets_spec = beacon.dataExtract.?(&parser, &opt_len);
    const sTargets_spec = targets_spec.?[0..@intCast(opt_len - 1)];

    debugPrint("args_len: {d}; opt_len: {d}\n", .{ args_len, opt_len });

    // verify if additional (optional) arguments are provided and if so process it:
    if (args_len - 8 > opt_len) {
        const buf_len = beacon.dataInt.?(&parser);

        const buf_ptr = beacon.dataExtract.?(&parser, &opt_len);
        const sBuf_ptr = buf_ptr.?[0..@intCast(opt_len - 1)];

        payloads_buf = @as([*]u8, @ptrFromInt(mem.readInt(usize, sBuf_ptr[0..@sizeOf(usize)], .little)))[0..@intCast(buf_len)];
    } else {
        payloads_buf = builtin_payloads;
    }

    debugPrint("UDP probes:\n {s}\n", .{payloads_buf});

    // spliting IP:port specification argument to IPs and ports parts
    var iter = mem.splitScalar(u8, sTargets_spec, ':');
    const sIP_spec = iter.next() orelse unreachable;
    const sPort_spec = iter.next() orelse "";

    // IPs to scan
    const sIPs = extractIPs(allocator, sIP_spec) catch return 1;
    defer allocator.free(sIPs);

    // ports to scan
    var sPorts: []u16 = undefined;
    // if no ports specification is provided, scan major ports with builtin UDP probes
    if (sPort_spec.len == 0) {
        sPorts = extractPorts(allocator, builtin_major_ports) catch return 1;
    } else {
        sPorts = extractPorts(allocator, sPort_spec) catch return 1;
    }
    defer allocator.free(sPorts);

    // Creating socket
    const fd = std.posix.socket(
        std.posix.AF.INET,
        std.posix.SOCK.DGRAM | std.posix.SOCK.CLOEXEC | std.posix.SOCK.NONBLOCK,
        0,
    ) catch return 1;
    defer closeSocket(fd);

    // Get local address and open/bind a socket
    var sl: std.posix.socklen_t = @sizeOf(std.posix.sockaddr.in);
    const family: std.posix.sa_family_t = std.posix.AF.INET;
    var sa: net.Address = undefined;
    @memset(@as([*]u8, @ptrCast(&sa))[0..@sizeOf(net.Address)], 0);
    sa.any.family = family;
    std.posix.bind(fd, &sa.any, sl) catch return 1;

    // Packet payloads parsing and preparation
    const payloads = parseRawPayloads(allocator, payloads_buf) catch return 1;
    defer {
        for (payloads) |p| {
            allocator.free(p.ports);
            allocator.free(p.service_name);
            allocator.free(p.data);
        }
        allocator.free(payloads);
    }

    var ports_data_map = std.AutoHashMap(u16, []u8).init(allocator);
    defer ports_data_map.deinit();

    for (payloads) |payload| {
        for (payload.ports) |port| {
            ports_data_map.put(port, payload.data) catch return 1;
        }
    }

    // Scanning
    if (sIPs.len == 0 or sPorts.len == 0)
        return 0;

    for (sIPs) |IP| {
        var dest_addr = net.Address.parseIp(IP, @as(u16, @intCast(0))) catch return 1;

        for (sPorts) |port| {
            if (ports_data_map.get(port)) |pkt_content| {
                //debugPrint("Scanning IP: {s} and port number: {d}; payload used:\n{s}\n", .{ IP, port, pkt_content });
                dest_addr.setPort(port);

                _ = std.posix.sendto(fd, pkt_content, 0, &dest_addr.any, sl) catch continue;
            }
        }
    }

    debugPrint("sIPs: {any}\n", .{sIPs});
    debugPrint("sPorts: {any}\n", .{sPorts});

    // Handling responses
    const timeout = 1000 * 3;
    var t2: u64 = @as(u64, @bitCast(std.time.milliTimestamp()));
    const t0 = t2;

    var answer_buf = [_]u8{0} ** 512;

    loop: while (t2 - t0 < timeout) : (t2 = @as(u64, @bitCast(std.time.milliTimestamp()))) {
        const rlen = posix.recvfrom(fd, &answer_buf, 0, &sa.any, &sl) catch |err| {
            //debugPrint("error {s}\n", .{@errorName(err)});
            _ = @errorName(err);
            continue :loop;
        };

        debugPrint("rlen: {d}\n", .{rlen});

        // Ignore non-identifiable packets
        if (rlen < 4) continue;

        for (sIPs) |IP| {
            for (sPorts) |port| {
                const scanned_addr = net.Address.parseIp(IP, port) catch continue;
                if (sa.eql(scanned_addr)) {
                    debugPrint("Host: {s}\tPort: {d}\tState: open\n", .{ IP, port });
                    _ = beacon.printf.?(0, "Host: %s\tPort: %d\tState: open\n", IP.ptr, port);
                }
            }
        }
    }

    debugPrint("DONE\n", .{});
    return 0;
}

pub fn closeSocket(sock: std.posix.socket_t) void {
    if (@import("builtin").os.tag == .windows) {
        _ = @import("bof_api").win32.closesocket.?(sock);
    } else {
        std.posix.close(sock);
    }
}

fn debugPrint(comptime format: []const u8, args: anytype) void {
    if (false) std.debug.print(format, args);
}
