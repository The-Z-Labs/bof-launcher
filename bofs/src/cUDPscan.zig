const std = @import("std");
const beacon = @import("bofapi").beacon;
const os = @import("bofapi").os;
const fmt = std.fmt;
const mem = std.mem;
const net = std.net;

const Payload = struct {
    ports: []u16,
    service_name: []u8,
    data: []u8,
};

// Example UDP probes borrowed from Nmap
const raw_payloads = [_][]const u8{
    "8888 AndroMouse AMSNIFF",
    "53,69,135,1761 DNSStatusRequest \x00\x00\x10\x00\x00\x00\x00\x00\x00\x00\x00\x00",
    "137 NBTStat \x80\xf0\x00\x10\x00\x01\x00\x00\x00\x00\x00\x00\x20\x43\x4bAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\x00\x00\x21\x00\x01",
    "389 LDAPSearchReqUDP \x30\x84\x00\x00\x00\x2d\x02\x01\x07\x63\x84\x00\x00\x00\x24\x04\x00\x0a\x01\x00\x0a\x01\x00\x02\x01\x00\x02\x01\x64\x01\x01\x00\x87\x0b\x6f\x62\x6a\x65\x63\x74\x43\x6c\x61\x73\x73\x30\x84\x00\x00\x00\x00",
    "88 Kerberos \x6a\x81\x6e\x30\x81\x6b\xa1\x03\x02\x01\x05\xa2\x03\x02\x01\x0a\xa4\x81\x5e\x30\x5c\xa0\x07\x03\x05\x00\x50\x80\x00\x10\xa2\x04\x1b\x02NM\xa3\x17\x30\x15\xa0\x03\x02\x01\x00\xa1\x0e\x30\x0c\x1b\x06krbtgt\x1b\x02NM\xa5\x11\x18\x0f19700101000000Z\xa7\x06\x02\x04\x1f\x1e\xb9\xd9\xa8\x17\x30\x15\x02\x01\x12\x02\x01\x11\x02\x01\x10\x02\x01\x17\x02\x01\x01\x02\x01\x03\x02\x01\x02",
    "123,5353,9100 NTPRequest \xe3\x00\x04\xfa\x00\x01\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xc5\x4f\x23\x4b\x71\xb1\x52\xf3",
};

fn parseRawPayloads(allocator: mem.Allocator, payloads: []const []const u8) ![]Payload {
    var list = std.ArrayList(Payload).init(allocator);
    defer list.deinit();

    for (payloads) |p| {
        var iter = mem.split(u8, p, " ");

        // get ports
        const ports_spec = iter.next() orelse return error.BadData;
        const ports = try extractPorts(allocator, ports_spec);
        errdefer allocator.free(ports);

        // get name
        const service_name_spec = iter.next() orelse return error.BadData;
        const service_name = try allocator.alloc(u8, service_name_spec.len);
        errdefer allocator.free(service_name);
        mem.copy(u8, service_name, service_name_spec);

        // get data
        const data_spec = iter.next() orelse return error.BadData;
        const data = try allocator.alloc(u8, data_spec.len);
        errdefer allocator.free(data);
        mem.copy(u8, data, data_spec);

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

    var iter = mem.tokenize(u8, port_spec, ",");

    while (iter.next()) |port_set| {
        if (mem.containsAtLeast(u8, port_set, 1, "-")) {
            // we're dealing with a port range, like: 1-3 in a set

            var iter2 = mem.tokenize(u8, port_set, "-");

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
            //we're dealing with just one port number in a set
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
    var iter = mem.split(u8, ip_spec, ".");
    var i: u32 = 0;
    var buf: [32]u8 = undefined;
    var buf_index: usize = 0;
    while (iter.next()) |ip_octet| {
        // badly formatted ip_spec, return empty list
        if (mem.eql(u8, ip_spec, ip_octet))
            return list.toOwnedSlice();
        mem.copy(u8, buf[buf_index..], ip_octet);
        buf_index += ip_octet.len;
        buf[buf_index] = '.';
        buf_index += 1;

        i += 1;
        if (i == 3) break;
    }
    const ip_last_octet = iter.next() orelse return list.toOwnedSlice();

    // Expanding last octet
    if (mem.containsAtLeast(u8, ip_last_octet, 1, "-")) {
        var iter2 = mem.tokenize(u8, ip_last_octet, "-");

        const sFirst_Num = iter2.next() orelse return list.toOwnedSlice();
        const first_num = fmt.parseInt(u16, sFirst_Num, 10) catch return list.toOwnedSlice();

        const sLast_Num = iter2.next() orelse return list.toOwnedSlice();
        const last_num = fmt.parseInt(u16, sLast_Num, 10) catch return list.toOwnedSlice();

        //std.debug.print("IP range: {d} - {d}\n", .{ first_num, last_num });

        var n = first_num;
        while (n <= last_num) {
            try list.append(try fmt.allocPrint(allocator, "{s}{d}", .{ buf[0..buf_index], n }));
            n += 1;
        }
    }

    return list.toOwnedSlice();
}

/// Arguments:
/// type: string; value: <target_specification:port_specification>
/// Example runs:
/// cUDPScan 192.168.0.1:21,80
/// cUDPScan 192.168.0.1:80-85
/// cUDPScan 102.168.1.1-2:22
/// cUDPScan 102.168.1.1-32:22-32,427
pub export fn go(args: ?[*]u8, args_len: i32) callconv(.C) u8 {
    if (args_len == 0) {
        _ = beacon.printf(0, "Usage: cUDPscan <IPs>:<ports>\n");
        return 1;
    }

    var opt_len: i32 = 0;
    var parser = beacon.datap{};

    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    beacon.dataParse(&parser, args, args_len);
    const targets_spec = beacon.dataExtract(&parser, &opt_len);

    // creating slice without terminating 0
    const sTargets_spec = targets_spec.?[0..@intCast(usize, opt_len - 1)];

    // spliting arguemnts to IPs and ports parts
    var iter = mem.split(u8, sTargets_spec, ":");
    const sIP_spec = iter.next() orelse unreachable;
    const sPort_spec = iter.next() orelse unreachable;

    // IPs to scan
    const sIPs = extractIPs(allocator, sIP_spec) catch return 1;
    defer allocator.free(sIPs);

    // ports to scan
    const sPorts = extractPorts(allocator, sPort_spec) catch return 1;
    defer allocator.free(sPorts);

    // Creating socket
    const fd = os.socket(
        os.AF.INET,
        os.SOCK.DGRAM | os.SOCK.CLOEXEC | os.SOCK.NONBLOCK,
        0,
    ) catch return 1;
    defer os.closeSocket(fd);

    // Get local address and open/bind a socket
    var sl: os.socklen_t = @sizeOf(os.sockaddr.in);
    var family: os.sa_family_t = os.AF.INET;
    var sa: net.Address = undefined;
    @memset(@ptrCast([*]u8, &sa)[0..@sizeOf(net.Address)], 0);
    sa.any.family = family;
    os.bind(fd, &sa.any, sl) catch return 1;

    // Packet payloads parsing and preparation
    const payloads = parseRawPayloads(allocator, raw_payloads[0..][0..]) catch return 1;
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
        var dest_addr = net.Address.parseIp(IP, @intCast(u16, 0)) catch return 1;

        for (sPorts) |port| {
            if (ports_data_map.get(port)) |pkt_content| {
                //std.debug.print("Scanning IP: {s} and port number: {d}; payload used:\n{s}\n", .{ IP, port, pkt_content });
                dest_addr.setPort(port);

                _ = os.sendto(fd, pkt_content, 0, &dest_addr.any, sl) catch continue;
            }
        }
    }

    // Handling responses
    const timeout = 1000 * 3;
    var t2: u64 = @bitCast(u64, std.time.milliTimestamp());
    var t0 = t2;

    var answer_buf = [_]u8{0} ** 512;

    while (t2 - t0 < timeout) : (t2 = @bitCast(u64, std.time.milliTimestamp())) {
        while (true) {
            const rlen = os.recvfrom(fd, &answer_buf, 0, &sa.any, &sl) catch break;

            // Ignore non-identifiable packets
            if (rlen < 4) continue;

            for (sIPs) |IP| {
                for (sPorts) |port| {
                    var scanned_addr = net.Address.parseIp(IP, port) catch continue;
                    if (sa.eql(scanned_addr)) {
                        std.debug.print("Host: {s}\tPort: {d}\tState: open\n", .{ IP, port });
                    }
                }
            }
        }
    }

    return 0;
}
