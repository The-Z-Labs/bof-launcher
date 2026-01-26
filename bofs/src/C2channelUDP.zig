const std = @import("std");
const assert = std.debug.assert;
const bof = @import("bof_launcher_api");
const beacon = @import("bof_api").beacon;

const State = @import("z-beac0n-core.zig").State;
const BofRes = @import("z-beac0n-core.zig").BofRes;

comptime {
    @import("bof_api").embedFunctionCode("__stackprobe__");
    @import("bof_api").embedFunctionCode("memcpy");
    @import("bof_api").embedFunctionCode("memset");
    @import("bof_api").embedFunctionCode("memmove");
}

pub const netConnectionType = enum(u8) {
    Heartbeat,
    ResourceFetch,
    TaskResult,
};

pub export fn netInit(allocator: *anyopaque) callconv(.c) *anyopaque {
    const alloc: *std.mem.Allocator = @ptrCast(@alignCast(allocator));

    const str = std.mem.join(alloc.*, "TODO", &[_][]const u8{}) catch unreachable;
    return @ptrCast(str);
}

pub export fn netConnect(state: *anyopaque, connectionType: netConnectionType, extra_data: ?*anyopaque) callconv(.c) ?*anyopaque {
    _ = state;
    _ = connectionType;
    _ = extra_data;

    std.log.info("netConnect called", .{});

    return null;
}

pub export fn netDisconnect(state: *anyopaque, net_connection: *anyopaque) callconv(.c) void {
    _ = net_connection;
    _ = state;

    std.log.info("netDisconnect called", .{});
}

pub export fn netExchange(
    state: *anyopaque,
    connectionType: netConnectionType,
    net_connection: *anyopaque,
    len: *u32,
    extra_data: ?*anyopaque,
) callconv(.c) ?*anyopaque {
    _ = state;
    _ = connectionType;
    _ = net_connection;
    _ = len;
    _ = extra_data;

    std.log.info("netExchange called", .{});

    return null;
}

pub export fn netMasquerade(state: *anyopaque, connectionType: netConnectionType, hdr_to_mask: *anyopaque, data_to_mask: ?*anyopaque, len: *u32) callconv(.c) ?*anyopaque {
    _ = state;
    _ = connectionType;
    _ = hdr_to_mask;
    _ = data_to_mask;
    _ = len;

    std.log.info("netMasquerade called", .{});

    return null;
}

pub export fn netUnmasquerade(state: *anyopaque, connectionType: netConnectionType, pkt_data: ?*anyopaque, len: *u32) callconv(.c) ?*anyopaque {
    _ = state;
    _ = connectionType;
    _ = pkt_data;
    _ = len;

    std.log.info("netUnmasquerade called", .{});

    return null;
}

pub export fn go(adata: ?[*]u8, alen: i32) callconv(.c) u8 {
    @import("bof_api").init(adata, alen, .{});
    return 0;
}

fn debugPrint(comptime format: []const u8, args: anytype) void {
    if (true) std.debug.print(format, args);
}
