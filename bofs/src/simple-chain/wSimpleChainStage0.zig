const std = @import("std");
const beacon = @import("bof_api").beacon;
const w32 = @import("bof_api").win32;
const shared = @import("wSimpleChainShared.zig");

pub export fn go(args: ?[*]u8, args_len: i32) callconv(.C) u8 {
    var parser = beacon.datap{};
    beacon.dataParse(&parser, args, args_len);

    var state: *shared.State = blk: {
        const mem = beacon.dataExtract(&parser, null).?[0..@sizeOf(usize)];
        break :blk @ptrFromInt(std.mem.readInt(usize, mem, .little));
    };

    var obj_attribs = w32.OBJECT_ATTRIBUTES{
        .Length = @sizeOf(w32.OBJECT_ATTRIBUTES),
        .RootDirectory = null,
        .ObjectName = null,
        .Attributes = w32.OBJ_INHERIT,
        .SecurityDescriptor = null,
        .SecurityQualityOfService = null,
    };
    var client_id = w32.CLIENT_ID{
        .UniqueProcess = @ptrFromInt(state.process_id),
        .UniqueThread = null,
    };
    state.nt_status = w32.NtOpenProcess(
        &state.process_handle,
        w32.PROCESS_CREATE_THREAD | w32.PROCESS_VM_OPERATION | w32.PROCESS_VM_WRITE,
        &obj_attribs,
        &client_id,
    );

    return 0;
}
