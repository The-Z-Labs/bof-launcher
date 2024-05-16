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

    state.number += 1;
    state.handle = w32.GetCurrentProcess();

    return 0;
}
