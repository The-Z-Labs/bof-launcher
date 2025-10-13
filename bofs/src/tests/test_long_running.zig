const std = @import("std");
const bofapi = @import("bof_api");
const beacon = bofapi.beacon;
const w32 = bofapi.win32;

comptime {
    @import("bof_api").embedFunctionCode("memcpy");
}

pub export fn go(adata: ?[*]u8, alen: i32) callconv(.c) u8 {
    @import("bof_api").init(adata, alen, .{});

    const printf = beacon.printf;

    _ = printf(.output, "--- test_long_running.zig ---\n");

    if (@import("builtin").os.tag == .windows) {
        const allocator = std.heap.page_allocator;

        var allocs1 = std.array_list.Managed([]u8).init(allocator);
        defer {
            for (allocs1.items) |alloc| allocator.free(alloc);
            allocs1.deinit();
        }

        for (0..10) |i| {
            {
                const mem = allocator.alloc(u8, 100 + 123 * i) catch return 1;
                allocs1.append(mem) catch return 1;
                _ = printf(.output, "alloc() returned: 0x%x\n", @intFromPtr(mem.ptr));
                w32.Sleep(0);
            }
            {
                const addr = w32.VirtualAlloc(null, 1024 + i * 1024, w32.MEM_COMMIT | w32.MEM_RESERVE, w32.PAGE_READWRITE);
                if (addr == null) return 2;
                _ = printf(.output, "VirtualAlloc() returned: 0x%x\n", @intFromPtr(addr));
                w32.Sleep(0);
                _ = w32.VirtualFree(addr, 0, w32.MEM_RELEASE);
            }
        }
    }

    return 0;
}
