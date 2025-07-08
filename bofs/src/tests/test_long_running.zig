const std = @import("std");
const bofapi = @import("bof_api");
const beacon = bofapi.beacon;
const w32 = bofapi.win32;

pub export fn go(_: ?[*]u8, _: i32) callconv(.C) u8 {
    _ = beacon.printf(0, "--- test_long_running.zig ---\n");

    if (@import("builtin").os.tag == .windows) {
        const allocator = bofapi.generic_allocator;

        var allocs1 = std.ArrayList([]u8).init(allocator);
        defer {
            for (allocs1.items) |alloc| allocator.free(alloc);
            allocs1.deinit();
        }

        for (0..10) |i| {
            {
                const mem = allocator.alloc(u8, 100 + 123 * i) catch return 1;
                allocs1.append(mem) catch return 1;
                _ = beacon.printf(0, "alloc() returned: 0x%x\n", @intFromPtr(mem.ptr));
                w32.Sleep(0);
            }
            {
                const addr = w32.VirtualAlloc(null, 1024 + i * 1024, w32.MEM_COMMIT | w32.MEM_RESERVE, w32.PAGE_READWRITE);
                if (addr == null) return 2;
                _ = beacon.printf(0, "VirtualAlloc() returned: 0x%x\n", @intFromPtr(addr));
                w32.Sleep(0);
                _ = w32.VirtualFree(addr, 0, w32.MEM_RELEASE);
            }
        }
    }

    return 0;
}
