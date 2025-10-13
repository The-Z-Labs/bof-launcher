const std = @import("std");
const w32 = @import("bof_api").win32;
const beacon = @import("bof_api").beacon;
const posix = @import("bof_api").posix;

fn getTokenInfo(allocator: std.mem.Allocator, token_type: w32.TOKEN_INFORMATION_CLASS) ?*anyopaque {
    _ = allocator;

    var token: w32.HANDLE = undefined;
    if (w32.OpenProcessToken(w32.GetCurrentProcess(), w32.TOKEN_READ, &token) != 0) {
        _ = beacon.printf(.output, "TOKEN OPENED!\n");

        var length: w32.DWORD = 0;
        _ = w32.GetTokenInformation(token, token_type, null, 0, &length);

        _ = beacon.printf(.output, "Length: %d\n", length);
    }
    return null;
}

pub export fn go(adata: ?[*]u8, alen: i32) callconv(.c) u8 {
    @import("bof_api").init(adata, alen, .{});

    const allocator = std.heap.page_allocator;

    if (@import("builtin").os.tag == .windows) {
        _ = getTokenInfo(allocator, .TokenUser);
    } else {
        const euid = posix.geteuid();
        const pwd = posix.getpwuid(euid);
        if (pwd) |p| {
            _ = beacon.printf(.output, "%s", p.name);
        }
    }

    return 0;
}
