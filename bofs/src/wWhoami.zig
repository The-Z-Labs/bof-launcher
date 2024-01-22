const std = @import("std");
const w32 = @import("bof_api").win32;
const beacon = @import("bof_api").beacon;

fn getTokenInfo(allocator: std.mem.Allocator, token_type: w32.TOKEN_INFORMATION_CLASS) ?*anyopaque {
    _ = allocator;

    var token: w32.HANDLE = undefined;
    if (w32.OpenProcessToken(w32.GetCurrentProcess(), w32.TOKEN_READ, &token) != 0) {
        _ = beacon.printf(0, "TOKEN OPENED!\n");

        var length: w32.DWORD = 0;
        _ = w32.GetTokenInformation(token, token_type, null, 0, &length);

        _ = beacon.printf(0, "Length: %d\n", length);
    }
    return null;
}

pub export fn go(_: ?[*]u8, _: i32) callconv(.C) u8 {
    //var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    //defer _ = gpa.deinit();
    //const allocator = gpa.allocator();

    const allocator = std.heap.page_allocator;

    _ = getTokenInfo(allocator, .TokenUser);

    return 0;
}
