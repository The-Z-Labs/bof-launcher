const w32 = @import("bof_api").win32;
const beacon = @import("bof_api").beacon;

fn getTokenInfo(token_type: w32.TOKEN_INFORMATION_CLASS) ?*anyopaque {
    _ = token_type;
    var token: w32.HANDLE = undefined;
    if (w32.OpenProcessToken(w32.GetCurrentProcess(), w32.TOKEN_READ, &token) == w32.TRUE) {
        _ = beacon.printf(
            0,
            "TOKEN OPENED!\n",
        );
    }
    return null;
}

pub export fn go(_: ?[*]u8, _: i32) callconv(.C) u8 {
    _ = getTokenInfo(.TokenUser);
    return 0;
}
