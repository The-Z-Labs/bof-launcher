const std = @import("std");
const WINAPI = std.os.windows.WINAPI;
const HMODULE = std.os.windows.HMODULE;
const HWND = std.os.windows.HWND;
const LPCSTR = std.os.windows.LPCSTR;
const UINT = std.os.windows.UINT;
const sw32 = @import("shellcode_win32.zig");

comptime {
    @export(wWinMainCRTStartup, .{ .name = "wWinMainCRTStartup" });
}

pub fn wWinMainCRTStartup() callconv(.C) void {
    @setAlignStack(16);

    const kernel32_base = sw32.getDllBase(sw32.hash_kernel32);

    const LoadLibraryA: *const fn ([*:0]const u8) callconv(WINAPI) ?HMODULE =
        @ptrFromInt(sw32.getProcAddress(kernel32_base, sw32.hash_LoadLibraryA));

    _ = LoadLibraryA(&str_user32);

    const user32_base = sw32.getDllBase(sw32.hash_user32);

    const MessageBoxA: *const fn (?HWND, ?LPCSTR, ?LPCSTR, UINT) callconv(WINAPI) c_int =
        @ptrFromInt(sw32.getProcAddress(user32_base, sw32.hash_MessageBoxA));

    _ = MessageBoxA(null, null, null, 0);
}

const str_user32: [11:0]u8 linksection(".text") = .{ 'u', 's', 'e', 'r', '3', '2', '.', 'd', 'l', 'l', 0 };
