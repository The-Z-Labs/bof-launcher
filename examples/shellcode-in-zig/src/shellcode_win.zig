const std = @import("std");
const w32 = std.os.windows;
const HMODULE = w32.HMODULE;
const HWND = w32.HWND;
const LPCSTR = w32.LPCSTR;
const UINT = w32.UINT;
const LPVOID = w32.LPVOID;
const SIZE_T = w32.SIZE_T;
const DWORD = w32.DWORD;
const BOOL = w32.BOOL;
const w32_loader = @import("win32_api_loader.zig");

comptime {
    @export(&wWinMainCRTStartup, .{ .name = "wWinMainCRTStartup" });
}

pub fn wWinMainCRTStartup() callconv(.c) void {
    const kernel32_base = w32_loader.getDllBase(w32_loader.hash_kernel32);

    const LoadLibraryA: *const fn ([*:0]const u8) callconv(.winapi) ?HMODULE =
        @ptrFromInt(w32_loader.getProcAddress(kernel32_base, w32_loader.hash_LoadLibraryA));

    _ = LoadLibraryA(&str_user32);

    const user32_base = w32_loader.getDllBase(w32_loader.hash_user32);

    const MessageBoxA: *const fn (?HWND, ?LPCSTR, ?LPCSTR, UINT) callconv(.winapi) c_int =
        @ptrFromInt(w32_loader.getProcAddress(user32_base, w32_loader.hash_MessageBoxA));

    const VirtualAlloc: *const fn (?LPVOID, SIZE_T, DWORD, DWORD) callconv(.winapi) ?LPVOID =
        @ptrFromInt(w32_loader.getProcAddress(kernel32_base, w32_loader.hash_VirtualAlloc));

    const VirtualFree: *const fn (?LPVOID, SIZE_T, DWORD) callconv(.winapi) BOOL =
        @ptrFromInt(w32_loader.getProcAddress(kernel32_base, w32_loader.hash_VirtualFree));

    const mem_size = 64 * 1024;
    const mem_addr = VirtualAlloc(
        null,
        mem_size,
        w32.MEM_COMMIT | w32.MEM_RESERVE,
        w32.PAGE_READWRITE,
    );
    defer _ = VirtualFree(mem_addr, 0, w32.MEM_RELEASE);

    const mem = @as([*]u8, @ptrCast(mem_addr))[0..mem_size];

    mem[0] = 0;
    mem[64] = 64;
    mem[128] = 128;

    if (mem[0] != 0) _ = MessageBoxA(null, null, null, 0);
    if (mem[64] != 64) _ = MessageBoxA(null, null, null, 0);
    if (mem[128] != 128) _ = MessageBoxA(null, null, null, 0);

    _ = MessageBoxA(null, &str_shellcode, &str_example, 0);
}

const str_user32: [11:0]u8 linksection(".text") = .{ 'u', 's', 'e', 'r', '3', '2', '.', 'd', 'l', 'l', 0 };
const str_example: [8:0]u8 linksection(".text") = .{ 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0 };
const str_shellcode: [10:0]u8 linksection(".text") = .{ 's', 'h', 'e', 'l', 'l', 'c', 'o', 'd', 'e', 0 };
