const builtin = @import("builtin");
const w32_loader = @import("win32_api_loader.zig");

const HMODULE = *opaque {};
const HWND = *opaque {};
const LPCSTR = [*:0]const u8;
const UINT = c_uint;
const LPVOID = *anyopaque;
const SIZE_T = usize;
const DWORD = u32;
const BOOL = c_int;

const MEM_COMMIT = 0x1000;
const MEM_RESERVE = 0x2000;
const MEM_RELEASE = 0x8000;
const PAGE_READWRITE = 0x04;

comptime {
    @export(&wWinMainCRTStartup, .{ .name = "wWinMainCRTStartup" });
}

pub fn wWinMainCRTStartup() callconv(.withStackAlign(.c, 1)) void {
    // Switch from the x87 fpu state set by windows to the state expected by the gnu abi.
    if (builtin.cpu.arch.isX86() and builtin.abi == .gnu) asm volatile ("fninit");

    const kernel32_base: usize = 0x7ffb055e0000;//w32_loader.getDllBase(w32_loader.hash_kernel32);

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
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE,
    );
    defer _ = VirtualFree(mem_addr, 0, MEM_RELEASE);

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
