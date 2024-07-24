const w32 = @import("bof_api").win32;

pub fn main() !void {
    const text_data = @embedFile("shellcode_in_zig_win_x64.bin");

    const addr = w32.VirtualAlloc(
        null,
        text_data.len,
        w32.MEM_COMMIT | w32.MEM_RESERVE,
        w32.PAGE_READWRITE,
    );
    defer _ = w32.VirtualFree(addr, 0, w32.MEM_RELEASE);

    const section = @as([*]u8, @ptrCast(addr))[0..text_data.len];

    @memcpy(section, text_data);

    var old_protection: w32.DWORD = 0;
    if (w32.VirtualProtect(
        section.ptr,
        section.len,
        w32.PAGE_EXECUTE_READ,
        &old_protection,
    ) == w32.FALSE) return error.VirtualProtectFailed;

    _ = w32.FlushInstructionCache(w32.GetCurrentProcess(), section.ptr, section.len);

    // Call our shellcode
    @as(*const fn () callconv(.C) void, @ptrCast(section.ptr))();
}
