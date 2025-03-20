const beacon = @import("bof_api").beacon;
const w32 = @import("bof_api").win32;

extern fn @"kernel32$VirtualFree"(
    lpAddress: ?w32.LPVOID,
    dwSize: w32.SIZE_T,
    dwFreeType: w32.DWORD,
) callconv(w32.WINAPI) w32.BOOL;

pub export fn go(arg_data: ?[*]u8, arg_len: i32) callconv(.C) u8 {
    _ = beacon.printf(0, "--- test_obj3.zig ---\n");

    if (@import("builtin").os.tag == .windows) {
        w32.Sleep(0);
        _ = beacon.printf(0, "CoGetCurrentProcess() returned: %d\n", w32.CoGetCurrentProcess());
        _ = beacon.printf(0, "GetCurrentProcessId() returned: %d\n", w32.GetCurrentProcessId());
        _ = beacon.printf(0, "GetCurrentProcess() returned: 0x%x\n", @intFromPtr(w32.GetCurrentProcess()));
        _ = beacon.printf(0, "GetCurrentThreadId() returned: %d\n", w32.GetCurrentThreadId());
        _ = beacon.printf(0, "GetCurrentThread() returned: 0x%x\n", @intFromPtr(w32.GetCurrentThread()));

        const addr = w32.VirtualAlloc(
            null,
            1024,
            w32.MEM_COMMIT | w32.MEM_RESERVE,
            w32.PAGE_READWRITE,
        );
        if (addr == null) return 255;
        _ = @"kernel32$VirtualFree"(addr, 0, w32.MEM_RELEASE);

        var tid: w32.DWORD = 123;
        _ = w32.CoGetCallerTID(&tid);
        _ = beacon.printf(0, "CoGetCallerTID() returned: %d\n", tid);

        const i: *u32 = @ptrCast(@alignCast(w32.CoTaskMemAlloc(4)));
        i.* = 0xc0dec0de;
        _ = beacon.printf(0, "CoTaskMemAlloc(): 0x%x\n", i.*);
        w32.CoTaskMemFree(i);
    }

    switch (@import("builtin").cpu.arch) {
        .x86 => _ = beacon.printf(0, "cpu.arch is x86\n"),
        .x86_64 => _ = beacon.printf(0, "cpu.arch is x86_64\n"),
        else => _ = beacon.printf(0, "cpu.arch is unknown\n"),
    }

    switch (@import("builtin").os.tag) {
        .windows => _ = beacon.printf(0, "os.tag is windows\n"),
        .linux => _ = beacon.printf(0, "os.tag is linux\n"),
        else => _ = beacon.printf(0, "os.tag is unknown\n"),
    }

    var parser: beacon.datap = .{};
    beacon.dataParse(&parser, arg_data, arg_len);

    if (beacon.dataLength(&parser) != 6 + 3 * @sizeOf(usize)) return 1;
    if (beacon.dataShort(&parser) != 123) return 1;

    if (beacon.dataLength(&parser) != 4 + 3 * @sizeOf(usize)) return 1;
    if (beacon.dataInt(&parser) != -456) return 1;

    if (beacon.dataLength(&parser) != 3 * @sizeOf(usize)) return 1;
    if (beacon.dataUSize(&parser) != 0xc0de_c0de) return 1;

    if (beacon.dataLength(&parser) != 2 * @sizeOf(usize)) return 1;

    const data = @as([*]i32, @ptrFromInt(beacon.dataUSize(&parser)))[0..beacon.dataUSize(&parser)];
    data[0] += 1;
    data[50] = 0x70de_c0de;
    data[99] -= 10;

    return 0;
}
