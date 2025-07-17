const std = @import("std");
const w32 = @import("bof_api").win32;

comptime {
    @import("bof_api").includeFunctionCode("memcpy");
}

pub export fn go(_: ?[*]u8, _: i32) callconv(.C) u8 {
    var name_buf: [128:0]u8 = undefined;
    const name_len = w32.GetModuleFileNameA.?(null, &name_buf, 128);
    const name = if (name_len == 0) "unknown" else name_buf[0..name_len];

    var buf: [1024]u8 = undefined;
    const info = std.fmt.bufPrintZ(
        buf[0..],
        \\Hi, I'm a simple BOF that has been injected to a process:
        \\
        \\GetModuleFileNameA() --> {s}
        \\GetCurrentProcessId() --> {d}
        \\GetCurrentThreadId() --> {d}
    ,
        .{ name, w32.GetCurrentProcessId.?(), w32.GetCurrentThreadId.?() },
    ) catch unreachable;

    // Try to find application window
    _ = w32.EnumWindows.?(enumWindows, 0);

    _ = w32.MessageBoxA.?(window, info.ptr, "wProcessInfoMessageBox BOF", w32.MB_SYSTEMMODAL | w32.MB_ICONASTERISK);

    return 0;
}

var window: ?w32.HWND = null;

fn enumWindows(hwnd: w32.HWND, _: w32.LPARAM) callconv(.winapi) w32.BOOL {
    var process_id: w32.DWORD = undefined;
    _ = w32.GetWindowThreadProcessId.?(hwnd, &process_id);

    if (process_id == w32.GetCurrentProcessId.?()) {
        window = hwnd;
        return w32.FALSE;
    }
    return w32.TRUE;
}
