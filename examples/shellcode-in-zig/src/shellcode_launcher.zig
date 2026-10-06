const w32 = @import("bof_launcher_win32");
const std = @import("std");

pub fn main(init: std.process.Init) !void {
    const allocator = init.gpa;
    const arena = init.arena.allocator();
    const io = init.io;

    const cmdline_args = (try init.minimal.args.toSlice(arena))[1..];
    if (cmdline_args.len != 1) {
        usage();
        return;
    }
    const shellcode_file = cmdline_args[0];

    const file = try std.Io.Dir.openFile(.cwd(), io, shellcode_file, .{});
    defer file.close(io);

    const file_stat = try file.stat(io);
    const file_data = try allocator.alloc(u8, @intCast(file_stat.size));
    defer allocator.free(file_data);

    var file_reader = file.reader(io, &.{});
    try file_reader.interface.readSliceAll(file_data);

    if (@import("builtin").os.tag == .windows) {
        // Extract .text section from input executable.
        const parser = try std.coff.Coff.init(file_data, false);
        const text_header = parser.getSectionByName(".text") orelse unreachable;
        const text_data = parser.getSectionData(text_header);

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

        @as(*const fn () callconv(.c) void, @ptrCast(section.ptr))();
    } else {
        const img = try std.posix.mmap(
            null,
            file_data.len,
            .{ .READ = true, .EXEC = true, .WRITE = true },
            .{ .TYPE = .PRIVATE, .ANONYMOUS = true },
            -1,
            0,
        );
        @memcpy(img, file_data);

        @as(*const fn () callconv(.c) void, @ptrCast(img))();
    }
}

fn usage() void {
    std.log.info(
        \\
        \\ USAGE:
        \\      shellcode_launcher <shellcode_exe_file>
        \\
    , .{});
}
