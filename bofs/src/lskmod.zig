///name: lskmod
///description: "Print the currently loaded kernel modules"
///author: Z-Labs
///tags: ['linux','host-recon','z-labs']
///OS: linux
///sources:
///    - 'https://raw.githubusercontent.com/The-Z-Labs/bof-launcher/main/bofs/src/lskmod.zig'
///examples: '
/// lskmod
///'
///errors:
///- name: FaileOpenFailure
///  code: 0x1
///  message: "Failed to open '/proc/modules' file"
///- name: UnknownError
///  code: 0x2
///  message: "Unknown error"
const std = @import("std");
const beacon = @import("bof_api").beacon;
const posix = @import("bof_api").posix;

fn getModulesList(allocator: std.mem.Allocator) !u8 {
    const fd = try std.posix.openZ("/proc/modules", .{ .ACCMODE = .RDONLY, .CLOEXEC = true }, 0);
    defer std.posix.close(fd);

    if (fd == -1)
        return 1;

    const file: std.fs.File = .{ .handle = fd };
    const file_content = try file.readToEndAlloc(allocator, std.math.maxInt(u32));

    std.mem.replaceScalar(u8, file_content, '\n', 0);
    var line_iter = std.mem.splitScalar(u8, file_content, 0);

    while (line_iter.next()) |line| {
        var iter = std.mem.tokenizeScalar(u8, line, ' ');
        const mod_name = iter.next() orelse return error.BadData;
        const mod_size = iter.next() orelse return error.BadData;
        const mod_usage = iter.next() orelse return error.BadData;
        const mod_usedby = iter.next() orelse return error.BadData;

        const mod_entry = try std.mem.joinZ(allocator, " ", &.{
            mod_name,
            mod_size,
            mod_usage,
            mod_usedby,
        });

        _ = beacon.printf.?(.output, "%s\n", mod_entry.ptr);
        allocator.free(mod_entry);
    }

    allocator.free(file_content);
    return 0;
}

pub export fn go() callconv(.C) u8 {
    const allocator = std.heap.page_allocator;

    return getModulesList(allocator) catch 2;
}
