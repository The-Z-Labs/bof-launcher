const std = @import("std");
const bof_launcher = @import("bof_launcher_api");

extern fn go(?[*]u8, i32) callconv(.c) u8;

pub fn main(init: std.process.Init) !void {
    try bof_launcher.initLauncher();
    defer bof_launcher.releaseLauncher();

    const arena = init.arena.allocator();
    const allocator = init.gpa;

    const cmdline_args = (try init.minimal.args.toSlice(arena))[1..];

    const bof_args = try bof_launcher.Args.init();
    defer bof_args.release();

    var file_data: ?[]const u8 = null;
    defer if (file_data) |fd| allocator.free(fd);

    bof_args.begin();
    for (cmdline_args) |arg| {
        // handle case when file:<filepath> argument is provided
        if (std.mem.indexOf(u8, arg, "file:") != null) {
            var iter = std.mem.tokenizeScalar(u8, arg, ':');

            _ = iter.next() orelse return error.BadData;
            const file_path = iter.next() orelse return error.BadData;

            file_data = try loadFileContent(allocator, init.io, file_path);

            const len_str = try std.fmt.allocPrint(allocator, "i:{d}", .{file_data.?.len});
            defer allocator.free(len_str);

            try bof_args.add(len_str);
            try bof_args.add(std.mem.asBytes(&file_data.?.ptr));

            continue;
        }
        try bof_args.add(arg);
    }
    bof_args.end();

    var context: *bof_launcher.Context = undefined;
    const res = bof_launcher.bofDebugRun(
        go,
        if (bof_launcher.bofArgsGetBuffer(bof_args)) |args| args else null,
        bof_launcher.bofArgsGetBufferSize(bof_args),
        &context,
    );
    if (res != 0) {
        std.debug.print("Failed to run BOF (error code: {d})\n", .{res});
        return;
    }
    defer context.release();

    if (context.getOutput()) |output| {
        std.debug.print("==========================================\n", .{});
        std.debug.print("{s}\n", .{output});
        std.debug.print("==========================================\n", .{});
    }

    std.debug.print("BOF exit code: {d}\n", .{context.getExitCode()});
}

fn loadFileContent(
    allocator: std.mem.Allocator,
    io: std.Io,
    file_path: []const u8,
) ![]const u8 {
    const file = try std.Io.Dir.openFileAbsolute(io, file_path, .{});
    defer file.close(io);

    const file_stat = try file.stat(io);
    const file_data = try allocator.alloc(u8, @intCast(file_stat.size));
    errdefer allocator.free(file_data);

    var file_reader = file.reader(io, &.{});
    try file_reader.interface.readSliceAll(file_data);

    return file_data;
}
