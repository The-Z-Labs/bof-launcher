const std = @import("std");
const bof_launcher = @import("bof_launcher_api");

extern fn go(_: ?[*]u8, _: i32) callconv(.C) u8;

pub fn main() !void {
    try bof_launcher.initLauncher();
    defer bof_launcher.releaseLauncher();

    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var cmd_args_iter = try std.process.argsWithAllocator(allocator);
    defer cmd_args_iter.deinit();

    const bof_args = try bof_launcher.Args.init();
    defer bof_args.release();

    var file_data: ?[]u8 = null;
    defer if (file_data) |fd| allocator.free(fd);

    bof_args.begin();
    while (cmd_args_iter.next()) |arg| {
        // handle case when file:<filepath> argument is provided
        if (std.mem.indexOf(u8, arg, "file:") != null) {
            var iter = std.mem.tokenize(u8, arg, ":");

            _ = iter.next() orelse return error.BadData;
            const file_path = iter.next() orelse return error.BadData;

            // load file content and remove final '\n' character (if present)

            file_data = try loadFileContent(allocator, @ptrCast(file_path));
            const trimmed_file_data = std.mem.trimRight(u8, file_data.?, "\n");

            const len_str = try std.fmt.allocPrint(allocator, "i:{d}", .{trimmed_file_data.len});
            defer allocator.free(len_str);

            try bof_args.add(len_str);
            try bof_args.add(std.mem.asBytes(&trimmed_file_data.ptr));

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
        std.debug.print("{s}", .{output});
        std.debug.print("==========================================\n", .{});
    }

    std.debug.print("BOF exit code: {d}\n", .{context.getExitCode()});
}

fn loadFileContent(
    allocator: std.mem.Allocator,
    file_path: [:0]const u8,
) ![]u8 {
    const file = try std.fs.openFileAbsoluteZ(file_path, .{});
    defer file.close();

    var file_data = std.ArrayList(u8).init(allocator);
    defer file_data.deinit();

    try file.reader().readAllArrayList(&file_data, 16 * 1024 * 1024);
    //try file_data.append(0);

    return file_data.toOwnedSlice();
}
