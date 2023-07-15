const std = @import("std");
const assert = std.debug.assert;
const bof = @import("bofapi").bof;

fn runBofFromFile(
    allocator: std.mem.Allocator,
    bof_path: [:0]const u8,
    arg_data_ptr: ?[*]u8,
    arg_data_len: i32,
) !u8 {
    const file = std.fs.openFileAbsoluteZ(bof_path, .{}) catch unreachable;
    defer file.close();

    const file_data = file.reader().readAllAlloc(allocator, 16 * 1024 * 1024) catch unreachable;
    defer allocator.free(file_data);

    const object = try bof.Object.initFromMemory(file_data.ptr, @intCast(file_data.len));
    defer object.release();

    const context = try object.run(arg_data_ptr, arg_data_len);
    defer context.release();

    if (context.getOutput()) |output| {
        try std.io.getStdOut().writer().print("{s}", .{output});
    }
    return context.getResult();
}

fn usage(name: [:0]const u8) void {
    const stdout = std.io.getStdOut();
    stdout.writer().print("Usage: {s} <bof>\n", .{name}) catch unreachable;
}

pub fn main() !u8 {
    ///////////////////////////////////////////////////////////
    // heap preparation
    ///////////////////////////////////////////////////////////
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    ///////////////////////////////////////////////////////////
    // command line arguments processing: opening BOF file
    ///////////////////////////////////////////////////////////
    var iter = try std.process.argsWithAllocator(allocator);
    defer iter.deinit();

    const prog_name = iter.next() orelse unreachable;
    const bof_name = iter.next() orelse {
        usage(prog_name);
        return error.BofError;
    };

    var bof_path_buffer: [std.fs.MAX_PATH_BYTES:0]u8 = undefined;
    const absolute_bof_path = std.fs.cwd().realpathZ(bof_name, bof_path_buffer[0..]) catch {
        usage(prog_name);
        return error.BofError;
    };
    bof_path_buffer[absolute_bof_path.len] = 0;

    ///////////////////////////////////////////////////////////
    // initializing bof-launcher
    ///////////////////////////////////////////////////////////
    try bof.initLauncher();
    defer bof.releaseLauncher();

    ///////////////////////////////////////////////////////////
    // command line arguments processing: handling BOF arguments
    ///////////////////////////////////////////////////////////
    const args = try bof.Args.init();
    defer args.release();

    while (iter.next()) |arg| {
        try args.add(arg.ptr, @intCast(arg.len));
    }

    args.finalize();

    ///////////////////////////////////////////////////////////
    // run selected BOF with provided arguments
    ///////////////////////////////////////////////////////////
    const result = try runBofFromFile(
        allocator,
        &bof_path_buffer,
        args.getBuffer(),
        args.getSize(),
    );

    return result;
}
