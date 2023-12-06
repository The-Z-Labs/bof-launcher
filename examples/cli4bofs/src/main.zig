const std = @import("std");
const assert = std.debug.assert;
const bof = @import("bof_launcher_api");

fn runBofFromFile(
    allocator: std.mem.Allocator,
    bof_path: [:0]const u8,
    arg_data: ?[]u8,
) !u8 {
    const file = std.fs.openFileAbsoluteZ(bof_path, .{}) catch unreachable;
    defer file.close();

    const file_data = file.reader().readAllAlloc(allocator, 16 * 1024 * 1024) catch unreachable;
    defer allocator.free(file_data);

    const object = try bof.Object.initFromMemory(file_data);
    defer object.release();

    const context = try object.runAsyncThread(arg_data, null, null);
    defer context.release();

    context.wait();

    if (context.getOutput()) |output| {
        try std.io.getStdOut().writer().print("{s}", .{output});
    }
    return context.getExitCode();
}

fn usage(name: [:0]const u8) void {
    const stdout = std.io.getStdOut();
    stdout.writer().print("Usage: {s} <BOF> [[prefix:]ARGUMENT]...\n\n", .{name}) catch unreachable;
    stdout.writer().print("Execute given BOF from filesystem with provided ARGUMENTs.\n\n", .{}) catch unreachable;
    stdout.writer().print("ARGUMENTS:\n\n", .{}) catch unreachable;
    stdout.writer().print("ARGUMENT's data type can be specified using one of following prefix:\n", .{}) catch unreachable;
    stdout.writer().print("\tshort OR s\t - 16-bit signed integer.\n", .{}) catch unreachable;
    stdout.writer().print("\tint OR i\t - 32-bit signed integer.\n", .{}) catch unreachable;
    stdout.writer().print("\tstr OR z\t - zero-terminated characters string.\n", .{}) catch unreachable;
    stdout.writer().print("\twstr OR Z\t - zero-terminated wide characters string.\n", .{}) catch unreachable;
    stdout.writer().print("\tfile OR b\t - special type followed by file path indicating that a pointer to a buffer filled with content of the file will be passed to BOF.\n", .{}) catch unreachable;
    stdout.writer().print("\nIf prefix is ommited then ARGUMENT is treated as a zero-terminated characters string (str / z).\n", .{}) catch unreachable;
    stdout.writer().print("\nEXAMPLES:\n\n", .{}) catch unreachable;
    stdout.writer().print("cli4bofs uname -a\n", .{}) catch unreachable;
    stdout.writer().print("cli4bofs udpScanner 192.168.2.2-10:427\n", .{}) catch unreachable;
    stdout.writer().print("cli4bofs udpScanner z:192.168.2.2-10:427\n", .{}) catch unreachable;
    stdout.writer().print("cli4bofs udpScanner 192.168.2.2-10:427 file:/path/to/file/with/udpPayloads\n", .{}) catch unreachable;
}

pub fn main() !u8 {
    const stdout = std.io.getStdOut();
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
        stdout.writer().print("No BOF provided. Aborting.\n\n", .{}) catch unreachable;
        usage(prog_name);
        return 0;
    };

    var bof_path_buffer: [std.fs.MAX_PATH_BYTES:0]u8 = undefined;
    const absolute_bof_path = std.fs.cwd().realpathZ(bof_name, bof_path_buffer[0..]) catch {
        stdout.writer().print("BOF not found. Aborting.\n\n", .{}) catch unreachable;
        usage(prog_name);
        return 0;
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

    args.begin();
    while (iter.next()) |arg| {
        try args.add(arg);
    }
    args.end();

    ///////////////////////////////////////////////////////////
    // run selected BOF with provided arguments
    ///////////////////////////////////////////////////////////
    const result = try runBofFromFile(
        allocator,
        &bof_path_buffer,
        args.getBuffer(),
    );

    stdout.writer().print("BOF exit code: {d}\n", .{result}) catch unreachable;
    return result;
}
