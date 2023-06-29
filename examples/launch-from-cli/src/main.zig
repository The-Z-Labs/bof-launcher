const std = @import("std");
const assert = std.debug.assert;
const bof = @import("bofapi").bof;

fn runBofFromFile(
    allocator: std.mem.Allocator,
    bof_name: [:0]const u8,
    bof_path: [:0]const u8,
    arg_data_ptr: ?[*]u8,
    arg_data_len: i32,
) c_int {
    const file = std.fs.openFileAbsoluteZ(bof_path, .{}) catch unreachable;
    defer file.close();

    const file_data = file.reader().readAllAlloc(allocator, 16 * 1024 * 1024) catch unreachable;
    defer allocator.free(file_data);

    var bof_handle: bof.Handle = undefined;
    const result = bof.loadAndRun(
        bof_name,
        file_data.ptr,
        @as(i32, @intCast(file_data.len)),
        arg_data_ptr,
        arg_data_len,
        &bof_handle,
    );
    defer bof.unload(bof_handle);

    if (bof.getOutput(bof_handle)) |output| {
        std.io.getStdOut().writer().print("{s}", .{output}) catch unreachable;
    }
    return result;
}

fn usage(name: [:0]const u8) void {
    const stdout = std.io.getStdOut();
    stdout.writer().print("Usage: {s} <bof>\n", .{name}) catch unreachable;
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
    if (bof.initLauncher() < 0) {
        stdout.writer().print("Failed to init 'bof launcher' library\n", .{}) catch unreachable;
        return error.BofError;
    }
    defer bof.deinitLauncher();

    ///////////////////////////////////////////////////////////
    // command line arguments processing: handling BOF arguments
    ///////////////////////////////////////////////////////////
    var params_blob: []u8 = undefined;
    var params: bof.ArgData = .{};

    var initialized: bool = false;
    while (iter.next()) |arg| {
        if (!initialized) {
            params_blob = try allocator.alloc(u8, 100);

            params.original = params_blob.ptr;
            params.buffer = params_blob.ptr + 4;
            params.length = @as(i32, @intCast(params_blob.len - 4));
            params.size = @as(i32, @intCast(params_blob.len));

            initialized = true;
        }
        _ = bof.packArg(&params, arg.ptr, @as(c_int, @intCast(arg.len)));
    }

    if (initialized) {
        // update size to real length of arguments string
        params.size = params.size - params.length;

        const len = params.size - 4;
        std.mem.copy(u8, params.original[0..4], std.mem.asBytes(&len));
    }

    ///////////////////////////////////////////////////////////
    // run selected BOF with provided arguments
    ///////////////////////////////////////////////////////////
    const result = runBofFromFile(allocator, bof_name, &bof_path_buffer, params.original, params.size);

    if (initialized) allocator.free(params_blob);

    if (result < 0 or result > 255) {
        stdout.writer().print("Failed to run bof\n", .{}) catch unreachable;
        return error.BofError;
    }

    return @as(u8, @intCast(result));
}
