const std = @import("std");
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
    _ = bof.load(bof_name, file_data.ptr, @intCast(file_data.len), &bof_handle);
    defer bof.unload(bof_handle);

    return bof.run(bof_handle, arg_data_ptr, arg_data_len);
}

fn testRunBofFromFile(
    bof_path: [:0]const u8,
    arg_data_ptr: ?[*]u8,
    arg_data_len: i32,
) !c_int {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();

    const allocator = gpa.allocator();

    const pathname = try std.mem.join(allocator, ".", &.{
        bof_path,
        if (@import("builtin").os.tag == .windows) "coff" else "elf",
        if (@import("builtin").cpu.arch == .x86_64) "x64" else "x86",
        "o",
    });
    defer allocator.free(pathname);

    var bof_path_buffer: [std.fs.MAX_PATH_BYTES:0]u8 = undefined;
    const absolute_bof_path = try std.fs.cwd().realpath(pathname, bof_path_buffer[0..]);
    bof_path_buffer[absolute_bof_path.len] = 0;

    return runBofFromFile(allocator, bof_path, &bof_path_buffer, arg_data_ptr, arg_data_len);
}

fn loadBofFromFile(allocator: std.mem.Allocator, bof_name: [:0]const u8) ![]u8 {
    const pathname = try std.mem.join(allocator, ".", &.{
        bof_name,
        if (@import("builtin").os.tag == .windows) "coff" else "elf",
        if (@import("builtin").cpu.arch == .x86_64) "x64" else "x86",
        "o",
    });
    defer allocator.free(pathname);

    var bof_path: [std.fs.MAX_PATH_BYTES:0]u8 = undefined;
    const absolute_bof_path = try std.fs.cwd().realpath(pathname, bof_path[0..]);
    bof_path[absolute_bof_path.len] = 0;

    const file = try std.fs.openFileAbsoluteZ(&bof_path, .{});
    defer file.close();

    return try file.reader().readAllAlloc(allocator, 16 * 1024 * 1024);
}

const expect = std.testing.expect;

test "bof-launcher.basic" {
    try expect(0 == bof.initLauncher());
    defer bof.deinitLauncher();

    // | Len (of whole string) | strAlen | strA\0 | strBlen | strB\0 | i32 = 3 | i16 = 5 |
    const hex_stream = "1900000004000000373737000d0000002f746d702f746573742e736800030000000500";
    var bytes: [hex_stream.len / 2]u8 = undefined;
    _ = try std.fmt.hexToBytes(&bytes, hex_stream);

    try expect(0 == try testRunBofFromFile("zig-out/bin/test_obj0", null, 0));
    try expect(123 == try testRunBofFromFile("zig-out/bin/test_beacon_format", &bytes, bytes.len));

    {
        try expect(0 == bof.initLauncher());
        defer bof.deinitLauncher();
        try expect(6 == try testRunBofFromFile("zig-out/bin/test_obj1", &bytes, bytes.len));
        try expect(15 == try testRunBofFromFile("zig-out/bin/test_obj2", &bytes, bytes.len));
        try expect(0 == try testRunBofFromFile("zig-out/bin/test_obj0", null, 0));
    }

    {
        bof.deinitLauncher();
        try expect(0 == bof.initLauncher());
        defer bof.deinitLauncher();
        try expect(6 == try testRunBofFromFile("zig-out/bin/test_obj1", &bytes, bytes.len));
        try expect(0 == try testRunBofFromFile("zig-out/bin/test_obj0", null, 0));
        try expect(6 == try testRunBofFromFile("zig-out/bin/test_obj1", &bytes, bytes.len));
        try expect(0 == try testRunBofFromFile("zig-out/bin/test_obj4", &bytes, bytes.len));
    }

    try expect(15 == try testRunBofFromFile("zig-out/bin/test_obj2", &bytes, bytes.len));
    try expect(123 == try testRunBofFromFile("zig-out/bin/test_beacon_format", &bytes, bytes.len));
    try expect(0 == try testRunBofFromFile("zig-out/bin/test_obj0", null, 0));
}

test "bof-launcher.beacon.format" {
    try expect(0 == bof.initLauncher());
    defer bof.deinitLauncher();

    const hex_stream = "1900000004000000373737000d0000002f746d702f746573742e736800030000000500";
    var bytes: [hex_stream.len / 2]u8 = undefined;
    _ = try std.fmt.hexToBytes(&bytes, hex_stream);

    try expect(123 == try testRunBofFromFile("zig-out/bin/test_beacon_format", &bytes, bytes.len));
}

extern fn ctestBasic0() c_int;
test "bof-launcher.ctest.basic0" {
    try expect(0 == bof.initLauncher());
    defer bof.deinitLauncher();
    try expect(ctestBasic0() == 1);
}

extern fn ctestBasic1(file_data: [*]const u8, file_size: c_int) c_int;
test "bof-launcher.ctest.basic1" {
    try expect(0 == bof.initLauncher());
    defer bof.deinitLauncher();

    const allocator = std.testing.allocator;

    const bof_data = try loadBofFromFile(allocator, "zig-out/bin/test_obj0");
    defer allocator.free(bof_data);

    try expect(ctestBasic1(bof_data.ptr, @intCast(bof_data.len)) == 1);
}

extern fn ctestBasic2(file_data: [*]const u8, file_size: c_int) c_int;
test "bof-launcher.ctest.basic2" {
    try expect(0 == bof.initLauncher());
    defer bof.deinitLauncher();
    const allocator = std.testing.allocator;

    const bof_data = try loadBofFromFile(allocator, "zig-out/bin/test_obj0");
    defer allocator.free(bof_data);

    try expect(ctestBasic2(bof_data.ptr, @intCast(bof_data.len)) == 1);
}

test "bof-launcher.bofs.load_run" {
    try expect(0 == bof.initLauncher());
    defer bof.deinitLauncher();
    const allocator = std.testing.allocator;

    const bof_data0 = try loadBofFromFile(allocator, "zig-out/bin/test_obj1");
    defer allocator.free(bof_data0);

    const bof_data1 = try loadBofFromFile(allocator, "zig-out/bin/test_obj2");
    defer allocator.free(bof_data1);

    var bof_handle0: bof.Handle = undefined;
    try expect(0 == bof.load("test_obj1", bof_data0.ptr, @intCast(bof_data0.len), &bof_handle0));
    defer bof.unload(bof_handle0);

    var bof_handle1: bof.Handle = undefined;
    try expect(0 == bof.load("test_obj2", bof_data1.ptr, @intCast(bof_data1.len), &bof_handle1));
    defer bof.unload(bof_handle1);

    try expect(1 == bof.isLoaded(bof_handle0));
    try expect(1 == bof.isLoaded(bof_handle1));

    const hex_stream = "1900000004000000373737000d0000002f746d702f746573742e736800030000000500";
    var bytes: [hex_stream.len / 2]u8 = undefined;
    _ = try std.fmt.hexToBytes(&bytes, hex_stream);

    try expect(bof.getOutput(bof_handle0) == null);
    try expect(bof.getOutput(bof_handle1) == null);

    try expect(6 == bof.run(bof_handle0, &bytes, @intCast(bytes.len)));
    try expect(15 == bof.run(bof_handle1, &bytes, @intCast(bytes.len)));
    try expect(15 == bof.run(bof_handle1, &bytes, @intCast(bytes.len)));
    try expect(6 == bof.run(bof_handle0, &bytes, @intCast(bytes.len)));
    try expect(15 == bof.run(bof_handle1, &bytes, @intCast(bytes.len)));

    try expect(bof.getOutput(bof_handle0) != null);
    if (bof.getOutput(bof_handle0)) |output| {
        std.debug.print("{s}", .{output});
    }

    bof.clearOutput(bof_handle0);
    try expect(bof.getOutput(bof_handle0) == null);

    try expect(6 == bof.run(bof_handle0, &bytes, @intCast(bytes.len)));
    try expect(bof.getOutput(bof_handle0) != null);
    if (bof.getOutput(bof_handle0)) |output| {
        std.debug.print("{s}", .{output});
    }

    bof.unload(bof_handle0);
    try expect(bof.run(bof_handle0, &bytes, @intCast(bytes.len)) < 0);
    try expect(bof.getOutput(bof_handle0) == null);

    bof.unload(bof_handle1);
    bof.unload(bof_handle1);
    try expect(bof.run(bof_handle1, &bytes, @intCast(bytes.len)) < 0);
    try expect(bof.getOutput(bof_handle1) == null);

    try expect(0 == bof.isLoaded(bof_handle0));
    try expect(0 == bof.isLoaded(bof_handle1));
}

test "bof-launcher.stress" {
    const allocator = std.testing.allocator;

    const bof_data = try loadBofFromFile(allocator, "zig-out/bin/test_obj0");
    defer allocator.free(bof_data);

    try expect(0 == bof.initLauncher());
    defer bof.deinitLauncher();

    for (0..64) |i| {
        var bof_handle: bof.Handle = undefined;
        try expect(0 == bof.load(
            "test",
            bof_data.ptr,
            @intCast(bof_data.len),
            &bof_handle,
        ));
        try expect(0 == bof.run(bof_handle, null, 0));
        if (i == 63) {
            bof.unload(bof_handle);
            try expect(0 == bof.load(
                "test",
                bof_data.ptr,
                @intCast(bof_data.len),
                &bof_handle,
            ));
            try expect(0 == bof.run(bof_handle, null, 0));
        }
    }
}

test "bof-launcher.bofs.runAsync" {
    try expect(0 == bof.initLauncher());
    defer bof.deinitLauncher();
    const allocator = std.testing.allocator;

    const bof_data = try loadBofFromFile(allocator, "zig-out/bin/test_async");
    defer allocator.free(bof_data);

    var bof_handle: bof.Handle = undefined;
    try expect(0 == bof.load("test_async", bof_data.ptr, @intCast(bof_data.len), &bof_handle));
    defer bof.unload(bof_handle);

    try expect(1 == bof.isLoaded(bof_handle));

    try expect(bof.getOutput(bof_handle) == null);

    var bof_context1: *bof.Context = undefined;
    try expect(0 == bof.runAsync(
        bof_handle,
        @ptrCast(@constCast(std.mem.asBytes(&[_]i32{ 8, 1 }))),
        8,
        null,
        null,
        &bof_context1,
    ));
    defer bof_context1.release();

    var bof_context2: *bof.Context = undefined;
    try expect(0 == bof.runAsync(
        bof_handle,
        @ptrCast(@constCast(std.mem.asBytes(&[_]i32{ 8, 2 }))),
        8,
        null,
        null,
        &bof_context2,
    ));
    defer bof_context2.release();

    var bof_context3: *bof.Context = undefined;
    try expect(0 == bof.runAsync(
        bof_handle,
        @ptrCast(@constCast(std.mem.asBytes(&[_]i32{ 8, 3 }))),
        8,
        null,
        null,
        &bof_context3,
    ));
    defer bof_context3.release();

    bof_context1.wait();
    bof_context2.wait();
    bof_context3.wait();

    try expect(bof_context1.isRunning() == false);
    try expect(bof_context2.isRunning() == false);
    try expect(bof_context3.isRunning() == false);

    std.debug.print("{s}", .{bof.getOutput(bof_handle).?});
}

test "bof-launcher.info" {
    try expect(0 == bof.initLauncher());
    defer bof.deinitLauncher();

    var buf: [512]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    const stream = fbs.writer();

    const allocator = std.testing.allocator;

    const data = try allocator.alloc(i32, 100);
    defer allocator.free(data);

    data[0] = 1;
    data[50] = 50;
    data[99] = 123;

    try stream.writeAll(std.mem.asBytes(&@as(i32, 10 + 3 * @sizeOf(usize))));
    try stream.writeAll(std.mem.asBytes(&@as(i16, 123)));
    try stream.writeAll(std.mem.asBytes(&@as(i32, -456)));
    try stream.writeAll(std.mem.asBytes(&@as(usize, 0xc0de_c0de)));

    // Pass a slice
    try stream.writeAll(std.mem.asBytes(&@intFromPtr(data.ptr)));
    try stream.writeAll(std.mem.asBytes(&data.len));

    const written = fbs.getWritten();

    try expect(written.len == 10 + 3 * @sizeOf(usize));

    const bof_data = try loadBofFromFile(allocator, "zig-out/bin/test_obj3");
    defer allocator.free(bof_data);

    var bof_handle: bof.Handle = undefined;
    try expect(0 == bof.load(
        "test_obj3",
        bof_data.ptr,
        @intCast(bof_data.len),
        &bof_handle,
    ));
    defer bof.unload(bof_handle);

    try expect(0 == bof.run(
        bof_handle,
        written.ptr,
        @intCast(written.len),
    ));

    std.debug.print("{s}", .{bof.getOutput(bof_handle).?});

    try expect(data[0] == 2);
    try expect(data[50] == 0x70de_c0de);
    try expect(data[99] == 113);
}
