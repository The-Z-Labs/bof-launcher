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

    return bof.loadAndRun(
        bof_name,
        file_data.ptr,
        @as(i32, @intCast(file_data.len)),
        arg_data_ptr,
        arg_data_len,
        null,
    );
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

    try expect(ctestBasic1(bof_data.ptr, @as(c_int, @intCast(bof_data.len))) == 1);
}

extern fn ctestBasic2(file_data: [*]const u8, file_size: c_int) c_int;
test "bof-launcher.ctest.basic2" {
    try expect(0 == bof.initLauncher());
    defer bof.deinitLauncher();
    const allocator = std.testing.allocator;

    const bof_data = try loadBofFromFile(allocator, "zig-out/bin/test_obj0");
    defer allocator.free(bof_data);

    try expect(ctestBasic2(bof_data.ptr, @as(c_int, @intCast(bof_data.len))) == 1);
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
    try expect(0 == bof.load("test_obj1", bof_data0.ptr, @as(c_int, @intCast(bof_data0.len)), &bof_handle0));
    defer bof.unload(bof_handle0);

    var bof_handle1: bof.Handle = undefined;
    try expect(0 == bof.load("test_obj2", bof_data1.ptr, @as(c_int, @intCast(bof_data1.len)), &bof_handle1));
    defer bof.unload(bof_handle1);

    try expect(1 == bof.isLoaded(bof_handle0));
    try expect(1 == bof.isLoaded(bof_handle1));

    const hex_stream = "1900000004000000373737000d0000002f746d702f746573742e736800030000000500";
    var bytes: [hex_stream.len / 2]u8 = undefined;
    _ = try std.fmt.hexToBytes(&bytes, hex_stream);

    try expect(bof.getOutput(bof_handle0) == null);
    try expect(bof.getOutput(bof_handle1) == null);

    try expect(6 == bof.run(bof_handle0, &bytes, @as(c_int, @intCast(bytes.len))));
    try expect(15 == bof.run(bof_handle1, &bytes, @as(c_int, @intCast(bytes.len))));
    try expect(15 == bof.run(bof_handle1, &bytes, @as(c_int, @intCast(bytes.len))));
    try expect(6 == bof.run(bof_handle0, &bytes, @as(c_int, @intCast(bytes.len))));
    try expect(15 == bof.run(bof_handle1, &bytes, @as(c_int, @intCast(bytes.len))));

    try expect(bof.getOutput(bof_handle0) != null);
    if (bof.getOutput(bof_handle0)) |output| {
        std.debug.print("{s}", .{output});
    }

    bof.clearOutput(bof_handle0);
    try expect(bof.getOutput(bof_handle0) == null);

    try expect(6 == bof.run(bof_handle0, &bytes, @as(c_int, @intCast(bytes.len))));
    try expect(bof.getOutput(bof_handle0) != null);
    if (bof.getOutput(bof_handle0)) |output| {
        std.debug.print("{s}", .{output});
    }

    bof.unload(bof_handle0);
    try expect(bof.run(bof_handle0, &bytes, @as(c_int, @intCast(bytes.len))) < 0);
    try expect(bof.getOutput(bof_handle0) == null);

    bof.unload(bof_handle1);
    bof.unload(bof_handle1);
    try expect(bof.run(bof_handle1, &bytes, @as(c_int, @intCast(bytes.len))) < 0);
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
        try expect(0 == bof.loadAndRun(
            "test",
            bof_data.ptr,
            @as(c_int, @intCast(bof_data.len)),
            null,
            0,
            &bof_handle,
        ));
        if (i == 63) {
            bof.unload(bof_handle);
            try expect(0 == bof.loadAndRun(
                "test",
                bof_data.ptr,
                @as(c_int, @intCast(bof_data.len)),
                null,
                0,
                &bof_handle,
            ));
        }
    }
}

const UserContext = struct {
    id: i32,
    done_event: std.Thread.ResetEvent = .{},
};

fn completionCallback(
    bof_handle: bof.Handle,
    run_result: c_int,
    user_context: ?*anyopaque,
) callconv(.C) void {
    _ = bof_handle;
    _ = run_result;
    const context = @as(*UserContext, @ptrCast(@alignCast(user_context)));
    context.done_event.set();
}

test "bof-launcher.bofs.runAsync" {
    try expect(0 == bof.initLauncher());
    defer bof.deinitLauncher();
    const allocator = std.testing.allocator;

    const bof_data = try loadBofFromFile(allocator, "zig-out/bin/test_async");
    defer allocator.free(bof_data);

    var bof_handle: bof.Handle = undefined;
    try expect(0 == bof.load("test_async", bof_data.ptr, @as(c_int, @intCast(bof_data.len)), &bof_handle));
    defer bof.unload(bof_handle);

    try expect(1 == bof.isLoaded(bof_handle));

    try expect(bof.getOutput(bof_handle) == null);

    var context1 = UserContext{ .id = 1 };
    var context2 = UserContext{ .id = 2 };
    var context3 = UserContext{ .id = 3 };

    var event1: *bof.Event = undefined;
    try expect(0 == bof.runAsync(
        bof_handle,
        @as([*]u8, @ptrCast(@constCast(std.mem.asBytes(&[_]i32{ 8, context1.id })))),
        8,
        null,
        null,
        &event1,
    ));
    defer event1.release();

    try expect(0 == bof.runAsync(
        bof_handle,
        @as([*]u8, @ptrCast(@constCast(std.mem.asBytes(&[_]i32{ 8, context2.id })))),
        8,
        completionCallback,
        @as(*UserContext, @ptrCast(&context2)),
        null,
    ));
    try expect(0 == bof.runAsync(
        bof_handle,
        @as([*]u8, @ptrCast(@constCast(std.mem.asBytes(&[_]i32{ 8, context3.id })))),
        8,
        completionCallback,
        @as(*UserContext, @ptrCast(&context3)),
        null,
    ));

    event1.wait();
    context2.done_event.wait();
    context3.done_event.wait();

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
    try expect(0 == bof.loadAndRun(
        "test_obj3",
        bof_data.ptr,
        @as(c_int, @intCast(bof_data.len)),
        written.ptr,
        @as(i32, @intCast(written.len)),
        &bof_handle,
    ));
    defer bof.unload(bof_handle);

    std.debug.print("{s}", .{bof.getOutput(bof_handle).?});

    try expect(data[0] == 2);
    try expect(data[50] == 0x70de_c0de);
    try expect(data[99] == 113);
}
