const std = @import("std");
const bof = @import("bof_launcher_api");

fn runBofFromFile(
    allocator: std.mem.Allocator,
    bof_path: [:0]const u8,
    arg_data_ptr: ?[*]u8,
    arg_data_len: i32,
) !*bof.Context {
    const file = try std.fs.openFileAbsoluteZ(bof_path, .{});
    defer file.close();

    const file_data = try file.reader().readAllAlloc(allocator, 16 * 1024 * 1024);
    defer allocator.free(file_data);

    const object = try bof.Object.initFromMemory(file_data);
    defer object.release();

    const context = try object.run(
        if (arg_data_ptr) |d| d[0..@intCast(arg_data_len)] else null,
    );

    return context;
}

fn testRunBofFromFile(
    bof_path: [:0]const u8,
    arg_data_ptr: ?[*]u8,
    arg_data_len: i32,
) !*bof.Context {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();

    const allocator = gpa.allocator();

    const pathname = try std.mem.join(allocator, ".", &.{
        bof_path,
        if (@import("builtin").os.tag == .windows) "coff" else "elf",
        switch (@import("builtin").cpu.arch) {
            .x86_64 => "x64.o",
            .x86 => "x86.o",
            .aarch64 => "aarch64.o",
            .arm => "arm.o",
            else => unreachable,
        },
    });
    defer allocator.free(pathname);

    var bof_path_buffer: [std.fs.max_path_bytes:0]u8 = undefined;
    const absolute_bof_path = try std.fs.cwd().realpath(pathname, bof_path_buffer[0..]);
    bof_path_buffer[absolute_bof_path.len] = 0;

    return runBofFromFile(allocator, &bof_path_buffer, arg_data_ptr, arg_data_len);
}

fn loadBofFromFile(allocator: std.mem.Allocator, bof_name: [:0]const u8) ![]u8 {
    const pathname = try std.mem.join(allocator, ".", &.{
        bof_name,
        if (@import("builtin").os.tag == .windows) "coff" else "elf",
        switch (@import("builtin").cpu.arch) {
            .x86_64 => "x64.o",
            .x86 => "x86.o",
            .aarch64 => "aarch64.o",
            .arm => "arm.o",
            else => unreachable,
        },
    });
    defer allocator.free(pathname);

    var bof_path: [std.fs.max_path_bytes:0]u8 = undefined;
    const absolute_bof_path = try std.fs.cwd().realpath(pathname, bof_path[0..]);
    bof_path[absolute_bof_path.len] = 0;

    const file = try std.fs.openFileAbsoluteZ(&bof_path, .{});
    defer file.close();

    return try file.reader().readAllAlloc(allocator, 16 * 1024 * 1024);
}

const expect = std.testing.expect;

test "bof-launcher.basic" {
    try bof.initLauncher();
    defer bof.releaseLauncher();

    // | Len (of whole string) | strAlen | strA\0 | strBlen | strB\0 | i32 = 3 | i16 = 5 |
    const hex_stream = "1900000004000000373737000d0000002f746d702f746573742e736800030000000500";
    var bytes: [hex_stream.len / 2]u8 = undefined;
    _ = try std.fmt.hexToBytes(&bytes, hex_stream);

    {
        const context = try testRunBofFromFile("zig-out/bin/test_obj0", null, 0);
        defer context.release();
        try expect(context.getExitCode() == 0);
        try std.testing.expectEqualStrings("--- test_obj0.zig ---\n", context.getOutput().?[0..22]);
        try std.testing.expectEqualStrings("Hello, go!\n", context.getOutput().?[22..][0..11]);
        try std.testing.expectEqualStrings("func() it\n", context.getOutput().?[22..][11..][0..10]);
    }
    {
        const context = try testRunBofFromFile("zig-out/bin/test_beacon_format", &bytes, bytes.len);
        defer context.release();
        try expect(context.getExitCode() == 123);
        try std.testing.expectEqualStrings("--- testBeaconFormat.c ---\n", context.getOutput().?[0..27]);
        try std.testing.expectEqualStrings("!!!! Start testBeaconFormat !!!!\n", context.getOutput().?[27..][0..33]);
        try std.testing.expectEqualStrings(
            "BeaconFormat test with end of string (EOS) issue:\n",
            context.getOutput().?[27..][33..][0..50],
        );
        try std.testing.expectEqualStrings(
            "The user passed in the integer: 13\n",
            context.getOutput().?[27..][33..][50..][0..35],
        );
        try std.testing.expectEqualStrings(
            "The user passed in the string: 777\n",
            context.getOutput().?[27..][33..][50..][35..][0..35],
        );
    }

    {
        try bof.initLauncher();
        defer bof.releaseLauncher();
        {
            const context = try testRunBofFromFile("zig-out/bin/test_obj1", &bytes, bytes.len);
            defer context.release();
            try expect(context.getExitCode() == 6);
            try std.testing.expectEqualStrings("--- test_obj1.zig ---\n", context.getOutput().?[0..22]);
            try std.testing.expectEqualStrings("BeaconPrintf has been called\n", context.getOutput().?[22..][0..29]);
        }
        {
            const context = try testRunBofFromFile("zig-out/bin/test_obj2", &bytes, bytes.len);
            defer context.release();
            try expect(context.getExitCode() == 15);
            try std.testing.expectEqualStrings("--- test_obj2.c ---\n", context.getOutput().?[0..20]);
            try std.testing.expectEqualStrings("bof\n", context.getOutput().?[20..][0..4]);
            try std.testing.expectEqualStrings("arg_len (from go): 35\n", context.getOutput().?[20..][4..][0..22]);
            try std.testing.expectEqualStrings("Length: (from go): 31\n", context.getOutput().?[20..][4..][22..][0..22]);
        }
        {
            const context = try testRunBofFromFile("zig-out/bin/test_obj0", null, 0);
            defer context.release();
            try expect(context.getExitCode() == 0);
            try std.testing.expectEqualStrings("--- test_obj0.zig ---\n", context.getOutput().?[0..22]);
            try std.testing.expectEqualStrings("Hello, go!\n", context.getOutput().?[22..][0..11]);
            try std.testing.expectEqualStrings("func() it\n", context.getOutput().?[22..][11..][0..10]);
        }
    }

    {
        bof.releaseLauncher();
        try bof.initLauncher();
        defer bof.releaseLauncher();
        {
            const context = try testRunBofFromFile("zig-out/bin/test_obj1", &bytes, bytes.len);
            defer context.release();
            try expect(context.getExitCode() == 6);
            try std.testing.expectEqualStrings("--- test_obj1.zig ---\n", context.getOutput().?[0..22]);
            try std.testing.expectEqualStrings("BeaconPrintf has been called\n", context.getOutput().?[22..][0..29]);
        }
        {
            const context = try testRunBofFromFile("zig-out/bin/test_obj0", null, 0);
            defer context.release();
            try expect(context.getExitCode() == 0);
            try std.testing.expectEqualStrings("--- test_obj0.zig ---\n", context.getOutput().?[0..22]);
            try std.testing.expectEqualStrings("Hello, go!\n", context.getOutput().?[22..][0..11]);
            try std.testing.expectEqualStrings("func() it\n", context.getOutput().?[22..][11..][0..10]);
        }
        {
            const context = try testRunBofFromFile("zig-out/bin/test_obj1", &bytes, bytes.len);
            defer context.release();
            try expect(context.getExitCode() == 6);
            try std.testing.expectEqualStrings("--- test_obj1.zig ---\n", context.getOutput().?[0..22]);
            try std.testing.expectEqualStrings("BeaconPrintf has been called\n", context.getOutput().?[22..][0..29]);
        }
        {
            const context = try testRunBofFromFile("zig-out/bin/test_obj4", &bytes, bytes.len);
            defer context.release();
            try expect(context.getExitCode() == 0);
            try std.testing.expectEqualStrings("--- test_obj4.zig ---\n", context.getOutput().?[0..22]);
        }
    }

    {
        const context = try testRunBofFromFile("zig-out/bin/test_obj2", &bytes, bytes.len);
        defer context.release();
        try expect(context.getExitCode() == 15);
        try std.testing.expectEqualStrings("--- test_obj2.c ---\n", context.getOutput().?[0..20]);
        try std.testing.expectEqualStrings("bof\n", context.getOutput().?[20..][0..4]);
        try std.testing.expectEqualStrings("arg_len (from go): 35\n", context.getOutput().?[20..][4..][0..22]);
        try std.testing.expectEqualStrings("Length: (from go): 31\n", context.getOutput().?[20..][4..][22..][0..22]);
    }
    {
        const context = try testRunBofFromFile("zig-out/bin/test_beacon_format", &bytes, bytes.len);
        defer context.release();
        try expect(context.getExitCode() == 123);
        try std.testing.expectEqualStrings("--- testBeaconFormat.c ---\n", context.getOutput().?[0..27]);
        try std.testing.expectEqualStrings("!!!! Start testBeaconFormat !!!!\n", context.getOutput().?[27..][0..33]);
        try std.testing.expectEqualStrings(
            "BeaconFormat test with end of string (EOS) issue:\n",
            context.getOutput().?[27..][33..][0..50],
        );
        try std.testing.expectEqualStrings(
            "The user passed in the integer: 13\n",
            context.getOutput().?[27..][33..][50..][0..35],
        );
        try std.testing.expectEqualStrings(
            "The user passed in the string: 777\n",
            context.getOutput().?[27..][33..][50..][35..][0..35],
        );
    }
    {
        const context = try testRunBofFromFile("zig-out/bin/test_obj0", null, 0);
        defer context.release();
        try expect(context.getExitCode() == 0);
        try std.testing.expectEqualStrings("--- test_obj0.zig ---\n", context.getOutput().?[0..22]);
        try std.testing.expectEqualStrings("Hello, go!\n", context.getOutput().?[22..][0..11]);
        try std.testing.expectEqualStrings("func() it\n", context.getOutput().?[22..][11..][0..10]);
    }
}

test "bof-launcher.beacon.format" {
    try bof.initLauncher();
    defer bof.releaseLauncher();

    const hex_stream = "1900000004000000373737000d0000002f746d702f746573742e736800030000000500";
    var bytes: [hex_stream.len / 2]u8 = undefined;
    _ = try std.fmt.hexToBytes(&bytes, hex_stream);

    {
        const context = try testRunBofFromFile("zig-out/bin/test_beacon_format", &bytes, bytes.len);
        defer context.release();
        try expect(context.getExitCode() == 123);
        try std.testing.expectEqualStrings("--- testBeaconFormat.c ---\n", context.getOutput().?[0..27]);
        try std.testing.expectEqualStrings("!!!! Start testBeaconFormat !!!!\n", context.getOutput().?[27..][0..33]);
        try std.testing.expectEqualStrings(
            "BeaconFormat test with end of string (EOS) issue:\n",
            context.getOutput().?[27..][33..][0..50],
        );
        try std.testing.expectEqualStrings(
            "The user passed in the integer: 13\n",
            context.getOutput().?[27..][33..][50..][0..35],
        );
        try std.testing.expectEqualStrings(
            "The user passed in the string: 777\n",
            context.getOutput().?[27..][33..][50..][35..][0..35],
        );
    }
}

extern fn ctestBasic0() c_int;
test "bof-launcher.ctest.basic0" {
    try bof.initLauncher();
    defer bof.releaseLauncher();
    try expect(ctestBasic0() == 1);
}

extern fn ctestBasic1(file_data: [*]const u8, file_size: c_int) c_int;
test "bof-launcher.ctest.basic1" {
    try bof.initLauncher();
    defer bof.releaseLauncher();

    const allocator = std.testing.allocator;

    const bof_data = try loadBofFromFile(allocator, "zig-out/bin/test_obj0");
    defer allocator.free(bof_data);

    try expect(ctestBasic1(bof_data.ptr, @intCast(bof_data.len)) == 1);
}

extern fn ctestBasic2(file_data: [*]const u8, file_size: c_int) c_int;
test "bof-launcher.ctest.basic2" {
    try bof.initLauncher();
    defer bof.releaseLauncher();
    const allocator = std.testing.allocator;

    const bof_data = try loadBofFromFile(allocator, "zig-out/bin/test_obj0");
    defer allocator.free(bof_data);

    try expect(ctestBasic2(bof_data.ptr, @intCast(bof_data.len)) == 1);
}

test "bof-launcher.bofs.load_run" {
    try bof.initLauncher();
    defer bof.releaseLauncher();

    const allocator = std.testing.allocator;

    const bof_data0 = try loadBofFromFile(allocator, "zig-out/bin/test_obj1");
    defer allocator.free(bof_data0);

    const bof_data1 = try loadBofFromFile(allocator, "zig-out/bin/test_obj2");
    defer allocator.free(bof_data1);

    const object0 = try bof.Object.initFromMemory(bof_data0);
    defer object0.release();

    const object1 = try bof.Object.initFromMemory(bof_data1);
    defer object1.release();

    try expect(object0.isValid());
    try expect(object1.isValid());
    const hex_stream = "1900000004000000373737000d0000002f746d702f746573742e736800030000000500";
    var bytes: [hex_stream.len / 2]u8 = undefined;
    _ = try std.fmt.hexToBytes(&bytes, hex_stream);

    const context0 = try object0.run(&bytes);
    defer context0.release();
    try expect(6 == context0.getExitCode());
    try std.testing.expectEqualStrings("--- test_obj1.zig ---", context0.getOutput().?[0..21]);
    try expect(context0.getObject().handle == object0.handle);
    const context1 = try object1.run(&bytes);
    defer context1.release();
    try expect(15 == context1.getExitCode());
    try std.testing.expectEqualStrings("--- test_obj2.c ---", context1.getOutput().?[0..19]);
    try expect(context1.isRunning() == false);
    try expect(context1.getObject().handle == object1.handle);

    const context2 = try object1.run(&bytes);
    defer context2.release();
    try expect(15 == context2.getExitCode());
    try std.testing.expectEqualStrings("--- test_obj2.c ---", context2.getOutput().?[0..19]);

    const context3 = try object0.run(&bytes);
    defer context3.release();
    try expect(6 == context3.getExitCode());
    try std.testing.expectEqualStrings("--- test_obj1.zig ---", context3.getOutput().?[0..21]);
    try expect(context3.isRunning() == false);

    const context4 = try object1.run(&bytes);
    defer context4.release();
    try expect(15 == context4.getExitCode());
    try std.testing.expectEqualStrings("--- test_obj2.c ---", context4.getOutput().?[0..19]);

    try expect(context3.getOutput() != null);

    try expect(object0.isValid());
    try expect(context0.getObject().isValid());

    object0.release();
    _ = object0.run(&bytes) catch {};
    try expect(context0.getOutput() != null);

    object1.release();
    object1.release();
    _ = object1.run(&bytes) catch {};

    try expect(!object0.isValid());
    try expect(!object1.isValid());
    try expect(!context4.getObject().isValid());
}

test "bof-launcher.stress" {
    const allocator = std.testing.allocator;

    const bof_data = try loadBofFromFile(allocator, "zig-out/bin/test_obj0");
    defer allocator.free(bof_data);

    try bof.initLauncher();
    defer bof.releaseLauncher();

    for (0..64) |i| {
        var object = try bof.Object.initFromMemory(bof_data);
        try expect(object.getProcAddress("func") != null);

        (try object.run(null)).release();
        if (i == 63) {
            try expect(object.isValid());
            object.release();
            try expect(!object.isValid());

            object = try bof.Object.initFromMemory(bof_data);
            try expect(object.isValid());
            const context = try object.run(null);
            defer context.release();

            try std.testing.expectEqualStrings("--- test_obj0.zig ---", context.getOutput().?[0..21]);
        }
    }
}

test "bof-launcher.bofs.runAsyncThread" {
    try bof.initLauncher();
    defer bof.releaseLauncher();

    const allocator = std.testing.allocator;

    const bof_data = try loadBofFromFile(allocator, "zig-out/bin/test_async");
    defer allocator.free(bof_data);

    const object = try bof.Object.initFromMemory(bof_data);
    defer object.release();

    try expect(object.isValid());

    const context1 = try object.runAsyncThread(
        @constCast(std.mem.asBytes(&[_]i32{ 8, 1 })),
        null,
        null,
    );
    defer context1.release();

    const context2 = try object.runAsyncThread(
        @constCast(std.mem.asBytes(&[_]i32{ 8, 2 })),
        null,
        null,
    );
    defer context2.release();

    const context3 = try object.runAsyncThread(
        @constCast(std.mem.asBytes(&[_]i32{ 8, 3 })),
        null,
        null,
    );
    defer context3.release();

    try expect(context1.getObject().handle == object.handle);
    try expect(context2.getObject().handle == object.handle);
    try expect(context3.getObject().handle == object.handle);

    context1.wait();
    context2.wait();
    context3.wait();

    try expect(context1.isRunning() == false);
    try expect(context2.isRunning() == false);
    try expect(context3.isRunning() == false);

    try expect(context1.getExitCode() == 1);
    try expect(context2.getExitCode() == 2);
    try expect(context3.getExitCode() == 3);

    try expect(context1.getOutput() != null);
    try expect(context2.getOutput() != null);
    try expect(context3.getOutput() != null);

    try std.testing.expectEqualStrings("--- test_async.zig ---", context1.getOutput().?[0..22]);
    try std.testing.expectEqualStrings("--- test_async.zig ---", context2.getOutput().?[0..22]);
    try std.testing.expectEqualStrings("--- test_async.zig ---", context3.getOutput().?[0..22]);

    //std.debug.print("{?s}\n", .{context1.getOutput()});
    //std.debug.print("{?s}\n", .{context2.getOutput()});
    //std.debug.print("{?s}\n", .{context3.getOutput()});
}

test "bof-launcher.bofs.runAsyncProcess" {
    if (@import("builtin").cpu.arch == .x86 and @import("builtin").os.tag == .windows) return error.SkipZigTest;

    try bof.initLauncher();
    defer bof.releaseLauncher();

    const allocator = std.testing.allocator;

    const bof_data = try loadBofFromFile(allocator, "zig-out/bin/test_async");
    defer allocator.free(bof_data);

    const object = try bof.Object.initFromMemory(bof_data);
    defer object.release();

    try expect(object.isValid());

    const context1 = try object.runAsyncProcess(
        @constCast(std.mem.asBytes(&[_]i32{ 8, 10 })),
        null,
        null,
    );
    defer context1.release();

    const context2 = try object.runAsyncProcess(
        @constCast(std.mem.asBytes(&[_]i32{ 8, 20 })),
        null,
        null,
    );
    defer context2.release();

    //const context3 = try object.runAsyncProcess(
    //    @constCast(std.mem.asBytes(&[_]i32{ 8, 30 })),
    //    null,
    //    null,
    //);
    //defer context3.release();

    try expect(context1.getObject().handle == object.handle);
    try expect(context2.getObject().handle == object.handle);
    //try expect(context3.getObject().handle == object.handle);

    context1.wait();
    context2.wait();
    //context3.wait();

    try expect(context1.isRunning() == false);
    try expect(context2.isRunning() == false);
    //try expect(context3.isRunning() == false);

    try expect(context1.getExitCode() == 10);
    try expect(context2.getExitCode() == 20);
    //try expect(context3.getExitCode() == 30);

    try expect(context1.getOutput() != null);
    try expect(context2.getOutput() != null);
    //try expect(context3.getOutput() != null);

    try std.testing.expectEqualStrings("--- test_async.zig ---", context1.getOutput().?[0..22]);
    try std.testing.expectEqualStrings("--- test_async.zig ---", context2.getOutput().?[0..22]);
    //try std.testing.expectEqualStrings("--- test_async.zig ---", context3.getOutput().?[0..22]);

    //std.debug.print("{?s}\n", .{context1.getOutput()});
    //std.debug.print("{?s}\n", .{context2.getOutput()});
    //std.debug.print("{?s}\n", .{context3.getOutput()});
}

test "bof-launcher.bofs.masking" {
    try bof.initLauncher();
    defer bof.releaseLauncher();

    try bof.memoryMaskWin32ApiCall("all", true);

    const allocator = std.testing.allocator;

    const bof_data1 = try loadBofFromFile(allocator, "zig-out/bin/test_long_running");
    defer allocator.free(bof_data1);

    const bof_data2 = try loadBofFromFile(allocator, "zig-out/bin/test_obj3");
    defer allocator.free(bof_data2);

    const object1 = try bof.Object.initFromMemory(bof_data1);
    defer object1.release();

    const object2 = try bof.Object.initFromMemory(bof_data2);
    defer object2.release();

    try expect(object1.isValid());
    try expect(object2.isValid());

    var contexts = std.ArrayList(*bof.Context).init(allocator);
    defer {
        for (contexts.items) |ctx| ctx.release();
        contexts.deinit();
    }

    for (0..10) |_| {
        const context = try object1.runAsyncThread(null, null, null);
        try contexts.append(context);
    }

    const context2 = try object2.run(null);
    defer context2.release();

    try expect(try bof.run(bof_data2) == 1);

    for (contexts.items) |ctx| ctx.wait();

    try expect(context2.isRunning() == false);

    for (contexts.items) |ctx| {
        try expect(ctx.getExitCode() == 0);
    }
    try expect(context2.getExitCode() == 1);

    try std.testing.expectEqualStrings("--- test_obj3.zig ---", context2.getOutput().?[0..21]);
}

test "bof-launcher.info" {
    try bof.initLauncher();
    defer bof.releaseLauncher();

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

    const object = try bof.Object.initFromMemory(bof_data);
    defer object.release();

    const context = try object.run(written);
    defer context.release();

    try expect(context.getExitCode() == 0);

    //std.debug.print("{s}", .{context.getOutput().?});

    try expect(data[0] == 2);
    try expect(data[50] == 0x70de_c0de);
    try expect(data[99] == 113);

    try std.testing.expectEqualStrings("--- test_obj3.zig ---", context.getOutput().?[0..21]);
}

test "bof-launcher.udpScanner" {
    try bof.initLauncher();
    defer bof.releaseLauncher();

    const allocator = std.testing.allocator;

    const bof_data = try loadBofFromFile(allocator, "zig-out/bin/udpScanner");
    defer allocator.free(bof_data);

    const object = try bof.Object.initFromMemory(bof_data);
    defer object.release();

    {
        const args = try bof.Args.init();
        defer args.release();

        args.begin();
        try args.add("127.0.0.1:1");
        args.end();

        const context = try object.run(args.getBuffer());
        defer context.release();
        try expect(context.getExitCode() == 0);
    }
    {
        const args = try bof.Args.init();
        defer args.release();

        args.begin();
        try args.add("127-0.0.1:1"); // bad data
        args.end();

        const context = try object.run(args.getBuffer());
        defer context.release();
        try expect(context.getExitCode() == 1);
    }
    {
        const context = try object.run(null);
        defer context.release();
        try expect(context.getExitCode() == 1);
        try expect(context.getOutput() != null); // error message
    }
}

test "bof-launcher.tcpScanner" {
    try bof.initLauncher();
    defer bof.releaseLauncher();

    const allocator = std.testing.allocator;

    const bof_data = try loadBofFromFile(allocator, "zig-out/bin/tcpScanner");
    defer allocator.free(bof_data);

    const object = try bof.Object.initFromMemory(bof_data);
    defer object.release();

    {
        const args = try bof.Args.init();
        defer args.release();

        args.begin();
        try args.add("127.0.0.1:1");
        args.end();

        const context = try object.run(args.getBuffer());
        defer context.release();
        try expect(context.getExitCode() == 0);
        try std.testing.expectEqualStrings("IP: 127.0.0.1:1\n", context.getOutput().?[0..16]);
        try std.testing.expectEqualStrings("port: 1\n", context.getOutput().?[16..][0..8]);
    }
    {
        const args = try bof.Args.init();
        defer args.release();

        args.begin();
        try args.add("127-0.0.1:1"); // bad IP
        args.end();

        const context = try object.run(args.getBuffer());
        defer context.release();
        try expect(context.getExitCode() == 2);
    }
    {
        const context = try object.run(null);
        defer context.release();
        try expect(context.getExitCode() == 1);
    }
}

test "bof-launcher.wWinverC" {
    if (@import("builtin").os.tag != .windows) return error.SkipZigTest;

    try bof.initLauncher();
    defer bof.releaseLauncher();

    const allocator = std.testing.allocator;

    const bof_data = try loadBofFromFile(allocator, "zig-out/bin/wWinverC");
    defer allocator.free(bof_data);

    const object = try bof.Object.initFromMemory(bof_data);
    defer object.release();

    const context = try object.run(null);
    defer context.release();

    try expect(context.getExitCode() == 0);
    try expect(context.getOutput() != null);
    try std.testing.expectEqualStrings("Windows version: ", context.getOutput().?[0..17]);
}

test "bof-launcher.wAsmTest" {
    if (@import("builtin").os.tag != .windows) return error.SkipZigTest;
    if (@import("builtin").cpu.arch != .x86_64) return error.SkipZigTest;

    try bof.initLauncher();
    defer bof.releaseLauncher();

    const allocator = std.testing.allocator;

    const bof_data = try loadBofFromFile(allocator, "zig-out/bin/wAsmTest");
    defer allocator.free(bof_data);

    const object = try bof.Object.initFromMemory(bof_data);
    defer object.release();

    const context = try object.run(null);
    defer context.release();

    try expect(context.getExitCode() == 0);
    try expect(context.getOutput() != null);
    try std.testing.expectEqualStrings("Hello from asm BOF on Windows! eax is 12345\n", context.getOutput().?[0..44]);
}

test "bof-launcher.lAsmTest" {
    if (@import("builtin").os.tag != .linux) return error.SkipZigTest;
    if (@import("builtin").cpu.arch != .x86_64) return error.SkipZigTest;

    try bof.initLauncher();
    defer bof.releaseLauncher();

    const allocator = std.testing.allocator;

    const bof_data = try loadBofFromFile(allocator, "zig-out/bin/lAsmTest");
    defer allocator.free(bof_data);

    const object = try bof.Object.initFromMemory(bof_data);
    defer object.release();

    const context = try object.run(null);
    defer context.release();

    try expect(context.getExitCode() == 0);
    try expect(context.getOutput() != null);
    try std.testing.expectEqualStrings("Hello from asm BOF on Linux! eax is 12345\n", context.getOutput().?[0..42]);
}

test "bof-launcher.getProcAddress" {
    const allocator = std.testing.allocator;

    const bof_data = try loadBofFromFile(allocator, "zig-out/bin/test_obj0");
    defer allocator.free(bof_data);

    try bof.initLauncher();
    defer bof.releaseLauncher();

    var object = try bof.Object.initFromMemory(bof_data);
    defer object.release();

    try expect(object.getProcAddress("func") != null);
    try expect(object.getProcAddress("func123") != null);

    const func: *const fn ([*:0]const u8) callconv(.C) u8 = @ptrCast(@alignCast(object.getProcAddress("func")));

    const func123: *const fn ([*:0]const u8) callconv(.C) u8 = @ptrCast(@alignCast(object.getProcAddress("func123")));

    try expect(func("aaa") == 0);
    try expect(func123("bbb") == 123);
}

test "bof-launcher.wProcessInjectionSrdi" {
    if (@import("builtin").os.tag != .windows) return error.SkipZigTest;
    if (@import("builtin").cpu.arch != .x86_64) return error.SkipZigTest;

    const allocator = std.testing.allocator;

    const hello_bof_data = try loadBofFromFile(allocator, "zig-out/bin/helloBof");
    defer allocator.free(hello_bof_data);

    const srdi_bof_data = try loadBofFromFile(allocator, "zig-out/bin/wProcessInjectionSrdi");
    defer allocator.free(srdi_bof_data);

    try bof.initLauncher();
    defer bof.releaseLauncher();

    const srdi_bof_object = try bof.Object.initFromMemory(srdi_bof_data);
    defer srdi_bof_object.release();

    const args = try bof.Args.init();
    defer args.release();

    args.begin();
    // BOF bytes len
    {
        const len_str = try std.fmt.allocPrint(allocator, "i:{d}", .{hello_bof_data.len});
        defer allocator.free(len_str);
        try args.add(len_str);
    }
    // BOF bytes pointer
    try args.add(std.mem.asBytes(&hello_bof_data.ptr));
    // PID
    try args.add("i:-1");
    // Optional: -dumpbin (dump final shellcode to disk)
    try args.add("-dumpbin");
    args.end();

    const context = try srdi_bof_object.run(args.getBuffer());
    defer context.release();

    try expect(context.getExitCode() == 0);
}

test "bof-launcher.runBofFromBof" {
    if (@import("builtin").os.tag != .windows) return error.SkipZigTest;

    try bof.initLauncher();
    defer bof.releaseLauncher();

    const allocator = std.testing.allocator;

    const bof_data = try loadBofFromFile(allocator, "zig-out/bin/runBofFromBof");
    defer allocator.free(bof_data);

    const object = try bof.Object.initFromMemory(bof_data);
    defer object.release();

    const context = try object.run(null);
    defer context.release();

    try expect(context.getExitCode() == 0);
    try expect(context.getOutput() != null);
    try std.testing.expectEqualStrings("[1] Child BOF exit code: 123\n", context.getOutput().?[0..29]);
    try std.testing.expectEqualStrings("[2] Child BOF exit code: 123\n", context.getOutput().?[29..][0..29]);
    try std.testing.expectEqualStrings("[2] Child BOF output: \n", context.getOutput().?[29..][29..][0..23]);
    try std.testing.expectEqualStrings("hello, bof!\n", context.getOutput().?[29..][29..][23..][0..12]);
}

test "bof-launcher.args" {
    try bof.initLauncher();
    defer bof.releaseLauncher();

    const allocator = std.testing.allocator;

    const bof_data = try loadBofFromFile(allocator, "zig-out/bin/test_args");
    defer allocator.free(bof_data);

    const object = try bof.Object.initFromMemory(bof_data);
    defer object.release();

    const args = try bof.Args.init();
    defer args.release();

    for (0..2) |_| {
        args.begin();
        try args.add("i:123");
        try args.add("int:-123");
        try args.add("i:2147483647"); // max signed int
        try args.add("i:-2147483648"); // min signed int
        try args.add("short:32767"); // max short
        try args.add("s:-32768"); // min short

        for (0..32) |i| {
            const str = try std.fmt.allocPrint(allocator, "i:{d}", .{i});
            defer allocator.free(str);
            try args.add(str);
        }
        try args.add("z:red apple");
        try args.add("str:green grid  ");
        try args.add("blue");

        try args.add("dksdjksadjksajdksajdksajdksajdksajdksajdksabxc daskildjald daskljdasldjska djkajdksalds s02w0201mskasl");
        args.end();

        const context = try object.run(args.getBuffer());
        defer context.release();
        try expect(context.getExitCode() == 0);
        try std.testing.expectEqualStrings("--- test_args.zig ---\n", context.getOutput().?[0..22]);
    }
}
