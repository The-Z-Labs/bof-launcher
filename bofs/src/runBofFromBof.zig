const beacon = @import("bof_api").beacon;
const w32 = @import("bof_api").win32;
const bof_launcher = @import("bof_launcher_api");

fn runBof(bof_bytes: []const u8) !void {
    const bof_object = try bof_launcher.Object.initFromMemory(bof_bytes);
    defer bof_object.release();

    const bof_context = try bof_object.run(null);
    defer bof_context.release();

    _ = beacon.printf(0, "[2] Child BOF exit code: %d\n", bof_context.getExitCode());
    if (bof_context.getOutput()) |output| {
        _ = beacon.printf(0, "[2] Child BOF output: \n%s", output.ptr);
    }
}

pub export fn go(_: ?[*]u8, _: i32) callconv(.C) u8 {
    const bof_bytes = @embedFile("helloBof.coff.x64.o");

    const bof_exit_code = bof_launcher.run(bof_bytes) catch -1;
    _ = beacon.printf(0, "[1] Child BOF exit code: %d\n", bof_exit_code);

    runBof(bof_bytes) catch return 1;

    return 0;
}
