const std = @import("std");
const bof_launcher = @import("bof_launcher_api");

extern fn go(_: ?[*]u8, _: i32) callconv(.C) u8;

pub fn main() !void {
    try bof_launcher.initLauncher();
    defer bof_launcher.releaseLauncher();

    var context: *bof_launcher.Context = undefined;
    const res = bof_launcher.bofDebugRun(go, null, 0, &context);
    if (res != 0) {
        std.debug.print("Failed to run BOF (error code: {d})\n", .{res});
        return;
    }
    defer context.release();

    std.debug.print("BOF exit code: {d}\n", .{context.getExitCode()});
}
