const std = @import("std");
const srdi = @import("srdi");

pub fn main() !void {
    const bytes = try srdi.allocateShellcode(
        @embedFile("bof_launcher_lib_embed"),
        @embedFile("z_beacon_embed"),
        0,
        @import("builtin").cpu.arch,
    );
    defer srdi.freeShellcode(bytes);

    const file = try std.fs.cwd().createFile(
        "implant_win_" ++ (if (@import("builtin").cpu.arch == .x86_64) "x64" else "x86") ++ ".bin",
        .{},
    );
    defer file.close();
    var writer = file.writer(&.{});
    try writer.interface.writeAll(bytes);
    try writer.interface.flush();
}
