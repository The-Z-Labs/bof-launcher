const std = @import("std");

const Options = @import("../../bof-launcher/build.zig").Options;

pub fn build(b: *std.Build, options: Options) void {
    if (options.target.query.os_tag != .windows) return;
    if (options.target.query.cpu_arch == .x86) return;

    const shellcode = b.addExecutable(.{
        .name = std.mem.join(b.allocator, "_", &.{
            "shellcode_in_zig",
            options.osTagStr(),
            options.cpuArchStr(),
        }) catch @panic("OOM"),
        .root_source_file = .{ .cwd_relative = thisDir() ++ "/src/shellcode.zig" },
        .target = options.target,
        .optimize = options.optimize,
        .single_threaded = true,
        .unwind_tables = false,
        .strip = true,
        .link_libc = false,
        .pic = true,
    });

    shellcode.pie = true;
    shellcode.subsystem = .Windows;
    shellcode.entry = .{ .symbol_name = "wWinMainCRTStartup" };

    b.installArtifact(shellcode);
}

inline fn thisDir() []const u8 {
    return comptime std.fs.path.dirname(@src().file) orelse ".";
}
