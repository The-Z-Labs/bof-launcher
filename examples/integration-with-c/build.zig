const std = @import("std");

const Options = @import("../../bof-launcher/build.zig").Options;

pub fn build(
    b: *std.Build,
    options: Options,
    bof_launcher_lib: *std.Build.Step.Compile,
) void {
    const exe = b.addExecutable(.{
        .name = std.mem.join(b.allocator, "_", &.{
            "integration_with_c",
            options.osTagStr(),
            options.cpuArchStr(),
        }) catch @panic("OOM"),
        .target = options.target,
        .optimize = options.optimize,
    });

    exe.addIncludePath(.{ .cwd_relative = thisDir() ++ "/../../bof-launcher/src" });
    exe.addCSourceFile(.{
        .file = .{ .cwd_relative = thisDir() ++ "/main.c" },
        .flags = &.{"-std=c99"},
    });

    exe.linkLibrary(bof_launcher_lib);
    exe.linkLibC();

    b.installArtifact(exe);
}

inline fn thisDir() []const u8 {
    return comptime std.fs.path.dirname(@src().file) orelse ".";
}
