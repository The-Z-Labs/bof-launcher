const std = @import("std");

const Options = @import("../../build.zig").Options;

pub fn build(
    b: *std.build.Builder,
    options: Options,
    bof_launcher_lib: *std.Build.CompileStep,
) void {
    const exe = b.addExecutable(.{
        .name = std.mem.join(b.allocator, "_", &.{
            "integration-with-c",
            options.osTagStr(),
            options.cpuArchStr(),
        }) catch @panic("OOM"),
        .target = options.target,
        .optimize = options.optimize,
    });
    if (options.optimize == .ReleaseSmall)
        exe.strip = true;

    exe.addIncludePath(.{ .path = thisDir() ++ "/../../include" });
    exe.addCSourceFile(.{
        .file = .{ .path = thisDir() ++ "/main.c" },
        .flags = &.{"-std=c99"},
    });

    exe.linkLibrary(bof_launcher_lib);
    exe.linkLibC();

    b.installArtifact(exe);
}

inline fn thisDir() []const u8 {
    return comptime std.fs.path.dirname(@src().file) orelse ".";
}
