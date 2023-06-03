const std = @import("std");

const bof_launcher = @import("../../bof-launcher/build.zig");

const Options = @import("../../build.zig").Options;

pub fn build(b: *std.build.Builder, options: Options) void {
    const exe = b.addExecutable(.{
        .name = std.mem.join(b.allocator, "_", &.{
            "example-cli-launcher",
            options.osTagStr(),
            options.cpuArchStr(),
        }) catch @panic("OOM"),
        .root_source_file = .{ .path = thisDir() ++ "/src/main.zig" },
        .target = options.target,
        .optimize = options.optimize,
    });
    if (options.optimize == .ReleaseSmall)
        exe.strip = true;

    const lib = bof_launcher.build(b, options);
    exe.step.dependOn(&lib.step);

    exe.linkLibrary(lib);

    const bofapi = b.createModule(.{
        .source_file = .{ .path = thisDir() ++ "/../../include/bofapi.zig" },
    });
    exe.addModule("bofapi", bofapi);

    b.installArtifact(exe);
}

inline fn thisDir() []const u8 {
    return comptime std.fs.path.dirname(@src().file) orelse ".";
}
