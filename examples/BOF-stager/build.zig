const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const bof_launcher_dep = b.dependency(
        "bof_launcher_lib",
        .{ .target = target, .optimize = optimize },
    );
    const bof_launcher_api_module = bof_launcher_dep.module("bof_launcher_api");
    const bof_launcher_lib = bof_launcher_dep.artifact(
        @import("bof_launcher_lib").libFileName(b.allocator, target, null),
    );

    const exe = b.addExecutable(.{
        .name = b.fmt(
            "bof_stager_{s}_{s}",
            .{
                @import("bof_launcher_lib").osTagStr(target),
                @import("bof_launcher_lib").cpuArchStr(target),
            },
        ),
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
    });
    exe.linkLibrary(bof_launcher_lib);
    exe.root_module.addImport("bof_launcher_api", bof_launcher_api_module);

    b.installArtifact(exe);
}
