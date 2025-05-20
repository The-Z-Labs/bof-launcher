const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const bof_launcher_dep = b.dependency(
        "bof_launcher_lib",
        .{ .target = target, .optimize = optimize },
    );
    const bof_launcher_lib = bof_launcher_dep.artifact(
        @import("bof_launcher_lib").libFileName(b.allocator, target, .static),
    );

    const exe = b.addExecutable(.{
        .name = b.fmt(
            "integration_with_c_{s}_{s}",
            .{
                @import("bof_launcher_lib").osTagStr(target),
                @import("bof_launcher_lib").cpuArchStr(target),
            },
        ),
        .target = target,
        .optimize = optimize,
    });
    exe.addIncludePath(bof_launcher_dep.path("src"));
    exe.addCSourceFile(.{
        .file = b.path("main.c"),
        .flags = &.{"-std=c99"},
    });
    exe.linkLibrary(bof_launcher_lib);
    exe.linkLibC();

    b.installArtifact(exe);
}
