const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const zig_yaml_module = b.dependency("zig_yaml", .{
            .target = target,
            .optimize = optimize,
    }).module("yaml");

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
            "bof_{s}_{s}",
            .{
                @import("bof_launcher_lib").osTagStr(target),
                @import("bof_launcher_lib").cpuArchStr(target),
            },
        ),
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/main.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });
    exe.root_module.linkLibrary(bof_launcher_lib);
    exe.root_module.addImport("bof_launcher_api", bof_launcher_api_module);
    exe.root_module.addImport("yaml", zig_yaml_module);

    const bofs_dep = b.dependency("bof_launcher_bofs", .{ .optimize = optimize });
    exe.root_module.addAnonymousImport("all_bof_yaml", .{
        .root_source_file = bofs_dep.namedLazyPath("all_bof_yaml"),
    });

    if (target.result.os.tag == .windows) {
        const injection_bof = b.dependency(
            "bof_launcher_bofs",
            .{ .optimize = optimize },
        ).artifact(b.fmt("wProcessInjectionSrdi.coff.{s}", .{@import("bof_launcher_lib").cpuArchStr(target)}));

        exe.root_module.addAnonymousImport("injection_bof_embed", .{
            .root_source_file = injection_bof.getEmittedBin(),
        });
    }

    b.installArtifact(exe);
}
