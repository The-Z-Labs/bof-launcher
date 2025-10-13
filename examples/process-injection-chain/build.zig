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

    const bofs_dep = b.dependency("bof_launcher_bofs", .{ .optimize = optimize });

    const win32_dep = b.dependency("bof_launcher_win32", .{});
    const win32_module = win32_dep.module("bof_launcher_win32");

    const exe = b.addExecutable(.{
        .name = b.fmt(
            "process_injection_chain_{s}_{s}",
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
    exe.root_module.addImport("bof_launcher_win32", win32_module);
    exe.root_module.addAnonymousImport(
        "shared",
        .{ .root_source_file = bofs_dep.path("src/process-injection-chain/wInjectionChainShared.zig") },
    );

    b.installArtifact(exe);
}
