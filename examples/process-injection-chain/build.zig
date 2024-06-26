const std = @import("std");

const bof_launcher = @import("../../bof-launcher/build.zig");

const Options = @import("../../bof-launcher/build.zig").Options;

pub fn build(
    b: *std.Build,
    options: Options,
    bof_launcher_lib: *std.Build.Step.Compile,
    bof_launcher_api_module: *std.Build.Module,
    bof_api_module: *std.Build.Module,
) void {
    if (options.target.query.os_tag != .windows) return;

    const exe = b.addExecutable(.{
        .name = std.mem.join(b.allocator, "_", &.{
            "process_injection_chain",
            options.osTagStr(),
            options.cpuArchStr(),
        }) catch @panic("OOM"),
        .root_source_file = .{ .cwd_relative = thisDir() ++ "/src/main.zig" },
        .target = options.target,
        .optimize = options.optimize,
    });

    exe.linkLibrary(bof_launcher_lib);

    const shared_module = b.addModule("shared", .{
        .root_source_file = .{ .cwd_relative = thisDir() ++ "/../../bofs/src/process-injection-chain/wInjectionChainShared.zig" },
    });
    shared_module.addImport("bof_api", bof_api_module);

    exe.root_module.addImport("bof_launcher_api", bof_launcher_api_module);
    exe.root_module.addImport("bof_api", bof_api_module);
    exe.root_module.addImport("shared", shared_module);

    b.installArtifact(exe);
}

inline fn thisDir() []const u8 {
    return comptime std.fs.path.dirname(@src().file) orelse ".";
}
