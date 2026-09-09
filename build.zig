const std = @import("std");

pub const supported_zig_version = std.SemanticVersion{ .major = 0, .minor = 16, .patch = 0 };

pub fn build(b: *std.Build) !void {
    ensureZigVersion() catch return;

    var threaded: std.Io.Threaded = .init_single_threaded;
    const io = threaded.io();

    std.Io.Dir.cwd().deleteTree(io, "zig-out") catch {};

    const supported_targets: []const std.Target.Query = &.{
        //.{ .cpu_arch = .x86, .os_tag = .windows, .abi = .gnu },
        //.{ .cpu_arch = .x86, .os_tag = .linux, .abi = .gnu },
        .{ .cpu_arch = .x86_64, .os_tag = .windows, .abi = .gnu },
        //.{ .cpu_arch = .x86_64, .os_tag = .linux, .abi = .gnu },
        //.{ .cpu_arch = .aarch64, .os_tag = .linux, .abi = .gnu },
        //.{
        //    .cpu_arch = .arm,
        //    .os_tag = .linux,
        //    .abi = .gnueabihf,
        //    .cpu_model = .{ .explicit = &std.Target.arm.cpu.arm1176jz_s }, // ARMv6kz
        //},
    };

    const optimize = b.option(
        std.builtin.OptimizeMode,
        "optimize",
        "Prioritize performance, safety, or binary size (-O flag)",
    ) orelse .ReleaseSmall;

    //const osTagStr = @import("bof_launcher_lib").osTagStr;
    //const cpuArchStr = @import("bof_launcher_lib").cpuArchStr;
    const libFileName = @import("bof_launcher_lib").libFileName;

    //
    // Install bof launcher library
    //
    for (supported_targets) |target_query| {
        const target = b.resolveTargetQuery(target_query);

        const bof_launcher_dep = b.dependency(
            "bof_launcher_lib",
            .{ .target = target, .optimize = optimize },
        );

        b.installArtifact(bof_launcher_dep.artifact(
            libFileName(b.allocator, target, null),
        ));

        // TODO: Shared library fails to build on Linux x86.
        if (target.result.cpu.arch == .x86 and target.result.os.tag == .linux) continue;

        b.installArtifact(bof_launcher_dep.artifact(
            libFileName(b.allocator, target, "shared"),
        ));
        if (target.result.os.tag == .linux) {
            b.installArtifact(bof_launcher_dep.artifact(
                libFileName(b.allocator, target, "shared_nolibc"),
            ));
        }
    }
}

fn ensureZigVersion() !void {
    var installed_ver = @import("builtin").zig_version;
    installed_ver.build = null;

    if (installed_ver.order(supported_zig_version) != .eq) {
        std.log.err("\n" ++
            \\---------------------------------------------------------------------------
            \\
            \\Installed Zig compiler version is not supported.
            \\
            \\Required version is: {any}
            \\Installed version: {any}
            \\
            \\Please install supported version and try again.
            \\
            \\---------------------------------------------------------------------------
            \\
        , .{ supported_zig_version, installed_ver });
        return error.ZigIsTooOld;
    }
}
