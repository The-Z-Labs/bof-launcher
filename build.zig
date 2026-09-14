const std = @import("std");

pub const supported_zig_version = std.SemanticVersion{ .major = 0, .minor = 16, .patch = 0 };

pub fn build(b: *std.Build) !void {
    ensureZigVersion() catch return;

    var threaded: std.Io.Threaded = .init_single_threaded;
    const io = threaded.io();

    std.Io.Dir.cwd().deleteTree(io, "zig-out") catch {};

    const supported_targets: []const std.Target.Query = &.{
        .{ .cpu_arch = .x86, .os_tag = .windows, .abi = .gnu },
        .{ .cpu_arch = .x86, .os_tag = .linux, .abi = .gnu },
        .{ .cpu_arch = .x86_64, .os_tag = .windows, .abi = .gnu },
        .{ .cpu_arch = .x86_64, .os_tag = .linux, .abi = .gnu },
        .{ .cpu_arch = .aarch64, .os_tag = .linux, .abi = .gnu },
        .{
            .cpu_arch = .arm,
            .os_tag = .linux,
            .abi = .gnueabihf,
            .cpu_model = .{ .explicit = &std.Target.arm.cpu.arm1176jz_s }, // ARMv6kz
        },
    };

    const optimize = b.option(
        std.builtin.OptimizeMode,
        "optimize",
        "Prioritize performance, safety, or binary size (-O flag)",
    ) orelse .ReleaseSmall;

    const osTagStr = @import("bof_launcher_lib").osTagStr;
    const cpuArchStr = @import("bof_launcher_lib").cpuArchStr;
    const libFileName = @import("bof_launcher_lib").libFileName;

    const has_python = blk: {
        _ = b.findProgram(&.{"python"}, &.{}) catch break :blk false;
        break :blk true;
    };

    //
    // Install and post-process BOFs
    //
    const bofs_install_path = "bin/bofs/";
    const bofs_dep = b.dependency("bof_launcher_bofs", .{ .optimize = optimize });
    for (@import("bof_launcher_bofs").bofs_to_build) |bof| {
        const full_name = bof.fullName(b.allocator);

        var prev_step = &b.addInstallArtifact(
            bofs_dep.artifact(full_name),
            .{
                .dest_dir = .{ .override = .{ .custom = bofs_install_path } },
                .dest_sub_path = if (bof.optimize != .Debug) b.fmt("{s}.o", .{full_name}) else null,
            },
        ).step;

        if (@import("builtin").cpu.arch == .x86_64) strip: {
            // Always skip debug exe
            if (std.mem.containsAtLeast(u8, full_name, 1, "debug")) break :strip;

            // Blacklist (llvm-objcopy can't remove section for some reason)
            if (std.mem.containsAtLeast(u8, full_name, 1, "udpScanner")) break :strip;
            if (std.mem.containsAtLeast(u8, full_name, 1, "tcpScanner")) break :strip;
            if (std.mem.containsAtLeast(u8, full_name, 1, "grep")) break :strip;
            if (std.mem.containsAtLeast(u8, full_name, 1, "find")) break :strip;
            //if (std.mem.containsAtLeast(u8, full_name, 1, "wProcessInjectionSrdi")) break :strip;

            if (std.mem.containsAtLeast(u8, full_name, 1, "coff")) {
                const run = b.addSystemCommand(&.{
                    "bin/llvm-objcopy",
                    "--remove-section=.red",
                    "--strip-unneeded",
                    b.fmt("zig-out/" ++ bofs_install_path ++ "{s}.o", .{full_name}),
                });
                run.step.dependOn(prev_step);
                prev_step = &run.step;
            }
        }

        if (has_python) boflint: {
            // Always skip debug exe
            if (std.mem.containsAtLeast(u8, full_name, 1, "debug")) break :boflint;

            // Blacklist (BOFs which use our custom bof*() API)
            if (std.mem.containsAtLeast(u8, full_name, 1, "runBofFromBof")) break :boflint;
            if (std.mem.containsAtLeast(u8, full_name, 1, "z-beac0n")) break :boflint;
            if (std.mem.containsAtLeast(u8, full_name, 1, "wAsmTest")) break :boflint;

            if (std.mem.containsAtLeast(u8, full_name, 1, "coff")) {
                const run = b.addSystemCommand(&.{
                    "python",
                    "utils/boflint.py",
                    "--logformat",
                    "vs",
                    "--loader",
                    "cs",
                    b.fmt("zig-out/" ++ bofs_install_path ++ "{s}.o", .{full_name}),
                });
                run.step.dependOn(prev_step);
                prev_step = &run.step;
            }
        }

        b.getInstallStep().dependOn(prev_step);
    }

    b.getInstallStep().dependOn(&b.addInstallFile(
        bofs_dep.namedLazyPath("bof_collection_doc"),
        "bof-collection.yaml",
    ).step);

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

        b.installArtifact(bof_launcher_dep.artifact(
            libFileName(b.allocator, target, "shared"),
        ));
        if (target.result.os.tag == .linux) {
            b.installArtifact(bof_launcher_dep.artifact(
                libFileName(b.allocator, target, "shared_nolibc"),
            ));
        }
    }

    for (supported_targets) |target_query| {
        const target = b.resolveTargetQuery(target_query);

        // integration with c
        {
            const dep = b.dependency("integration_with_c", .{ .target = target, .optimize = optimize });
            const exe = dep.artifact(b.fmt(
                "integration_with_c_{s}_{s}",
                .{ osTagStr(target), cpuArchStr(target) },
            ));
            b.installArtifact(exe);
        }

        // bof stager
        //const dep = b.dependency("bof_stager", .{ .target = target, .optimize = optimize });
        //const exe = dep.artifact(b.fmt("bof_stager_{s}_{s}", .{ osTagStr(target), cpuArchStr(target) }));
        //b.installArtifact(exe);
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
