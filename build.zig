const std = @import("std");

pub const supported_zig_version = std.SemanticVersion{ .major = 0, .minor = 14, .patch = 1 };

pub fn build(b: *std.Build) !void {
    ensureZigVersion() catch return;

    std.fs.cwd().deleteTree("zig-out") catch {};

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

    //
    // Install BOFs
    //
    const bofs_path = "bin/bofs";
    const bofs_dep = b.dependency("bof_launcher_bofs", .{ .optimize = optimize });
    for (@import("bof_launcher_bofs").bofs_to_build) |bof| {
        const full_name = bof.fullName(b.allocator);
        b.getInstallStep().dependOn(&b.addInstallArtifact(
            bofs_dep.artifact(full_name),
            .{
                .dest_dir = .{ .override = .{ .custom = bofs_path } },
                .dest_sub_path = if (bof.optimize != .Debug) b.fmt("{s}.o", .{full_name}) else null,
            },
        ).step);
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

    //
    // Install examples
    //
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
        {
            const dep = b.dependency("bof_stager", .{ .target = target, .optimize = optimize });
            const exe = dep.artifact(b.fmt("bof_stager_{s}_{s}", .{ osTagStr(target), cpuArchStr(target) }));
            b.installArtifact(exe);
        }
    }

    // shellcode in zig
    for ([_]std.Target.Query{
        .{ .cpu_arch = .x86_64, .os_tag = .windows, .abi = .gnu },
        .{ .cpu_arch = .x86_64, .os_tag = .linux, .abi = .gnu },
    }) |target_query| {
        const target = b.resolveTargetQuery(target_query);

        const dep = b.dependency("shellcode_in_zig", .{ .target = target, .optimize = optimize });
        const shellcode_launcher_exe = dep.artifact(b.fmt(
            "shellcode_launcher_{s}_{s}",
            .{ osTagStr(target), cpuArchStr(target) },
        ));
        b.installArtifact(shellcode_launcher_exe);

        const shellcode_name = b.fmt("shellcode_{s}_{s}", .{ osTagStr(target), cpuArchStr(target) });
        const shellcode_exe = dep.artifact(shellcode_name);
        b.installArtifact(shellcode_exe);

        if (target.result.os.tag == .linux) {
            const copy = b.addObjCopy(shellcode_exe.getEmittedBin(), .{ .format = .bin, .only_section = ".text" });
            const install = b.addInstallBinFile(copy.getOutput(), b.fmt("{s}.bin", .{shellcode_name}));
            b.getInstallStep().dependOn(&install.step);
        }
    }

    // process injection chain
    for ([_]std.Target.Query{
        .{ .cpu_arch = .x86, .os_tag = .windows, .abi = .gnu },
        .{ .cpu_arch = .x86_64, .os_tag = .windows, .abi = .gnu },
    }) |target_query| {
        const target = b.resolveTargetQuery(target_query);

        const dep = b.dependency("process_injection_chain", .{ .target = target, .optimize = optimize });
        const exe = dep.artifact(b.fmt("process_injection_chain_{s}_{s}", .{ osTagStr(target), cpuArchStr(target) }));
        b.installArtifact(exe);
    }

    // implant
    for ([_]std.Target.Query{
        .{ .cpu_arch = .x86_64, .os_tag = .linux, .abi = .gnu },
    }) |target_query| {
        const target = b.resolveTargetQuery(target_query);

        const dep = b.dependency("implant", .{ .target = target, .optimize = optimize });
        const implant_exe = dep.artifact(b.fmt(
            "z-beac0n_{s}_{s}",
            .{ osTagStr(target), cpuArchStr(target) },
        ));
        b.installArtifact(implant_exe);

        const shellcode_name = b.fmt("shellcode_binary_temp_{s}_{s}", .{ osTagStr(target), cpuArchStr(target) });
        const shellcode_exe = dep.artifact(shellcode_name);
        b.installArtifact(shellcode_exe);

        const copy = b.addObjCopy(shellcode_exe.getEmittedBin(), .{ .format = .bin, .only_section = ".text" });
        const install = b.addInstallBinFile(
            copy.getOutput(),
            b.fmt("z-beac0n_{s}_{s}.bin", .{ osTagStr(target), cpuArchStr(target) }),
        );
        b.getInstallStep().dependOn(&install.step);
    }

    //
    // Build, install and run tests
    //
    const test_step = b.step("test", "Run all tests");

    for (supported_targets) |target_query| {
        const target = b.resolveTargetQuery(target_query);

        const bof_launcher_dep = b.dependency(
            "bof_launcher_lib",
            .{ .target = target, .optimize = optimize },
        );
        const bof_launcher_api_module = bof_launcher_dep.module("bof_launcher_api");

        const bof_launcher_lib = bof_launcher_dep.artifact(
            libFileName(b.allocator, target, null),
        );

        const bof_api_module = bofs_dep.module("bof_api");

        const win32_dep = b.dependency("bof_launcher_win32", .{});
        const win32_module = win32_dep.module("bof_launcher_win32");

        const tests = b.addTest(.{
            .name = "bof-launcher-tests",
            .root_source_file = bofs_dep.path("src/tests/tests.zig"),
            .target = target,
            .optimize = optimize,
            //.filter = "load_all_bofs",
        });
        tests.addIncludePath(bof_launcher_dep.path("src"));
        tests.linkLibrary(bof_launcher_lib);
        tests.addCSourceFile(.{
            .file = bofs_dep.path("src/tests/tests.c"),
            .flags = &.{"-std=c99"},
        });
        tests.linkLibC();
        tests.root_module.addImport("bof_api", bof_api_module);
        tests.root_module.addImport("bof_launcher_api", bof_launcher_api_module);
        tests.root_module.addImport("bof_launcher_win32", win32_module);

        const run_step = b.addRunArtifact(tests);
        run_step.skip_foreign_checks = true;
        run_step.step.dependOn(b.getInstallStep());

        test_step.dependOn(&run_step.step);
    }

    const boflint_step = b.step("boflint", "Run boflint.py");

    for (@import("bof_launcher_bofs").bofs_to_build) |bof| {
        const full_name = bof.fullName(b.allocator);

        if (std.mem.containsAtLeast(u8, full_name, 1, "debug")) continue;

        if (std.mem.containsAtLeast(u8, full_name, 1, "coff") and
            (std.mem.containsAtLeast(u8, full_name, 1, "x64") or std.mem.containsAtLeast(u8, full_name, 1, "x86")))
        {
            const run_step = b.addSystemCommand(&.{
                "python",
                "utils/boflint.py",
                "--logformat",
                "vs",
                "--loader",
                "cs",
                b.fmt("zig-out/bin/bofs/{s}.o", .{full_name}),
            });
            run_step.step.dependOn(b.getInstallStep());

            boflint_step.dependOn(&run_step.step);
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
