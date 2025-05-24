const std = @import("std");

pub const min_zig_version = std.SemanticVersion{ .major = 0, .minor = 14, .patch = 1 };

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

    const std_target = b.standardTargetOptions(.{ .whitelist = supported_targets });
    const optimize = b.option(
        std.builtin.OptimizeMode,
        "optimize",
        "Prioritize performance, safety, or binary size (-O flag)",
    ) orelse .ReleaseSmall;

    const targets_to_build: []const std.Target.Query = if (b.user_input_options.contains("target"))
        &.{std_target.query}
    else
        supported_targets;

    const bofs_dep = b.dependency("bof_launcher_bofs", .{ .optimize = optimize });

    // Install BOFs
    for (@import("bof_launcher_bofs").bofs_to_build) |bof| {
        for (bof.formats) |format| {
            for (bof.archs) |arch| {
                if (format == .coff and arch == .aarch64) continue;
                if (format == .coff and arch == .arm) continue;

                const full_name = @import("bof_launcher_bofs").Bof.fullName(
                    b.allocator,
                    bof.name,
                    format,
                    arch,
                    .ReleaseSmall,
                );
                const obj = bofs_dep.artifact(full_name);
                b.getInstallStep().dependOn(&b.addInstallArtifact(
                    obj,
                    .{
                        .dest_dir = .{ .override = .bin },
                        .dest_sub_path = b.fmt("{s}.o", .{full_name}),
                    },
                ).step);

                if (optimize == .Debug) {
                    const debug_exe = bofs_dep.artifact(@import("bof_launcher_bofs").Bof.fullName(
                        b.allocator,
                        bof.name,
                        format,
                        arch,
                        .Debug,
                    ));
                    b.installArtifact(debug_exe);
                }
            }
        }
    }

    // Install bof launcher library
    for (targets_to_build) |target_query| {
        const target = b.resolveTargetQuery(target_query);

        const bof_launcher_dep = b.dependency(
            "bof_launcher_lib",
            .{ .target = target, .optimize = optimize },
        );

        _ = bof_launcher_dep.module("bof_launcher_api");

        const bof_launcher_lib = bof_launcher_dep.artifact(
            @import("bof_launcher_lib").libFileName(b.allocator, target, .static),
        );
        b.installArtifact(bof_launcher_lib);

        if (target.result.cpu.arch != .x86) { // TODO: Shared library fails to build on x86.
            const bof_launcher_shared_lib = bof_launcher_dep.artifact(
                @import("bof_launcher_lib").libFileName(b.allocator, target, .dynamic),
            );
            b.installArtifact(bof_launcher_shared_lib);
        }
    }

    const osTagStr = @import("bof_launcher_lib").osTagStr;
    const cpuArchStr = @import("bof_launcher_lib").cpuArchStr;

    // Install examples
    for (targets_to_build) |target_query| {
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

        // process injection chain
        if (target.result.os.tag == .windows) {
            const dep = b.dependency("process_injection_chain", .{ .target = target, .optimize = optimize });
            const exe = dep.artifact(b.fmt("process_injection_chain_{s}_{s}", .{ osTagStr(target), cpuArchStr(target) }));
            b.installArtifact(exe);
        }

        // shellcode in zig
        if (target.result.cpu.arch == .x86_64) {
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

        // implant
        if (target.result.os.tag == .linux and target.result.cpu.arch == .x86_64) {
            const dep = b.dependency("implant", .{ .target = target, .optimize = optimize });
            const implant_exe = dep.artifact(b.fmt(
                "implant_executable_{s}_{s}",
                .{ osTagStr(target), cpuArchStr(target) },
            ));
            b.installArtifact(implant_exe);

            const shellcode_name = b.fmt("implant_shellcode_{s}_{s}", .{ osTagStr(target), cpuArchStr(target) });
            const shellcode_exe = dep.artifact(shellcode_name);
            b.installArtifact(shellcode_exe);

            const copy = b.addObjCopy(shellcode_exe.getEmittedBin(), .{ .format = .bin, .only_section = ".text" });
            const install = b.addInstallBinFile(copy.getOutput(), b.fmt("{s}.bin", .{shellcode_name}));
            b.getInstallStep().dependOn(&install.step);
        }
    }

    // Build, install and run tests
    const test_step = b.step("test", "Run all tests");

    for (targets_to_build) |target_query| {
        const target = b.resolveTargetQuery(target_query);

        // TODO: Compiler bug? Looks like all tests pass but test runner reports error.
        if (target.result.cpu.arch == .x86 and target.result.os.tag == .linux and optimize == .ReleaseSmall) {
            continue;
        }

        const bof_launcher_dep = b.dependency(
            "bof_launcher_lib",
            .{ .target = target, .optimize = optimize },
        );
        const bof_launcher_api_module = bof_launcher_dep.module("bof_launcher_api");

        const bof_launcher_lib = bof_launcher_dep.artifact(
            @import("bof_launcher_lib").libFileName(b.allocator, target, .static),
        );

        const bof_api_module = bofs_dep.module("bof_api");

        const tests = b.addTest(.{
            .name = "bof-launcher-tests",
            .root_source_file = bofs_dep.path("src/tests/tests.zig"),
            .target = target,
            .optimize = optimize,
            //.filter = "masking",
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

        const run_step = b.addRunArtifact(tests);
        run_step.skip_foreign_checks = true;
        run_step.step.dependOn(b.getInstallStep());

        test_step.dependOn(&run_step.step);
    }
}

fn ensureZigVersion() !void {
    var installed_ver = @import("builtin").zig_version;
    installed_ver.build = null;

    if (installed_ver.order(min_zig_version) != .eq) {
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
        , .{ min_zig_version, installed_ver });
        return error.ZigIsTooOld;
    }
}
