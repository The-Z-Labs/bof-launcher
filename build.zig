const std = @import("std");

pub const Options = struct {
    target: std.zig.CrossTarget,
    optimize: std.builtin.Mode,

    pub fn osTagStr(options: Options) []const u8 {
        return switch (options.target.getOsTag()) {
            .windows => "win",
            .linux => "lin",
            else => unreachable,
        };
    }

    pub fn cpuArchStr(options: Options) []const u8 {
        return switch (options.target.getCpuArch()) {
            .x86_64 => "x64",
            .x86 => "x86",
            .aarch64 => "aarch64",
            .arm => "arm",
            else => unreachable,
        };
    }

    pub fn objFormatStr(options: Options) []const u8 {
        return switch (options.target.getOsTag()) {
            .windows => "coff",
            .linux => "elf",
            else => unreachable,
        };
    }
};

pub fn build(b: *std.build.Builder) void {
    const optimize = b.option(
        std.builtin.Mode,
        "optimize",
        "Prioritize performance, safety, or binary size (-O flag)",
    ) orelse .ReleaseSmall;

    const bof_api_module = b.createModule(.{
        .source_file = .{ .path = thisDir() ++ "/include/bofapi.zig" },
    });

    const supported_targets = [_]std.zig.CrossTarget{
        .{ .cpu_arch = .x86, .os_tag = .windows, .abi = .gnu },
        .{ .cpu_arch = .x86, .os_tag = .linux, .abi = .gnu },
        .{ .cpu_arch = .x86_64, .os_tag = .windows, .abi = .gnu },
        .{ .cpu_arch = .x86_64, .os_tag = .linux, .abi = .gnu },
        .{ .cpu_arch = .aarch64, .os_tag = .linux, .abi = .gnu },
        .{ .cpu_arch = .arm, .os_tag = .linux, .abi = .gnueabihf },
    };

    const test_step = b.step("test", "Run all tests");

    for (supported_targets) |target| {
        const options = Options{ .target = target, .optimize = optimize };

        //
        // Build test BOFs
        //
        @import("tests/build.zig").buildTestBofs(b, options, bof_api_module);

        //
        // Bof-launcher library
        //
        const bof_launcher_lib = @import("bof-launcher/build.zig").build(b, options, bof_api_module);

        //
        // Examples: command line launcher
        //
        @import("examples/cli4bofs/build.zig").build(b, options, bof_launcher_lib, bof_api_module);

        //
        // Examples: baby stager
        //
        //@import("examples/baby-stager/build.zig").build(b, options, bof_launcher_lib, bof_api_module);

        //
        // Examples: integration with c
        //
        @import("examples/integration-with-c/build.zig").build(b, options, bof_launcher_lib);

        //
        // Run test BOFs (`zig build test`)
        //
        if (options.target.cpu_arch == @import("builtin").cpu.arch and
            options.target.os_tag == @import("builtin").os.tag)
        {
            test_step.dependOn(&@import("tests/build.zig").runTests(
                b,
                options,
                bof_launcher_lib,
                bof_api_module,
            ).step);
        }

        // TODO: Zig bug? Error in the test runner on Linux (tests pass but memory error is reported).
        if (@import("builtin").os.tag == .linux and options.target.cpu_arch == .x86) continue;

        if (options.target.cpu_arch == .x86 and @import("builtin").cpu.arch == .x86_64 and
            options.target.os_tag == @import("builtin").os.tag)
        {
            test_step.dependOn(&@import("tests/build.zig").runTests(
                b,
                options,
                bof_launcher_lib,
                bof_api_module,
            ).step);
        }
    }

    //
    // BOFs
    //
    @import("bofs/build.zig").build(b, bof_api_module);

    //
    // Additional Windows tests
    //
    if (@import("builtin").os.tag == .windows and @import("builtin").cpu.arch == .x86_64) {
        const udp_scanner_x64 = b.addSystemCommand(&.{
            "zig-out/bin/cli4bofs_win_x64.exe", "zig-out/bin/udpScanner.coff.x64.o", "192.168.0.1:2-10",
        });
        const udp_scanner_x86 = b.addSystemCommand(&.{
            "zig-out/bin/cli4bofs_win_x86.exe", "zig-out/bin/udpScanner.coff.x86.o", "192.168.0.1:2-10",
        });

        udp_scanner_x64.step.dependOn(b.getInstallStep());
        udp_scanner_x86.step.dependOn(b.getInstallStep());

        test_step.dependOn(&udp_scanner_x64.step);
        test_step.dependOn(&udp_scanner_x86.step);
    }

    //
    // Additional Linux tests
    //
    if (@import("builtin").os.tag == .linux and @import("builtin").cpu.arch == .x86_64) {
        const udp_scanner_x64 = b.addSystemCommand(&.{
            "zig-out/bin/cli4bofs_lin_x64", "zig-out/bin/udpScanner.elf.x64.o", "192.168.0.1:2-10",
        });
        const udp_scanner_x86 = b.addSystemCommand(&.{
            "zig-out/bin/cli4bofs_lin_x86", "zig-out/bin/udpScanner.elf.x86.o", "192.168.0.1:2-10",
        });

        udp_scanner_x64.step.dependOn(b.getInstallStep());
        udp_scanner_x86.step.dependOn(b.getInstallStep());

        test_step.dependOn(&udp_scanner_x64.step);
        test_step.dependOn(&udp_scanner_x86.step);

        // Try to run on aarch64 using qemu
        aarch64_blk: {
            const result = std.ChildProcess.run(.{
                .allocator = b.allocator,
                .argv = &.{ "qemu-aarch64", "--version" },
                .cwd = thisDir(),
            }) catch break :aarch64_blk;

            if (result.term.Exited == 0) {
                const udp_scanner_aarch64 = b.addSystemCommand(&.{
                    "qemu-aarch64",
                    "-L",
                    "/usr/aarch64-linux-gnu",
                    "zig-out/bin/cli4bofs_lin_aarch64",
                    "zig-out/bin/udpScanner.elf.aarch64.o",
                    "192.168.0.1:2-10",
                });
                udp_scanner_aarch64.step.dependOn(b.getInstallStep());

                const test_obj0_aarch64 = b.addSystemCommand(&.{
                    "qemu-aarch64",
                    "-L",
                    "/usr/aarch64-linux-gnu",
                    "zig-out/bin/cli4bofs_lin_aarch64",
                    "zig-out/bin/test_obj0.elf.aarch64.o",
                });
                test_obj0_aarch64.step.dependOn(b.getInstallStep());

                test_step.dependOn(&udp_scanner_aarch64.step);
                test_step.dependOn(&test_obj0_aarch64.step);
            }
        }

        // Try to run on arm using qemu
        arm_blk: {
            const result = std.ChildProcess.run(.{
                .allocator = b.allocator,
                .argv = &.{ "qemu-arm", "--version" },
                .cwd = thisDir(),
            }) catch break :arm_blk;

            if (result.term.Exited == 0) {
                const udp_scanner_arm = b.addSystemCommand(&.{
                    "qemu-arm",
                    "-L",
                    "/usr/arm-linux-gnueabihf",
                    "zig-out/bin/cli4bofs_lin_arm",
                    "zig-out/bin/udpScanner.elf.arm.o",
                    "192.168.0.1:2-10",
                });
                udp_scanner_arm.step.dependOn(b.getInstallStep());

                const test_obj0_arm = b.addSystemCommand(&.{
                    "qemu-arm",
                    "-L",
                    "/usr/arm-linux-gnueabihf",
                    "zig-out/bin/cli4bofs_lin_arm",
                    "zig-out/bin/test_obj0.elf.arm.o",
                });
                test_obj0_arm.step.dependOn(b.getInstallStep());

                test_step.dependOn(&udp_scanner_arm.step);
                test_step.dependOn(&test_obj0_arm.step);
            }
        }
    }
}

inline fn thisDir() []const u8 {
    return comptime std.fs.path.dirname(@src().file) orelse ".";
}
