const std = @import("std");

pub const min_zig_version = std.SemanticVersion{ .major = 0, .minor = 13, .patch = 0 };

const Options = @import("bof-launcher/build.zig").Options;

pub fn build(b: *std.Build) void {
    ensureZigVersion() catch return;

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
        std.builtin.Mode,
        "optimize",
        "Prioritize performance, safety, or binary size (-O flag)",
    ) orelse .ReleaseSmall;

    const bof_api_module = b.addModule("bof_api", .{
        .root_source_file = b.path("include/bof_api.zig"),
    });
    const bof_launcher_api_module = b.addModule("bof_launcher_api", .{
        .root_source_file = b.path("bof-launcher/src/bof_launcher_api.zig"),
    });

    const targets_to_build: []const std.Target.Query = if (b.user_input_options.contains("target"))
        &.{std_target.query}
    else
        supported_targets;

    const test_step = b.step("test", "Run all tests");
    test_step.dependOn(b.getInstallStep());

    for (targets_to_build) |target_query| {
        const options = Options{ .target = b.resolveTargetQuery(target_query), .optimize = optimize };

        //
        // Build test BOFs
        //
        @import("tests/build.zig").buildTestBofs(b, options, bof_api_module);

        //
        // Bof-launcher library
        //
        const bof_launcher_lib = @import("bof-launcher/build.zig").build(b, options);

        //
        // Examples: baby stager
        //
        @import("examples/baby-stager/build.zig").build(
            b,
            options,
            bof_launcher_lib,
            bof_launcher_api_module,
        );

        //
        // Examples: process injection chain
        //
        @import("examples/process-injection-chain/build.zig").build(
            b,
            options,
            bof_launcher_lib,
            bof_launcher_api_module,
            bof_api_module,
        );

        //
        // Examples: shellcode in zig
        //
        @import("examples/shellcode-in-zig/build.zig").build(b, options);

        //
        // Examples: integration with c
        //
        @import("examples/integration-with-c/build.zig").build(b, options, bof_launcher_lib);

        //
        // Run test BOFs (`zig build test`)
        //
        if (options.target.result.os.tag == @import("builtin").os.tag) {
            test_step.dependOn(&@import("tests/build.zig").runTests(
                b,
                options,
                bof_launcher_lib,
                bof_launcher_api_module,
                bof_api_module,
            ).step);
        }
    }

    //
    // BOFs
    //
    @import("bofs/build.zig").build(b, bof_api_module) catch unreachable;
}

inline fn thisDir() []const u8 {
    return comptime std.fs.path.dirname(@src().file) orelse ".";
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
