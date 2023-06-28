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
    const options = Options{
        .target = b.standardTargetOptions(.{}),
        .optimize = b.option(
            std.builtin.Mode,
            "optimize",
            "Prioritize performance, safety, or binary size (-O flag)",
        ) orelse .ReleaseSmall,
    };

    //
    // Bof-launcher library
    //
    const bof_launcher_lib = @import("bof-launcher/build.zig").build(b, options);

    //
    // Bofs
    //
    @import("bofs/build.zig").build(b, options);

    //
    // Examples: command linie launcher
    //
    @import("examples/launch-from-cli/build.zig").build(b, options, bof_launcher_lib);

    //
    // Examples: baby stager
    //
    @import("examples/baby-stager/build.zig").build(b, options, bof_launcher_lib);

    //
    // Tests
    //
    const test_step = b.step("test", "Run all tests");
    test_step.dependOn(@import("tests/build.zig").runTests(b, options, bof_launcher_lib));
}
