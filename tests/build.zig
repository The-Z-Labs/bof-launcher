const std = @import("std");
const bof_launcher = @import("../bof-launcher/build.zig");

const Options = @import("../bof-launcher/build.zig").Options;

pub fn runTests(
    b: *std.build.Builder,
    options: Options,
    bof_launcher_lib: *std.Build.CompileStep,
    bof_launcher_api_module: *std.Build.Module,
    bof_api_module: *std.Build.Module,
) *std.build.RunStep {
    const tests = b.addTest(.{
        .name = "bof-launcher-tests",
        .root_source_file = .{ .path = thisDir() ++ "/src/tests.zig" },
        .target = options.target,
        .optimize = options.optimize,
    });
    tests.addIncludePath(.{ .path = thisDir() ++ "/../bof-launcher/src" });
    tests.linkLibrary(bof_launcher_lib);
    tests.addCSourceFile(.{
        .file = .{ .path = thisDir() ++ "/src/tests.c" },
        .flags = &.{"-std=c99"},
    });
    tests.linkLibC();
    tests.addModule("bof_api", bof_api_module);
    tests.addModule("bof_launcher_api", bof_launcher_api_module);
    tests.step.dependOn(b.getInstallStep());
    return b.addRunArtifact(tests);
}

pub fn buildTestBofs(
    b: *std.build.Builder,
    options: Options,
    bof_api_module: *std.Build.Module,
) void {
    // Cross-platform (Windows, Linux) tests written in Zig
    inline for (.{
        "test_obj0",
        "test_obj1",
        "test_async",
        "test_obj3",
        "test_obj4",
    }) |name| {
        const obj = b.addObject(.{
            .name = name,
            .root_source_file = .{ .path = thisDir() ++ "/src/" ++ name ++ ".zig" },
            .target = options.target,
            .optimize = .ReleaseSmall,
        });
        obj.addModule("bof_api", bof_api_module);
        obj.force_pic = true;
        obj.single_threaded = true;
        obj.strip = true;
        obj.unwind_tables = false;

        const dest_path = std.mem.join(b.allocator, ".", &.{
            "bin/" ++ name,
            options.objFormatStr(),
            options.cpuArchStr(),
            "o",
        }) catch @panic("OOM");

        b.getInstallStep().dependOn(
            &b.addInstallFile(obj.getOutputSource(), dest_path).step,
        );
    }

    // Cross-platform (Windows, Linux) tests written in C
    inline for (.{
        "test_beacon_format",
        "test_obj2",
    }) |name| {
        const obj = b.addObject(.{
            .name = name,
            .target = options.target,
            .optimize = .ReleaseSmall,
        });
        obj.addIncludePath(.{ .path = thisDir() ++ "/../include" });
        obj.addCSourceFile(.{
            .file = .{ .path = thisDir() ++ "/src/" ++ name ++ ".c" },
            .flags = &.{"-std=c99"},
        });
        obj.force_pic = true;
        obj.single_threaded = true;
        obj.strip = true;
        obj.unwind_tables = false;

        const dest_path = std.mem.join(b.allocator, ".", &.{
            "bin/" ++ name,
            options.objFormatStr(),
            options.cpuArchStr(),
            "o",
        }) catch @panic("OOM");

        b.getInstallStep().dependOn(
            &b.addInstallFile(obj.getOutputSource(), dest_path).step,
        );
    }
}

inline fn thisDir() []const u8 {
    return comptime std.fs.path.dirname(@src().file) orelse ".";
}
