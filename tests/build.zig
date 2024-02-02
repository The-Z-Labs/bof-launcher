const std = @import("std");
const bof_launcher = @import("../bof-launcher/build.zig");

const Options = @import("../bof-launcher/build.zig").Options;

pub fn runTests(
    b: *std.Build,
    options: Options,
    bof_launcher_lib: *std.Build.Step.Compile,
    bof_launcher_api_module: *std.Build.Module,
    bof_api_module: *std.Build.Module,
) *std.Build.Step.Run {
    const tests = b.addTest(.{
        .name = "bof-launcher-tests",
        .root_source_file = .{ .path = thisDir() ++ "/src/tests.zig" },
        .target = options.target,
        .optimize = options.optimize,
        //.filter = "udpScanner",
    });
    tests.addIncludePath(.{ .path = thisDir() ++ "/../bof-launcher/src" });
    tests.linkLibrary(bof_launcher_lib);
    tests.addCSourceFile(.{
        .file = .{ .path = thisDir() ++ "/src/tests.c" },
        .flags = &.{"-std=c99"},
    });
    tests.linkLibC();
    tests.root_module.addImport("bof_api", bof_api_module);
    tests.root_module.addImport("bof_launcher_api", bof_launcher_api_module);
    tests.step.dependOn(b.getInstallStep());

    const run_step = b.addRunArtifact(tests);
    run_step.skip_foreign_checks = true;
    return run_step;
}

pub fn buildTestBofs(
    b: *std.Build,
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
        obj.root_module.addImport("bof_api", bof_api_module);
        obj.root_module.pic = true;
        obj.root_module.single_threaded = true;
        obj.root_module.strip = true;
        obj.root_module.unwind_tables = false;

        const dest_path = std.mem.join(b.allocator, ".", &.{
            "bin/" ++ name,
            options.objFormatStr(),
            options.cpuArchStr(),
            "o",
        }) catch @panic("OOM");

        b.getInstallStep().dependOn(
            &b.addInstallFile(obj.getEmittedBin(), dest_path).step,
        );
    }

    // Cross-platform (Windows, Linux) tests written in C
    inline for (.{
        "test_beacon_format",
        "test_obj2",
    }) |name| {
        const obj = b.addObject(.{
            .name = name,
            // TODO: Zig bug. Remove below line once fixed.
            .root_source_file = .{ .path = thisDir() ++ "/src/dummy.zig" },
            .target = options.target,
            .optimize = .ReleaseSmall,
        });
        obj.addIncludePath(.{ .path = thisDir() ++ "/../include" });
        obj.addCSourceFile(.{
            .file = .{ .path = thisDir() ++ "/src/" ++ name ++ ".c" },
            .flags = &.{"-std=c99"},
        });
        obj.root_module.pic = true;
        obj.root_module.single_threaded = true;
        obj.root_module.strip = true;
        obj.root_module.unwind_tables = false;

        const dest_path = std.mem.join(b.allocator, ".", &.{
            "bin/" ++ name,
            options.objFormatStr(),
            options.cpuArchStr(),
            "o",
        }) catch @panic("OOM");

        b.getInstallStep().dependOn(
            &b.addInstallFile(obj.getEmittedBin(), dest_path).step,
        );
    }
}

inline fn thisDir() []const u8 {
    return comptime std.fs.path.dirname(@src().file) orelse ".";
}
