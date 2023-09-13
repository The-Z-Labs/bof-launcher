const std = @import("std");
const bof_launcher = @import("../bof-launcher/build.zig");

const Options = @import("../build.zig").Options;

pub fn runTests(
    b: *std.build.Builder,
    options: Options,
    bof_launcher_lib: *std.Build.CompileStep,
) *std.build.Step {
    const tests = b.addTest(.{
        .name = "bof-launcher-tests",
        .root_source_file = .{ .path = thisDir() ++ "/src/tests.zig" },
        .target = options.target,
        .optimize = options.optimize,
    });

    tests.addIncludePath(.{ .path = thisDir() ++ "/../include" });
    tests.linkLibrary(bof_launcher_lib);
    tests.addCSourceFile(.{
        .file = .{ .path = thisDir() ++ "/src/tests.c" },
        .flags = &.{"-std=c99"},
    });
    tests.linkLibC();

    const bofapi = b.createModule(.{
        .source_file = .{ .path = thisDir() ++ "/../include/bofapi.zig" },
    });
    tests.addModule("bofapi", bofapi);

    tests.step.dependOn(buildTestObjs(b, options, bofapi));

    return &b.addRunArtifact(tests).step;
}

fn buildTestObjs(b: *std.build.Builder, options: Options, bofapi: *std.Build.Module) *std.build.Step {
    const parent_step = b.allocator.create(std.Build.Step) catch @panic("OOM");
    parent_step.* = std.Build.Step.init(.{ .id = .custom, .name = "bof-launcher-tests-objs", .owner = b });

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
        obj.addModule("bofapi", bofapi);
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

        const obj_install = b.addInstallFile(obj.getOutputSource(), dest_path);
        obj_install.step.dependOn(&obj.step);

        parent_step.dependOn(&obj_install.step);
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

        const obj_install = b.addInstallFile(obj.getOutputSource(), dest_path);
        obj_install.step.dependOn(&obj.step);

        parent_step.dependOn(&obj_install.step);
    }

    return parent_step;
}

inline fn thisDir() []const u8 {
    return comptime std.fs.path.dirname(@src().file) orelse ".";
}
