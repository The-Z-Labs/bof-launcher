const std = @import("std");

const Options = @import("../build.zig").Options;

pub fn build(
    b: *std.build.Builder,
    options: Options,
    bof_api_module: *std.Build.Module,
) *std.Build.CompileStep {
    const static_lib = b.addStaticLibrary(.{
        .name = std.mem.join(b.allocator, "_", &.{
            "bof-launcher",
            options.osTagStr(),
            options.cpuArchStr(),
        }) catch @panic("OOM"),
        .root_source_file = .{ .path = thisDir() ++ "/src/bof_launcher.zig" },
        .target = options.target,
        .optimize = options.optimize,

        // TODO: This is a workaround for `std.Thread.spawn()` on Linux.
        //.link_libc = options.target.os_tag == .linux,
    });
    static_lib.addModule("bofapi", bof_api_module);
    if (options.target.os_tag == .windows) {
        static_lib.linkSystemLibrary2("ws2_32", .{});
        static_lib.linkSystemLibrary2("ole32", .{});
    }
    buildLib(static_lib);
    b.installArtifact(static_lib);

    if (options.target.getCpuArch() != .x86) { // TODO: Shared library fails to build on x86.
        const shared_lib = b.addSharedLibrary(.{
            .name = std.mem.join(b.allocator, "_", &.{
                "bof-launcher",
                options.osTagStr(),
                options.cpuArchStr(),
                "shared",
            }) catch @panic("OOM"),
            .root_source_file = .{ .path = thisDir() ++ "/src/bof_launcher.zig" },
            .target = options.target,
            .optimize = options.optimize,

            // TODO: This is a workaround for `std.Thread.spawn()` on Linux.
            //.link_libc = options.target.os_tag == .linux,
        });
        shared_lib.addModule("bofapi", bof_api_module);
        if (options.target.os_tag == .windows) {
            shared_lib.linkSystemLibrary2("ws2_32", .{});
            shared_lib.linkSystemLibrary2("ole32", .{});
        }
        buildLib(shared_lib);
        b.installArtifact(shared_lib);
    }

    return static_lib;
}

fn buildLib(lib: *std.Build.CompileStep) void {
    lib.force_pic = true;
    lib.addIncludePath(.{ .path = thisDir() ++ "/../include" });
    lib.addCSourceFile(.{
        .file = .{ .path = thisDir() ++ "/src/beacon/beacon_impl.c" },
        .flags = &.{"-std=c99"},
    });
    lib.addCSourceFile(.{
        .file = .{ .path = thisDir() ++ "/src/beacon/stb_sprintf.c" },
        .flags = &.{ "-std=c99", "-fno-sanitize=undefined" },
    });
}

inline fn thisDir() []const u8 {
    return comptime std.fs.path.dirname(@src().file) orelse ".";
}
