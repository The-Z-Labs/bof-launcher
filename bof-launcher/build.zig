const std = @import("std");

const Options = @import("../build.zig").Options;

pub fn build(b: *std.build.Builder, options: Options) *std.Build.CompileStep {
    const bofapi = b.createModule(.{
        .source_file = .{ .path = thisDir() ++ "/../include/bofapi.zig" },
    });

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
        .link_libc = @import("builtin").os.tag == .linux,
    });
    static_lib.addModule("bofapi", bofapi);
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
            .link_libc = @import("builtin").os.tag == .linux,
        });
        shared_lib.addModule("bofapi", bofapi);
        buildLib(shared_lib);
        b.installArtifact(shared_lib);
    }

    return static_lib;
}

fn buildLib(lib: *std.Build.CompileStep) void {
    lib.force_pic = true;
    lib.addIncludePath(thisDir() ++ "/../include");
    lib.addCSourceFile(thisDir() ++ "/src/beacon/beacon_impl.c", &.{"-std=c99"});
    lib.addCSourceFile(thisDir() ++ "/src/beacon/stb_sprintf.c", &.{ "-std=c99", "-fno-sanitize=undefined" });
}

inline fn thisDir() []const u8 {
    return comptime std.fs.path.dirname(@src().file) orelse ".";
}
