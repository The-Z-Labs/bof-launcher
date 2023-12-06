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

pub fn build(b: *std.build.Builder, options: Options) *std.Build.CompileStep {
    const static_lib = b.addStaticLibrary(.{
        .name = std.mem.join(b.allocator, "_", &.{
            "bof-launcher",
            options.osTagStr(),
            options.cpuArchStr(),
        }) catch @panic("OOM"),
        .root_source_file = .{ .path = thisDir() ++ "/src/bof_launcher.zig" },
        .target = options.target,
        .optimize = options.optimize,

        // TODO: Remove this
        .link_libc = options.target.os_tag == .linux,
    });
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

            // TODO: Remove this
            .link_libc = options.target.os_tag == .linux,
        });
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
