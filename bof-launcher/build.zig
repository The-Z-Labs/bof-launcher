const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    _ = b.addModule("bof_launcher_api", .{
        .root_source_file = b.path("src/bof_launcher_api.zig"),
    });

    const win32_dep = b.dependency("bof_launcher_win32", .{});
    const win32_module = win32_dep.module("bof_launcher_win32");

    if (target.result.abi != .none) {
        const static_lib = b.addStaticLibrary(.{
            .name = libFileName(b.allocator, target, .static),
            .root_source_file = b.path("src/bof_launcher.zig"),
            .target = target,
            .optimize = optimize,
            .link_libc = target.result.os.tag == .linux,
        });
        static_lib.root_module.addImport("bof_launcher_win32", win32_module);
        buildLib(b, static_lib, target, optimize);
    }

    // TODO: Shared library fails to build on Linux x86.
    if (target.result.cpu.arch == .x86 and target.result.os.tag == .linux) return;

    const shared_lib = b.addSharedLibrary(.{
        .name = libFileName(b.allocator, target, .dynamic),
        .root_source_file = b.path("src/bof_launcher.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = target.result.os.tag == .linux and target.result.abi != .none,
    });
    shared_lib.root_module.addImport("bof_launcher_win32", win32_module);
    buildLib(b, shared_lib, target, optimize);
}

fn buildLib(
    b: *std.Build,
    lib: *std.Build.Step.Compile,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.Mode,
) void {
    lib.root_module.pic = true;
    if (optimize == .ReleaseSmall) {
        lib.root_module.unwind_tables = .none;
    }
    lib.addCSourceFile(.{
        .file = b.path("src/beacon/beacon_impl.c"),
        .flags = &.{"-std=c99"},
    });
    lib.addCSourceFile(.{
        .file = b.path("src/beacon/stb_sprintf.c"),
        .flags = &.{ "-std=c99", "-fno-sanitize=undefined" },
    });
    if (target.result.os.tag == .windows) {
        lib.linkSystemLibrary2("ws2_32", .{});
        lib.linkSystemLibrary2("ole32", .{});
    }
    lib.bundle_compiler_rt = true;
    if (target.result.cpu.arch == .x86 and target.result.os.tag == .linux) {
        // TODO: LTO causes problems on Linux x86 (segfault in Zig test runner)
        lib.want_lto = false;
    } else {
        lib.want_lto = true;
    }
    b.installArtifact(lib);
}

pub fn osTagStr(target: std.Build.ResolvedTarget) []const u8 {
    return switch (target.result.os.tag) {
        .windows => "win",
        .linux => "lin",
        else => unreachable,
    };
}

pub fn cpuArchStr(target: std.Build.ResolvedTarget) []const u8 {
    return switch (target.result.cpu.arch) {
        .x86_64 => "x64",
        .x86 => "x86",
        .aarch64 => "aarch64",
        .arm => "arm",
        else => unreachable,
    };
}

pub fn libFileName(
    allocator: std.mem.Allocator,
    target: std.Build.ResolvedTarget,
    linkage: std.builtin.LinkMode,
) []const u8 {
    if (linkage == .dynamic and target.result.abi != .none) {
        return std.mem.join(
            allocator,
            "_",
            &.{ "bof_launcher", osTagStr(target), cpuArchStr(target), "shared" },
        ) catch @panic("OOM");
    } else if (linkage == .dynamic and target.result.abi == .none) {
        return std.mem.join(
            allocator,
            "_",
            &.{ "bof_launcher", osTagStr(target), cpuArchStr(target), "shared_nolibc" },
        ) catch @panic("OOM");
    }
    return std.mem.join(
        allocator,
        "_",
        &.{ "bof_launcher", osTagStr(target), cpuArchStr(target) },
    ) catch @panic("OOM");
}
