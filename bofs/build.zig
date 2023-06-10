const std = @import("std");

const Options = @import("../build.zig").Options;

const BofLang = enum { zig, c };
const BofFormat = enum { coff, elf };
const BofArch = enum { x64, x86 };

const Bof = struct {
    dir: ?[]const u8 = null,
    name: []const u8,
    langs: []const BofLang,
    formats: []const BofFormat,
    archs: []const BofArch,

    fn getCrossTarget(format: BofFormat, arch: BofArch) std.zig.CrossTarget {
        return .{
            .cpu_arch = switch (arch) {
                .x64 => .x86_64,
                .x86 => .x86,
            },
            .os_tag = switch (format) {
                .coff => .windows,
                .elf => .linux,
            },
            .abi = .gnu,
        };
    }
};

// Naming convention:
// c* - cross platform BOFs
// l* - Linux-only BOFs
// w* - Windows-only BOFs
const bofs = [_]Bof{
    .{ .name = "lUname", .langs = &.{.zig}, .formats = &.{.elf}, .archs = &.{ .x64, .x86 } },
    .{ .name = "cUDPscan", .langs = &.{.zig}, .formats = &.{ .elf, .coff }, .archs = &.{ .x64, .x86 } },
    .{ .name = "wWinver", .langs = &.{.zig}, .formats = &.{.coff}, .archs = &.{ .x64, .x86 } },
};

pub fn build(b: *std.build.Builder, _: Options) void {
    // Get directory with `windows.h` (and others windows headers) from zig installation.
    const windows_include_dir = std.fs.path.join(
        b.allocator,
        &.{ std.fs.path.dirname(b.zig_exe).?, "/lib/libc/include/any-windows-any" },
    ) catch unreachable;

    const bofapi = b.createModule(.{
        .source_file = .{ .path = thisDir() ++ "/../include/bofapi.zig" },
    });

    for (bofs) |bof| {
        const bof_src_path = std.mem.join(
            b.allocator,
            "",
            &.{ thisDir(), "/src/", if (bof.dir) |dir| dir else "", bof.name },
        ) catch unreachable;

        for (bof.langs) |lang| {
            for (bof.formats) |format| {
                for (bof.archs) |arch| {
                    const target = Bof.getCrossTarget(format, arch);
                    const obj = switch (lang) {
                        .zig => b.addObject(.{
                            .name = bof.name,
                            .root_source_file = .{
                                .path = std.mem.join(
                                    b.allocator,
                                    "",
                                    &.{ bof_src_path, ".zig" },
                                ) catch unreachable,
                            },
                            .target = target,
                            .optimize = .ReleaseSmall,
                        }),
                        .c => blk: {
                            const obj = b.addObject(.{
                                .name = bof.name,
                                .target = target,
                                .optimize = .ReleaseSmall,
                            });
                            obj.addCSourceFile(
                                std.mem.join(b.allocator, "", &.{ bof_src_path, ".c" }) catch unreachable,
                                &.{
                                    "-DWINBASEAPI=",
                                    "-D_CRTIMP=",
                                    "-DLDAPAPI=",
                                    "-DBOF",
                                    "-std=c99",
                                    "-masm=intel",
                                    "-inline-asm=intel",
                                    if (format == .coff) "-DDECLSPEC_IMPORT=" else "",
                                },
                            );
                            if (format == .coff)
                                obj.addIncludePath(windows_include_dir);
                            break :blk obj;
                        },
                    };
                    obj.addModule("bofapi", bofapi);
                    obj.addIncludePath(thisDir() ++ "/../include");
                    obj.force_pic = true;
                    obj.single_threaded = true;
                    obj.strip = true;

                    b.getInstallStep().dependOn(
                        &b.addInstallFile(
                            obj.getOutputSource(),
                            std.mem.join(b.allocator, "", &.{
                                "bin/",
                                bof.name,
                                ".",
                                @tagName(format),
                                ".",
                                @tagName(arch),
                                ".o",
                            }) catch unreachable,
                        ).step,
                    );
                }
            }
        }
    }
}

inline fn thisDir() []const u8 {
    return comptime std.fs.path.dirname(@src().file) orelse ".";
}
