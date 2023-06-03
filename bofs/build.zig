const std = @import("std");

const Options = @import("../build.zig").Options;

const BofLang = enum { zig, c };
const BofFormat = enum { coff, elf };
const BofArch = enum { x64, x86 };

const Bof = struct {
    dir: []const u8,
    name: []const u8,
    lang: BofLang,
    format: BofFormat,
    arch: BofArch,

    fn getCrossTarget(bof: Bof) std.zig.CrossTarget {
        return .{
            .cpu_arch = switch (bof.arch) {
                .x64 => .x86_64,
                .x86 => .x86,
            },
            .os_tag = switch (bof.format) {
                .coff => .windows,
                .elf => .linux,
            },
            .abi = .gnu,
        };
    }

    fn getFullName(comptime bof: Bof) []const u8 {
        return bof.name ++ "." ++ @tagName(bof.format) ++ "." ++ @tagName(bof.arch) ++ ".o";
    }
};

// Naming convention:
// c* - cross platform BOFs
// l* - Linux-only BOFs
// w* - Windows-only BOFs
const bofs = [_]Bof{
    .{ .dir = "", .name = "lUname", .lang = .zig, .format = .elf, .arch = .x64 },
    .{ .dir = "", .name = "lUname", .lang = .zig, .format = .elf, .arch = .x86 },

    .{ .dir = "", .name = "cUDPscan", .lang = .zig, .format = .elf, .arch = .x64 },
    .{ .dir = "", .name = "cUDPscan", .lang = .zig, .format = .elf, .arch = .x86 },
    .{ .dir = "", .name = "cUDPscan", .lang = .zig, .format = .coff, .arch = .x64 },
    .{ .dir = "", .name = "cUDPscan", .lang = .zig, .format = .coff, .arch = .x86 },
};

pub fn build(b: *std.build.Builder, _: Options) void {
    // Get directory with `windows.h` (and others windows headers) from zig installation.
    const windows_include_dir = std.fs.path.join(
        b.allocator,
        &.{ std.fs.path.dirname(b.zig_exe).?, "/lib/libc/include/any-windows-any" },
    ) catch unreachable;
    defer b.allocator.free(windows_include_dir);

    const bofapi = b.createModule(.{
        .source_file = .{ .path = thisDir() ++ "/../include/bofapi.zig" },
    });

    inline for (bofs) |bof| {
        const target = bof.getCrossTarget();
        const obj = switch (bof.lang) {
            .zig => b.addObject(.{
                .name = bof.name,
                .root_source_file = .{ .path = thisDir() ++ "/src/" ++ bof.dir ++ bof.name ++ ".zig" },
                .target = target,
                .optimize = .ReleaseSmall,
            }),
            .c => blk: {
                const obj = b.addObject(.{
                    .name = bof.name,
                    .target = target,
                    .optimize = .ReleaseSmall,
                });
                @setEvalBranchQuota(5001);
                obj.addCSourceFile(thisDir() ++ "/src/" ++ bof.dir ++ bof.name ++ ".c", &.{
                    "-DWINBASEAPI=",
                    "-D_CRTIMP=",
                    "-DLDAPAPI=",
                    "-DBOF",
                    "-std=c99",
                    "-masm=intel",
                    "-inline-asm=intel",
                    if (bof.format == .coff) "-DDECLSPEC_IMPORT=" else "",
                });
                if (bof.format == .coff)
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
            &b.addInstallFile(obj.getOutputSource(), "bin/" ++ comptime bof.getFullName()).step,
        );
    }
}

inline fn thisDir() []const u8 {
    return comptime std.fs.path.dirname(@src().file) orelse ".";
}
