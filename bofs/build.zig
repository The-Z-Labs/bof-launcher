// -----------------------------------------------------------------------------
// BOFs TABLEs
// -----------------------------------------------------------------------------

// BOFs included with bof-launcher
const bofs = [_]Bof{
    .{ .name = "helloBof", .formats = &.{.elf}, .archs = &.{ .x64, .x86, .aarch64, .arm } },
    .{ .name = "uname", .formats = &.{.elf}, .archs = &.{ .x64, .x86, .aarch64, .arm } },
    .{ .name = "uptime", .formats = &.{.elf}, .archs = &.{ .x64, .x86, .aarch64, .arm } },
    //.{ .name = "uptimeC", .formats = &.{.elf}, .archs = &.{ .x64, .x86, .aarch64, .arm } },
    .{ .name = "udpScanner", .formats = &.{ .elf, .coff }, .archs = &.{ .x64, .x86, .aarch64, .arm } },
    .{ .name = "wWinver", .formats = &.{.coff}, .archs = &.{ .x64, .x86 } },
    .{ .name = "wWinverC", .formats = &.{.coff}, .archs = &.{ .x64, .x86 } },
    .{ .name = "wWhoami", .formats = &.{.coff}, .archs = &.{ .x64, .x86 } },
    //.{ .name = "adcs_enum_com2", .go = "entry", .dir = "adcs_enum_com2/", .formats = &.{.coff}, .archs = &.{ .x64, .x86 } },
};

// other BOFs for building should be defined here
// ...
// -----------------------------------------------------------------------------

const std = @import("std");
const Options = @import("../build.zig").Options;

const BofLang = enum { zig, c };
const BofFormat = enum { coff, elf };
const BofArch = enum { x64, x86, aarch64, arm };

const Bof = struct {
    dir: ?[]const u8 = null,
    // source file name with go() function if in other file than .name
    go: ?[]const u8 = null,
    name: []const u8,
    formats: []const BofFormat,
    archs: []const BofArch,

    fn getCrossTarget(format: BofFormat, arch: BofArch) std.zig.CrossTarget {
        return .{
            .cpu_arch = switch (arch) {
                .x64 => .x86_64,
                .x86 => .x86,
                .aarch64 => .aarch64,
                .arm => .arm,
            },
            .os_tag = switch (format) {
                .coff => .windows,
                .elf => .linux,
            },
            .abi = if (arch == .arm) .gnueabihf else .gnu,
        };
    }
};

pub fn build(
    b: *std.build.Builder,
    bof_api_module: *std.Build.Module,
) void {
    // Get directory with `windows.h` (and others windows headers) from zig installation.
    const windows_include_dir = std.fs.path.join(
        b.allocator,
        &.{ std.fs.path.dirname(b.zig_exe).?, "/lib/libc/include/any-windows-any" },
    ) catch unreachable;

    var bofsList = std.ArrayList(Bof).init(b.allocator);
    defer bofsList.deinit();

    // appending BOFs included with bof-launcher
    for (bofs) |bof| {
        bofsList.append(bof) catch unreachable;
    }

    // additional/3rdparty BOFs for building should be appended here
    // ...

    for (bofsList.items) |bof| {
        const bof_src_path = std.mem.join(
            b.allocator,
            "",
            &.{ thisDir(), "/src/", if (bof.dir) |dir| dir else "", if (bof.go) |go| go else bof.name },
        ) catch unreachable;

        const lang: BofLang = blk: {
            std.fs.accessAbsolute(
                std.mem.join(b.allocator, "", &.{ bof_src_path, ".zig" }) catch unreachable,
                .{},
            ) catch break :blk .c;
            break :blk .zig;
        };

        for (bof.formats) |format| {
            for (bof.archs) |arch| {
                if (format == .coff and arch == .aarch64) continue;
                if (format == .coff and arch == .arm) continue;

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
                        obj.addCSourceFile(.{
                            .file = .{
                                .path = std.mem.join(
                                    b.allocator,
                                    "",
                                    &.{ bof_src_path, ".c" },
                                ) catch unreachable,
                            },
                            .flags = &.{
                                "-I/usr/include",
                                "-DWINBASEAPI=",
                                "-D_CRTIMP=",
                                "-DLDAPAPI=",
                                "-DBOF",
                                "-std=c99",
                                "-masm=intel",
                                "-inline-asm=intel",
                                if (format == .coff) "-DDECLSPEC_IMPORT=" else "",
                            },
                        });
                        if (format == .coff)
                            obj.addIncludePath(.{ .path = windows_include_dir });
                        break :blk obj;
                    },
                };
                obj.addModule("bofapi", bof_api_module);
                obj.addIncludePath(.{ .path = thisDir() ++ "/../include" });
                obj.force_pic = true;
                obj.single_threaded = true;
                obj.strip = true;
                obj.unwind_tables = false;

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

inline fn thisDir() []const u8 {
    return comptime std.fs.path.dirname(@src().file) orelse ".";
}
