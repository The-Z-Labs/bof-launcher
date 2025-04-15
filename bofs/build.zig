const bofs_included_in_launcher = [_]Bof{
    .{ .name = "helloBof", .formats = &.{ .elf, .coff }, .archs = &.{ .x64, .x86, .aarch64, .arm } },
    .{ .name = "runBofFromBof", .formats = &.{.coff}, .archs = &.{ .x64, .x86 } },
    .{ .name = "misc", .formats = &.{.elf}, .archs = &.{ .x64, .x86, .aarch64, .arm } },
    .{ .name = "udpScanner", .formats = &.{ .elf, .coff }, .archs = &.{ .x64, .x86, .aarch64, .arm } },
    .{ .name = "tcpScanner", .formats = &.{ .elf, .coff }, .archs = &.{ .x64, .x86, .aarch64, .arm } },
    .{ .name = "simple", .formats = &.{ .elf, .coff }, .archs = &.{ .x64, .x86, .aarch64, .arm } },
    .{ .name = "wWinver", .formats = &.{.coff}, .archs = &.{ .x64, .x86 } },
    .{ .name = "wWinverC", .formats = &.{.coff}, .archs = &.{ .x64, .x86 } },
    .{ .name = "wWhoami", .formats = &.{.coff}, .archs = &.{ .x64, .x86 } },
    .{ .name = "wDirectSyscall", .formats = &.{.coff}, .archs = &.{.x64} },
    .{ .name = "lAsmTest", .formats = &.{.elf}, .archs = &.{.x64} },
    .{ .name = "uname", .dir = "coreutils/", .formats = &.{.elf}, .archs = &.{ .x64, .x86, .aarch64, .arm } },
    .{ .name = "hostid", .dir = "coreutils/", .formats = &.{.elf}, .archs = &.{ .x64, .x86, .aarch64, .arm } },
    .{ .name = "hostname", .dir = "coreutils/", .formats = &.{.elf}, .archs = &.{ .x64, .x86, .aarch64, .arm } },
    .{ .name = "uptime", .dir = "coreutils/", .formats = &.{.elf}, .archs = &.{ .x64, .x86, .aarch64, .arm } },
    .{ .name = "id", .dir = "coreutils/", .formats = &.{.elf}, .archs = &.{ .x64, .x86, .aarch64, .arm } },
    .{ .name = "ifconfig", .dir = "net-tools/", .formats = &.{.elf}, .archs = &.{ .x64, .x86, .aarch64, .arm } },
    .{ .name = "wCloneProcess", .formats = &.{.coff}, .archs = &.{ .x64, .x86 } },
    .{ .name = "wInjectionChainStage0", .dir = "process-injection-chain/", .formats = &.{.coff}, .archs = &.{ .x64, .x86 } },
    .{ .name = "wInjectionChainStage1", .dir = "process-injection-chain/", .formats = &.{.coff}, .archs = &.{ .x64, .x86 } },
    .{ .name = "wInjectionChainStage2", .dir = "process-injection-chain/", .formats = &.{.coff}, .archs = &.{ .x64, .x86 } },
    .{ .name = "wInjectionChainStage3", .dir = "process-injection-chain/", .formats = &.{.coff}, .archs = &.{ .x64, .x86 } },
    .{ .name = "wInjectionChainStage1A", .dir = "process-injection-chain/", .formats = &.{.coff}, .archs = &.{.x64} },
    .{ .name = "wInjectionChainStage2C", .dir = "process-injection-chain/", .formats = &.{.coff}, .archs = &.{ .x64, .x86 } },
    .{ .name = "kmodLoader", .formats = &.{.elf}, .archs = &.{ .x64, .x86, .aarch64, .arm } },
    //.{ .name = "adcs_enum_com2", .srcfile = "entry", .dir = "adcs_enum_com2/", .formats = &.{.coff}, .archs = &.{ .x64, .x86 } },
};

// Additional/3rdparty BOFs for building should be added below

const bofs_my_custom = [_]Bof{
    //.{ .name = "bof", .formats = &.{ .elf, .coff }, .archs = &.{ .x64, .x86, .aarch64, .arm } },
};

fn addBofsToBuild(bofs_to_build: *std.ArrayList(Bof)) !void {
    try bofs_to_build.appendSlice(bofs_included_in_launcher[0..]);

    try bofs_to_build.appendSlice(bofs_my_custom[0..]);
}

const std = @import("std");
const Options = @import("../build.zig").Options;

const BofLang = enum { zig, c, @"asm" };
const BofFormat = enum { coff, elf };
const BofArch = enum { x64, x86, aarch64, arm };

const Bof = struct {
    dir: ?[]const u8 = null,
    // source Filename with contains go(). Only set if go() is in other file than .name
    srcfile: ?[]const u8 = null,
    name: []const u8,
    formats: []const BofFormat,
    archs: []const BofArch,

    fn getTargetQuery(format: BofFormat, arch: BofArch) std.Target.Query {
        if (arch == .arm) {
            // We basically force ARMv6 here.
            return .{
                .cpu_arch = .arm,
                .os_tag = .linux,
                .abi = .gnueabihf,
                .cpu_model = .{ .explicit = &std.Target.arm.cpu.arm1176jz_s }, // ARMv6kz
            };
        }
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
    b: *std.Build,
    bof_parent_step: *std.Build.Step,
    bof_optimize: std.builtin.Mode,
    bof_launcher_api_module: *std.Build.Module,
    bof_api_module: *std.Build.Module,
    bof_launcher_lib_map: std.StringHashMap(*std.Build.Step.Compile),
) !void {
    var bofs_to_build = std.ArrayList(Bof).init(b.allocator);
    defer bofs_to_build.deinit();

    const ZigEnv = struct {
        lib_dir: []const u8,
    };
    const zig_env_args: [2][]const u8 = .{ b.graph.zig_exe, "env" };
    var out_code: u8 = undefined;
    const zig_env = try b.runAllowFail(&zig_env_args, &out_code, .Ignore);
    const parsed_str = try std.json.parseFromSlice(ZigEnv, b.allocator, zig_env, .{ .ignore_unknown_fields = true });
    defer parsed_str.deinit();
    const lib_dir = parsed_str.value.lib_dir;

    try addBofsToBuild(&bofs_to_build);

    try generateBofCollectionYaml(b.allocator, bofs_to_build);

    const windows_include_dir = try std.fs.path.join(
        b.allocator,
        &.{ lib_dir, "/libc/include/any-windows-any" },
    );
    const linux_libc_include_dir = try std.fs.path.join(
        b.allocator,
        &.{ lib_dir, "/libc/include/generic-glibc" },
    );
    const linux_any_include_dir = try std.fs.path.join(
        b.allocator,
        &.{ lib_dir, "/libc/include/any-linux-any" },
    );

    for (bofs_to_build.items) |bof| {
        const source_file_path, const lang = try getBofSourcePathAndLang(b.allocator, bof);

        for (bof.formats) |format| {
            for (bof.archs) |arch| {
                if (format == .coff and arch == .aarch64) continue;
                if (format == .coff and arch == .arm) continue;

                const full_bof_name = try std.mem.join(
                    b.allocator,
                    ".",
                    &.{ bof.name, @tagName(format), @tagName(arch), "o" },
                );
                const bin_full_bof_name = try std.mem.join(b.allocator, "/", &.{ "bin", full_bof_name });

                if (lang == .@"asm") {
                    // We provide fasm binaries only for x86.
                    if (@import("builtin").cpu.arch != .x86_64 and @import("builtin").cpu.arch != .x86)
                        continue;

                    const run_fasm = b.addSystemCommand(&.{
                        thisDir() ++ "/../bin/fasm" ++ if (@import("builtin").os.tag == .windows) ".exe" else "",
                    });
                    run_fasm.addFileArg(.{ .cwd_relative = source_file_path });
                    const output_path = run_fasm.addOutputFileArg(full_bof_name);

                    b.getInstallStep().dependOn(&b.addInstallFile(output_path, bin_full_bof_name).step);

                    continue; // This is all we need to do in case of asm BOF. Continue to the next BOF.
                }

                const target = b.resolveTargetQuery(Bof.getTargetQuery(format, arch));
                const obj = switch (lang) {
                    .@"asm" => unreachable,
                    .zig => b.addObject(.{
                        .name = bof.name,
                        .root_source_file = .{ .cwd_relative = source_file_path },
                        .target = target,
                        .optimize = bof_optimize,
                    }),
                    .c => blk: {
                        const obj = b.addObject(.{
                            .name = bof.name,
                            // TODO: Zig bug. Remove below line once fixed.
                            .root_source_file = b.path("tests/src/dummy.zig"),
                            .target = target,
                            .optimize = bof_optimize,
                        });
                        obj.addCSourceFile(.{
                            .file = .{ .cwd_relative = source_file_path },
                            .flags = &.{
                                "-DBOF", "-D_GNU_SOURCE",
                                if (arch == .x86 or arch == .x64)
                                    "-include" ++ thisDir() ++ "/src/force_intel_asm.h"
                                else
                                    "",
                                if (arch == .x86) "-DWOW64" else "",
                            },
                        });
                        if (format == .coff) {
                            obj.addIncludePath(.{ .cwd_relative = windows_include_dir });
                        } else if (format == .elf) {
                            const linux_include_dir = try std.mem.join(
                                b.allocator,
                                "",
                                &.{
                                    lib_dir,
                                    "/libc/include/",
                                    @tagName(target.result.cpu.arch),
                                    "-linux-",
                                    @tagName(target.result.abi),
                                },
                            );
                            obj.addIncludePath(.{ .cwd_relative = linux_include_dir });
                            obj.addIncludePath(.{ .cwd_relative = linux_libc_include_dir });
                            obj.addIncludePath(.{ .cwd_relative = linux_any_include_dir });
                        }
                        break :blk obj;
                    },
                };
                obj.addIncludePath(b.path("include"));
                obj.root_module.addImport("bof_api", bof_api_module);
                obj.root_module.pic = true;
                obj.root_module.single_threaded = true;
                obj.root_module.strip = if (bof_optimize == .Debug) false else true;
                obj.root_module.unwind_tables = false;

                // Needed for BOFs that launch other BOFs
                obj.root_module.addAnonymousImport("bof_launcher_api", .{
                    .root_source_file = .{ .cwd_relative = thisDir() ++ "/../bof-launcher/src/bof_launcher_api.zig" },
                });

                obj.step.dependOn(bof_parent_step);

                // Build debug executable in debug mode.
                if (bof_optimize == .Debug) {
                    const linux_triple = target.result.linuxTriple(b.allocator) catch unreachable;

                    const full_debug_exe_name = try std.mem.join(
                        b.allocator,
                        ".",
                        &.{ bof.name, @tagName(format), @tagName(arch) },
                    );
                    const debug_exe = b.addExecutable(.{
                        .root_source_file = .{ .cwd_relative = thisDir() ++ "/src/_debug_entry.zig" },
                        .name = full_debug_exe_name,
                        .target = target,
                        .optimize = bof_optimize,
                    });
                    debug_exe.linkLibrary(bof_launcher_lib_map.get(linux_triple).?);
                    debug_exe.linkLibC();
                    debug_exe.root_module.addImport("bof_launcher_api", bof_launcher_api_module);
                    if (target.query.os_tag == .windows) {
                        debug_exe.linkSystemLibrary2("ws2_32", .{});
                        debug_exe.linkSystemLibrary2("ole32", .{});
                        debug_exe.linkSystemLibrary2("kernel32", .{});
                    }
                    debug_exe.addObject(obj);
                    b.installArtifact(debug_exe);
                } else {
                    b.getInstallStep().dependOn(&b.addInstallFile(obj.getEmittedBin(), bin_full_bof_name).step);
                }
            }
        }
    }
}

fn generateBofCollectionYaml(
    allocator: std.mem.Allocator,
    bofs_to_build: std.ArrayList(Bof),
) !void {
    const doc_file = try std.fs.cwd().createFile("BOF-collection.yaml", .{});
    defer doc_file.close();

    for (bofs_to_build.items) |bof| {
        const source_file_path, const lang = try getBofSourcePathAndLang(allocator, bof);

        if (lang != .@"asm") {
            const source_file = try std.fs.openFileAbsolute(source_file_path, .{});
            defer source_file.close();

            const source = try source_file.readToEndAlloc(allocator, std.math.maxInt(u32));
            defer allocator.free(source);

            _ = std.mem.replace(u8, source, "\r\n", "\n", source);

            var line_number: u32 = 1;
            var iter = std.mem.splitSequence(u8, source, "\n");
            while (iter.next()) |source_line| {
                if (source_line.len >= 3 and std.mem.eql(u8, source_line[0..3], "///")) {
                    if (line_number == 1) try doc_file.writeAll("---\n");
                    line_number += 1;
                    try doc_file.writeAll(source_line[3..]);
                    try doc_file.writeAll("\n");
                }
            }
        }
    }
}

fn getBofSourcePathAndLang(
    allocator: std.mem.Allocator,
    bof: Bof,
) !struct { []const u8, BofLang } {
    const bof_src_path = try std.mem.join(
        allocator,
        "",
        &.{
            thisDir(),
            "/src/",
            if (bof.dir) |dir| dir else "",
            if (bof.srcfile) |srcfile| srcfile else bof.name,
        },
    );

    const lang: BofLang = blk: {
        std.fs.accessAbsolute(
            try std.mem.join(allocator, ".", &.{ bof_src_path, "zig" }),
            .{},
        ) catch {
            std.fs.accessAbsolute(
                try std.mem.join(allocator, ".", &.{ bof_src_path, "asm" }),
                .{},
            ) catch break :blk .c;

            break :blk .@"asm";
        };
        break :blk .zig;
    };

    const extension = blk: {
        std.fs.accessAbsolute(
            try std.mem.join(allocator, ".", &.{ bof_src_path, "cpp" }),
            .{},
        ) catch {
            break :blk @tagName(lang);
        };
        break :blk "cpp";
    };

    const source_file_path = try std.mem.join(allocator, ".", &.{ bof_src_path, extension });

    return .{ source_file_path, lang };
}

inline fn thisDir() []const u8 {
    return comptime std.fs.path.dirname(@src().file) orelse ".";
}
