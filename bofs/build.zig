const bofs_included_in_launcher = [_]Bof{
    .{ .name = "helloBof", .formats = &.{ .elf, .coff }, .archs = &.{ .x64, .x86, .aarch64, .arm } },
    .{ .name = "wProcessInfoMessageBox", .formats = &.{.coff}, .archs = &.{ .x64, .x86 } },
    .{ .name = "wProcessInjectionSrdi", .formats = &.{.coff}, .archs = &.{ .x64, .x86 } },
    .{ .name = "runBofFromBof", .formats = &.{.coff}, .archs = &.{ .x64, .x86 } },
    .{ .name = "misc", .formats = &.{.elf}, .archs = &.{ .x64, .x86, .aarch64, .arm } },
    .{ .name = "udpScanner", .formats = &.{ .elf, .coff }, .archs = &.{ .x64, .x86, .aarch64, .arm } },
    .{ .name = "tcpScanner", .formats = &.{ .elf, .coff }, .archs = &.{ .x64, .x86, .aarch64, .arm } },
    .{ .name = "simple", .formats = &.{ .elf, .coff }, .archs = &.{ .x64, .x86, .aarch64, .arm } },
    .{ .name = "wWinver", .formats = &.{.coff}, .archs = &.{ .x64, .x86 } },
    .{ .name = "wWinverC", .formats = &.{.coff}, .archs = &.{ .x64, .x86 }, .cflagsFn = cflags_wWinverC },
    .{ .name = "whoami", .formats = &.{ .elf, .coff }, .archs = &.{ .x64, .x86, .aarch64, .arm } },
    .{ .name = "wAsmTest", .formats = &.{.coff}, .archs = &.{.x64} },
    .{ .name = "lAsmTest", .formats = &.{.elf}, .archs = &.{.x64} },
    .{ .name = "uname", .dir = "coreutils/", .formats = &.{.elf}, .archs = &.{ .x64, .x86, .aarch64, .arm } },
    .{ .name = "hostid", .dir = "coreutils/", .formats = &.{.elf}, .archs = &.{ .x64, .x86, .aarch64, .arm } },
    .{ .name = "hostname", .dir = "coreutils/", .formats = &.{.elf}, .archs = &.{ .x64, .x86, .aarch64, .arm } },
    .{ .name = "uptime", .dir = "coreutils/", .formats = &.{.elf}, .archs = &.{ .x64, .x86, .aarch64, .arm } },
    .{ .name = "id", .dir = "coreutils/", .formats = &.{.elf}, .archs = &.{ .x64, .x86, .aarch64, .arm } },
    .{ .name = "cat", .formats = &.{.elf, .coff}, .archs = &.{ .x64, .x86, .aarch64, .arm } },
    .{ .name = "pwd", .formats = &.{.elf, .coff}, .archs = &.{ .x64, .x86, .aarch64, .arm } },
    .{ .name = "cd", .formats = &.{.elf, .coff}, .archs = &.{ .x64, .x86, .aarch64, .arm } },
    .{ .name = "ls", .formats = &.{.elf, .coff}, .archs = &.{ .x64, .x86, .aarch64, .arm } },
    .{ .name = "ifconfig", .dir = "net-tools/", .formats = &.{.elf}, .archs = &.{ .x64, .x86, .aarch64, .arm } },
    .{ .name = "wCloneProcess", .formats = &.{.coff}, .archs = &.{ .x64, .x86 } },
    .{ .name = "wInjectionChainStage0", .dir = "process-injection-chain/", .formats = &.{.coff}, .archs = &.{ .x64, .x86 } },
    .{ .name = "wInjectionChainStage1", .dir = "process-injection-chain/", .formats = &.{.coff}, .archs = &.{ .x64, .x86 } },
    .{ .name = "wInjectionChainStage2", .dir = "process-injection-chain/", .formats = &.{.coff}, .archs = &.{ .x64, .x86 } },
    .{ .name = "wInjectionChainStage3", .dir = "process-injection-chain/", .formats = &.{.coff}, .archs = &.{ .x64, .x86 } },
    .{ .name = "wInjectionChainStage2C", .dir = "process-injection-chain/", .formats = &.{.coff}, .archs = &.{ .x64, .x86 } },
    .{ .name = "kmodLoader", .formats = &.{.elf}, .archs = &.{ .x64, .x86, .aarch64, .arm } },
    .{ .name = "lskmod", .formats = &.{.elf}, .archs = &.{ .x64, .x86, .aarch64, .arm } },
    //.{ .name = "sniffer", .formats = &.{.elf}, .archs = &.{.x64}, .cflagsFn = cflags_sniffer },
    // BOF0 - special purpose BOF that acts as a standalone implant and uses other BOFs as its post-ex modules:
    .{ .name = "z-beac0n-core", .formats = &.{ .elf, .coff }, .archs = &.{ .x64, .x86, .aarch64, .arm } },
};

const bofs_for_testing = [_]Bof{
    .{ .name = "test_obj0", .dir = "tests/", .formats = &.{ .elf, .coff }, .archs = &.{ .x64, .x86, .aarch64, .arm } },
    .{ .name = "test_obj1", .dir = "tests/", .formats = &.{ .elf, .coff }, .archs = &.{ .x64, .x86, .aarch64, .arm } },
    .{ .name = "test_obj2", .dir = "tests/", .formats = &.{ .elf, .coff }, .archs = &.{ .x64, .x86, .aarch64, .arm } },
    .{ .name = "test_obj3", .dir = "tests/", .formats = &.{ .elf, .coff }, .archs = &.{ .x64, .x86, .aarch64, .arm } },
    .{ .name = "test_obj4", .dir = "tests/", .formats = &.{ .elf, .coff }, .archs = &.{ .x64, .x86, .aarch64, .arm } },
    .{ .name = "test_async", .dir = "tests/", .formats = &.{ .elf, .coff }, .archs = &.{ .x64, .x86, .aarch64, .arm } },
    .{ .name = "test_long_running", .dir = "tests/", .formats = &.{ .elf, .coff }, .archs = &.{ .x64, .x86, .aarch64, .arm } },
    .{ .name = "test_beacon_format", .dir = "tests/", .formats = &.{ .elf, .coff }, .archs = &.{ .x64, .x86, .aarch64, .arm } },
    .{ .name = "test_args", .dir = "tests/", .formats = &.{ .elf, .coff }, .archs = &.{ .x64, .x86, .aarch64, .arm } },
};

// Additional/3rdparty BOFs for building should be added below

const bofs_my_custom = [_]Bof{
    //.{ .name = "bof", .formats = &.{ .elf, .coff }, .archs = &.{ .x64, .x86, .aarch64, .arm } },
};

pub const bofs_to_build = bofs_included_in_launcher ++ bofs_for_testing ++ bofs_my_custom;

const std = @import("std");

const BofLang = enum { zig, c, @"asm" };
const BofFormat = enum { coff, elf };
const BofArch = enum { x64, x86, aarch64, arm };

pub const Bof = struct {
    dir: ?[]const u8 = null,
    // source Filename with contains go(). Only set if go() is in other file than .name
    srcfile: ?[]const u8 = null,
    name: []const u8,
    formats: []const BofFormat,
    archs: []const BofArch,
    cflagsFn: ?CFlagsFn = null,

    pub fn getTargetQuery(format: BofFormat, arch: BofArch) std.Target.Query {
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
                .arm => unreachable,
            },
            .os_tag = switch (format) {
                .coff => .windows,
                .elf => .linux,
            },
            .abi = .gnu,
        };
    }

    pub fn fullName(
        allocator: std.mem.Allocator,
        name: []const u8,
        format: BofFormat,
        arch: BofArch,
        optimize: std.builtin.OptimizeMode,
    ) []const u8 {
        if (optimize == .Debug) {
            return std.mem.join(
                allocator,
                ".",
                &.{ name, @tagName(format), @tagName(arch), "debug" },
            ) catch @panic("OOM");
        }
        return std.mem.join(
            allocator,
            ".",
            &.{ name, @tagName(format), @tagName(arch) },
        ) catch @panic("OOM");
    }
};

pub fn build(b: *std.Build) !void {
    const bof_optimize = b.standardOptimizeOption(.{});

    const win32_dep = b.dependency("bof_launcher_win32", .{});

    const bof_api_module = b.addModule("bof_api", .{
        .root_source_file = b.path("src/include/bof_api.zig"),
    });
    bof_api_module.addAnonymousImport(
        "bof_launcher_win32",
        .{ .root_source_file = win32_dep.path("src/win32.zig") },
    );

    try generateBofCollectionYaml(b, &bofs_to_build);

    for (bofs_to_build) |bof| {
        const source_file_path, const lang = try getBofSourcePathAndLang(b, bof);

        for (bof.formats) |format| {
            for (bof.archs) |arch| {
                if (format == .coff and arch == .aarch64) continue;
                if (format == .coff and arch == .arm) continue;

                const full_name = Bof.fullName(b.allocator, bof.name, format, arch, .ReleaseSmall);

                const target = b.resolveTargetQuery(Bof.getTargetQuery(format, arch));

                const bof_launcher_dep = b.dependency(
                    "bof_launcher_lib",
                    .{ .target = target, .optimize = bof_optimize },
                );
                const bof_launcher_api_module = bof_launcher_dep.module("bof_launcher_api");

                const bof_launcher_lib = bof_launcher_dep.artifact(
                    @import("bof_launcher_lib").libFileName(b.allocator, target, null),
                );

                const obj = try addBofObj(
                    b,
                    full_name,
                    lang,
                    source_file_path,
                    target,
                    .ReleaseSmall,
                    format,
                    arch,
                    bof_api_module,
                    bof_launcher_dep,
                    bof.cflagsFn,
                );
                b.getInstallStep().dependOn(&b.addInstallArtifact(
                    obj,
                    .{
                        .dest_dir = .{ .override = .bin },
                        .dest_sub_path = b.fmt("{s}.o", .{full_name}),
                    },
                ).step);

                // Build debug executable from a BOF.
                if (bof_optimize == .Debug) {
                    const full_name_debug = Bof.fullName(b.allocator, bof.name, format, arch, .Debug);
                    const debug_obj = try addBofObj(
                        b,
                        full_name_debug,
                        lang,
                        source_file_path,
                        target,
                        .Debug,
                        format,
                        arch,
                        bof_api_module,
                        bof_launcher_dep,
                        bof.cflagsFn,
                    );
                    const debug_exe = b.addExecutable(.{
                        .root_source_file = b.path("src/_debug_entry.zig"),
                        .name = full_name_debug,
                        .target = target,
                        .optimize = .Debug,
                    });
                    debug_exe.linkLibrary(bof_launcher_lib);
                    debug_exe.linkLibC();
                    debug_exe.root_module.addImport("bof_launcher_api", bof_launcher_api_module);
                    if (target.query.os_tag == .windows) {
                        debug_exe.linkSystemLibrary2("ws2_32", .{});
                        debug_exe.linkSystemLibrary2("ole32", .{});
                    }
                    debug_exe.addObject(debug_obj);
                    b.installArtifact(debug_exe);
                }
            }
        }
    }
}

fn addBofObj(
    b: *std.Build,
    full_name: []const u8,
    lang: BofLang,
    source_file_path: []const u8,
    target: std.Build.ResolvedTarget,
    bof_optimize: std.builtin.OptimizeMode,
    format: BofFormat,
    arch: BofArch,
    bof_api_module: *std.Build.Module,
    bof_launcher_dep: *std.Build.Dependency,
    cflagsFn: ?CFlagsFn,
) !*std.Build.Step.Compile {
    const obj = switch (lang) {
        .@"asm" => blk: {
            const obj = b.addAssembly(.{
                .name = full_name,
                .source_file = b.path(source_file_path),
                .target = target,
                .optimize = bof_optimize,
            });
            if (cflagsFn) |callback| _ = callback(b, obj, format, arch);
            break :blk obj;
        },
        .zig => blk: {
            const obj = b.addObject(.{
                .name = full_name,
                .root_source_file = b.path(source_file_path),
                .target = target,
                .optimize = bof_optimize,
                .link_libc = false,
            });
            if (cflagsFn) |callback| _ = callback(b, obj, format, arch);
            break :blk obj;
        },
        .c => blk: {
            const obj = b.addObject(.{
                .name = full_name,
                .root_module = b.createModule(.{
                    // TODO: Zig bug. `.root_source_file = null` should be possible.
                    .root_source_file = b.path("src/tests/dummy.zig"),
                    .target = target,
                    .optimize = bof_optimize,
                    .link_libc = true,
                }),
            });
            const flags = if (cflagsFn) |cflags| cflags(b, obj, format, arch) else &.{};
            obj.root_module.addCSourceFile(.{
                .file = b.path(source_file_path),
                .flags = flags,
            });
            break :blk obj;
        },
    };

    obj.root_module.pic = true;
    obj.root_module.single_threaded = true;
    obj.root_module.strip = if (bof_optimize == .Debug) false else true;
    obj.root_module.unwind_tables = .none;

    if (lang != .@"asm") {
        obj.root_module.addIncludePath(b.path("src/include"));
        obj.root_module.addImport("bof_api", bof_api_module);
        // Needed for BOFs that launch other BOFs
        obj.root_module.addAnonymousImport(
            "bof_launcher_api",
            .{ .root_source_file = bof_launcher_dep.path("src/bof_launcher_api.zig") },
        );

        if (target.result.cpu.arch == .x86 and
            target.result.os.tag == .linux)
        {
            // TODO: Shared library fails to build on Linux x86.
        } else {
            const bof_launcher_shared_lib = bof_launcher_dep.artifact(
                @import("bof_launcher_lib").libFileName(b.allocator, target, "shared"),
            );
            obj.root_module.addAnonymousImport("bof_launcher_lib_embed", .{
                .root_source_file = bof_launcher_shared_lib.getEmittedBin(),
            });
        }
    }

    return obj;
}

const CFlagsFn = *const fn (*std.Build, *std.Build.Step.Compile, BofFormat, BofArch) []const []const u8;

fn cflags_wWinverC(b: *std.Build, obj: *std.Build.Step.Compile, format: BofFormat, arch: BofArch) []const []const u8 {
    _ = .{ b, obj, format, arch };
    return &.{"-DMY_DEFINE"};
}

fn cflags_sniffer(b: *std.Build, obj: *std.Build.Step.Compile, format: BofFormat, arch: BofArch) []const []const u8 {
    _ = .{ format, arch };

    obj.root_module.addIncludePath(b.path("dependencies/libpcap"));
    obj.root_module.addObjectFile(b.path("dependencies/libpcap/libpcap.a"));

    return &.{};
}

fn generateBofCollectionYaml(b: *std.Build, bofs: []const Bof) !void {
    const doc_file = try std.fs.cwd().createFile("BOF-collection.yaml", .{});
    defer doc_file.close();

    for (bofs) |bof| {
        const source_file_path, const lang = try getBofSourcePathAndLang(b, bof);

        if (lang != .@"asm") {
            const source_file = try std.fs.cwd().openFile(b.pathFromRoot(source_file_path), .{});
            defer source_file.close();

            const source = try source_file.readToEndAlloc(b.allocator, std.math.maxInt(u32));
            defer b.allocator.free(source);

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
    b: *std.Build,
    bof: Bof,
) !struct { []const u8, BofLang } {
    const bof_src_path = try std.mem.join(
        b.allocator,
        "",
        &.{
            "src/",
            if (bof.dir) |dir| dir else "",
            if (bof.srcfile) |srcfile| srcfile else bof.name,
        },
    );

    const lang: BofLang = blk: {
        std.fs.cwd().access(b.fmt("{s}.zig", .{b.pathFromRoot(bof_src_path)}), .{}) catch {
            std.fs.cwd().access(b.fmt("{s}.s", .{b.pathFromRoot(bof_src_path)}), .{}) catch break :blk .c;
            break :blk .@"asm";
        };
        break :blk .zig;
    };

    const extension = switch (lang) {
        .zig => "zig",
        .c => "c",
        .@"asm" => "s",
    };

    const source_file_path = b.fmt("{s}.{s}", .{ bof_src_path, extension });

    return .{ source_file_path, lang };
}
