//
// BEGIN: BOF TABLES
//
const BofTableItem = struct {
    name: []const u8,
    formats: []const BofFormat,
    archs: []const BofArch,
    dir: ?[]const u8 = null,
    custom_build_fn: ?CustomBuildFn = null,

    // Source file name which contains go() entry point. Set it only if go() is in other file than name of the BOF.
    srcfile: ?[]const u8 = null,
};

const bofs_included_in_launcher = [_]BofTableItem{
    .{ .name = "helloBof", .formats = &.{ .elf, .coff }, .archs = &.{ .x64, .x86, .aarch64, .arm } },
    .{ .name = "wProcessInfoMessageBox", .formats = &.{.coff}, .archs = &.{ .x64, .x86 } },
    .{ .name = "wProcessInjectionSrdi", .formats = &.{.coff}, .archs = &.{ .x64, .x86 } },
    .{ .name = "runBofFromBof", .formats = &.{.coff}, .archs = &.{ .x64, .x86 } },
    .{ .name = "misc", .formats = &.{.elf}, .archs = &.{ .x64, .x86, .aarch64, .arm } },
    .{ .name = "udpScanner", .formats = &.{ .elf, .coff }, .archs = &.{ .x64, .x86, .aarch64, .arm } },
    .{ .name = "tcpScanner", .formats = &.{ .elf, .coff }, .archs = &.{ .x64, .x86, .aarch64, .arm } },
    .{ .name = "simple", .formats = &.{.elf}, .archs = &.{ .x64, .x86, .aarch64, .arm } },
    .{ .name = "wWinver", .formats = &.{.coff}, .archs = &.{ .x64, .x86 } },
    .{ .name = "wWinverC", .formats = &.{.coff}, .archs = &.{ .x64, .x86 }, .custom_build_fn = build_wWinverC },
    .{ .name = "whoami", .formats = &.{ .elf, .coff }, .archs = &.{ .x64, .x86, .aarch64, .arm } },
    .{ .name = "wAsmTest", .formats = &.{.coff}, .archs = &.{.x64} },
    .{ .name = "lAsmTest", .formats = &.{.elf}, .archs = &.{.x64} },
    .{ .name = "uname", .dir = "coreutils/", .formats = &.{.elf}, .archs = &.{ .x64, .x86, .aarch64, .arm } },
    .{ .name = "hostid", .dir = "coreutils/", .formats = &.{.elf}, .archs = &.{ .x64, .x86, .aarch64, .arm } },
    .{ .name = "hostname", .dir = "coreutils/", .formats = &.{.elf}, .archs = &.{ .x64, .x86, .aarch64, .arm } },
    .{ .name = "uptime", .dir = "coreutils/", .formats = &.{.elf}, .archs = &.{ .x64, .x86, .aarch64, .arm } },
    .{ .name = "id", .dir = "coreutils/", .formats = &.{.elf}, .archs = &.{ .x64, .x86, .aarch64, .arm } },
    .{ .name = "who", .dir = "coreutils/", .formats = &.{.elf}, .archs = &.{ .x64, .x86, .aarch64, .arm } },
    .{ .name = "cat", .formats = &.{ .elf, .coff }, .archs = &.{ .x64, .x86, .aarch64, .arm } },
    .{ .name = "pwd", .formats = &.{ .elf, .coff }, .archs = &.{ .x64, .x86, .aarch64, .arm } },
    .{ .name = "cd", .formats = &.{ .elf, .coff }, .archs = &.{ .x64, .x86, .aarch64, .arm } },
    .{ .name = "ls", .formats = &.{ .elf, .coff }, .archs = &.{ .x64, .x86, .aarch64, .arm } },
    .{ .name = "ifconfig", .dir = "net-tools/", .formats = &.{.elf}, .archs = &.{ .x64, .x86, .aarch64, .arm } },
    .{ .name = "wCloneProcess", .formats = &.{.coff}, .archs = &.{ .x64, .x86 } },
    .{ .name = "wInjectionChainStage0", .dir = "process-injection-chain/", .formats = &.{.coff}, .archs = &.{ .x64, .x86 } },
    .{ .name = "wInjectionChainStage1", .dir = "process-injection-chain/", .formats = &.{.coff}, .archs = &.{ .x64, .x86 } },
    .{ .name = "wInjectionChainStage2", .dir = "process-injection-chain/", .formats = &.{.coff}, .archs = &.{ .x64, .x86 } },
    .{ .name = "wInjectionChainStage3", .dir = "process-injection-chain/", .formats = &.{.coff}, .archs = &.{ .x64, .x86 } },
    .{ .name = "wInjectionChainStage2C", .dir = "process-injection-chain/", .formats = &.{.coff}, .archs = &.{ .x64, .x86 } },
    .{ .name = "kmodLoader", .formats = &.{.elf}, .archs = &.{ .x64, .x86, .aarch64, .arm } },
    .{ .name = "lskmod", .formats = &.{.elf}, .archs = &.{ .x64, .x86, .aarch64, .arm } },
    .{ .name = "sniffer", .formats = &.{.elf}, .archs = &.{ .x64, .x86, .aarch64, .arm }, .custom_build_fn = build_sniffer },
    .{ .name = "snifferBOF", .formats = &.{.elf}, .archs = &.{ .x64, .x86, .aarch64, .arm }, .custom_build_fn = build_sniffer },
    // BOF0 - special purpose BOF that acts as a standalone implant and uses other BOFs as its post-ex modules:
    .{ .name = "z-beac0n-core", .formats = &.{ .elf, .coff }, .archs = &.{ .x64, .x86, .aarch64, .arm } },
};

const bofs_for_testing = [_]BofTableItem{
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

// Additional/3rdparty BOFs for building should be added below:

const bofs_my_custom = [_]BofTableItem{
    //.{ .name = "bof", .formats = &.{ .elf, .coff }, .archs = &.{ .x64, .x86, .aarch64, .arm } },
};

// YOU CAN ADD OR REMOVE BOF TABLES HERE:
const bof_tables = bofs_included_in_launcher ++ bofs_for_testing ++ bofs_my_custom;

//
// END: BOF TABLES
//

pub var bofs_to_build: []const Bof = undefined;

pub fn build(b: *std.Build) !void {
    const optimize = b.standardOptimizeOption(.{});

    bofs_to_build = genBofList(b, optimize);

    try generateBofCollectionYaml(b);

    for (bofs_to_build) |bof| {
        const target = bof.target;

        const bof_launcher_dep = b.dependency(
            "bof_launcher_lib",
            .{ .target = target, .optimize = optimize },
        );
        const bof_launcher_api_module = bof_launcher_dep.module("bof_launcher_api");

        const bof_launcher_lib = bof_launcher_dep.artifact(
            @import("bof_launcher_lib").libFileName(b.allocator, target, null),
        );

        const full_name = bof.fullName(b.allocator);

        if (bof.optimize == .Debug) {
            const win32_dep = b.dependency("bof_launcher_win32", .{ .bof = false });
            const win32_module = win32_dep.module("bof_launcher_win32");
            const bof_api_module = b.addModule("bof_api", .{
                .root_source_file = b.path("src/include/bof_api.zig"),
            });
            bof_api_module.addImport("bof_launcher_win32", win32_module);

            const debug_obj = try addBofObj(
                b,
                bof,
                full_name,
                bof_api_module,
                bof_launcher_dep,
            );
            const debug_exe = b.addExecutable(.{
                .root_source_file = b.path("src/_debug_entry.zig"),
                .name = full_name,
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
        } else {
            const win32_dep = b.dependency("bof_launcher_win32", .{ .bof = true });
            const win32_module = win32_dep.module("bof_launcher_win32");
            const bof_api_module = b.addModule("bof_api", .{
                .root_source_file = b.path("src/include/bof_api.zig"),
            });
            bof_api_module.addImport("bof_launcher_win32", win32_module);

            const obj = try addBofObj(
                b,
                bof,
                full_name,
                bof_api_module,
                bof_launcher_dep,
            );
            b.getInstallStep().dependOn(&b.addInstallArtifact(
                obj,
                .{
                    .dest_dir = .{ .override = .bin },
                    .dest_sub_path = b.fmt("{s}.o", .{full_name}),
                },
            ).step);
        }
    }
}

const std = @import("std");

const BofLang = enum { zig, c, @"asm" };
const BofFormat = enum { coff, elf };
const BofArch = enum { x64, x86, aarch64, arm };

pub const Bof = struct {
    dir: ?[]const u8,
    srcfile: ?[]const u8,
    name: []const u8,
    format: BofFormat,
    arch: BofArch,
    lang: BofLang,
    custom_build_fn: ?CustomBuildFn,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
    source_file_path: []const u8,

    fn init(b: *std.Build, item: BofTableItem, format: BofFormat, arch: BofArch, optimize: std.builtin.OptimizeMode) Bof {
        const bof_src_path = std.mem.join(
            b.allocator,
            "",
            &.{
                "src/",
                if (item.dir) |dir| dir else "",
                if (item.srcfile) |srcfile| srcfile else item.name,
            },
        ) catch @panic("OOM");

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

        return .{
            .dir = item.dir,
            .srcfile = item.srcfile,
            .name = item.name,
            .format = format,
            .arch = arch,
            .custom_build_fn = item.custom_build_fn,
            .optimize = optimize,
            .lang = lang,
            .source_file_path = source_file_path,
            .target = b.resolveTargetQuery(getTargetQuery(format, arch)),
        };
    }

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
                .arm => unreachable,
            },
            .os_tag = switch (format) {
                .coff => .windows,
                .elf => .linux,
            },
            .abi = .gnu,
        };
    }

    pub fn fullName(bof: Bof, allocator: std.mem.Allocator) []const u8 {
        if (bof.optimize == .Debug) {
            return std.mem.join(
                allocator,
                ".",
                &.{ bof.name, @tagName(bof.format), @tagName(bof.arch), "debug" },
            ) catch @panic("OOM");
        }
        return std.mem.join(
            allocator,
            ".",
            &.{ bof.name, @tagName(bof.format), @tagName(bof.arch) },
        ) catch @panic("OOM");
    }
};

fn genBofList(b: *std.Build, optimize: std.builtin.OptimizeMode) []const Bof {
    const static = struct {
        // Mul by 16 because we have 2 formats, 4 archs and 2 optimize modes.
        var bofs: [bof_tables.len * 16]Bof = undefined;
    };

    var index: usize = 0;
    for (bof_tables) |item| {
        for (item.formats) |format| {
            for (item.archs) |arch| {
                if (format == .coff and arch == .aarch64) continue;
                if (format == .coff and arch == .arm) continue;

                static.bofs[index] = Bof.init(b, item, format, arch, .ReleaseSmall);
                index += 1;

                if (optimize == .Debug) {
                    static.bofs[index] = Bof.init(b, item, format, arch, .Debug);
                    index += 1;
                }
            }
        }
    }

    return static.bofs[0..index];
}

fn addBofObj(
    b: *std.Build,
    bof: Bof,
    full_name: []const u8,
    bof_api_module: *std.Build.Module,
    bof_launcher_dep: *std.Build.Dependency,
) !*std.Build.Step.Compile {
    const obj = switch (bof.lang) {
        .@"asm" => blk: {
            const obj = b.addAssembly(.{
                .name = full_name,
                .source_file = b.path(bof.source_file_path),
                .target = bof.target,
                .optimize = bof.optimize,
            });
            if (bof.custom_build_fn) |customBuild| _ = customBuild(b, obj, bof);
            break :blk obj;
        },
        .zig => blk: {
            const obj = b.addObject(.{
                .name = full_name,
                .root_source_file = b.path(bof.source_file_path),
                .target = bof.target,
                .optimize = bof.optimize,
                .link_libc = false,
            });
            if (bof.custom_build_fn) |customBuild| _ = customBuild(b, obj, bof);
            break :blk obj;
        },
        .c => blk: {
            const obj = b.addObject(.{
                .name = full_name,
                .root_module = b.createModule(.{
                    // TODO: Zig bug. `.root_source_file = null` should be possible.
                    .root_source_file = b.path("src/tests/dummy.zig"),
                    .target = bof.target,
                    .optimize = bof.optimize,
                    .link_libc = true,
                }),
            });
            const std_flags = [_][]const u8{"-fdeclspec"};
            const custom_flags = if (bof.custom_build_fn) |customBuild| customBuild(b, obj, bof) else &.{};

            const flags = try b.allocator.alloc([]const u8, custom_flags.len + std_flags.len);
            defer b.allocator.free(flags);

            for (0..std_flags.len) |i| flags[i] = std_flags[i];
            for (0..custom_flags.len) |i| flags[i + std_flags.len] = custom_flags[i];

            obj.root_module.addCSourceFile(.{
                .file = b.path(bof.source_file_path),
                .flags = flags,
            });
            break :blk obj;
        },
    };

    obj.root_module.pic = true;
    obj.root_module.single_threaded = true;
    obj.root_module.strip = if (bof.optimize == .Debug) false else true;
    if (bof.optimize != .Debug) {
        obj.root_module.unwind_tables = .none;
        obj.root_module.omit_frame_pointer = true;
        obj.root_module.stack_protector = false;
        obj.root_module.stack_check = false;
    }

    if (bof.lang != .@"asm") {
        obj.root_module.addIncludePath(b.path("src/include"));
        obj.root_module.addIncludePath(bof_launcher_dep.path("src/beacon"));
        obj.root_module.addImport("bof_api", bof_api_module);
        // Needed for BOFs that launch other BOFs
        obj.root_module.addAnonymousImport(
            "bof_launcher_api",
            .{ .root_source_file = bof_launcher_dep.path("src/bof_launcher_api.zig") },
        );

        if (bof.target.result.cpu.arch == .x86 and
            bof.target.result.os.tag == .linux)
        {
            // TODO: Shared library fails to build on Linux x86.
        } else {
            const bof_launcher_shared_lib = bof_launcher_dep.artifact(
                @import("bof_launcher_lib").libFileName(b.allocator, bof.target, "shared"),
            );
            obj.root_module.addAnonymousImport("bof_launcher_lib_embed", .{
                .root_source_file = bof_launcher_shared_lib.getEmittedBin(),
            });
        }
    }

    return obj;
}

const CustomBuildFn = *const fn (*std.Build, *std.Build.Step.Compile, Bof) []const []const u8;

fn build_wWinverC(b: *std.Build, obj: *std.Build.Step.Compile, bof: Bof) []const []const u8 {
    _ = .{ b, obj, bof };
    return &.{"-DMY_DEFINE"};
}

fn build_sniffer(b: *std.Build, obj: *std.Build.Step.Compile, bof: Bof) []const []const u8 {
    const pcap_dep = b.dependency("pcap", .{});

    const pcap = b.addStaticLibrary(.{
        .name = b.fmt("pcap.{s}", .{@tagName(bof.arch)}),
        .target = bof.target,
        .optimize = bof.optimize,
        .link_libc = true,
        .pic = true,
    });
    pcap.addIncludePath(pcap_dep.path("."));
    pcap.addCSourceFiles(.{
        .root = pcap_dep.path("."),
        .files = &.{
            "pcap-linux.c",
            "sf-pcapng.c",
            "pcap-common.c",
            "pcap-usb-linux-common.c",
            "fad-getad.c",
            "pcap.c",
            "gencode.c",
            "optimize.c",
            "nametoaddr.c",
            "etherent.c",
            "fmtutils.c",
            "pcap-util.c",
            "savefile.c",
            "sf-pcap.c",
            "bpf_dump.c",
            "bpf_image.c",
            "bpf_filter.c",
            "scanner.c",
            "grammar.c",
            "missing/strlcpy.c",
            "missing/strlcat.c",
        },
        .flags = &.{
            "-std=gnu99",
            "-Dthread_local=",
            "-DBUILDING_PCAP",
            "-DHAVE_CONFIG_H",
        },
    });

    const pcap_config = b.addConfigHeader(
        .{
            .style = .{ .autoconf_undef = pcap_dep.path("config.h.in") },
        },
        .{
            .ARPA_INET_H_DECLARES_ETHER_HOSTTON = null,
            .BDEBUG = null,
            .ENABLE_REMOTE = null,
            .HAVE_AIX_GETNETBYNAME_R = null,
            .HAVE_AIX_GETPROTOBYNAME_R = null,
            .HAVE_ASPRINTF = 1,
            .HAVE_CONFIG_HAIKUCONFIG_H = null,
            .HAVE_DAGAPI_H = null,
            .HAVE_DAG_API = null,
            .HAVE_DAG_GET_ERF_TYPES = null,
            .HAVE_DAG_GET_STREAM_ERF_TYPES = null,
            .HAVE_DAG_LARGE_STREAMS_API = null,
            .HAVE_DAG_VDAG = null,
            .HAVE_DECL_ETHER_HOSTTON = 1,
            .HAVE_DL_HP_PPA_INFO_T_DL_MODULE_ID_1 = null,
            .HAVE_DL_PASSIVE_REQ_T = null,
            .HAVE_ETHER_HOSTTON = 1,
            .HAVE_FFS = null,
            .HAVE_FSEEKO = 1,
            .HAVE_GETSPNAM = null,
            .HAVE_GNU_STRERROR_R = null,
            .HAVE_HPUX10_20_OR_LATER = null,
            .HAVE_HPUX9 = null,
            .HAVE_INTTYPES_H = 1,
            .HAVE_LIBBSD = null,
            .HAVE_LIBDLPI = null,
            .HAVE_LIBNL = null,
            .HAVE_LINUX_COMPILER_H = null,
            .HAVE_LINUX_GETNETBYNAME_R = null,
            .HAVE_LINUX_GETPROTOBYNAME_R = null,
            .HAVE_LINUX_NET_TSTAMP_H = 1,
            .HAVE_LINUX_SOCKET_H = null,
            .HAVE_LINUX_USBDEVICE_FS_H = null,
            .HAVE_LINUX_WIRELESS_H = null,
            .HAVE_MEMORY_H = null,
            .HAVE_NETPACKET_PACKET_H = null,
            .HAVE_NET_BPF_H = null,
            .HAVE_NET_ENET_H = null,
            .HAVE_NET_IF_DL_H = null,
            .HAVE_NET_IF_H = null,
            .HAVE_NET_IF_MEDIA_H = null,
            .HAVE_NET_IF_TYPES_H = null,
            .HAVE_NET_NIT_H = null,
            .HAVE_NET_PFILT_H = null,
            .HAVE_NET_RAW_H = null,
            .HAVE_OPENSSL = null,
            .HAVE_OS_PROTO_H = null,
            .HAVE_POSIX_STRERROR_R = null,
            .HAVE_SEPTEL_API = null,
            .HAVE_SNF_API = null,
            .HAVE_SOCKLEN_T = 1,
            .HAVE_SOLARIS = null,
            .HAVE_SOLARIS_IRIX_GETNETBYNAME_R = null,
            .HAVE_SOLARIS_IRIX_GETPROTOBYNAME_R = null,
            .HAVE_STDINT_H = 1,
            .HAVE_STDLIB_H = 1,
            .HAVE_STRERROR = null,
            .HAVE_STRINGS_H = 1,
            .HAVE_STRING_H = 1,
            .HAVE_STRLCAT = null,
            .HAVE_STRLCPY = null,
            .HAVE_STRTOK_R = 1,
            .HAVE_STRUCT_BPF_TIMEVAL = null,
            .HAVE_STRUCT_ETHER_ADDR = null,
            .HAVE_STRUCT_MSGHDR_MSG_CONTROL = null,
            .HAVE_STRUCT_MSGHDR_MSG_FLAGS = null,
            .HAVE_STRUCT_RTE_ETHER_ADDR = null,
            .HAVE_STRUCT_SOCKADDR_HCI_HCI_CHANNEL = null,
            .HAVE_STRUCT_SOCKADDR_SA_LEN = null,
            .HAVE_STRUCT_SOCKADDR_STORAGE = null,
            .HAVE_STRUCT_TPACKET_AUXDATA_TP_VLAN_TCI = 1,
            .HAVE_STRUCT_USBDEVFS_CTRLTRANSFER_BREQUESTTYPE = null,
            .HAVE_SYS_BUFMOD_H = null,
            .HAVE_SYS_DLPI_EXT_H = null,
            .HAVE_SYS_DLPI_H = null,
            .HAVE_SYS_IOCCOM_H = null,
            .HAVE_SYS_NET_NIT_H = null,
            .HAVE_SYS_SOCKIO_H = null,
            .HAVE_SYS_STAT_H = 1,
            .HAVE_SYS_TYPES_H = 1,
            .HAVE_TC_API = null,
            .HAVE_UNISTD_H = 1,
            .HAVE_VASPRINTF = 1,
            .HAVE_VSYSLOG = null,
            .HAVE__WCSERROR_S = null,
            .HAVE___ATOMIC_LOAD_N = 1,
            .HAVE___ATOMIC_STORE_N = 1,
            .INET6 = null,
            .NETINET_ETHER_H_DECLARES_ETHER_HOSTTON = 1,
            .NETINET_IF_ETHER_H_DECLARES_ETHER_HOSTTON = null,
            .NET_ETHERNET_H_DECLARES_ETHER_HOSTTON = null,
            .NO_PROTOCHAIN = null,
            .PACKAGE_BUGREPORT = "https://github.com/the-tcpdump-group/libpcap/issues",
            .PACKAGE_NAME = "pcap",
            .PACKAGE_STRING = "pcap 1.10.4",
            .PACKAGE_TARNAME = "libpcap",
            .PACKAGE_URL = "https://www.tcpdump.org/",
            .PACKAGE_VERSION = "1.10.4",
            .PCAP_SUPPORT_BT = null,
            .PCAP_SUPPORT_BT_MONITOR = null,
            .PCAP_SUPPORT_DBUS = null,
            .PCAP_SUPPORT_DPDK = null,
            .PCAP_SUPPORT_LINUX_USBMON = null,
            .PCAP_SUPPORT_NETFILTER = null,
            .PCAP_SUPPORT_NETMAP = null,
            .PCAP_SUPPORT_RDMASNIFF = null,
            .SIZEOF_CONST_VOID_P = @sizeOf(usize),
            .SIZEOF_VOID_P = @sizeOf(usize),
            .STDC_HEADERS = 1,
            .STRINGS_H_DECLARES_FFS = null,
            .SYS_ETHERNET_H_DECLARES_ETHER_HOSTTON = null,
            .YYDEBUG = null,
            .YYTEXT_POINTER = 1,
            ._FILE_OFFSET_BITS = null,
            ._LARGEFILE_SOURCE = null,
            ._LARGE_FILES = null,
            ._SUN = null,
            .@"const" = null,
            .@"inline" = null,
            .sinix = null,
        },
    );
    if (bof.optimize == .Debug) {
        pcap_config.addValue("BDEBUG", i32, 1);
        pcap_config.addValue("YYDEBUG", i32, 1);
    }
    pcap.addConfigHeader(pcap_config);

    const generated = b.addWriteFiles();
    pcap.addIncludePath(generated.getDirectory());
    _ = generated.addCopyFile(pcap_config.getOutput(), pcap_config.include_path);

    obj.root_module.addIncludePath(pcap_dep.path("."));
    obj.root_module.linkLibrary(pcap);

    return &.{};
}

fn generateBofCollectionYaml(b: *std.Build) !void {
    var list = std.ArrayList(u8).init(b.allocator);
    defer list.deinit();

    const doc_file = list.writer();

    for (bof_tables) |item| {
        const bof = Bof.init(b, item, item.formats[0], item.archs[0], .ReleaseSmall);
        if (bof.lang == .@"asm") continue;

        const source_file = try std.fs.cwd().openFile(b.pathFromRoot(bof.source_file_path), .{});
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

    const wf = b.addWriteFiles();
    const doc_file_path = wf.add("bof-collection.yaml", list.items);
    b.addNamedLazyPath("bof_collection_doc", doc_file_path);

    b.getInstallStep().dependOn(&b.addInstallFile(doc_file_path, "bof-collection.yaml").step);
}
