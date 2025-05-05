const std = @import("std");

const Options = @import("../../bof-launcher/build.zig").Options;

const home_path = "examples/shellcode-in-zig/";

pub fn build(
    b: *std.Build,
    options: Options,
    bof_api_module: *std.Build.Module,
) void {
    //if (options.target.query.os_tag != .windows) return;
    if (options.target.query.cpu_arch != .x86_64) return;

    if (options.target.query.os_tag == .windows) {
        const shellcode_exe = b.addExecutable(.{
            .name = std.mem.join(b.allocator, "_", &.{
                "shellcode",
                options.osTagStr(),
                options.cpuArchStr(),
            }) catch @panic("OOM"),
            .root_source_file = b.path(home_path ++ "src/shellcode.zig"),
            .target = options.target,
            .optimize = .ReleaseSmall,
            .single_threaded = true,
            .unwind_tables = false,
            .strip = true,
            .link_libc = false,
            .pic = true,
        });
        shellcode_exe.pie = true;
        shellcode_exe.subsystem = .Windows;
        shellcode_exe.entry = .{ .symbol_name = "wWinMainCRTStartup" };
        shellcode_exe.bundle_compiler_rt = false;

        b.installArtifact(shellcode_exe);
    }

    // shellcode crafting based on:
    // https://github.com/chivay/shellcodez/
    if (options.target.query.os_tag == .linux) {
        const name = std.mem.join(b.allocator, "_", &.{
            "shellcode",
            options.osTagStr(),
            options.cpuArchStr(),
        }) catch @panic("OOM");

        const optimize = std.builtin.OptimizeMode.ReleaseSmall;
        const exe = b.addExecutable(.{
            .name = name,
            .root_source_file = b.path(home_path ++ "src/lnx_shellcode.zig"),
            .target = options.target,
            .optimize = optimize,
            .single_threaded = true,
        });
        exe.link_eh_frame_hdr = false;
        exe.link_emit_relocs = false;
        exe.use_llvm = true;
        exe.pie = true;
        exe.setLinkerScript(b.path(home_path ++ "src/linker.ld"));

        const copied = b.addObjCopy(exe.getEmittedBin(), .{
            .format = .bin,
            .only_section = ".text",
        });

        const install_step = b.addInstallBinFile(
            copied.getOutput(),
            std.fmt.allocPrint(b.allocator, "{s}.bin", .{name}) catch unreachable,
        );
        b.getInstallStep().dependOn(&install_step.step);
        b.installArtifact(exe);
    }

    const shellcode_launcher_exe = b.addExecutable(.{
        .name = std.mem.join(b.allocator, "_", &.{
            "shellcode_launcher",
            options.osTagStr(),
            options.cpuArchStr(),
        }) catch @panic("OOM"),
        .root_source_file = b.path(home_path ++ "src/shellcode_launcher.zig"),
        .target = options.target,
        .optimize = options.optimize,
    });
    shellcode_launcher_exe.root_module.addImport("bof_api", bof_api_module);

    b.installArtifact(shellcode_launcher_exe);
}

inline fn thisDir() []const u8 {
    return comptime std.fs.path.dirname(@src().file) orelse ".";
}
