const std = @import("std");

const Options = @import("../../bof-launcher/build.zig").Options;

pub fn build(
    b: *std.Build,
    options: Options,
    bof_api_module: *std.Build.Module,
) void {
    if (options.target.query.os_tag != .windows) return;
    if (options.target.query.cpu_arch == .x86) return;

    const shellcode_exe = b.addExecutable(.{
        .name = std.mem.join(b.allocator, "_", &.{
            "shellcode_in_zig",
            options.osTagStr(),
            options.cpuArchStr(),
        }) catch @panic("OOM"),
        .root_source_file = b.path("examples/shellcode-in-zig/src/shellcode.zig"),
        .target = options.target,
        .optimize = options.optimize,
        .single_threaded = true,
        .unwind_tables = false,
        .strip = true,
        .link_libc = false,
        .pic = true,
    });
    shellcode_exe.pie = true;
    shellcode_exe.subsystem = .Windows;
    shellcode_exe.entry = .{ .symbol_name = "wWinMainCRTStartup" };

    const shellcode_launcher_exe = b.addExecutable(.{
        .name = std.mem.join(b.allocator, "_", &.{
            "shellcode_launcher",
            options.osTagStr(),
            options.cpuArchStr(),
        }) catch @panic("OOM"),
        .root_source_file = b.path("examples/shellcode-in-zig/src/shellcode_launcher.zig"),
        .target = options.target,
        .optimize = options.optimize,
    });
    shellcode_launcher_exe.root_module.addImport("bof_api", bof_api_module);

    b.installArtifact(shellcode_exe);
    b.installArtifact(shellcode_launcher_exe);
}
