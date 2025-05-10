const std = @import("std");

const bof_launcher = @import("../../bof-launcher/build.zig");

const Options = @import("../../bof-launcher/build.zig").Options;

const home_path = "examples/implant/";

pub fn build(
    b: *std.Build,
    options: Options,
    bof_launcher_lib: *std.Build.Step.Compile,
    bof_launcher_api_module: *std.Build.Module,
) void {
    if (options.target.query.cpu_arch != .x86_64) return;

    if (options.target.query.os_tag == .linux) {

        //
        // building executable
        //
        const exe = b.addExecutable(.{
            .name = std.mem.join(b.allocator, "_", &.{
                "implant-executable",
                options.osTagStr(),
                options.cpuArchStr(),
            }) catch @panic("OOM"),
            .root_source_file = .{ .cwd_relative = home_path ++ "src/main.zig" },
            .target = options.target,
            .optimize = options.optimize,
        });

        exe.linkLibrary(bof_launcher_lib);
        exe.root_module.addImport("bof_launcher_api", bof_launcher_api_module);

        b.getInstallStep().dependOn(&b.addInstallArtifact(exe, .{
            .dest_dir = .{ .override = .{ .custom = "../" ++ home_path ++ "src/_embed_generated" } },
        }).step);

        b.installArtifact(exe);

        //
        // building shellcode
        //
        const name = std.mem.join(b.allocator, "_", &.{
            "implant-shellcode",
            options.osTagStr(),
            options.cpuArchStr(),
        }) catch @panic("OOM");

        const optimize = std.builtin.OptimizeMode.ReleaseSmall;
        const shellcode = b.addExecutable(.{
            .name = name,
            .root_source_file = .{ .cwd_relative = home_path ++ "src/shellcode.zig" },
            .target = options.target,
            .optimize = optimize,
            .link_libc = false,
            .single_threaded = true,
        });
        shellcode.link_eh_frame_hdr = false;
        shellcode.link_emit_relocs = false;
        shellcode.use_llvm = true;
        shellcode.pie = true;
        shellcode.setLinkerScript(b.path("examples/shellcode-in-zig/src/linker.ld"));

        const copied = b.addObjCopy(shellcode.getEmittedBin(), .{
            .format = .bin,
            .only_section = ".text",
        });

        const install_step = b.addInstallBinFile(
            copied.getOutput(),
            std.fmt.allocPrint(b.allocator, "{s}.bin", .{name}) catch unreachable,
        );
        b.getInstallStep().dependOn(&install_step.step);
        b.installArtifact(shellcode);
    }
}
