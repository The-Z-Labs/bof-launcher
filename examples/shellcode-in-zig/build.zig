const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const shellcode_name = b.fmt(
        "shellcode_{s}_{s}",
        .{ osTagStr(target), cpuArchStr(target) },
    );

    if (target.result.os.tag == .windows) {
        const shellcode_win_exe = b.addExecutable(.{
            .name = shellcode_name,
            .root_module = b.createModule(.{
                .root_source_file = b.path("src/shellcode_win.zig"),
                .target = target,
                .optimize = .ReleaseSmall,
                .single_threaded = true,
                .unwind_tables = .none,
                .strip = true,
                .link_libc = false,
                .pic = true,
            }),
        });
        shellcode_win_exe.pie = true;
        shellcode_win_exe.subsystem = .Windows;
        shellcode_win_exe.entry = .{ .symbol_name = "wWinMainCRTStartup" };
        shellcode_win_exe.bundle_compiler_rt = false;

        b.installArtifact(shellcode_win_exe);
    } else if (target.result.os.tag == .linux) {
        // Shellcode crafting based on: https://github.com/chivay/shellcodez
        const shellcode_lin_exe = b.addExecutable(.{
            .name = shellcode_name,
            .root_module = b.createModule(.{
                .root_source_file = b.path("src/shellcode_lin.zig"),
                .target = target,
                .optimize = .ReleaseSmall,
                .single_threaded = true,
            }),
        });
        shellcode_lin_exe.link_eh_frame_hdr = false;
        shellcode_lin_exe.link_emit_relocs = false;
        shellcode_lin_exe.use_llvm = true;
        shellcode_lin_exe.pie = true;
        shellcode_lin_exe.setLinkerScript(b.path("src/linker.ld"));

        const copy = b.addObjCopy(shellcode_lin_exe.getEmittedBin(), .{ .format = .bin, .only_section = ".text" });
        const install = b.addInstallBinFile(copy.getOutput(), b.fmt("{s}.bin", .{shellcode_name}));
        b.getInstallStep().dependOn(&install.step);
        b.installArtifact(shellcode_lin_exe);
    }

    const shellcode_launcher_exe = b.addExecutable(.{
        .name = b.fmt(
            "shellcode_launcher_{s}_{s}",
            .{ osTagStr(target), cpuArchStr(target) },
        ),
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/shellcode_launcher.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });
    if (target.result.os.tag == .windows) {
        shellcode_launcher_exe.root_module.linkSystemLibrary("ws2_32", .{});
        shellcode_launcher_exe.root_module.linkSystemLibrary("ole32", .{});
        shellcode_launcher_exe.root_module.linkSystemLibrary("user32", .{});
        shellcode_launcher_exe.root_module.linkSystemLibrary("advapi32", .{});
    }

    if (target.result.os.tag == .windows) {
        const win32_dep = b.dependency("bof_launcher_win32", .{});
        const win32_module = win32_dep.module("bof_launcher_win32");
        shellcode_launcher_exe.root_module.addImport("bof_launcher_win32", win32_module);
    }

    b.installArtifact(shellcode_launcher_exe);
}

fn osTagStr(target: std.Build.ResolvedTarget) []const u8 {
    return switch (target.result.os.tag) {
        .windows => "win",
        .linux => "lin",
        else => unreachable,
    };
}

fn cpuArchStr(target: std.Build.ResolvedTarget) []const u8 {
    return switch (target.result.cpu.arch) {
        .x86_64 => "x64",
        .x86 => "x86",
        .aarch64 => "aarch64",
        .arm => "arm",
        else => unreachable,
    };
}
