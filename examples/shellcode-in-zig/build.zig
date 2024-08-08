const std = @import("std");

const Options = @import("../../bof-launcher/build.zig").Options;

const home_path = "examples/shellcode-in-zig/";

pub fn build(
    b: *std.Build,
    options: Options,
    bof_api_module: *std.Build.Module,
) void {
    if (options.target.query.os_tag != .windows) return;
    if (options.target.query.cpu_arch != .x86_64) return;

    const shellcode_exe = b.addExecutable(.{
        .name = std.mem.join(b.allocator, "_", &.{
            "shellcode_in_zig",
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

    b.installArtifact(shellcode_exe);
    b.installArtifact(shellcode_launcher_exe);

    const dump_text_section = DumpTextSection.create(b, shellcode_exe.getEmittedBin());
    shellcode_launcher_exe.step.dependOn(&dump_text_section.step);
}

const DumpTextSection = struct {
    step: std.Build.Step,
    input_file: std.Build.LazyPath,

    const base_id: std.Build.Step.Id = .custom;

    fn create(owner: *std.Build, input_file: std.Build.LazyPath) *DumpTextSection {
        const dump_text_section = owner.allocator.create(DumpTextSection) catch @panic("OOM");
        dump_text_section.* = DumpTextSection{
            .step = std.Build.Step.init(.{
                .id = base_id,
                .name = owner.fmt("dump_text_section {s}", .{input_file.getDisplayName()}),
                .owner = owner,
                .makeFn = make,
            }),
            .input_file = input_file,
        };
        input_file.addStepDependencies(&dump_text_section.step);
        return dump_text_section;
    }

    fn make(step: *std.Build.Step, _: std.Progress.Node) !void {
        const b = step.owner;
        const dump_text_section: *DumpTextSection = @fieldParentPtr("step", step);

        const full_src_path = dump_text_section.input_file.getPath2(b, step);

        const file_exe = try std.fs.cwd().openFile(full_src_path, .{});
        defer file_exe.close();

        const file_exe_data = try file_exe.reader().readAllAlloc(b.allocator, 16 * 1024 * 1024);
        defer b.allocator.free(file_exe_data);

        const parser = try std.coff.Coff.init(file_exe_data, false);

        const text_header = parser.getSectionByName(".text") orelse unreachable;
        const text_data = parser.getSectionData(text_header);

        {
            // Write file to bin/ directory
            const file_bin = try std.fs.cwd().createFile(
                try std.mem.join(
                    b.allocator,
                    "",
                    &.{ b.getInstallPath(.bin, std.fs.path.stem(full_src_path)), ".bin" },
                ),
                .{},
            );
            defer file_bin.close();

            try file_bin.writer().writeAll(text_data);
        }
        {
            // Write file to src/ directory
            const file_bin = try std.fs.cwd().createFile(
                try std.mem.join(
                    b.allocator,
                    "",
                    &.{ home_path, "src/", std.fs.path.stem(full_src_path), ".bin" },
                ),
                .{},
            );
            defer file_bin.close();

            try file_bin.writer().writeAll(text_data);
        }
    }
};
