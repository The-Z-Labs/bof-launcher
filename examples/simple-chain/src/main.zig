const std = @import("std");
const assert = std.debug.assert;
const bof = @import("bof_launcher_api");
const w32 = @import("bof_api").win32;
const shared = @import("shared");

pub const std_options = .{
    .log_level = .info,
};

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    try bof.initLauncher();
    defer bof.releaseLauncher();

    const state = try allocator.create(shared.State);
    defer allocator.destroy(state);

    state.number = 0;
    state.handle = w32.GetCurrentProcess();

    const coff_stage0 = try loadBofFromFile(allocator, "wSimpleChainStage0");
    defer allocator.free(coff_stage0);

    const coff_stage1 = try loadBofFromFile(allocator, "wSimpleChainStage1");
    defer allocator.free(coff_stage1);

    const bof_stage0 = try bof.Object.initFromMemory(coff_stage0);
    defer bof_stage0.release();

    const bof_stage1 = try bof.Object.initFromMemory(coff_stage1);
    defer bof_stage1.release();

    const ptr_as_bytes = std.mem.asBytes(&@intFromPtr(state));

    const args = try bof.Args.init();
    defer args.release();
    args.begin();
    try args.add(ptr_as_bytes);
    args.end();

    const ctx_stage0 = try bof_stage0.run(args.getBuffer());
    defer ctx_stage0.release();

    std.debug.print("number is: {d}\n", .{state.number});

    const ctx_stage1 = try bof_stage1.run(args.getBuffer());
    defer ctx_stage1.release();

    std.debug.print("number is: {d}\n", .{state.number});
}

fn loadBofFromFile(allocator: std.mem.Allocator, bof_name: [:0]const u8) ![]const u8 {
    const pathname = try std.mem.join(allocator, ".", &.{
        bof_name,
        if (@import("builtin").os.tag == .windows) "coff" else "elf",
        switch (@import("builtin").cpu.arch) {
            .x86_64 => "x64",
            .x86 => "x86",
            .aarch64 => "aarch64",
            .arm => "arm",
            else => unreachable,
        },
        "o",
    });
    defer allocator.free(pathname);

    var bof_path: [std.fs.MAX_PATH_BYTES:0]u8 = undefined;
    const absolute_bof_path = try std.fs.cwd().realpath(pathname, bof_path[0..]);
    bof_path[absolute_bof_path.len] = 0;

    const file = try std.fs.openFileAbsoluteZ(&bof_path, .{});
    defer file.close();

    return try file.reader().readAllAlloc(allocator, 16 * 1024 * 1024);
}
