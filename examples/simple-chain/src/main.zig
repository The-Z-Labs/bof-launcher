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

    var cmd_args_iter = try std.process.argsWithAllocator(allocator);
    defer cmd_args_iter.deinit();

    _ = cmd_args_iter.next() orelse unreachable;
    const pid_str = cmd_args_iter.next() orelse {
        try usage();
        return;
    };
    const pid = try std.fmt.parseInt(u32, pid_str, 10);

    try bof.initLauncher();
    defer bof.releaseLauncher();

    const bof_stage0 = blk: {
        const coff = try loadBofFromFile(allocator, "wSimpleChainStage0");
        defer allocator.free(coff);
        break :blk try bof.Object.initFromMemory(coff);
    };
    defer bof_stage0.release();

    const bof_stage1 = blk: {
        const coff = try loadBofFromFile(allocator, "wSimpleChainStage1");
        defer allocator.free(coff);
        break :blk try bof.Object.initFromMemory(coff);
    };
    defer bof_stage1.release();

    const bof_stage2 = blk: {
        const coff = try loadBofFromFile(allocator, "wSimpleChainStage2");
        defer allocator.free(coff);
        break :blk try bof.Object.initFromMemory(coff);
    };
    defer bof_stage2.release();

    const bof_stage3 = blk: {
        const coff = try loadBofFromFile(allocator, "wSimpleChainStage3");
        defer allocator.free(coff);
        break :blk try bof.Object.initFromMemory(coff);
    };
    defer bof_stage3.release();

    const state = try allocator.create(shared.State);
    defer allocator.destroy(state);
    state.* = .{ .process_id = pid };

    const args = try bof.Args.init();
    defer args.release();
    args.begin();
    try args.add(std.mem.asBytes(&@intFromPtr(state)));
    args.end();

    const ctx_stage0 = try bof_stage0.run(args.getBuffer());
    defer ctx_stage0.release();

    std.debug.print("nt status: {d}\n", .{state.nt_status});

    const ctx_stage1 = try bof_stage1.run(args.getBuffer());
    defer ctx_stage1.release();

    std.debug.print("nt status: {d}\n", .{state.nt_status});

    const ctx_stage2 = try bof_stage2.run(args.getBuffer());
    defer ctx_stage2.release();

    std.debug.print("nt status: {d}\n", .{state.nt_status});

    const ctx_stage3 = try bof_stage3.run(args.getBuffer());
    defer ctx_stage3.release();

    std.debug.print("nt status: {d}\n", .{state.nt_status});

    var thread_handle: w32.HANDLE = undefined;
    state.nt_status = w32.NtCreateThreadEx(
        &thread_handle,
        0x1fffff,
        null,
        state.process_handle,
        @ptrFromInt(state.base_address),
        null,
        0,
        0,
        0,
        0,
        null,
    );
    std.debug.print("nt status: {d}\n", .{state.nt_status});

    state.nt_status = w32.NtClose(thread_handle);

    std.debug.print("nt status: {d}\n", .{state.nt_status});
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

fn usage() !void {
    const stdout = std.io.getStdOut().writer();
    try stdout.print(
        \\
        \\ USAGE:
        \\      simple_chain <PID>
        \\ ARGS:
        \\      <PID>       Remote process ID.
        \\ 
    , .{});
}
