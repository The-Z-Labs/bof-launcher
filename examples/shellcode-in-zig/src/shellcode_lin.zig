const builtin = @import("builtin");
const std = @import("std");
const main = @import("main");

pub export fn _start() linksection(".startup") callconv(.Naked) noreturn {
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
    const bof_launcher_bytes = @embedFile("bof_launcher_lib_nolibc_embed");

    const stdout = std.io.getStdOut().writer();
    stdout.print("Zig-based shellcode on Linux 0x{x}\n", .{@intFromPtr(bof_launcher_bytes.ptr)}) catch {};

    _ = std.os.linux.syscall1(.exit, 0);
    unreachable;
}
