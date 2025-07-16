pub const beacon = @import("beacon.zig");
pub const win32 = @import("bof_launcher_win32");
pub const posix = @import("posix.zig");
pub const asn1 = @import("asn1.zig");
pub const kerberos = @import("kerberos.zig");

const std = @import("std");

pub fn print(@"type": beacon.CallbackType, comptime fmt: []const u8, args: anytype) void {
    const len = std.fmt.count(fmt, args);
    if (len < 4096) {
        var buf: [4096]u8 = undefined;
        const str = std.fmt.bufPrintZ(buf[0..], fmt, args) catch unreachable;
        _ = beacon.printf.?(@"type", "%s", str.ptr);
    } else {
        const str = std.fmt.allocPrintZ(generic_allocator, fmt, args) catch unreachable;
        defer generic_allocator.free(str);
        _ = beacon.printf.?(@"type", "%s", str.ptr);
    }
}

pub const generic_allocator = std.mem.Allocator{
    .ptr = undefined,
    .vtable = &generic_allocator_vtable,
};
const generic_allocator_vtable = std.mem.Allocator.VTable{
    .alloc = bofAlloc,
    .resize = bofResize,
    .remap = bofRemap,
    .free = bofFree,
};
fn bofAlloc(_: *anyopaque, len: usize, _: std.mem.Alignment, _: usize) ?[*]u8 {
    return @as(?[*]u8, @ptrCast(bofLauncherAllocateMemory(len)));
}
fn bofResize(_: *anyopaque, buf: []u8, _: std.mem.Alignment, new_len: usize, _: usize) bool {
    if (new_len <= buf.len) return true;
    return false;
}
fn bofRemap(_: *anyopaque, buf: []u8, _: std.mem.Alignment, new_len: usize, _: usize) ?[*]u8 {
    if (new_len <= buf.len) return buf.ptr;
    return null;
}
fn bofFree(_: *anyopaque, buf: []u8, _: std.mem.Alignment, _: usize) void {
    bofLauncherFreeMemory(buf.ptr);
}

extern fn bofLauncherAllocateMemory(size: usize) callconv(.C) ?*anyopaque;
extern fn bofLauncherFreeMemory(maybe_ptr: ?*anyopaque) callconv(.C) void;

//
// Redirectors (for Cobalt Strike compat)
//
comptime {
    if (@import("builtin").mode != .Debug and @import("builtin").os.tag == .windows and win32.bof) {
        @export(&RE_memcpy, .{ .name = "memcpy", .linkage = .strong });
        @export(&RE_memset, .{ .name = "memset", .linkage = .strong });
        if (arch == .x86) {
            @export(&RE_chkstk, .{ .name = "_alloca", .linkage = .strong });
        } else if (arch == .x86_64) {
            @export(&RE___chkstk_ms, .{ .name = "___chkstk_ms", .linkage = .strong });
        }
    }
}

fn RE_memcpy(noalias dest: ?[*]u8, noalias src: ?[*]const u8, len: usize) callconv(.c) ?[*]u8 {
    @setRuntimeSafety(false);

    for (0..len) |i| {
        dest.?[i] = src.?[i];
    }

    return dest;
}

fn RE_memset(dest: ?[*]u8, c: u8, len: usize) callconv(.c) ?[*]u8 {
    @setRuntimeSafety(false);

    for (0..len) |i| {
        dest.?[i] = c;
    }

    return dest;
}

fn RE_chkstk() callconv(.Naked) void {
    @setRuntimeSafety(false);
    @call(.always_inline, win_probe_stack_adjust_sp, .{});
}
fn RE___chkstk_ms() callconv(.Naked) void {
    @setRuntimeSafety(false);
    @call(.always_inline, win_probe_stack_only, .{});
}

const arch = @import("builtin").cpu.arch;

fn win_probe_stack_adjust_sp() void {
    @setRuntimeSafety(false);

    switch (arch) {
        .x86_64 => {
            asm volatile (
                \\         push   %%rcx
                \\         cmp    $0x1000,%%rax
                \\         lea    16(%%rsp),%%rcx
                \\         jb     1f
                \\ 2:
                \\         sub    $0x1000,%%rcx
                \\         test   %%rcx,(%%rcx)
                \\         sub    $0x1000,%%rax
                \\         cmp    $0x1000,%%rax
                \\         ja     2b
                \\ 1:
                \\         sub    %%rax,%%rcx
                \\         test   %%rcx,(%%rcx)
                \\
                \\         lea    8(%%rsp),%%rax
                \\         mov    %%rcx,%%rsp
                \\         mov    -8(%%rax),%%rcx
                \\         push   (%%rax)
                \\         sub    %%rsp,%%rax
                \\         ret
            );
        },
        .x86 => {
            asm volatile (
                \\         push   %%ecx
                \\         cmp    $0x1000,%%eax
                \\         lea    8(%%esp),%%ecx
                \\         jb     1f
                \\ 2:
                \\         sub    $0x1000,%%ecx
                \\         test   %%ecx,(%%ecx)
                \\         sub    $0x1000,%%eax
                \\         cmp    $0x1000,%%eax
                \\         ja     2b
                \\ 1:
                \\         sub    %%eax,%%ecx
                \\         test   %%ecx,(%%ecx)
                \\
                \\         lea    4(%%esp),%%eax
                \\         mov    %%ecx,%%esp
                \\         mov    -4(%%eax),%%ecx
                \\         push   (%%eax)
                \\         sub    %%esp,%%eax
                \\         ret
            );
        },
        else => unreachable,
    }
}

fn win_probe_stack_only() void {
    @setRuntimeSafety(false);

    switch (arch) {
        .x86_64 => {
            asm volatile (
                \\         push   %%rcx
                \\         push   %%rax
                \\         cmp    $0x1000,%%rax
                \\         lea    24(%%rsp),%%rcx
                \\         jb     1f
                \\ 2:
                \\         sub    $0x1000,%%rcx
                \\         test   %%rcx,(%%rcx)
                \\         sub    $0x1000,%%rax
                \\         cmp    $0x1000,%%rax
                \\         ja     2b
                \\ 1:
                \\         sub    %%rax,%%rcx
                \\         test   %%rcx,(%%rcx)
                \\         pop    %%rax
                \\         pop    %%rcx
                \\         ret
            );
        },
        .x86 => {
            asm volatile (
                \\         push   %%ecx
                \\         push   %%eax
                \\         cmp    $0x1000,%%eax
                \\         lea    12(%%esp),%%ecx
                \\         jb     1f
                \\ 2:
                \\         sub    $0x1000,%%ecx
                \\         test   %%ecx,(%%ecx)
                \\         sub    $0x1000,%%eax
                \\         cmp    $0x1000,%%eax
                \\         ja     2b
                \\ 1:
                \\         sub    %%eax,%%ecx
                \\         test   %%ecx,(%%ecx)
                \\         pop    %%eax
                \\         pop    %%ecx
                \\         ret
            );
        },
        else => unreachable,
    }
}
