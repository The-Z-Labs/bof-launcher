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
// Functions that can be generated implicitly by the compiler
//
pub fn embedFunctionCode(name: []const u8) void {
    comptime {
        const want_windows_v2u64_abi = @import("compiler_rt/common.zig").want_windows_v2u64_abi;

        if (@import("builtin").mode != .Debug) {
            if (std.mem.eql(u8, name, "__stackprobe__")) {
                if (@import("builtin").os.tag == .windows) {
                    if (@import("builtin").cpu.arch == .x86) {
                        xexport(&@import("compiler_rt/stack_probe.zig")._chkstk, "_alloca");
                    } else if (@import("builtin").cpu.arch == .x86_64) {
                        xexport(&@import("compiler_rt/stack_probe.zig").___chkstk_ms, "___chkstk_ms");
                    }
                }
            } else if (std.mem.eql(u8, name, "memcpy")) {
                xexport(&memcpy, "memcpy");
            } else if (std.mem.eql(u8, name, "memset")) {
                xexport(&memset, "memset");
            } else if (std.mem.eql(u8, name, "__udivdi3")) {
                xexport(&@import("compiler_rt/int.zig").__udivdi3, "__udivdi3");
            } else if (std.mem.eql(u8, name, "__divdi3")) {
                xexport(&@import("compiler_rt/int.zig").__divdi3, "__divdi3");
            } else if (std.mem.eql(u8, name, "__modti3")) {
                if (want_windows_v2u64_abi) {
                    xexport(&@import("compiler_rt/modti3.zig").__modti3_windows_x86_64, "__modti3");
                } else {
                    xexport(&@import("compiler_rt/modti3.zig").__modti3, "__modti3");
                }
            } else if (std.mem.eql(u8, name, "__umoddi3")) {
                xexport(&@import("compiler_rt/int.zig").__umoddi3, "__umoddi3");
            } else if (std.mem.eql(u8, name, "__divti3")) {
                if (want_windows_v2u64_abi) {
                    xexport(&@import("compiler_rt/divti3.zig").__divti3_windows_x86_64, "__divti3");
                } else {
                    xexport(&@import("compiler_rt/divti3.zig").__divti3, "__divti3");
                }
            } else if (std.mem.eql(u8, name, "__ashlti3")) {
                xexport(&@import("compiler_rt/shift.zig").__ashlti3, "__ashlti3");
            } else if (std.mem.eql(u8, name, "__ashldi3")) {
                xexport(&@import("compiler_rt/shift.zig").__ashldi3, "__ashldi3");
            } else if (std.mem.eql(u8, name, "__lshrdi3")) {
                xexport(&@import("compiler_rt/shift.zig").__lshrdi3, "__lshrdi3");
            } else {
                unreachable;
            }
        }
    }
}

fn xexport(comptime ptr: *const anyopaque, name: []const u8) void {
    @export(ptr, .{ .name = name, .linkage = .strong });
}

fn memcpy(noalias dest: ?[*]u8, noalias src: ?[*]const u8, len: usize) callconv(.c) ?[*]u8 {
    @setRuntimeSafety(false);

    for (0..len) |i| {
        dest.?[i] = src.?[i];
    }

    return dest;
}

fn memset(dest: ?[*]u8, c: u8, len: usize) callconv(.c) ?[*]u8 {
    @setRuntimeSafety(false);

    for (0..len) |i| {
        dest.?[i] = c;
    }

    return dest;
}

comptime {
    if (@import("builtin").mode != .Debug and @import("builtin").os.tag == .windows) {
        _ = win32;
    }
}
