pub const beacon = @import("beacon.zig");
pub const win32 = @import("bof_launcher_win32");
pub const posix = @import("posix.zig");
pub const asn1 = @import("asn1.zig");
pub const kerberos = @import("kerberos.zig");

const std = @import("std");

pub fn print(comptime fmt: []const u8, args: anytype) void {
    const len = std.fmt.count(fmt, args);
    if (len < 4096) {
        var buf: [4096]u8 = undefined;
        const str = std.fmt.bufPrintZ(buf[0..], fmt, args) catch unreachable;
        _ = beacon.printf.?(0, "%s", str.ptr);
    } else {
        const str = std.fmt.allocPrintZ(generic_allocator, fmt, args) catch unreachable;
        defer generic_allocator.free(str);
        _ = beacon.printf.?(0, "%s", str.ptr);
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
