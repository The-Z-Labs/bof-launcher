pub const beacon = @import("beacon.zig");
pub const win32 = @import("bof_launcher_win32");
pub const posix = @import("posix.zig");
pub const asn1 = @import("asn1.zig");
pub const kerberos = @import("kerberos.zig");

const std = @import("std");

pub const bof_allocator = std.mem.Allocator{
    .ptr = undefined,
    .vtable = &bof_allocator_vtable,
};
const bof_allocator_vtable = std.mem.Allocator.VTable{
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
