pub const beacon = @import("beacon.zig");
pub const win32 = @import("win32.zig");
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
    .free = bofFree,
};
fn bofAlloc(_: *anyopaque, len: usize, _: u8, _: usize) ?[*]u8 {
    return @as(?[*]u8, @ptrCast(bofLauncherAllocateMemory(len)));
}
fn bofResize(_: *anyopaque, buf: []u8, _: u8, new_len: usize, _: usize) bool {
    if (new_len <= buf.len) return true;
    return false;
}
fn bofFree(_: *anyopaque, buf: []u8, _: u8, _: usize) void {
    bofLauncherFreeMemory(buf.ptr);
}

extern fn bofLauncherAllocateMemory(size: usize) callconv(.C) ?*anyopaque;
extern fn bofLauncherFreeMemory(maybe_ptr: ?*anyopaque) callconv(.C) void;
