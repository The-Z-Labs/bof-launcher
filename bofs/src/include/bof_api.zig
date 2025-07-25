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
        const str = std.fmt.allocPrintZ(std.heap.page_allocator, fmt, args) catch unreachable;
        defer std.heap.page_allocator.free(str);
        _ = beacon.printf.?(@"type", "%s", str.ptr);
    }
}

//
// Functions that can be generated implicitly by the compiler
//
pub fn embedFunctionCode(name: []const u8) void {
    comptime {
        const want_windows_v2u64_abi = @import("compiler_rt/common.zig").want_windows_v2u64_abi;
        const want_aeabi = @import("compiler_rt/common.zig").want_aeabi;

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
            } else if (std.mem.eql(u8, name, "__aeabi_llsr")) {
                if (want_aeabi) xexport(&@import("compiler_rt/shift.zig").__aeabi_llsr, "__aeabi_llsr");
            } else if (std.mem.eql(u8, name, "__aeabi_llsl")) {
                if (want_aeabi) xexport(&@import("compiler_rt/shift.zig").__aeabi_llsl, "__aeabi_llsl");
            } else if (std.mem.eql(u8, name, "__aeabi_uldivmod")) {
                if (want_aeabi) xexport(&@import("compiler_rt/arm.zig").__aeabi_uldivmod, "__aeabi_uldivmod");
            } else if (std.mem.eql(u8, name, "__aeabi_uidiv")) {
                if (want_aeabi) xexport(&@import("compiler_rt/int.zig").__aeabi_uidiv, "__aeabi_uidiv");
            } else if (std.mem.eql(u8, name, "__aeabi_ldivmod")) {
                if (want_aeabi) xexport(&@import("compiler_rt/arm.zig").__aeabi_ldivmod, "__aeabi_ldivmod");
            } else if (std.mem.eql(u8, name, "__aeabi_uidivmod")) {
                if (want_aeabi) xexport(&@import("compiler_rt/arm.zig").__aeabi_uidivmod, "__aeabi_uidivmod");
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
