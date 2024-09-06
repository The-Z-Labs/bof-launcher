const std = @import("std");
const beacon = @import("bof_api").beacon;

// BOF-specific error codes
const kmodErrors = enum(u8) {
    NoRootPermissions = 1,
    BadModuleSignature,
    ModuleAlreadyExists,
    NoSuchModule,
    OutOfMemory,
    InvalidImageFormat,
};

const syscalls = switch (@import("builtin").cpu.arch) {
    .x86 => std.os.linux.syscalls.X86,
    .x86_64 => std.os.linux.syscalls.X64,
    .arm => std.os.linux.syscalls.Arm,
    .aarch64 => std.os.linux.syscalls.Arm64,
    else => unreachable,
};

pub export fn kmodLoad(module_image: [*]const u8, len: usize, param_values: [*:0]const u8) callconv(.C) u8 {
    debugPrint("Loading kernel module: {s}\n", .{param_values});

    const rc = std.os.linux.syscall3(syscalls.init_module, @intFromPtr(module_image), len, @intFromPtr(param_values));
    switch (std.os.linux.E.init(rc)) {
        .SUCCESS => {},
        .PERM => return @intFromEnum(kmodErrors.NoRootPermissions),
        .BADMSG => return @intFromEnum(kmodErrors.BadModuleSignature),
        .EXIST => return @intFromEnum(kmodErrors.ModuleAlreadyExists),
        .NOMEM => return @intFromEnum(kmodErrors.OutOfMemory),
        .NOEXEC => return @intFromEnum(kmodErrors.InvalidImageFormat),
        else => |errno| debugPrint("init_module failure: {s}", .{@tagName(errno)}),
    }

    return 0;
}

pub export fn kmodRemove(name: [*:0]const u8, flags: u32) callconv(.C) u8 {

    const rc = std.os.linux.syscall2(syscalls.delete_module, @intFromPtr(name), flags);
    switch (std.os.linux.E.init(rc)) {
        .SUCCESS => {},
        .PERM => return @intFromEnum(kmodErrors.NoRootPermissions),
        .NOENT => return @intFromEnum(kmodErrors.NoSuchModule),
        .NOMEM => return @intFromEnum(kmodErrors.OutOfMemory),
        else => |errno| debugPrint("delete_module failure: {s}", .{@tagName(errno)}),
    }

    return 0;
}

fn debugPrint(comptime format: []const u8, args: anytype) void {
    if (true) std.debug.print(format, args);
}
