///name: pwd
///description: "Print name of current/working directory"
///author: Z-Labs
///tags: ['windows', 'linux','host-recon','z-labs']
///OS: cross
///sources:
///    - 'https://raw.githubusercontent.com/The-Z-Labs/bof-launcher/main/bofs/src/pwd.zig'
///examples: '
/// pwd
///'
///errors:
///- name: AccesDenied
///  code: 0x1
///  message: "Permission to read or search a component of the filename was denied"
///- name: CwdUnlinked
///  code: 0x2
///  message: "The current working directory has been unlinked"
///- name: NameTooLong
///  code: 0x3
///  message: "Name too long"
///- name: UnknownError
///  code: 0x4
///  message: "Unknown error"
const std = @import("std");
const posix = @import("std").posix;
const bofapi = @import("bof_api");
const beacon = bofapi.beacon;

comptime {
    @import("bof_api").embedFunctionCode("memcpy");
    @import("bof_api").embedFunctionCode("memmove");
    @import("bof_api").embedFunctionCode("memset");
    @import("bof_api").embedFunctionCode("__stackprobe__");
}

// BOF-specific error codes
const BofErrors = enum(u8) {
    AccesDenied = 0x1,
    CwdUnlinked,
    NameTooLong,
    UnknownError,
};

fn getCwd() !u8 {
    var buf: [4096]u8 = undefined;
    const str = try std.posix.getcwd(buf[0..]);
    bofapi.print(.output, "{s}", .{str});
    return 0;
}

pub export fn go(adata: ?[*]u8, alen: i32) callconv(.c) u8 {
    @import("bof_api").init(adata, alen, .{});

    return getCwd() catch |err| switch (err) {
        error.NameTooLong => @intFromEnum(BofErrors.NameTooLong),
        error.CurrentWorkingDirectoryUnlinked => @intFromEnum(BofErrors.CwdUnlinked),
        else => @intFromEnum(BofErrors.UnknownError),
    };
}
