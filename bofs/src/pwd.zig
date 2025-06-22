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
const beacon = @import("bof_api").beacon;
const posix = @import("std").posix;

// BOF-specific error codes
const BofErrors = enum(u8) {
    AccesDenied = 0x1,
    CwdUnlinked,
    NameTooLong,
    UnknownError,
};

fn getCwd() !u8 {
    var buf: [4096]u8 = undefined;
    _ = try std.posix.getcwd(buf[0..buf.len]);
    _ = beacon.printf(0, "%s", &buf);

    return 0;
}

pub export fn go() callconv(.C) u8 {

    return getCwd() catch |err| switch (err) {
        std.posix.GetCwdError.NameTooLong => return @intFromEnum(BofErrors.NameTooLong),
        std.posix.GetCwdError.CurrentWorkingDirectoryUnlinked => return @intFromEnum(BofErrors.CwdUnlinked),
        else => return @intFromEnum(BofErrors.UnknownError),
    };
}
