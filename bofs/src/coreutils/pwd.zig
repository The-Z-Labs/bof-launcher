///name: pwd
///description: "Print name of current/working directory"
///author: Z-Labs
///tags: ['linux','host-recon','z-labs']
///OS: linux
///sources:
///    - 'https://raw.githubusercontent.com/The-Z-Labs/bof-launcher/main/bofs/src/coreutils/pwd.zig'
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
///- name: OutOfMemory
///  code: 0x3
///  message: "Out of memory"
///- name: UnknownError
///  code: 0x4
///  message: "Unknown error"
const std = @import("std");
const beacon = @import("bof_api").beacon;
const linux = @import("bof_api").os.linux;

// BOF-specific error codes
const BofErrors = enum(u8) {
    AccesDenied = 0x1,
    CwdUnlinked,
    OutOfMemory,
    UnknownError,
};

pub export fn go() callconv(.C) u8 {
    var buf: [4096]u8 = undefined;
    const rc = std.os.linux.getcwd(&buf, buf.len);
    switch (std.os.linux.E.init(rc)) {
        .SUCCESS => {},
        .ACCES => return @intFromEnum(BofErrors.AccesDenied),
        .NOENT => return @intFromEnum(BofErrors.CwdUnlinked),
        .NOMEM => return @intFromEnum(BofErrors.OutOfMemory),
        else => return @intFromEnum(BofErrors.UnknownError),
    }

    _ = beacon.printf(0, "%s", &buf);
    return 0;
}
