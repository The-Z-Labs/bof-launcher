///name: cd
///description: "Change current working directory"
///author: Z-Labs
///tags: ['windows', 'linux','host-recon','z-labs']
///OS: cross
///sources:
///    - 'https://raw.githubusercontent.com/The-Z-Labs/bof-launcher/main/bofs/src/cd.zig'
///examples: '
/// cd /etc
/// cd C:\Windows
///'
///arguments:
///- name: dir_path
///  desc: "path to change to"
///  type: string
///  required: true
///errors:
///- name: AccessDenied
///  code: 0x1
///  message: "Access to the directory denied"
///- name: SymLinkLoop
///  code: 0x2
///  message: "Symlink loop"
///- name: NameTooLong
///  code: 0x3
///  message: "Directory too long"
///- name: FileNotFound
///  code: 0x4
///  message: "No such directory"
///- name: SystemResources
///  code: 0x5
///  message: "System resources"
///- name: NotDir
///  code: 0x6
///  message: "No directory"
///- name: DirNotProvided
///  code: 0x7
///  message: "Directory not provided"
///- name: UnknownError
///  code: 0x8
///  message: "Unknown error"
const std = @import("std");
const beacon = @import("bof_api").beacon;
const posix = @import("bof_api").posix;

// BOF-specific error codes
const BofErrors = enum(u8) {
    AccessDenied = 0x1,
    SymLinkLoop,
    NameTooLong,
    FileNotFound,
    SystemResources,
    NotDir,
    DirNotProvided,
    UnknownError,
};

fn changeDir(file_path: [*:0]const u8) !u8 {
    try std.posix.chdir(std.mem.span(file_path));
    return 0;
}

pub export fn go(args: ?[*]u8, args_len: i32) callconv(.C) u8 {
    var parser = beacon.datap{};
    beacon.dataParse.?(&parser, args, args_len);

    if (beacon.dataExtract.?(&parser, null)) |file_path| {
        return changeDir(file_path) catch |err| switch (err) {
            error.AccessDenied => @intFromEnum(BofErrors.AccessDenied),
            error.SymLinkLoop => @intFromEnum(BofErrors.SymLinkLoop),
            error.NameTooLong => @intFromEnum(BofErrors.NameTooLong),
            error.FileNotFound => @intFromEnum(BofErrors.FileNotFound),
            error.SystemResources => @intFromEnum(BofErrors.SystemResources),
            error.NotDir => @intFromEnum(BofErrors.NotDir),
            else => @intFromEnum(BofErrors.UnknownError),
        };
    } else return @intFromEnum(BofErrors.DirNotProvided);
}

comptime {
    @import("bof_api").includeStackProbeCode();
}
