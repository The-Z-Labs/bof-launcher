///name: cat
///description: "Print content of a file"
///author: Z-Labs
///tags: ['windows', 'linux','host-recon','z-labs']
///OS: cross
///sources:
///    - 'https://raw.githubusercontent.com/The-Z-Labs/bof-launcher/main/bofs/src/cat.zig'
///examples: '
/// cat /etc/passwd
/// cat C:\Windows\System32\drivers\etc\hosts
///'
///arguments:
///- name: file_path
///  desc: "path to the file to be printed"
///  type: string
///  required: true
///errors:
///- name: AccessDenied
///  code: 0x1
///  message: "Failed to open provided file"
///- name: FileNotFound
///  code: 0x2
///  message: "File not found"
///- name: AntivirusInterference
///  code: 0x3
///  message: "Possible Antivirus Interference while opening the file"
///- name: FileNotProvided
///  code: 0x4
///  message: "No file provided"
///- name: StreamTooLong
///  code: 0x5
///  message: "File is very large"
///- name: UnknownError
///  code: 0x6
///  message: "Unknown error"
const std = @import("std");
const bofapi = @import("bof_api");
const beacon = bofapi.beacon;
const posix = bofapi.posix;

// BOF-specific error codes
const BofErrors = enum(u8) {
    AccessDenied = 0x1,
    FileNotFound,
    AntivirusInterference,
    FileNotProvided,
    StreamTooLong,
    UnknownError,
};

fn getFileContent(file_path: [*:0]u8) !u8 {
    const file = try std.fs.openFileAbsoluteZ(file_path, .{});
    defer file.close();

    const content = try file.reader().readAllAlloc(bofapi.generic_allocator, 4 * 1024 * 1024);
    defer bofapi.generic_allocator.free(content);

    bofapi.print("{s}", .{content});

    return 0;
}

pub export fn go(args: ?[*]u8, args_len: i32) callconv(.C) u8 {
    var parser = beacon.datap{};
    beacon.dataParse.?(&parser, args, args_len);

    if (beacon.dataExtract.?(&parser, null)) |file_path| {
        return getFileContent(file_path) catch |err| switch (err) {
            error.AccessDenied => @intFromEnum(BofErrors.AccessDenied),
            error.FileNotFound => @intFromEnum(BofErrors.FileNotFound),
            error.AntivirusInterference => @intFromEnum(BofErrors.AntivirusInterference),
            error.StreamTooLong => @intFromEnum(BofErrors.StreamTooLong),
            else => @intFromEnum(BofErrors.UnknownError),
        };
    } else return @intFromEnum(BofErrors.FileNotProvided);
}
