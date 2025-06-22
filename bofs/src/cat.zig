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
///- name: UnknownError
///  code: 0x5
///  message: "Unknown error"
const std = @import("std");
const beacon = @import("bof_api").beacon;
const posix = @import("bof_api").posix;

// BOF-specific error codes
const BofErrors = enum(u8) {
    AccessDenied = 0x1,
    FileNotFound,
    AntivirusInterference,
    FileNotProvided,
    UnknownError,
};

fn getFileContent(file_path: [*:0]u8) !u8 {

    const file = try std.fs.openFileAbsoluteZ(file_path, .{});
    defer file.close();
    
    var aBuf = [_]u8{0} ** 4097;
    const buf = aBuf[0 .. aBuf.len - 1];

    while(try file.read(buf) != 0) {
        _ = beacon.printf(0, "%s", buf.ptr);
    }
    
    return 0;
}

pub export fn go(args: ?[*]u8, args_len: i32) callconv(.C) u8 {
    var parser = beacon.datap{};
    beacon.dataParse(&parser, args, args_len);

    if(beacon.dataExtract(&parser, null)) |file_path| {
        return getFileContent(file_path) catch |err| switch (err) {
            std.fs.File.OpenError.AccessDenied => return @intFromEnum(BofErrors.AccessDenied),
            std.fs.File.OpenError.FileNotFound => return @intFromEnum(BofErrors.FileNotFound),
            std.fs.File.OpenError.AntivirusInterference => return @intFromEnum(BofErrors.AntivirusInterference),
            else => return @intFromEnum(BofErrors.UnknownError),
        };
    } else
        return @intFromEnum(BofErrors.FileNotProvided);
}
