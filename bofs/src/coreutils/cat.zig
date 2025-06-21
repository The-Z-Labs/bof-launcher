///name: cat
///description: "Print content of a file"
///author: Z-Labs
///tags: ['linux','host-recon','z-labs']
///OS: linux
///sources:
///    - 'https://raw.githubusercontent.com/The-Z-Labs/bof-launcher/main/bofs/src/coreutils/cat.zig'
///examples: '
/// cat /etc/passwd
///'
///errors:
///- name: FileNotProvided
///  code: 0x1
///  message: "No file provided"
///- name: FileOpenFailure 
///  code: 0x2
///  message: "Failed to open provided file"
///- name: UnknownError
///  code: 0x3
///  message: "Unknown error"
const std = @import("std");
const beacon = @import("bof_api").beacon;
const posix = @import("bof_api").posix;

// BOF-specific error codes
const BofErrors = enum(u8) {
    FileNotProvided = 0x1,
    FileOpenFailure,
    UnknownError,
};

fn getFileContent(file_path: [*:0]u8) !u8 {
    const fd = try std.posix.openZ(file_path, .{ .ACCMODE = .RDONLY, .CLOEXEC = true }, 0);
    defer std.posix.close(fd);
    
    if (fd == -1)
        return @intFromEnum(BofErrors.FileOpenFailure);

    const file: std.fs.File = .{ .handle = fd };

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
        return getFileContent(file_path) catch @intFromEnum(BofErrors.UnknownError);
    } else
        return @intFromEnum(BofErrors.FileNotProvided);
}
