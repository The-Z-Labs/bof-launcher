///name: ls
///description: "List directory content"
///author: Z-Labs
///tags: ['windows', 'linux','host-recon','z-labs']
///OS: cross
///sources:
///    - 'https://raw.githubusercontent.com/The-Z-Labs/bof-launcher/main/bofs/src/ls.zig'
///examples: '
/// ls
/// ls C:\Windows\System32\
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
///- name: DirNotProvided
///  code: 0x4
///  message: "No directory provided"
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
    DirNotProvided,
    UnknownError,
};

fn listDirContent(dir_path: [*:0]u8) !u8 {

    var iter_dir = try std.fs.openDirAbsoluteZ(dir_path, .{ .iterate = true });
    defer iter_dir.close();

    var iter = iter_dir.iterate();
    while (try iter.next()) |entry| {
        const f = try iter_dir.openFile(entry.name, .{});
        defer f.close();

        const f_stat = try f.stat();
        const f_metadata = try f.metadata();

        if (entry.kind == .directory) {
            _ = beacon.printf(0, "d");
        } else
            _ = beacon.printf(0, "-");

        const perm = f_metadata.permissions();
        if (@import("builtin").os.tag == .linux) {
            if(perm.inner.unixHas(.user, .read)) _ = beacon.printf(0, "r") else _ = beacon.printf(0, "-");
            if(perm.inner.unixHas(.user, .write)) _ = beacon.printf(0, "w") else _ = beacon.printf(0, "-");
            if(perm.inner.unixHas(.user, .execute)) _ = beacon.printf(0, "x") else _ = beacon.printf(0, "-");

            if(perm.inner.unixHas(.group, .read)) _ = beacon.printf(0, "r") else _ = beacon.printf(0, "-");
            if(perm.inner.unixHas(.group, .write)) _ = beacon.printf(0, "w") else _ = beacon.printf(0, "-");
            if(perm.inner.unixHas(.group, .execute)) _ = beacon.printf(0, "x") else _ = beacon.printf(0, "-");

            if(perm.inner.unixHas(.other, .read)) _ = beacon.printf(0, "r") else _ = beacon.printf(0, "-");
            if(perm.inner.unixHas(.other, .write)) _ = beacon.printf(0, "w") else _ = beacon.printf(0, "-");
            if(perm.inner.unixHas(.other, .execute)) _ = beacon.printf(0, "x") else _ = beacon.printf(0, "-");
        }

        _ = beacon.printf(0, "\t%d\t%s", f_stat.size, entry.name.ptr);
        if (entry.kind == .directory)
            _ = beacon.printf(0, "/");
        _ = beacon.printf(0, "\n");
    }

    return 0;
}

pub export fn go(args: ?[*]u8, args_len: i32) callconv(.C) u8 {
    var parser = beacon.datap{};
    beacon.dataParse(&parser, args, args_len);

    if(beacon.dataExtract(&parser, null)) |dir_path| {
        return listDirContent(dir_path) catch |err| switch (err) {
            std.fs.File.OpenError.FileNotFound => return @intFromEnum(BofErrors.FileNotFound),
            else => return @intFromEnum(BofErrors.UnknownError),
        };
    } else
        return @intFromEnum(BofErrors.DirNotProvided);
}
