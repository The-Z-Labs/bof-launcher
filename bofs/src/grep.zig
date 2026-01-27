///name: grep
///description: "Print lines that match patterns"
///author: Z-Labs
///tags: ['windows', 'linux','host-recon','z-labs']
///OS: cross
///sources:
///    - 'https://raw.githubusercontent.com/The-Z-Labs/bof-launcher/main/bofs/src/grep.zig'
///examples: '
/// grep root /etc/passwd
/// grep '^[^#\n]' /etc/hosts
///'
///arguments:
///- name: pattern
///  desc: "Searched pattern in an extended regular expression syntax"
///  type: string
///  required: true
///- name: file_path
///  desc: "Path to the file for searching"
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
const Regex = @import("regex").Regex;

comptime {
    @import("bof_api").embedFunctionCode("memcpy");
    @import("bof_api").embedFunctionCode("memset");
    @import("bof_api").embedFunctionCode("memmove");
    @import("bof_api").embedFunctionCode("__aeabi_llsl");
    @import("bof_api").embedFunctionCode("__aeabi_uidiv");
    @import("bof_api").embedFunctionCode("__udivdi3");
    @import("bof_api").embedFunctionCode("__ashldi3");
    @import("bof_api").embedFunctionCode("__stackprobe__");
}

// BOF-specific error codes
const BofErrors = enum(u8) {
    AccessDenied = 0x1,
    FileNotFound,
    AntivirusInterference,
    FileNotProvided,
    StreamTooLong,
    UnknownError,
};

fn getFileContent(allocator: std.mem.Allocator, pattern: []const u8, file_path: [*:0]u8) !u8 {
    const file = try std.fs.openFileAbsoluteZ(file_path, .{});
    defer file.close();

    const file_stat = try file.stat();

    const file_data = try allocator.alloc(u8, @intCast(file_stat.size));
    defer allocator.free(file_data);

    var file_reader = file.reader(&.{});
    try file_reader.interface.readSliceAll(file_data);

    var reader: std.Io.Reader = .fixed(file_data);

    var re = try Regex.compile(allocator, pattern);

    while (try reader.takeDelimiter('\n')) |line| {
        if(try re.partialMatch(line)) {
            bofapi.print(.output, "{s}\n", .{line});
        }
    }

    return 0;
}

pub export fn go(adata: ?[*]u8, alen: i32) callconv(.c) u8 {
    @import("bof_api").init(adata, alen, .{});

    const allocator = std.heap.page_allocator;

    var parser = beacon.datap{};
    beacon.dataParse(&parser, adata, alen);

    const pattern = beacon.dataExtract(&parser, null);

    if (beacon.dataExtract(&parser, null)) |file_path| {
        return getFileContent(allocator, std.mem.sliceTo(pattern.?, 0), file_path) catch |err| switch (err) {
            error.AccessDenied => @intFromEnum(BofErrors.AccessDenied),
            error.FileNotFound => @intFromEnum(BofErrors.FileNotFound),
            error.AntivirusInterference => @intFromEnum(BofErrors.AntivirusInterference),
            else => @intFromEnum(BofErrors.UnknownError),
        };
    } else return @intFromEnum(BofErrors.FileNotProvided);
}
