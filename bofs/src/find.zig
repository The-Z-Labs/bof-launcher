///name: find
///description: "Search for files in a directory hierarchy. Simple version of find(1) utility."
///author: Z-Labs
///tags: ['windows', 'linux','host-recon','z-labs']
///OS: cross
///sources:
///    - 'https://raw.githubusercontent.com/The-Z-Labs/bof-launcher/main/bofs/src/find.zig'
///examples: '
/// find .
/// find /home/user -type s
///'
///arguments:
///- name: dir_path
///  desc: "path to the directory to be listed"
///  type: string
///  required: true
///- name: test
///  desc: "Type of test to conduct, supported: -type|-regex|-perm"
///  type: string
///  required: false
///- name: test_param
///  desc: "Parameter for selected test"
///  type: string
///  required: false
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
///- name: TestParamNotProvided
///  code: 0x5
///  message: "Test param (e.g. -type *file_type*) not provided"
///- name: OutOfMemory
///  code: 0x6
///  message: "Not sufficient memory available"
///- name: UnknownError
///  code: 0x7
///  message: "Unknown error"
const std = @import("std");
const linux = std.os.linux;
const bofapi = @import("bof_api");
const posix = bofapi.posix;
const beacon = bofapi.beacon;
const Regex = @import("regex").Regex;

// Simple version of find(1) utility: search for files in a directory hierarchy. Limitations:
// Never  follow  symbolic  links
// -maxdepth always set to 3 (i.e. sub- and sub-sub- directories are searched)
// Only one "test" supported at a time
// Supported "Tests":
// -type {b,c,d,p,f,l,s} - only one file type at a time can be searched for (i.e: -type f,l is not supported)
// -regex PATTERN
// -perm
// Supported "Actions":
// Only -print action is supported

comptime {
    @import("bof_api").embedFunctionCode("memcpy");
    @import("bof_api").embedFunctionCode("memset");
    @import("bof_api").embedFunctionCode("memmove");
    @import("bof_api").embedFunctionCode("__stackprobe__");
    @import("bof_api").embedFunctionCode("__udivdi3");
    @import("bof_api").embedFunctionCode("__ashldi3");
    @import("bof_api").embedFunctionCode("__aeabi_uldivmod");
    @import("bof_api").embedFunctionCode("__aeabi_uidivmod");
    @import("bof_api").embedFunctionCode("__aeabi_uidiv");
    @import("bof_api").embedFunctionCode("__aeabi_llsl");
}

// BOF-specific error codes
const BofErrors = enum(u8) {
    AccessDenied = 0x1,
    FileNotFound,
    AntivirusInterference,
    DirNotProvided,
    TestParamNotProvided,
    OutOfMemory,
    UnknownError,
};

// RFC3339 implementation taken from:
// https://www.aolium.com/karlseguin/cf03dee6-90e1-85ac-8442-cf9e6c11602a
pub const DateTime = struct {
    year: u16,
    month: u8,
    day: u8,
    hour: u8,
    minute: u8,
    second: u8,
};

pub fn fromTimestamp(ts: u64) DateTime {
    const SECONDS_PER_DAY = 86400;
    const DAYS_PER_YEAR = 365;
    const DAYS_IN_4YEARS = 1461;
    const DAYS_IN_100YEARS = 36524;
    const DAYS_IN_400YEARS = 146097;
    const DAYS_BEFORE_EPOCH = 719468;

    const seconds_since_midnight: u64 = @rem(ts, SECONDS_PER_DAY);
    var day_n: u64 = DAYS_BEFORE_EPOCH + ts / SECONDS_PER_DAY;
    var temp: u64 = 0;

    temp = 4 * (day_n + DAYS_IN_100YEARS + 1) / DAYS_IN_400YEARS - 1;
    var year: u16 = @intCast(100 * temp);
    day_n -= DAYS_IN_100YEARS * temp + temp / 4;

    temp = 4 * (day_n + DAYS_PER_YEAR + 1) / DAYS_IN_4YEARS - 1;
    year += @intCast(temp);
    day_n -= DAYS_PER_YEAR * temp + temp / 4;

    var month: u8 = @intCast((5 * day_n + 2) / 153);
    const day: u8 = @intCast(day_n - (@as(u64, @intCast(month)) * 153 + 2) / 5 + 1);

    month += 3;
    if (month > 12) {
        month -= 12;
        year += 1;
    }

    return DateTime{
        .year = year,
        .month = month,
        .day = day,
        .hour = @intCast(seconds_since_midnight / 3600),
        .minute = @intCast(seconds_since_midnight % 3600 / 60),
        .second = @intCast(seconds_since_midnight % 60),
    };
}

pub fn toRFC3339(dt: DateTime) [20]u8 {
    var buf: [20]u8 = undefined;

    var w: std.Io.Writer = .fixed(buf[0..4]);
    w.printInt(dt.year, 10, .lower, .{ .width = 4, .fill = '0' }) catch unreachable;

    buf[4] = '-';
    paddingTwoDigits(buf[5..7], dt.month);
    buf[7] = '-';
    paddingTwoDigits(buf[8..10], dt.day);
    buf[10] = ' ';

    paddingTwoDigits(buf[11..13], dt.hour);
    buf[13] = ':';
    paddingTwoDigits(buf[14..16], dt.minute);
    buf[16] = ':';
    paddingTwoDigits(buf[17..19], dt.second);
    buf[19] = 0;

    return buf;
}

fn paddingTwoDigits(buf: *[2]u8, value: u8) void {
    switch (value) {
        0 => buf.* = "00".*,
        1 => buf.* = "01".*,
        2 => buf.* = "02".*,
        3 => buf.* = "03".*,
        4 => buf.* = "04".*,
        5 => buf.* = "05".*,
        6 => buf.* = "06".*,
        7 => buf.* = "07".*,
        8 => buf.* = "08".*,
        9 => buf.* = "09".*,
        else => {
            var w: std.Io.Writer = .fixed(buf[0..2]);
            w.printInt(value, 10, .lower, .{}) catch unreachable;
        },
    }
}
// end of RFC3339 implementation

fn filesProcess(allocator: std.mem.Allocator, files_list: []u8, test_type: [*:0]u8, test_param: [*:0]u8) ![] u8 {

    const ttype = std.mem.sliceTo(test_type, 0);
    const param = std.mem.sliceTo(test_param, 0);

    var reader: std.Io.Reader = .fixed(files_list);

    var aw: std.Io.Writer.Allocating = .init(allocator);
    defer aw.deinit();

    const TestType = enum(u8) {
        FileType = 0x1,
        Perm,
        Regex,
    };

    var re: Regex = undefined;
    var testType: TestType = .FileType;
    var fileKind: std.fs.File.Kind = .file;

    if(std.mem.eql(u8, ttype, "-type")) {
        testType = .FileType;

        if(std.mem.eql(u8, param, "b")) {
            fileKind = .block_device;
        } else if(std.mem.eql(u8, param, "c")) {
            fileKind = .character_device;
        } else if(std.mem.eql(u8, param, "d")) {
            fileKind = .directory;
        } else if(std.mem.eql(u8, param, "p")) {
            fileKind = .named_pipe;
        } else if(std.mem.eql(u8, param, "f")) {
            fileKind = .file;
        } else if(std.mem.eql(u8, param, "l")) {
            fileKind = .sym_link;
        } else if(std.mem.eql(u8, param, "s")) {
            fileKind = .unix_domain_socket;
        }

    } else if(std.mem.eql(u8, ttype, "-regex")) {
        testType = .Regex;
        re = try Regex.compile(allocator, param);

    } else if(std.mem.eql(u8, ttype, "-perm")) {
        testType = .Perm;
    }

    while (try reader.takeDelimiter('\n')) |line| {

        if(testType == .FileType) {
            // lstat is not available for aarch64
            if (@import("builtin").os.tag == .linux and @import("builtin").cpu.arch != .aarch64) {
                const l0 = try allocator.dupe(u8, line);
                defer allocator.free(l0);
                std.mem.replaceScalar(u8, l0, '\n', 0);

                var stat: std.os.linux.Stat = undefined;
                _ = std.os.linux.lstat(@ptrCast(l0.ptr), &stat);

                if (std.os.linux.S.ISLNK(stat.mode) and (fileKind == .sym_link)) {
                    try aw.writer.print("{s}\n", .{line});
                } else
                if (std.os.linux.S.ISBLK(stat.mode) and (fileKind == .block_device)) {
                    try aw.writer.print("{s}\n", .{line});
                } else
                if (std.os.linux.S.ISCHR(stat.mode) and (fileKind == .character_device)) {
                    try aw.writer.print("{s}\n", .{line});
                } else
                if (std.os.linux.S.ISDIR(stat.mode) and (fileKind == .directory)) {
                    try aw.writer.print("{s}\n", .{line});
                } else
                if (std.os.linux.S.ISFIFO(stat.mode) and (fileKind == .named_pipe)) {
                    try aw.writer.print("{s}\n", .{line});
                } else
                if (std.os.linux.S.ISREG(stat.mode) and (fileKind == .file)) {
                    try aw.writer.print("{s}\n", .{line});
                } else
                if (std.os.linux.S.ISSOCK(stat.mode) and (fileKind == .unix_domain_socket)) {
                    try aw.writer.print("{s}\n", .{line});
                }
            }

        } else if(testType == .Regex) {
            if(try re.partialMatch(line)) {
                try aw.writer.print("{s}\n", .{line});
            }
        } else if(testType == .Perm) {
            bofapi.print(.output, "Test: -perm {s}\n", .{param});
        }
    }

    return aw.toOwnedSlice();
}

// find with -maxdepth 3
fn filesList(allocator: std.mem.Allocator, dir_path: [*:0]u8) ![]u8 {

    var aw: std.Io.Writer.Allocating = .init(allocator);
    defer aw.deinit();

    var dir = std.fs.openDirAbsoluteZ(dir_path, .{ .access_sub_paths = true, .iterate = true }) catch |err| switch (err) {
        error.AccessDenied => return error.AccessDenied,
        error.PermissionDenied => return error.AccessDenied,
        else => return error.UnknownError,
    };
    defer dir.close();

    var iter = dir.iterate();
    while (try iter.next()) |ent| {
        try aw.writer.print("{s}/{s}\n", .{dir_path, ent.name});

        if (ent.kind == .directory) {

            var sub_dir = dir.openDir(ent.name, .{ .access_sub_paths = true, .iterate = true }) catch |err| switch (err) {
                error.AccessDenied => continue,
                error.PermissionDenied => continue,
                else => break,
            };
            defer sub_dir.close();

            var sub_iter = sub_dir.iterate();
            while (try sub_iter.next()) |sub_entry| {
                try aw.writer.print("{s}/{s}/{s}\n", .{dir_path, ent.name, sub_entry.name});

                if (sub_entry.kind == .directory) {

                    var sub2_dir = sub_dir.openDir(sub_entry.name, .{ .access_sub_paths = true, .iterate = true }) catch |err| switch (err) {
                        error.AccessDenied => continue,
                        error.PermissionDenied => continue,
                        else => break,
                    };
                    defer sub2_dir.close();

                    var sub2_iter = sub2_dir.iterate();
                    while (try sub2_iter.next()) |sub2_entry| {
                        try aw.writer.print("{s}/{s}/{s}/{s}\n", .{dir_path, ent.name, sub_entry.name, sub2_entry.name});
                    }
                }
            }
        }

    }

    return aw.toOwnedSlice();
}

pub export fn go(adata: ?[*]u8, alen: i32) callconv(.c) u8 {
    @import("bof_api").init(adata, alen, .{});

    const allocator = std.heap.page_allocator;
    var processedFiles: []u8 = undefined;

    var parser = beacon.datap{};
    beacon.dataParse(&parser, adata, alen);

    if (beacon.dataExtract(&parser, null)) |dir_path| {

        const files = filesList(allocator, dir_path) catch |err| switch (err) {
            error.AccessDenied => return @intFromEnum(BofErrors.AccessDenied),
            else => return @intFromEnum(BofErrors.UnknownError),
        };
        defer allocator.free(files);

        var reader: std.Io.Reader = .fixed(files);

        if (beacon.dataExtract(&parser, null)) |test_type| {
            if (beacon.dataExtract(&parser, null)) |test_param| {

                processedFiles = filesProcess(allocator, files, test_type, test_param) catch |err| switch (err) {
                    error.OutOfMemory => return @intFromEnum(BofErrors.OutOfMemory),
                    else => return @intFromEnum(BofErrors.UnknownError),
                };

                reader = .fixed(processedFiles);

            } else return @intFromEnum(BofErrors.TestParamNotProvided);

        }

        while (reader.takeDelimiter('\n') catch return @intFromEnum(BofErrors.UnknownError)) |line| {
            bofapi.print(.output, "{s}\n", .{line});
        }

    } else return @intFromEnum(BofErrors.DirNotProvided);

    allocator.free(processedFiles);
    return 0;
}
