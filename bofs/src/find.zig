///name: find
///description: "Search for files in a directory hierarchy. Simple version of find(1) utility."
///author: Z-Labs
///tags: ['windows', 'linux','host-recon','z-labs']
///OS: cross
///sources:
///    - 'https://raw.githubusercontent.com/The-Z-Labs/bof-launcher/main/bofs/src/find.zig'
///examples: '
/// Considerations:
///    -maxdepth hardcoded to 3
///    symbolic links are not followed
///    one find "test" supported at a time
///
//  Supported find(1) "Tests":
//    -type {b,c,d,p,f,l,s}
//    -regex PATTERN
//    -perm -MODE
//
//  Supported find(1) "Actions":
//    -print action is supported
///
/// Find and list unix socket in a given directory:
///   find /home/user -type s
///
/// List files hich have r and w permission for their owner and group and only r for other users, without regard to the presence of any extra permission bits:
///   find . -perm -664
///
/// Search for set-user-ID files and directories, without regard to the presence of any extra permission bits:
///   find . -perm -4000
///
/// List files matching provided regex (match on the whole path, not a search):
///   find /etc/apt -regex .*archive.*
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
///- name: NoSuchTest
///  code: 0x7
///  message: "Urecognized test type provided"
///- name: BadParameter
///  code: 0x8
///  message: "Parameter for chosen test is badly formatted"
///- name: UnknownError
///  code: 0x9
///  message: "Unknown error"
const std = @import("std");
const linux = std.os.linux;
const bofapi = @import("bof_api");
const posix = bofapi.posix;
const beacon = bofapi.beacon;
const Regex = @import("regex").Regex;

// Simple version of find(1) utility: search for files in a directory hierarchy. Limitations:


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
    NoSuchTest,
    BadParameter,
    UnknownError,
};

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
    var req_perm: u32 = undefined;

    // initial file processing preparation
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
        bofapi.print(.output, "Parma:{s}\n", .{param});
        if(!std.mem.startsWith(u8, param, "-"))
            return error.BadParameter;

        req_perm = try std.fmt.parseUnsigned(u32, std.mem.trimStart(u8, param, "-"), 8);
    }
    else
        return error.NoSuchTest;

    // file processing: running requested tests on files
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
            if(try re.match(line)) {
                try aw.writer.print("{s}\n", .{line});
            }
        } else if(testType == .Perm) {
            bofapi.print(.output, "Test: -perm {s}\n", .{param});
            if (@import("builtin").os.tag == .linux and @import("builtin").cpu.arch != .aarch64) {

                const l0 = try allocator.dupe(u8, line);
                defer allocator.free(l0);
                std.mem.replaceScalar(u8, l0, '\n', 0);

                var stat: std.os.linux.Stat = undefined;
                _ = std.os.linux.lstat(@ptrCast(l0.ptr), &stat);

                const file_mode_mask = stat.mode & ~@as(u16, std.os.linux.S.IFMT);

                if((req_perm & file_mode_mask) != 0)
                    try aw.writer.print("{s}\n", .{line});
            }
        }
    }

    return aw.toOwnedSlice();
}

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
                    error.NoSuchTest => return @intFromEnum(BofErrors.NoSuchTest),
                    error.BadParameter => return @intFromEnum(BofErrors.BadParameter),
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
