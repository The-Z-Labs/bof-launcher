///name: ls
///description: "List given directory content"
///author: Z-Labs
///tags: ['windows', 'linux','host-recon','z-labs']
///OS: cross
///sources:
///    - 'https://raw.githubusercontent.com/The-Z-Labs/bof-launcher/main/bofs/src/ls.zig'
///examples: '
/// ls /
/// ls C:\Windows\System32\
///'
///arguments:
///- name: dir_path
///  desc: "path to the directory to be listed"
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
const linux = std.os.linux;
const posix = @import("bof_api").posix;
const beacon = @import("bof_api").beacon;

// BOF-specific error codes
const BofErrors = enum(u8) {
    AccessDenied = 0x1,
    FileNotFound,
    AntivirusInterference,
    DirNotProvided,
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
    _ = std.fmt.formatIntBuf(buf[0..4], dt.year, 10, .lower, .{ .width = 4, .fill = '0' });
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
        else => _ = std.fmt.formatIntBuf(buf, value, 10, .lower, .{}),
    }
}
// end of RFC3339 implementation

fn listDirContent(dir_path: [*:0]u8) !u8 {
    var iter_dir = try std.fs.openDirAbsoluteZ(dir_path, .{ .iterate = true });
    defer iter_dir.close();

    var iter = iter_dir.iterate();
    while (try iter.next()) |entry| {

        // print entry type
        if (entry.kind == .directory) {
            _ = beacon.printf(0, "d");
        } else if (entry.kind == .sym_link) {
            _ = beacon.printf(0, "l");
        } else if (entry.kind == .block_device) {
            _ = beacon.printf(0, "b");
        } else if (entry.kind == .character_device) {
            _ = beacon.printf(0, "c");
        } else if (entry.kind == .unix_domain_socket) {
            _ = beacon.printf(0, "u");
        } else _ = beacon.printf(0, "-");

        if (@import("builtin").os.tag == .linux) {
            var statx: std.os.linux.Statx = undefined;
            _ = std.os.linux.statx(iter_dir.fd, @ptrCast(entry.name.ptr), std.os.linux.AT.STATX_SYNC_AS_STAT |
                std.os.linux.AT.NO_AUTOMOUNT |
                std.os.linux.AT.SYMLINK_NOFOLLOW, std.os.linux.STATX_MODE |
                std.os.linux.STATX_UID |
                std.os.linux.STATX_GID |
                std.os.linux.STATX_MTIME |
                std.os.linux.STATX_SIZE, &statx);

            // print permissions
            if ((statx.mode & std.os.linux.S.IRUSR) != 0) _ = beacon.printf(0, "r") else _ = beacon.printf(0, "-");
            if ((statx.mode & std.os.linux.S.IWUSR) != 0) _ = beacon.printf(0, "w") else _ = beacon.printf(0, "-");
            if ((statx.mode & std.os.linux.S.IXUSR) != 0) {
                if ((statx.mode & std.os.linux.S.ISUID) != 0) {
                    _ = beacon.printf(0, "s");
                } else _ = beacon.printf(0, "x");
            } else _ = beacon.printf(0, "-");

            if ((statx.mode & std.os.linux.S.IRGRP) != 0) _ = beacon.printf(0, "r") else _ = beacon.printf(0, "-");
            if ((statx.mode & std.os.linux.S.IWGRP) != 0) _ = beacon.printf(0, "w") else _ = beacon.printf(0, "-");
            if ((statx.mode & std.os.linux.S.IXGRP) != 0) {
                if ((statx.mode & std.os.linux.S.ISGID) != 0) {
                    _ = beacon.printf(0, "s");
                } else _ = beacon.printf(0, "x");
            } else _ = beacon.printf(0, "-");

            if ((statx.mode & std.os.linux.S.IROTH) != 0) _ = beacon.printf(0, "r") else _ = beacon.printf(0, "-");
            if ((statx.mode & std.os.linux.S.IWOTH) != 0) _ = beacon.printf(0, "w") else _ = beacon.printf(0, "-");

            if ((statx.mode & std.os.linux.S.ISVTX) != 0) {
                _ = beacon.printf(0, "t");
            } else if ((statx.mode & std.os.linux.S.IXOTH) != 0) {
                _ = beacon.printf(0, "x");
            } else _ = beacon.printf(0, "-");

            // print file ownership
            if (posix.getpwuid(statx.uid)) |pwd| {
                _ = beacon.printf(0, "\t%s", pwd.name);
            }
            if (posix.getgrgid(statx.gid)) |grp| {
                _ = beacon.printf(0, " %s", grp.gr_name);
            }

            // print file size
            _ = beacon.printf(0, "\t%9d", statx.size);

            // print last modification time
            const dt = fromTimestamp(@intCast(statx.mtime.sec));
            const timeStr = toRFC3339(dt);
            _ = beacon.printf(0, " %s", &timeStr);
        }

        // print file name
        {
            var entry_print: [2048]u8 = undefined;
            @memcpy(entry_print[0..], entry.name);
            entry_print[entry.name.len] = 0;
            _ = beacon.printf(0, "\t%s", &entry_print);
        }

        // additional prints (based on entry type)
        if (entry.kind == .directory)
            _ = beacon.printf(0, "/");

        if (entry.kind == .sym_link) {
            var buf = [_]u8{0} ** 4097;
            _ = try std.posix.readlinkat(iter_dir.fd, entry.name, buf[0 .. buf.len - 1]);
            _ = beacon.printf(0, " -> %s", &buf);
        }

        // end of line
        _ = beacon.printf(0, "\n");
    }

    return 0;
}

pub export fn go(args: ?[*]u8, args_len: i32) callconv(.C) u8 {
    var parser = beacon.datap{};
    beacon.dataParse(&parser, args, args_len);

    if (beacon.dataExtract(&parser, null)) |dir_path| {
        return listDirContent(dir_path) catch |err| switch (err) {
            std.fs.File.OpenError.FileNotFound => return @intFromEnum(BofErrors.FileNotFound),
            else => return @intFromEnum(BofErrors.UnknownError),
        };
    } else return @intFromEnum(BofErrors.DirNotProvided);
}
