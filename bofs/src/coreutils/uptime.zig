const std = @import("std");
const beacon = @import("bof_api").beacon;
const posix = @import("bof_api").posix;

// TODO BOF:
// https://gitlab.com/procps-ng/procps/-/blob/master/src/w.c
//

const LOADAVG_FILE = "/proc/loadavg";
const UPTIME_FILE = "/proc/uptime";

// BOF-specific error codes
const BofErrors = enum(u8) {
    AccessDenied = 0x1,
    AntivirusInterference,
    FileNotFound,
    FileBusy,
    UnknownError,
};


fn getUptimeLinux() !u8 {
    var buffer = [_]u8{0} ** 100;

    const f = try std.fs.openFileAbsoluteZ(UPTIME_FILE, .{ .mode = .read_only} );
    defer f.close();

    const uptimeStr = try f.reader().readUntilDelimiterOrEof(&buffer, '.') orelse
        return @intFromEnum(BofErrors.UnknownError);

    const SECONDS_PER_DAY = 86400;
    const uptimeSec = try std.fmt.parseInt(u64, uptimeStr, 10); 

    _ = beacon.printf(0, "up: ");

    const days: u8 = @intCast(uptimeSec / SECONDS_PER_DAY);
    const hours: u8 = @intCast(uptimeSec % SECONDS_PER_DAY / 3600);
    const minutes: u8 = @intCast(uptimeSec % SECONDS_PER_DAY % 3600 / 60);

    if(days > 0) {
        _ = beacon.printf(0, "%d ", days);
        if(days == 1) { _ = beacon.printf(0, "day "); } else _ = beacon.printf(0, "days ");
    }
    if(hours > 0) {
        _ = beacon.printf(0, "%d ", hours);
        if(hours == 1) { _ = beacon.printf(0, "hour "); } else _ = beacon.printf(0, "hours ");
    }
    if(minutes > 0) {
        _ = beacon.printf(0, "%d ", minutes);
        if(minutes == 1) { _ = beacon.printf(0, "minute "); } else _ = beacon.printf(0, "minutes ");
    }

    // get number of users on the system
    _ = posix.setutxent();

    var nuser: u32 = 0;
    var ut_entry = posix.getutxent();
    while (ut_entry) |ut| {
        if ((ut.ut_type == posix.USER_PROCESS) and ((ut.ut_user[0]) != 0)) {
            nuser = nuser + 1;
        }

        ut_entry = posix.getutxent();
    }
    _ = posix.endutxent();
    _ = beacon.printf(0, " users: %d", nuser);

    _ = beacon.printf(0, "\n");

    return 0;
}

pub export fn go() callconv(.C) u8 {

    if (@import("builtin").os.tag == .linux) {
        return getUptimeLinux() catch |err| switch (err) {
            std.fs.File.OpenError.AntivirusInterference => return @intFromEnum(BofErrors.AntivirusInterference),
            std.fs.File.OpenError.AccessDenied => return @intFromEnum(BofErrors.AccessDenied),
            std.fs.File.OpenError.FileNotFound => return @intFromEnum(BofErrors.FileNotFound),
            std.fs.File.OpenError.FileBusy => return @intFromEnum(BofErrors.FileBusy),
            else => return @intFromEnum(BofErrors.UnknownError),
        };
    }

    return 0;
}
