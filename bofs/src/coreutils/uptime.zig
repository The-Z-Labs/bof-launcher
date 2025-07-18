const std = @import("std");
const beacon = @import("bof_api").beacon;
const posix = @import("bof_api").posix;

comptime {
    @import("bof_api").embedFunctionCode("__udivdi3");
    @import("bof_api").embedFunctionCode("__ashldi3");
    @import("bof_api").embedFunctionCode("__aeabi_uldivmod");
    @import("bof_api").embedFunctionCode("__aeabi_uidiv");
    @import("bof_api").embedFunctionCode("__aeabi_llsl");
}

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
    const printf = beacon.printf.?;

    var buffer = [_]u8{0} ** 100;

    const f = try std.fs.openFileAbsoluteZ(UPTIME_FILE, .{ .mode = .read_only });
    defer f.close();

    const uptimeStr = try f.reader().readUntilDelimiterOrEof(&buffer, '.') orelse
        return @intFromEnum(BofErrors.UnknownError);

    const SECONDS_PER_DAY = 86400;
    const uptimeSec = try std.fmt.parseInt(u64, uptimeStr, 10);

    _ = printf(.output, "up: ");

    const days: u8 = @intCast(uptimeSec / SECONDS_PER_DAY);
    const hours: u8 = @intCast(uptimeSec % SECONDS_PER_DAY / 3600);
    const minutes: u8 = @intCast(uptimeSec % SECONDS_PER_DAY % 3600 / 60);

    if (days > 0) {
        _ = printf(.output, "%d ", days);
        if (days == 1) {
            _ = printf(.output, "day ");
        } else _ = printf(.output, "days ");
    }
    if (hours > 0) {
        _ = printf(.output, "%d ", hours);
        if (hours == 1) {
            _ = printf(.output, "hour ");
        } else _ = printf(.output, "hours ");
    }
    if (minutes > 0) {
        _ = printf(.output, "%d ", minutes);
        if (minutes == 1) {
            _ = printf(.output, "minute ");
        } else _ = printf(.output, "minutes ");
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
    _ = printf(.output, " users: %d", nuser);

    _ = printf(.output, "\n");

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
