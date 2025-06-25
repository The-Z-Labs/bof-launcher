const std = @import("std");
const beacon = @import("bof_api").beacon;
const posix = @import("bof_api").posix;

// https://gitlab.com/procps-ng/procps/-/blob/master/src/uptime.c
// https://gitlab.com/procps-ng/procps/-/blob/master/library/uptime.c
// https://github.com/trustedsec/CS-Situational-Awareness-BOF/blob/master/src/SA/uptime/entry.c
//
// TODO BOF: 
// https://gitlab.com/procps-ng/procps/-/blob/master/src/w.c

// BOF-specific error codes
const BofErrors = enum(u8) {
    AccessDenied = 0x1,
    AntivirusInterference,
    FileNotFound,
    FileBusy,
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
    .second = @intCast(seconds_since_midnight % 60)
  };
}

pub fn toRFC3339(dt: DateTime) [20]u8 {
  var buf: [20]u8 = undefined;
  _ = std.fmt.formatIntBuf(buf[0..4], dt.year, 10, .lower, .{.width = 4, .fill = '0'});
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

fn getUptimeLinux() !u8 {
    var buffer = [_]u8{0} ** 100;

    const f = try std.fs.openFileAbsoluteZ("/proc/uptime", .{ .mode = .read_only} );
    defer f.close();

    _ = try f.reader().readUntilDelimiterOrEof(&buffer, '\n') orelse
        return @intFromEnum(BofErrors.UnknownError);

    var iter = std.mem.splitScalar(u8, &buffer, ' ');
    const upt = iter.next() orelse return @intFromEnum(BofErrors.UnknownError);
    const idlet = iter.next() orelse return @intFromEnum(BofErrors.UnknownError);

    const uptime = @as(u64, @intFromFloat(try std.fmt.parseFloat(f64, upt)));
    _ = beacon.printf(0, "%s %d\n", &buffer, uptime);

    const dt = fromTimestamp(uptime);
    const timeStr = toRFC3339(dt);
    _ = beacon.printf(0, "%s", &timeStr);

    const idletime = @as(u64, @intFromFloat(try std.fmt.parseFloat(f64, idlet)));
    _ = beacon.printf(0, "%s %d\n", &buffer, idletime);

    const dt2 = fromTimestamp(idletime);
    const timeStr2 = toRFC3339(dt2);
    _ = beacon.printf(0, "%s", &timeStr2);

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
