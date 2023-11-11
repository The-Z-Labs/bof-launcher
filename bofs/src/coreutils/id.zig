const std = @import("std");
const os = std.os;
const fmt = std.fmt;
const beacon = @import("bofapi").beacon;
const posix = @import("bofapi").posix;

pub export fn go() callconv(.C) u8 {
    const uid = posix.getuid();
    const gid = posix.getgid();

    const passwd = posix.getpwuid(uid);
    const group = posix.getgrgid(gid);

    if (passwd == null or group == null) {
        return 1;
    }

    _ = beacon.printf(0, "uid=%d", uid);
    if (passwd) |p|
        _ = beacon.printf(0, "(%s) ", p.pw_name);

    _ = beacon.printf(0, "gid=%d", gid);
    if (group) |g|
        _ = beacon.printf(0, "(%s)", g.gr_name);

    return 0;
}
