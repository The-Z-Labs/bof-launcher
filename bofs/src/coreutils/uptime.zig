const std = @import("std");
const beacon = @import("bofapi").beacon;
const unix = @import("bofapi").unix;

pub export fn go() callconv(.C) u8 {
    unix.setutxent();

    var ut: ?*unix.utmpx = unix.getutxent();

    if (ut) |utx| {
        _ = beacon.printf(0, "User %s\n", utx.ut_user);
        _ = beacon.printf(0, "Type %d\n", utx.ut_type);
    }

    unix.endutxent();
    return 0;
}
