const std = @import("std");
const beacon = @import("bof_api").beacon;
const posix = @import("bof_api").posix;

pub export fn go() callconv(.C) u8 {
    posix.setutxent();

    const ut: ?*posix.utmpx = posix.getutxent();

    if (ut) |utx| {
        _ = beacon.printf(0, "User %s\n", utx.ut_user);
        _ = beacon.printf(0, "Type %d\n", utx.ut_type);
    }

    posix.endutxent();
    return 0;
}
