const std = @import("std");
const beacon = @import("bofapi").beacon;
const unix = @import("bofapi").unix;

pub export fn go() callconv(.C) u8 {
    _ = beacon.printf(0, "uptime BOF\n");

    unix.setutxent();

    _ = unix.puts("Just testing.\n");

    unix.endutxent();
    return 0;
}
