const std = @import("std");
const beacon = @import("bofapi").beacon;
const unix = @import("bofapi").unix;

pub export fn go() callconv(.C) u8 {
    _ = beacon.printf(0, "uptime BOF\n");

    _ = unix.puts("Just testing.\n");

    return 0;
}
