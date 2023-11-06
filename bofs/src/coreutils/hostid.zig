const std = @import("std");
const beacon = @import("bofapi").beacon;
const unix = @import("bofapi").unix;

pub export fn go() callconv(.C) u8 {
    const id = unix.gethostid();
    _ = beacon.printf(0, "%08x\n", id);

    return 0;
}
