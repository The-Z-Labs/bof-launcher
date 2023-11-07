const std = @import("std");
const beacon = @import("bofapi").beacon;
const posix = @import("bofapi").posix;

pub export fn go() callconv(.C) u8 {
    const id = posix.gethostid();
    _ = beacon.printf(0, "%08x\n", id);

    return 0;
}
