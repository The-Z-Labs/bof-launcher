const std = @import("std");
const beacon = @import("bof_api").beacon;
const posix = @import("bof_api").posix;

pub export fn go() callconv(.C) u8 {
    const id = posix.gethostid();
    _ = beacon.printf(0, "%08x\n", id);

    return 0;
}
