const std = @import("std");
const assert = std.debug.assert;
const bof = @import("bof_launcher_api");

const bof_raw = @embedFile("z_beacon_embed");

pub export fn launch() noreturn {

    _ = bof.run(bof_raw[0..bof_raw.len]) catch unreachable;

    unreachable;
}
