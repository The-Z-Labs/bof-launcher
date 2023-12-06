const beacon = @import("bof_api").beacon;

pub export fn go(_: ?[*]u8, _: i32) callconv(.C) u8 {
    _ = beacon.printf(0, "hello, bof!\n");
    return 0;
}
