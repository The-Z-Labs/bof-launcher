const beacon = @import("bofapi").beacon;

pub export fn go(_: ?[*]u8, _: i32) callconv(.C) u8 {
    //_ = beacon.printf(0, "hello, bof!");
    return 0;
}
