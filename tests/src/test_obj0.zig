const std = @import("std");
const beacon = @import("bof_api").beacon;
const krb = @import("bof_api").kerberos;

noinline fn func(msg: [:0]const u8) u8 {
    _ = beacon.printf(0, "func() %s\n", msg.ptr);
    return 0;
}

pub export fn go(arg_data: ?[*]u8, arg_len: i32) callconv(.C) u8 {
    _ = arg_data;
    _ = arg_len;
    _ = beacon.printf(0, "--- test_obj0.zig ---\n");

    var buf: [512]u8 = undefined;
    const packet = krb.encodeAsReq(buf[0..], "aaaaaaaa", "bbbbbbbb") catch unreachable;
    _ = packet;

    var fbs = std.io.fixedBufferStream(&buf);

    fbs.writer().print("Hello, {s}!\n", .{"go"}) catch unreachable;
    fbs.writer().writeByte(0) catch unreachable;

    _ = beacon.printf(0, "%s", &buf);

    return func("it");
}
