const std = @import("std");
const beacon = @import("bof_api").beacon;
const krb = @import("bof_api").kerberos;

comptime {
    @import("bof_api").embedFunctionCode("memcpy");
    @import("bof_api").embedFunctionCode("memmove");
}

pub export fn func(msg: [*:0]const u8) callconv(.c) u8 {
    _ = beacon.printf(.output, "func() %s\n", msg);
    return 0;
}

export fn func123(msg: [*:0]const u8) callconv(.c) u8 {
    _ = beacon.printf(.output, "func123() %s\n", msg);
    return 123;
}

pub export fn go(adata: ?[*]u8, alen: i32) callconv(.c) u8 {
    @import("bof_api").init(adata, alen, .{});

    _ = beacon.printf(.output, "--- test_obj0.zig ---\n");

    var buf: [512]u8 = undefined;
    const packet = krb.encodeAsReq(buf[0..], "aaaaaaaa", "bbbbbbbb") catch unreachable;
    _ = packet;

    var fbs = std.io.fixedBufferStream(&buf);

    fbs.writer().print("Hello, {s}!\n", .{"go"}) catch unreachable;
    fbs.writer().writeByte(0) catch unreachable;

    _ = beacon.printf(.output, "%s", &buf);

    return @call(.never_inline, func, .{"it"});
}
