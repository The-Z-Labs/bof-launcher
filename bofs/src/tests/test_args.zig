const std = @import("std");
const beacon = @import("bof_api").beacon;

pub export fn go(arg_data: ?[*]u8, arg_len: i32) callconv(.C) u8 {
    _ = beacon.printf.?(0, "--- test_args.zig ---\n");

    if (arg_data == null) return 1;

    var parser = beacon.datap{};
    beacon.dataParse.?(&parser, arg_data, arg_len);

    if (beacon.dataInt.?(&parser) != 123) return 1;
    if (beacon.dataInt.?(&parser) != -123) return 1;
    if (beacon.dataInt.?(&parser) != 2147483647) return 1;
    if (beacon.dataInt.?(&parser) != -2147483648) return 1;
    if (beacon.dataShort.?(&parser) != 32767) return 1;
    if (beacon.dataShort.?(&parser) != -32768) return 1;

    for (0..32) |i| {
        if (beacon.dataInt.?(&parser) != i) return 1;
    }

    {
        if (!std.mem.eql(u8, "red apple", std.mem.span(beacon.dataExtract.?(&parser, null).?))) return 1;

        var len: i32 = 0;
        if (!std.mem.eql(u8, "green grid  ", std.mem.span(beacon.dataExtract.?(&parser, &len).?))) return 1;
        if (len != 13) return 1;

        const str = beacon.dataExtract.?(&parser, &len).?;
        if (len != 5) return 1;
        if (str[@intCast(len - 1)] != 0) return 1;
        if (!std.mem.eql(u8, "blue", std.mem.span(str))) return 1;
    }

    if (!std.mem.eql(u8, "dksdjksadjksajdksajdksajdksajdksajdksajdksabxc\ndaskildjald daskljdasldjska\tdjkajdksalds s02w0201mskasl", std.mem.span(beacon.dataExtract.?(&parser, null).?))) return 1;

    return 0;
}
