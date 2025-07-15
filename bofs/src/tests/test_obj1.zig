const std = @import("std");
const fmt = std.fmt;
const beacon = @import("bof_api").beacon;

var global_var: i32 = 3;

fn func() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();
    var list = std.ArrayList(i32).init(allocator);
    defer list.deinit();
    try list.append(1);
    list.append(2) catch unreachable;
    list.append(3) catch return;

    if (list.items[0] != 1) return error.WrongValue;
    if (list.items[1] != 2) return error.WrongValue;
    if (list.items[2] != 3) return error.WrongValue;

    global_var += 1;
}

pub export fn go(arg_data: ?[*]u8, arg_len: i32) callconv(.C) u8 {
    const printf = beacon.printf.?;

    _ = printf(0, "--- test_obj1.zig ---\n");

    _ = printf(0, "BeaconPrintf %s\n", "has been called");
    var parser = beacon.datap{};

    beacon.dataParse.?(&parser, arg_data, arg_len);
    const len = beacon.dataLength.?(&parser);
    const permissions = beacon.dataExtract.?(&parser, null);
    const path = beacon.dataExtract.?(&parser, null);
    const num = beacon.dataInt.?(&parser);
    const num_short = beacon.dataShort.?(&parser);
    if (arg_len > 0) {
        _ = printf(0, "arg_len (from go): %d\n", arg_len);
        _ = printf(0, "Length: (from go): %d\n", len);

        //const stdout = std.io.getStdErr().writer();
        //const slice = arg_data.?[0..@as(usize, @intCast(arg_len))];
        //const str = fmt.fmtSliceHexLower(slice);
        //stdout.print("bof debug: arg_data (slice): {any}\n", .{str}) catch unreachable;

        _ = printf(0, "permissions: (from go): %s\n", permissions);
        _ = printf(0, "path: (from go): %s\n", path);
        _ = printf(0, "number (int): (from go): %d\n", num);
        _ = printf(0, "number (short): (from go): %d\n", num_short);
    }

    func() catch unreachable;

    _ = printf(0, "BeaconPrintf %s\n", "has been called second time");

    const buf = "Hello world!";
    _ = printf(0, "aaaaaaaaaaaaaaa %s %d\n", buf, global_var);

    global_var += 2;
    const ret = global_var;
    global_var = 3;
    return @intCast(ret);
}
