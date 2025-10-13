const std = @import("std");
const fmt = std.fmt;
const beacon = @import("bof_api").beacon;

comptime {
    @import("bof_api").embedFunctionCode("memcpy");
    @import("bof_api").embedFunctionCode("memset");
    @import("bof_api").embedFunctionCode("memmove");
    @import("bof_api").embedFunctionCode("__udivdi3");
    @import("bof_api").embedFunctionCode("__ashldi3");
    @import("bof_api").embedFunctionCode("__aeabi_llsl");
    @import("bof_api").embedFunctionCode("__aeabi_uldivmod");
    @import("bof_api").embedFunctionCode("__aeabi_uidiv");
}
pub const panic = std.debug.no_panic;

var global_var: i32 = 3;

fn func() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();
    var list = std.array_list.Managed(i32).init(allocator);
    defer list.deinit();
    try list.append(1);
    list.append(2) catch unreachable;
    list.append(3) catch return;

    if (list.items[0] != 1) return error.WrongValue;
    if (list.items[1] != 2) return error.WrongValue;
    if (list.items[2] != 3) return error.WrongValue;

    global_var += 1;
}

pub export fn go(adata: ?[*]u8, alen: i32) callconv(.c) u8 {
    @import("bof_api").init(adata, alen, .{});

    const printf = beacon.printf;

    _ = printf(.output, "--- test_obj1.zig ---\n");

    _ = printf(.output, "BeaconPrintf %s\n", "has been called");
    var parser = beacon.datap{};

    beacon.dataParse(&parser, adata, alen);
    const len = beacon.dataLength(&parser);
    const permissions = beacon.dataExtract(&parser, null);
    const path = beacon.dataExtract(&parser, null);
    const num = beacon.dataInt(&parser);
    const num_short = beacon.dataShort(&parser);
    if (alen > 0) {
        _ = printf(.output, "arg_len (from go): %d\n", alen);
        _ = printf(.output, "Length: (from go): %d\n", len);

        //const stdout = std.io.getStdErr().writer();
        //const slice = arg_data.?[0..@as(usize, @intCast(arg_len))];
        //const str = fmt.fmtSliceHexLower(slice);
        //stdout.print("bof debug: arg_data (slice): {any}\n", .{str}) catch unreachable;

        _ = printf(.output, "permissions: (from go): %s\n", permissions);
        _ = printf(.output, "path: (from go): %s\n", path);
        _ = printf(.output, "number (int): (from go): %d\n", num);
        _ = printf(.output, "number (short): (from go): %d\n", num_short);
    }

    func() catch unreachable;

    _ = printf(.output, "BeaconPrintf %s\n", "has been called second time");

    const buf = "Hello world!";
    _ = printf(.output, "aaaaaaaaaaaaaaa %s %d\n", buf, global_var);

    global_var += 2;
    const ret = global_var;
    global_var = 3;
    return @intCast(ret);
}
