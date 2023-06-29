const beacon = @import("bofapi").beacon;
const w32 = @import("bofapi").win32;

pub export fn go(arg_data: ?[*]u8, arg_len: i32) callconv(.C) u8 {
    _ = beacon.printf(0, "\n--- test_obj3.zig ---\n");

    if (@import("builtin").os.tag == .windows) {
        w32.Sleep(0);
        _ = beacon.printf(0, "CoGetCurrentProcess() returned: %d\n", w32.CoGetCurrentProcess());
    }

    switch (@import("builtin").cpu.arch) {
        .x86 => _ = beacon.printf(0, "cpu.arch is x86\n"),
        .x86_64 => _ = beacon.printf(0, "cpu.arch is x86_64\n"),
        else => _ = beacon.printf(0, "cpu.arch is unknown\n"),
    }

    switch (@import("builtin").os.tag) {
        .windows => _ = beacon.printf(0, "os.tag is windows\n"),
        .linux => _ = beacon.printf(0, "os.tag is linux\n"),
        else => _ = beacon.printf(0, "os.tag is unknown\n"),
    }

    var parser: beacon.datap = .{};
    beacon.dataParse(&parser, arg_data, arg_len);

    if (beacon.dataLength(&parser) != 6 + 3 * @sizeOf(usize)) return 1;
    if (beacon.dataShort(&parser) != 123) return 1;

    if (beacon.dataLength(&parser) != 4 + 3 * @sizeOf(usize)) return 1;
    if (beacon.dataInt(&parser) != -456) return 1;

    if (beacon.dataLength(&parser) != 3 * @sizeOf(usize)) return 1;
    if (beacon.dataUSize(&parser) != 0xc0de_c0de) return 1;

    if (beacon.dataLength(&parser) != 2 * @sizeOf(usize)) return 1;

    const data = @as([*]i32, @ptrFromInt(beacon.dataUSize(&parser)))[0..beacon.dataUSize(&parser)];
    data[0] += 1;
    data[50] = 0x70de_c0de;
    data[99] -= 10;

    return 0;
}
