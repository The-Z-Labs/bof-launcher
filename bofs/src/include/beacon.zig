pub const datap = extern struct {
    original: [*]u8 = undefined,
    buffer: [*]u8 = undefined,
    length: i32 = 0,
    size: i32 = 0,
};

pub const formatp = extern struct {
    original: ?[*]u8 = null,
    buffer: ?[*]u8 = null,
    length: i32 = 0,
    size: i32 = 0,
};

fn def(comptime T: type, comptime funcname: []const u8) T {
    return @extern(T, .{
        .name = funcname,
        .is_dll_import = @import("builtin").mode != .debug,
    });
}

pub const CallbackType = enum(i32) {
    output = 0x0,
    output_oem = 0x1e,
    output_utf8 = 0x20,
    err = 0x0d,
    custom = 0x1000,
    custom_last = 0x13ff,
};

pub fn printf(@"type": CallbackType, fmt: [*:0]const u8, args: anytype) i32 {
    const f = def(*const fn (CallbackType, [*:0]const u8, ...) callconv(.c) i32, "BeaconPrintf");
    return @call(.auto, f, .{@"type", fmt} ++ args);
}

pub fn formatPrintf(parser: ?*formatp, fmt: [*:0]const u8, args: anytype) i32 {
    const f = def(*const fn (?*formatp, [*:0]const u8, ...) callconv(.c) i32, "BeaconFormatPrintf");
    return @call(.auto, f, .{parser, fmt} ++ args);
}

pub fn output(@"type": CallbackType, data: ?[*]u8, len: i32) callconv(.c) void {
    const f = def(*const @TypeOf(output), "BeaconOutput");
    f(@"type", data, len);
}

pub fn dataParse(parser: ?*datap, buffer: ?[*]u8, size: i32) callconv(.c) void {
    const f = def(*const @TypeOf(dataParse), "BeaconDataParse");
    f(parser, buffer, size);
}

pub fn dataExtract(parser: ?*datap, size: ?*i32) callconv(.c) ?[*:0]u8 {
    const f = def(*const @TypeOf(dataExtract), "BeaconDataExtract");
    return f(parser, size);
}

pub fn dataInt(parser: *datap) callconv(.c) i32 {
    const f = def(*const @TypeOf(dataInt), "BeaconDataInt");
    return f(parser);
}

pub fn dataShort(parser: *datap) callconv(.c) i16 {
    const f = def(*const @TypeOf(dataShort), "BeaconDataShort");
    return f(parser);
}

pub fn dataLength(parser: *datap) callconv(.c) i32 {
    const f = def(*const @TypeOf(dataLength), "BeaconDataLength");
    return f(parser);
}

pub fn formatAlloc(format: ?*formatp, maxsz: i32) callconv(.c) void {
    const f = def(*const @TypeOf(formatAlloc), "BeaconFormatAlloc");
    f(format, maxsz);
}

pub fn formatReset(format: ?*formatp) callconv(.c) void {
    const f = def(*const @TypeOf(formatReset), "BeaconFormatReset");
    f(format);
}

pub fn formatFree(format: ?*formatp) callconv(.c) void {
    const f = def(*const @TypeOf(formatFree), "BeaconFormatFree");
    f(format);
}

pub fn formatAppend(format: ?*formatp, text: [*]u8, len: i32) callconv(.c) void {
    const f = def(*const @TypeOf(formatAppend), "BeaconFormatAppend");
    f(format, text, len);
}

pub fn formatToString(format: ?*formatp, size: ?*i32) callconv(.c) [*]u8 {
    const f = def(*const @TypeOf(formatToString), "BeaconFormatToString");
    return f(format, size);
}

pub fn formatInt(format: ?*formatp, value: i32) callconv(.c) void {
    const f = def(*const @TypeOf(formatInt), "BeaconFormatInt");
    f(format, value);
}

pub fn toWideChar(src: ?[*:0]const u8, dst: ?[*]u16, max: i32) callconv(.c) i32 {
    const f = def(*const @TypeOf(toWideChar), "toWideChar");
    return f(src, dst, max);
}

pub fn addValue(key: ?[*:0]const u8, ptr: ?*anyopaque) callconv(.c) i32 {
    const f = def(*const @TypeOf(addValue), "BeaconAddValue");
    return f(key, ptr);
}

pub fn getValue(key: ?[*:0]const u8) callconv(.c) ?*anyopaque {
    const f = def(*const @TypeOf(getValue), "BeaconGetValue");
    return f(key);
}

pub fn removeValue(key: ?[*:0]const u8) callconv(.c) i32 {
    const f = def(*const @TypeOf(removeValue), "BeaconRemoveValue");
    return f(key);
}

pub fn isAdmin() callconv(.c) bool {
    const f = def(*const @TypeOf(isAdmin), "BeaconIsAdmin");
    return f();
}
