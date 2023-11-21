const std = @import("std");
const mem = std.mem;

extern fn allocateAndZeroMemory(num: usize, size: usize) callconv(.C) ?*anyopaque;
extern fn freeMemory(ptr: ?*anyopaque) callconv(.C) void;

pub const datap = extern struct {
    original: [*]u8,
    buffer: [*]u8,
    length: i32,
    size: i32,
};

pub const formatp = extern struct {
    original: ?[*]u8,
    buffer: ?[*]u8,
    length: i32,
    size: i32,
};

pub extern fn BeaconPrintf(typ: i32, fmt: [*:0]const u8, ...) callconv(.C) i32;
pub extern fn BeaconOutput(typ: i32, data: ?[*]u8, len: i32) callconv(.C) void;
pub extern fn BeaconFormatPrintf(parser: ?*formatp, fmt: [*:0]const u8, ...) callconv(.C) i32;

pub extern fn getEnviron() callconv(.C) [*:null]?[*:0]const u8;

pub export fn getOSName() callconv(.C) [*:0]const u8 {
    return switch (@import("builtin").os.tag) {
        .windows => "windows",
        .freebsd => "freebsd",
        .macos => "apple",
        .openbsd => "openbsd",
        .linux => "lin",
        else => "unk",
    };
}

pub export fn BeaconDataParse(parser: ?*datap, buffer: ?[*]u8, size: i32) callconv(.C) void {
    if (parser == null)
        return;

    parser.?.original = buffer orelse return;
    parser.?.buffer = buffer orelse return;
    parser.?.length = size - 4;
    parser.?.size = size - 4;
    parser.?.buffer += 4;
    return;
}

pub export fn BeaconDataInt(parser: *datap) callconv(.C) i32 {
    var fourbyteint: i32 = 0;
    if (parser.length < 4) {
        return 0;
    }
    mem.copy(u8, std.mem.asBytes(&fourbyteint), parser.buffer[0..4]);

    parser.buffer += 4;
    parser.length -= 4;
    return fourbyteint;
}

pub export fn BeaconDataShort(parser: *datap) callconv(.C) i16 {
    var twobyteint: i16 = 0;
    if (parser.length < 2) {
        return 0;
    }
    mem.copy(u8, std.mem.asBytes(&twobyteint), parser.buffer[0..2]);

    parser.buffer += 2;
    parser.length -= 2;
    return twobyteint;
}

pub export fn BeaconDataUSize(parser: *datap) callconv(.C) usize {
    var data: usize = 0;
    if (parser.length < @sizeOf(usize)) {
        return 0;
    }
    mem.copy(u8, std.mem.asBytes(&data), parser.buffer[0..@sizeOf(usize)]);

    parser.buffer += @sizeOf(usize);
    parser.length -= @sizeOf(usize);
    return data;
}

pub export fn BeaconDataLength(parser: *datap) callconv(.C) i32 {
    return parser.length;
}

pub export fn BeaconDataExtract(parser: ?*datap, size: ?*i32) callconv(.C) ?[*]u8 {
    var length: i32 = 0;

    var outdata: ?[*]u8 = null;
    if (parser.?.length < 4) {
        return null;
    }
    mem.copy(u8, std.mem.asBytes(&length), parser.?.buffer[0..4]);

    parser.?.buffer += 4;

    outdata = parser.?.buffer;
    if (outdata == null) {
        return null;
    }
    parser.?.length -= 4;
    parser.?.length -= length;
    parser.?.buffer += @as(usize, @intCast(length));
    if (size != null and outdata != null) {
        size.?.* = length;
    }
    return outdata;
}

pub export fn BeaconFormatAlloc(format: ?*formatp, maxsz: i32) callconv(.C) void {
    if (format == null)
        return;

    format.?.original = @as([*]u8, @ptrCast(allocateAndZeroMemory(@as(usize, @intCast(maxsz)), 1)));
    format.?.buffer = format.?.original;
    format.?.length = 0;
    format.?.size = maxsz;
}

pub export fn BeaconFormatReset(format: ?*formatp) callconv(.C) void {
    @memset(format.?.original.?[0..@as(usize, @intCast(format.?.size))], 0);
    format.?.buffer = format.?.original;
    format.?.length = 0;
}

pub export fn BeaconFormatFree(format: ?*formatp) callconv(.C) void {
    if (format == null) {
        return;
    }
    if (format.?.original != null) {
        freeMemory(format.?.original.?);
        format.?.original = null;
    }
    format.?.buffer = null;
    format.?.length = 0;
    format.?.size = 0;
}

pub export fn BeaconFormatAppend(format: ?*formatp, text: [*]u8, len: i32) callconv(.C) void {
    mem.copy(u8, format.?.buffer.?[0..@as(usize, @intCast(len))], text[0..@as(usize, @intCast(len))]);
    format.?.buffer.? += @as(usize, @intCast(len));
    format.?.length += len;
}

pub export fn BeaconFormatToString(format: ?*formatp, size: ?*i32) callconv(.C) [*]u8 {
    if (size != null) size.?.* = format.?.length;
    return format.?.original.?;
}

pub export fn BeaconFormatInt(format: ?*formatp, value: i32) callconv(.C) void {
    const indata: i32 = value;
    var outdata: i32 = 0;
    if (format.?.length + 4 > format.?.size) {
        return;
    }
    outdata = @byteSwap(indata);
    mem.copy(u8, format.?.buffer.?[0..4], std.mem.asBytes(&outdata));
    format.?.length += 4;
    format.?.buffer.? += @as(usize, 4);
}
