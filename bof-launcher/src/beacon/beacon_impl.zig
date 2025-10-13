const std = @import("std");
const mem = std.mem;

extern fn bofLauncherAllocateAndZeroMemory(num: usize, size: usize) callconv(.c) ?*anyopaque;
extern fn bofLauncherFreeMemory(ptr: ?*anyopaque) callconv(.c) void;

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

pub extern fn BeaconPrintf(typ: i32, fmt: [*:0]const u8, ...) callconv(.c) i32;
pub extern fn BeaconOutput(typ: i32, data: ?[*]u8, len: i32) callconv(.c) void;
pub extern fn BeaconFormatPrintf(parser: ?*formatp, fmt: [*:0]const u8, ...) callconv(.c) i32;

pub export fn BeaconDataParse(parser: ?*datap, buffer: ?[*]u8, size: i32) callconv(.c) void {
    if (parser == null)
        return;

    parser.?.original = buffer orelse return;
    parser.?.buffer = buffer orelse return;
    parser.?.length = size - 4;
    parser.?.size = size - 4;
    parser.?.buffer += 4;
    return;
}

pub export fn BeaconDataInt(parser: *datap) callconv(.c) i32 {
    var fourbyteint: i32 = 0;
    if (parser.length < 4) {
        return 0;
    }
    @memcpy(std.mem.asBytes(&fourbyteint), parser.buffer[0..4]);

    parser.buffer += 4;
    parser.length -= 4;
    return fourbyteint;
}

pub export fn BeaconDataShort(parser: *datap) callconv(.c) i16 {
    var twobyteint: i16 = 0;
    if (parser.length < 2) {
        return 0;
    }
    @memcpy(std.mem.asBytes(&twobyteint), parser.buffer[0..2]);

    parser.buffer += 2;
    parser.length -= 2;
    return twobyteint;
}

pub export fn BeaconDataLength(parser: *datap) callconv(.c) i32 {
    return parser.length;
}

pub export fn BeaconDataExtract(parser: ?*datap, size: ?*i32) callconv(.c) ?[*:0]u8 {
    var length: i32 = 0;

    var outdata: ?[*]u8 = null;
    if (parser.?.length < 4) {
        return null;
    }
    @memcpy(std.mem.asBytes(&length), parser.?.buffer[0..4]);

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
    return @ptrCast(outdata);
}

pub export fn BeaconFormatAlloc(format: ?*formatp, maxsz: i32) callconv(.c) void {
    if (format == null)
        return;

    format.?.original = @as([*]u8, @ptrCast(bofLauncherAllocateAndZeroMemory(@as(usize, @intCast(maxsz)), 1)));
    format.?.buffer = format.?.original;
    format.?.length = 0;
    format.?.size = maxsz;
}

pub export fn BeaconFormatReset(format: ?*formatp) callconv(.c) void {
    @memset(format.?.original.?[0..@as(usize, @intCast(format.?.size))], 0);
    format.?.buffer = format.?.original;
    format.?.length = 0;
}

pub export fn BeaconFormatFree(format: ?*formatp) callconv(.c) void {
    if (format == null) {
        return;
    }
    if (format.?.original != null) {
        bofLauncherFreeMemory(format.?.original.?);
        format.?.original = null;
    }
    format.?.buffer = null;
    format.?.length = 0;
    format.?.size = 0;
}

pub export fn BeaconFormatAppend(format: ?*formatp, text: [*]u8, len: i32) callconv(.c) void {
    @memcpy(format.?.buffer.?[0..@as(usize, @intCast(len))], text[0..@as(usize, @intCast(len))]);
    format.?.buffer.? += @as(usize, @intCast(len));
    format.?.length += len;
}

pub export fn BeaconFormatToString(format: ?*formatp, size: ?*i32) callconv(.c) [*]u8 {
    if (size != null) size.?.* = format.?.length;
    return format.?.original.?;
}

pub export fn BeaconFormatInt(format: ?*formatp, value: i32) callconv(.c) void {
    const indata: i32 = value;
    var outdata: i32 = 0;
    if (format.?.length + 4 > format.?.size) {
        return;
    }
    outdata = @byteSwap(indata);
    @memcpy(format.?.buffer.?[0..4], std.mem.asBytes(&outdata));
    format.?.length += 4;
    format.?.buffer.? += @as(usize, 4);
}
