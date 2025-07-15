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

pub const printf = def(?PFN_BeaconPrintf, "BeaconPrintf");
pub const output = def(?PFN_BeaconOutput, "BeaconOutput");

pub const dataParse = def(?PFN_BeaconDataParse, "BeaconDataParse");
pub const dataExtract = def(?PFN_BeaconDataExtract, "BeaconDataExtract");
pub const dataInt = def(?PFN_BeaconDataInt, "BeaconDataInt");
pub const dataShort = def(?PFN_BeaconDataShort, "BeaconDataShort");
pub const dataLength = def(?PFN_BeaconDataLength, "BeaconDataLength");

pub const formatPrintf = def(?PFN_BeaconFormatPrintf, "BeaconFormatPrintf");
pub const formatAlloc = def(?PFN_BeaconFormatAlloc, "BeaconFormatAlloc");
pub const formatReset = def(?PFN_BeaconFormatReset, "BeaconFormatReset");
pub const formatFree = def(?PFN_BeaconFormatFree, "BeaconFormatFree");
pub const formatAppend = def(?PFN_BeaconFormatAppend, "BeaconFormatAppend");
pub const formatToString = def(?PFN_BeaconFormatToString, "BeaconFormatToString");
pub const formatInt = def(?PFN_BeaconFormatInt, "BeaconFormatInt");

fn def(comptime T: type, comptime funcname: []const u8) T {
    return @extern(T, .{ .name = funcname, .is_dll_import = @import("builtin").mode != .Debug });
}

const PFN_BeaconPrintf = *const fn (typ: i32, fmt: [*:0]const u8, ...) callconv(.c) i32;
const PFN_BeaconOutput = *const fn (typ: i32, data: ?[*]u8, len: i32) callconv(.c) void;

const PFN_BeaconDataParse = *const fn (parser: ?*datap, buffer: ?[*]u8, size: i32) callconv(.c) void;
const PFN_BeaconDataExtract = *const fn (parser: ?*datap, size: ?*i32) callconv(.c) ?[*:0]u8;
const PFN_BeaconDataInt = *const fn (parser: *datap) callconv(.c) i32;
const PFN_BeaconDataShort = *const fn (parser: *datap) callconv(.c) i16;
const PFN_BeaconDataLength = *const fn (parser: *datap) callconv(.c) i32;

const PFN_BeaconFormatPrintf = *const fn (parser: ?*formatp, fmt: [*:0]const u8, ...) callconv(.c) i32;
const PFN_BeaconFormatAlloc = *const fn (format: ?*formatp, maxsz: i32) callconv(.c) void;
const PFN_BeaconFormatReset = *const fn (format: ?*formatp) callconv(.c) void;
const PFN_BeaconFormatFree = *const fn (format: ?*formatp) callconv(.c) void;
const PFN_BeaconFormatAppend = *const fn (format: ?*formatp, text: [*]u8, len: i32) callconv(.c) void;
const PFN_BeaconFormatToString = *const fn (format: ?*formatp, size: ?*i32) callconv(.c) [*]u8;
const PFN_BeaconFormatInt = *const fn (format: ?*formatp, value: i32) callconv(.c) void;
