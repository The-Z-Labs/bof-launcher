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

pub fn init() void {
    printf = def(PFN_BeaconPrintf, "BeaconPrintf");
    output = def(PFN_BeaconOutput, "BeaconOutput");

    dataParse = def(PFN_BeaconDataParse, "BeaconDataParse");
    dataExtract = def(PFN_BeaconDataExtract, "BeaconDataExtract");
    dataInt = def(PFN_BeaconDataInt, "BeaconDataInt");
    dataShort = def(PFN_BeaconDataShort, "BeaconDataShort");
    dataLength = def(PFN_BeaconDataLength, "BeaconDataLength");

    formatPrintf = def(PFN_BeaconFormatPrintf, "BeaconFormatPrintf");
    formatAlloc = def(PFN_BeaconFormatAlloc, "BeaconFormatAlloc");
    formatReset = def(PFN_BeaconFormatReset, "BeaconFormatReset");
    formatFree = def(PFN_BeaconFormatFree, "BeaconFormatFree");
    formatAppend = def(PFN_BeaconFormatAppend, "BeaconFormatAppend");
    formatToString = def(PFN_BeaconFormatToString, "BeaconFormatToString");
    formatInt = def(PFN_BeaconFormatInt, "BeaconFormatInt");
}

pub var printf: PFN_BeaconPrintf = undefined;
pub var output: PFN_BeaconOutput = undefined;

pub var dataParse: PFN_BeaconDataParse = undefined;
pub var dataExtract: PFN_BeaconDataExtract = undefined;
pub var dataInt: PFN_BeaconDataInt = undefined;
pub var dataShort: PFN_BeaconDataShort = undefined;
pub var dataLength: PFN_BeaconDataLength = undefined;

pub var formatPrintf: PFN_BeaconFormatPrintf = undefined;
pub var formatAlloc: PFN_BeaconFormatAlloc = undefined;
pub var formatReset: PFN_BeaconFormatReset = undefined;
pub var formatFree: PFN_BeaconFormatFree = undefined;
pub var formatAppend: PFN_BeaconFormatAppend = undefined;
pub var formatToString: PFN_BeaconFormatToString = undefined;
pub var formatInt: PFN_BeaconFormatInt = undefined;

fn def(comptime T: type, comptime funcname: []const u8) T {
    return @extern(T, .{
        .name = funcname,
        .is_dll_import = @import("builtin").mode != .Debug,
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

const PFN_BeaconPrintf = *const fn (@"type": CallbackType, fmt: [*:0]const u8, ...) callconv(.c) i32;
const PFN_BeaconOutput = *const fn (@"type": CallbackType, data: ?[*]u8, len: i32) callconv(.c) void;

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
