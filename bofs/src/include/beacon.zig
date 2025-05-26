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

pub const printf = BeaconPrintf;
pub const output = BeaconOutput;
pub const formatPrintf = BeaconPrintf;
pub const dataParse = BeaconDataParse;
pub const dataInt = BeaconDataInt;
pub const dataShort = BeaconDataShort;
pub const dataLength = BeaconDataLength;
pub const dataExtract = BeaconDataExtract;
pub const formatAlloc = BeaconFormatAlloc;
pub const formatReset = BeaconFormatReset;
pub const formatFree = BeaconFormatFree;
pub const formatAppend = BeaconFormatAppend;
pub const formatToString = BeaconFormatToString;
pub const formatInt = BeaconFormatInt;
pub const dataUSize = BeaconDataUSize;

extern fn BeaconPrintf(typ: i32, fmt: [*:0]const u8, ...) callconv(.C) i32;
extern fn BeaconOutput(typ: i32, data: ?[*]u8, len: i32) callconv(.C) void;
extern fn BeaconFormatPrintf(parser: ?*formatp, fmt: [*:0]const u8, ...) callconv(.C) i32;
extern fn BeaconDataParse(parser: ?*datap, buffer: ?[*]u8, size: i32) callconv(.C) void;
extern fn BeaconDataInt(parser: *datap) callconv(.C) i32;
extern fn BeaconDataShort(parser: *datap) callconv(.C) i16;
extern fn BeaconDataLength(parser: *datap) callconv(.C) i32;
extern fn BeaconDataExtract(parser: ?*datap, size: ?*i32) callconv(.C) ?[*:0]u8;
extern fn BeaconFormatAlloc(format: ?*formatp, maxsz: i32) callconv(.C) void;
extern fn BeaconFormatReset(format: ?*formatp) callconv(.C) void;
extern fn BeaconFormatFree(format: ?*formatp) callconv(.C) void;
extern fn BeaconFormatAppend(format: ?*formatp, text: [*]u8, len: i32) callconv(.C) void;
extern fn BeaconFormatToString(format: ?*formatp, size: ?*i32) callconv(.C) [*]u8;
extern fn BeaconFormatInt(format: ?*formatp, value: i32) callconv(.C) void;
extern fn BeaconDataUSize(parser: *datap) callconv(.C) usize;

pub extern fn getEnviron() callconv(.C) [*:null]?[*:0]const u8;
pub extern fn getOSName() callconv(.C) [*:0]const u8;
