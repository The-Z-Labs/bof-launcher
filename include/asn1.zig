// https://github.com/nektro/zig-asn1

const std = @import("std");
const string = []const u8;
const assert = std.debug.assert;

pub const Tag = enum(u8) {
    // zig fmt: off
    end_of_content      = @as(u8, 0) | @intFromEnum(PC.primitive),
    boolean             = @as(u8, 1) | @intFromEnum(PC.primitive),
    integer             = @as(u8, 2) | @intFromEnum(PC.primitive),
    bit_string          = @as(u8, 3) | @intFromEnum(PC.primitive),
    octet_string        = @as(u8, 4) | @intFromEnum(PC.primitive),
    null                = @as(u8, 5) | @intFromEnum(PC.primitive),
    object_identifier   = @as(u8, 6) | @intFromEnum(PC.primitive),
    object_descriptor   = @as(u8, 7) | @intFromEnum(PC.primitive),
    external_type       = @as(u8, 8) | @intFromEnum(PC.primitive),
    real_type           = @as(u8, 9) | @intFromEnum(PC.primitive),
    enumerated_type     = @as(u8,10) | @intFromEnum(PC.primitive),
    embedded_pdv        = @as(u8,11) | @intFromEnum(PC.primitive),
    utf8_string         = @as(u8,12) | @intFromEnum(PC.primitive),
    relative_oid        = @as(u8,13) | @intFromEnum(PC.primitive),
    time                = @as(u8,14) | @intFromEnum(PC.primitive),
    _reserved2          = @as(u8,15) | @intFromEnum(PC.primitive),
    sequence            = @as(u8,16) | @intFromEnum(PC.constructed),
    set                 = @as(u8,17) | @intFromEnum(PC.constructed),
    numeric_string      = @as(u8,18) | @intFromEnum(PC.primitive),
    printable_string    = @as(u8,19) | @intFromEnum(PC.primitive),
    teletex_string      = @as(u8,20) | @intFromEnum(PC.primitive),
    videotex_string     = @as(u8,21) | @intFromEnum(PC.primitive),
    ia5_string          = @as(u8,22) | @intFromEnum(PC.primitive),
    utc_time            = @as(u8,23) | @intFromEnum(PC.primitive),
    generalized_time    = @as(u8,24) | @intFromEnum(PC.primitive),
    graphic_string      = @as(u8,25) | @intFromEnum(PC.primitive),
    visible_string      = @as(u8,26) | @intFromEnum(PC.primitive),
    general_string      = @as(u8,27) | @intFromEnum(PC.primitive),
    universal_string    = @as(u8,28) | @intFromEnum(PC.primitive),
    unrestricted_string = @as(u8,29) | @intFromEnum(PC.primitive),
    bmp_string          = @as(u8,30) | @intFromEnum(PC.primitive),
    date                = @as(u8,31) | @intFromEnum(PC.primitive),
    _,

    
    const PC = enum(u8) {
        primitive   = 0b00000000,
        constructed = 0b00100000,
    };

    const Class = enum(u8) {
        universal   = 0b00000000,
        application = 0b01000000,
        context     = 0b10000000,
        private     = 0b11000000,
    };
    // zig fmt: on

    pub fn int(tag: Tag) u8 {
        return @intFromEnum(tag);
    }

    pub fn extra(pc: PC, class: Class, ty: u5) Tag {
        var res: u8 = ty;
        res |= @intFromEnum(pc);
        res |= @intFromEnum(class);
        return @enumFromInt(res);
    }

    pub fn read(reader: anytype) !Tag {
        return @enumFromInt(try reader.readByte());
    }
};

pub const Length = packed struct(u8) {
    len: u7,
    form: enum(u1) { short, long },

    pub fn read(reader: anytype) !u64 {
        const octet: Length = @bitCast(try reader.readByte());
        switch (octet.form) {
            .short => return octet.len,
            .long => {
                var res: u64 = 0;
                assert(octet.len <= 8); // long form length exceeds bounds of u64
                assert(octet.len > 0); // TODO indefinite form
                for (0..octet.len) |i| {
                    res |= (@as(u64, try reader.readByte()) << @as(u6, @intCast(8 * (octet.len - 1 - @as(u6, @intCast(i))))));
                }
                return res;
            },
        }
    }
};

fn expectTag(reader: anytype, tag: Tag) !void {
    const actual = try Tag.read(reader);
    if (actual != tag) return error.UnexpectedTag;
}

fn expectLength(reader: anytype, len: u64) !void {
    const actual = try Length.read(reader);
    if (actual != len) return error.UnexpectedLength;
}

pub fn readBoolean(reader: anytype) !bool {
    try expectTag(reader, .boolean);
    try expectLength(reader, 1);
    return (try reader.readByte()) > 0;
}

pub fn readInt(reader: anytype, comptime Int: type) !Int {
    comptime assert(@bitSizeOf(Int) % 8 == 0);
    const L2Int = std.math.Log2Int(Int);
    try expectTag(reader, .integer);
    const len = try Length.read(reader);
    assert(len <= 8); // TODO implement readIntBig
    assert(len > 0);
    assert(len <= @sizeOf(Int));
    var res: Int = 0;
    for (0..len) |i| {
        res |= (@as(Int, try reader.readByte()) << @as(L2Int, @intCast(8 * (len - 1 - @as(L2Int, @intCast(i))))));
    }
    return res;
}

pub fn readNull(reader: anytype) !void {
    try expectTag(reader, .null);
    try expectLength(reader, 0);
}
