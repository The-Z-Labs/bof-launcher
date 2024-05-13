const std = @import("std");
const asn1 = @import("asn1.zig");
const Tag = asn1.Tag;

pub fn encodeAsReq(buffer: []u8, user_name: []const u8, realm: []const u8) ![]const u8 {
    std.debug.assert(user_name.len <= 100);
    std.debug.assert(realm.len <= 100);

    var fbs_write = std.io.fixedBufferStream(buffer);
    const w = fbs_write.writer();

    // Length of the entire packet
    try w.writeInt(u32, 0xffff_ffff, .big); // Dummy value, computed later

    // AS-REQ          ::= [APPLICATION 10] KDC-REQ
    try w.writeByte(Tag.extra(.constructed, .application, 10).int());
    try w.writeByte(0b1000_0010); // 2-bytes length
    try w.writeInt(u16, 0xffff, .big); // Dummy value, computed later, offset: 6

    // KDC-REQ         ::= SEQUENCE {
    try w.writeByte(@intFromEnum(Tag.sequence));
    try w.writeByte(0b1000_0010); // 2-bytes length
    try w.writeInt(u16, 0xffff, .big); // Dummy value, computed later, offset: 10

    //        pvno            [1] INTEGER (5) , (version)
    try w.writeByte(Tag.extra(.constructed, .context, 1).int());
    try w.writeByte(3);
    try w.writeByte(@intFromEnum(Tag.integer));
    try w.writeByte(1);
    try w.writeByte(5);

    //        msg-type        [2] INTEGER (10 -- AS -- | 12 -- TGS --),
    try w.writeByte(Tag.extra(.constructed, .context, 2).int());
    try w.writeByte(3);
    try w.writeByte(@intFromEnum(Tag.integer));
    try w.writeByte(1);
    try w.writeByte(10);

    //        req-body        [4] KDC-REQ-BODY
    try w.writeByte(Tag.extra(.constructed, .context, 4).int());
    try w.writeByte(0b1000_0010); // 2-bytes length
    try w.writeInt(u16, 0xffff, .big); // Dummy value, computed later, offset: 24

    // KDC-REQ-BODY    ::= SEQUENCE {
    try w.writeByte(@intFromEnum(Tag.sequence));
    try w.writeByte(0b1000_0010); // 2-bytes length
    try w.writeInt(u16, 0xffff, .big); // Dummy value, computed later, offset: 28

    //        kdc-options             [0] KDCOptions,
    try w.writeByte(Tag.extra(.constructed, .context, 0).int());
    try w.writeByte(7);
    try w.writeByte(@intFromEnum(Tag.bit_string));
    try w.writeByte(5);
    try w.writeByte(0); // padding
    try w.writeInt(u32, 0x40000000, .big);

    //        cname                   [1] PrincipalName OPTIONAL
    try w.writeByte(Tag.extra(.constructed, .context, 1).int());
    try w.writeByte(@intCast(user_name.len + 13));
    try w.writeByte(@intFromEnum(Tag.sequence));
    try w.writeByte(@intCast(user_name.len + 11));
    try w.writeByte(Tag.extra(.constructed, .context, 0).int());
    try w.writeByte(3);
    try w.writeByte(@intFromEnum(Tag.integer));
    try w.writeByte(1);
    try w.writeByte(1); // type == 1 (NT-PRINCIPAL)
    try w.writeByte(Tag.extra(.constructed, .context, 1).int());
    try w.writeByte(@intCast(user_name.len + 4));
    try w.writeByte(@intFromEnum(Tag.sequence));
    try w.writeByte(@intCast(user_name.len + 2));
    try w.writeByte(@intFromEnum(Tag.general_string));
    try w.writeByte(@intCast(user_name.len));
    try w.writeAll(user_name);

    //        realm                   [2] Realm
    try w.writeByte(Tag.extra(.constructed, .context, 2).int());
    try w.writeByte(@intCast(realm.len + 2));
    try w.writeByte(@intFromEnum(Tag.general_string));
    try w.writeByte(@intCast(realm.len));
    try w.writeAll(realm);

    //        sname                   [3] PrincipalName OPTIONAL,
    try w.writeByte(Tag.extra(.constructed, .context, 3).int());
    try w.writeByte(@intCast(realm.len + 21));
    try w.writeByte(@intFromEnum(Tag.sequence));
    try w.writeByte(@intCast(realm.len + 19));
    try w.writeByte(Tag.extra(.constructed, .context, 0).int());
    try w.writeByte(3);
    try w.writeByte(@intFromEnum(Tag.integer));
    try w.writeByte(1);
    try w.writeByte(2); // type == 2 (NT-SRV-INST)
    try w.writeByte(Tag.extra(.constructed, .context, 1).int());
    try w.writeByte(@intCast(realm.len + 12));
    try w.writeByte(@intFromEnum(Tag.sequence));
    try w.writeByte(@intCast(realm.len + 10));
    try w.writeByte(@intFromEnum(Tag.general_string));
    try w.writeByte("krbtgt".len);
    try w.writeAll("krbtgt");
    try w.writeByte(@intFromEnum(Tag.general_string));
    try w.writeByte(@intCast(realm.len));
    try w.writeAll(realm);

    //        till                    [5] KerberosTime,
    try w.writeByte(Tag.extra(.constructed, .context, 5).int());
    try w.writeByte(17);
    try w.writeByte(@intFromEnum(Tag.generalized_time));
    try w.writeByte(15);
    try w.writeAll("19700101000000Z"); // No expiration date

    //        nonce                   [7] UInt32,
    try w.writeByte(Tag.extra(.constructed, .context, 7).int());
    try w.writeByte(6);
    try w.writeByte(@intFromEnum(Tag.integer));
    try w.writeByte(4);
    try w.writeInt(u32, 155874945, .big);

    //        etype                   [8] SEQUENCE OF Int32 -- EncryptionType
    try w.writeByte(Tag.extra(.constructed, .context, 8).int());
    try w.writeByte(14);
    try w.writeByte(@intFromEnum(Tag.sequence));
    try w.writeByte(12);
    try w.writeByte(@intFromEnum(Tag.integer));
    try w.writeByte(1);
    try w.writeByte(18); //      { ['aes256-cts-hmac-sha1-96'] = 18 },
    try w.writeByte(@intFromEnum(Tag.integer));
    try w.writeByte(1);
    try w.writeByte(17); //      { ['aes128-cts-hmac-sha1-96'] = 17 },
    try w.writeByte(@intFromEnum(Tag.integer));
    try w.writeByte(1);
    try w.writeByte(16); //      { ['des3-cbc-sha1'] = 16 },
    try w.writeByte(@intFromEnum(Tag.integer));
    try w.writeByte(1);
    try w.writeByte(23); //      { ['rc4-hmac'] = 23 },

    // Fixups
    const total_len: u32 = @intCast(fbs_write.getWritten().len);
    std.mem.writeInt(u32, buffer[0..4], total_len - 4, .big);
    std.mem.writeInt(u16, buffer[6..8], @intCast(total_len - 8), .big);
    std.mem.writeInt(u16, buffer[10..12], @intCast(total_len - 12), .big);
    std.mem.writeInt(u16, buffer[24..26], @intCast(total_len - 26), .big);
    std.mem.writeInt(u16, buffer[28..30], @intCast(total_len - 30), .big);

    return fbs_write.getWritten();
}
