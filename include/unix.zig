const std = @import("std");
const c = std.c;

// stdio prototypes:
pub extern fn puts([*:0]const u8) callconv(.C) i32;
pub extern fn printf([*:0]const u8, ...) callconv(.C) i32;

// time types:
// https://pubs.opengroup.org/onlinepubs/9699919799/basedefs/time.h.html
pub extern fn ctime(c.time_t) callconv(.C) [*:0]const u8;

// user accounting database definitions:
// https://pubs.opengroup.org/onlinepubs/9699919799/basedefs/utmpx.h.html
pub const utmpx = extern struct {
    ut_user: [*:0]const u8,
    ut_id: [*:0]const u8,
    ut_line: [*:0]const u8,
    ut_pid: c.pid_t,
    ut_type: i16,
    ut_tv: ?*c.timeval,
};

pub extern fn setutxent() callconv(.C) void;
pub extern fn getutxent() callconv(.C) *utmpx;
pub extern fn getutxid(*utmpx) callconv(.C) *utmpx;
pub extern fn endutxent() callconv(.C) void;
