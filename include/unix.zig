//! This file is meant to provide POSIX API to BOFs
//! Rules for adding new functions here:
//! * do not add any printing/formating functions use
//! `include/beacon.zig` instead
//! * make sure that the function isn't already in zig `std.os`
//! * make sure that the function isn't already in zig `std.c`
//! * if glibc implements a function you want to add
//! then add its zig prototype here
//! * if glibc implementation doesn't exist (rare case)
//! or is buggy, consider adding your own implementation

const std = @import("std");
const os = std.os;
const c = std.c;

//
// POSIX time types:
// https://pubs.opengroup.org/onlinepubs/9699919799/basedefs/time.h.html
//
pub extern fn ctime(c.time_t) callconv(.C) [*:0]const u8;

pub extern fn puts(str: [*:0]const u8) c_int;

//
// POSIX user accounting database definitions:
// https://pubs.opengroup.org/onlinepubs/9699919799/basedefs/utmpx.h.html
// glibc: /usr/include/bits/utmpx.h
//
pub const utmpx = extern struct {
    ut_type: i16,
    ut_pid: c.pid_t,
    ut_line: [*:0]const u8,
    ut_id: [*:0]const u8,
    ut_user: [*:0]const u8,
    ut_host: [*:0]const u8,
    ut_exit_termination: i16,
    ut_exit_exit: i16,
    ut_session: i32,
    ut_tv: ?*c.timeval,
};

// Values for the `ut_type' field of a `struct utmpx'.
pub const EMPTY = 0;
pub const RUN_LVL = 1;
pub const BOOT_TIME = 2;
pub const NEW_TIME = 3;
pub const OLD_TIME = 4;
pub const INIT_PROCESS = 5;
pub const LOGIN_PROCESS = 6;
pub const USER_PROCESS = 7;
pub const DEAD_PROCESS = 8;
pub const ACCOUNTING = 9;

pub extern fn setutxent() callconv(.C) void;
pub extern fn getutxent() callconv(.C) ?*utmpx;
pub extern fn getutxid(*utmpx) callconv(.C) *utmpx;
pub extern fn endutxent() callconv(.C) void;

//
// standard symbolic constants and types in POSIX:
// https://pubs.opengroup.org/onlinepubs/9699919799/basedefs/unistd.h.html
//

// https://pubs.opengroup.org/onlinepubs/9699919799/functions/gethostid.html
pub extern fn gethostid() callconv(.C) c_long;
