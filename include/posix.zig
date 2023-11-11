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
// group structure definition
// https://pubs.opengroup.org/onlinepubs/9699919799/basedefs/grp.h.html
//
pub const group = extern struct {
    gr_name: [*:0]const u8,
    gr_gid: c.gid_t,
    gr_mem: [*][*:0]const u8,
};

//
// password structure definitions
// https://pubs.opengroup.org/onlinepubs/9699919799/basedefs/pwd.h.html
// TODO
//pub const passwd = extern struct {
//    pw_name: [*:0]const u8,
//    pw_uid: c.uid_t,
//    pw_gid: c.gid_t,
//    pw_dir: [*:0]const u8,
//    pw_shell: [*:0]const u8,
//};

//
// standard symbolic constants and types in POSIX:
// https://pubs.opengroup.org/onlinepubs/9699919799/basedefs/unistd.h.html
//

// https://pubs.opengroup.org/onlinepubs/9699919799/functions/gethostid.html
pub extern fn gethostid() callconv(.C) c_long;

// https://pubs.opengroup.org/onlinepubs/9699919799/functions/gethostname.html
pub const HOST_NAME_MAX = 64;
pub extern fn gethostname(name: [*:0]u8, namelen: usize) callconv(.C) i32;

// https://pubs.opengroup.org/onlinepubs/9699919799/functions/getuid.html
pub extern fn getuid() callconv(.C) c.uid_t;
// https://pubs.opengroup.org/onlinepubs/9699919799/functions/geteuid.html
pub extern fn geteuid() callconv(.C) c.uid_t;
// https://pubs.opengroup.org/onlinepubs/9699919799/functions/getgid.html
pub extern fn getgid() callconv(.C) c.gid_t;
// https://pubs.opengroup.org/onlinepubs/9699919799/functions/getegid.html
pub extern fn getegid() callconv(.C) c.gid_t;
// https://pubs.opengroup.org/onlinepubs/9699919799/functions/getgrgid.html
pub extern fn getgrgid(c.gid_t) callconv(.C) ?*group;
// https://pubs.opengroup.org/onlinepubs/9699919799/functions/getgroups.html
pub extern fn getgroups(gidsetsize: i32, grouplist: []c.gid_t) callconv(.C) i32;
// https://pubs.opengroup.org/onlinepubs/9699919799/functions/getpwuid.html
pub extern fn getpwuid(uid: c.uid_t) callconv(.C) ?*c.passwd;
