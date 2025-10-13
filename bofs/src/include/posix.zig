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
const native_os = @import("builtin").os.tag;
const windows = std.os.windows;

const cast = std.math.cast;

//
// POSIX time types:
// https://pubs.opengroup.org/onlinepubs/9699919799/basedefs/time.h.html
//
pub extern fn ctime(c.time_t) callconv(.c) [*:0]const u8;

//
// POSIX user accounting database definitions:
// https://pubs.opengroup.org/onlinepubs/9699919799/basedefs/utmpx.h.html
// glibc: /usr/include/bits/utmpx.h
//
pub const utmpx = extern struct {
    ut_type: i16,
    ut_pid: c.pid_t,
    ut_line: [32]u8,
    ut_id: [4]u8,
    ut_user: [32]u8,
    ut_host: [256]u8,
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

pub extern fn setutxent() callconv(.c) void;
pub extern fn getutxent() callconv(.c) ?*utmpx;
pub extern fn getutxid(*utmpx) callconv(.c) *utmpx;
pub extern fn endutxent() callconv(.c) void;

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
pub extern fn gethostid() callconv(.c) c_long;

// https://pubs.opengroup.org/onlinepubs/9699919799/functions/gethostname.html
pub const HOST_NAME_MAX = 64;
pub extern fn gethostname(name: [*:0]u8, namelen: usize) callconv(.c) i32;

// https://pubs.opengroup.org/onlinepubs/9699919799/functions/getuid.html
pub extern fn getuid() callconv(.c) c.uid_t;
// https://pubs.opengroup.org/onlinepubs/9699919799/functions/geteuid.html
pub extern fn geteuid() callconv(.c) c.uid_t;
// https://pubs.opengroup.org/onlinepubs/9699919799/functions/getgid.html
pub extern fn getgid() callconv(.c) c.gid_t;
// https://pubs.opengroup.org/onlinepubs/9699919799/functions/getegid.html
pub extern fn getegid() callconv(.c) c.gid_t;
// https://pubs.opengroup.org/onlinepubs/9699919799/functions/getgrgid.html
pub extern fn getgrgid(c.gid_t) callconv(.c) ?*group;
// https://pubs.opengroup.org/onlinepubs/9699919799/functions/getgroups.html
pub extern fn getgroups(gidsetsize: i32, grouplist: [*]c.gid_t) callconv(.c) i32;
// https://pubs.opengroup.org/onlinepubs/9699919799/functions/getpwuid.html
pub extern fn getpwuid(uid: c.uid_t) callconv(.c) ?*c.passwd;
// https://pubs.opengroup.org/onlinepubs/9699919799/functions/getpwnam.html
pub extern fn getpwnam(name: [*:0]u8) callconv(.c) ?*c.passwd;

// TODO: Remove this and use std.posix.recvfrom() once fixed (current version requires libc).
pub fn recvfrom(
    sockfd: std.posix.socket_t,
    buf: []u8,
    flags: u32,
    src_addr: ?*std.posix.sockaddr,
    addrlen: ?*std.posix.socklen_t,
) std.posix.RecvFromError!usize {
    if (native_os == .windows) {
        const rc = windows.recvfrom(sockfd, buf.ptr, buf.len, flags, src_addr, addrlen);
        if (rc == windows.ws2_32.SOCKET_ERROR) {
            switch (windows.ws2_32.WSAGetLastError()) {
                .WSANOTINITIALISED => unreachable,
                .WSAECONNRESET => return error.ConnectionResetByPeer,
                .WSAEINVAL => return error.SocketNotBound,
                .WSAEMSGSIZE => return error.MessageTooBig,
                .WSAENETDOWN => return error.NetworkSubsystemFailed,
                .WSAENOTCONN => return error.SocketNotConnected,
                .WSAEWOULDBLOCK => return error.WouldBlock,
                .WSAETIMEDOUT => return error.ConnectionTimedOut,
                // TODO: handle more errors
                else => |err| return windows.unexpectedWSAError(err),
            }
        } else {
            return @intCast(rc);
        }
    }
    return std.posix.recvfrom(sockfd, buf, flags, src_addr, addrlen);
}

// TODO: Remove this and use std.posix.getsockoptError() once fixed (current version requires libc on Windows!).
pub fn getsockoptError(sockfd: std.posix.fd_t) std.posix.ConnectError!void {
    if (native_os == .windows) {
        var err_code: i32 = undefined;
        var size: i32 = @sizeOf(i32);
        const rc = windows.ws2_32.getsockopt(@ptrCast(sockfd), std.posix.SOL.SOCKET, std.posix.SO.ERROR, @ptrCast(&err_code), &size);
        if (rc == windows.ws2_32.SOCKET_ERROR) {
            switch (windows.ws2_32.WSAGetLastError()) {
                .WSANOTINITIALISED => unreachable,
                .WSAEFAULT => unreachable,
                .WSAENETDOWN => return error.NetworkUnreachable,
                .WSAEINVAL => return error.Unexpected,
                .WSAEINPROGRESS => unreachable,
                .WSAENOPROTOOPT => unreachable,
                .WSAENOTSOCK => return error.SystemResources,
                else => return error.Unexpected,
            }
        } else {
            switch (@as(windows.ws2_32.WinsockError, @enumFromInt(err_code))) {
                windows.ws2_32.WinsockError.WSAECONNREFUSED => return error.ConnectionRefused,
                else => return error.Unexpected,
            }
        }
    }
    return std.posix.getsockoptError(sockfd);
}

// TODO: Remove this and use std.posix.poll() once fixed (current version requires libc on Windows!).
pub fn poll(fds: []std.posix.pollfd, timeout: i32) std.posix.PollError!usize {
    if (native_os == .windows) {
        while (true) {
            const fds_count = cast(std.posix.nfds_t, fds.len) orelse return error.SystemResources;
            const rc = windows.poll(fds.ptr, fds_count, timeout);
            if (rc == windows.ws2_32.SOCKET_ERROR) {
                switch (windows.ws2_32.WSAGetLastError()) {
                    .WSAENETDOWN => return error.NetworkSubsystemFailed,
                    .WSAEFAULT => unreachable,
                    .WSAEINVAL => unreachable,
                    .WSAENOBUFS => unreachable,
                    else => return error.Unexpected,
                }
            } else {
                return @intCast(rc);
            }
        }
    }
    return std.posix.poll(fds, timeout);
}
