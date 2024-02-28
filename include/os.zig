const builtin = @import("builtin");
const std = @import("std");
const os = std.os;
const socket_t = os.socket_t;
const SendToError = os.SendToError;
const windows = std.os.windows;
const system = std.os.system;
const errno = system.getErrno;
const unexpectedErrno = std.os.unexpectedErrno;
const RecvFromError = std.os.RecvFromError;
const w32 = @import("win32.zig");

pub const SOCK = os.SOCK;
pub const AF = os.AF;
pub const socket = os.socket;
pub const bind = os.bind;
pub const socklen_t = os.socklen_t;
pub const sockaddr = os.sockaddr;
pub const sa_family_t = os.sa_family_t;

pub fn closeSocket(sock: socket_t) void {
    if (builtin.os.tag == .windows) {
        _ = w32.closesocket(sock);
    } else {
        os.close(sock);
    }
}

pub fn sendto(
    /// The file descriptor of the sending socket.
    sockfd: socket_t,
    /// Message to send.
    buf: []const u8,
    flags: u32,
    dest_addr: ?*const sockaddr,
    addrlen: socklen_t,
) SendToError!usize {
    if (builtin.os.tag == .windows) {
        switch (windows.ws2_32.sendto(sockfd, buf.ptr, @as(i32, @intCast(buf.len)), @as(i32, @intCast(flags)), dest_addr.?, @as(i32, @intCast(addrlen)))) {
            windows.ws2_32.SOCKET_ERROR => switch (windows.ws2_32.WSAGetLastError()) {
                .WSAEACCES => return error.AccessDenied,
                .WSAEADDRNOTAVAIL => return error.AddressNotAvailable,
                .WSAECONNRESET => return error.ConnectionResetByPeer,
                .WSAEMSGSIZE => return error.MessageTooBig,
                .WSAENOBUFS => return error.SystemResources,
                .WSAENOTSOCK => return error.FileDescriptorNotASocket,
                .WSAEAFNOSUPPORT => return error.AddressFamilyNotSupported,
                .WSAEDESTADDRREQ => unreachable, // A destination address is required.
                .WSAEFAULT => unreachable, // The lpBuffers, lpTo, lpOverlapped, lpNumberOfBytesSent, or lpCompletionRoutine parameters are not part of the user address space, or the lpTo parameter is too small.
                .WSAEHOSTUNREACH => return error.NetworkUnreachable,
                // TODO: WSAEINPROGRESS, WSAEINTR
                .WSAEINVAL => unreachable,
                .WSAENETDOWN => return error.NetworkSubsystemFailed,
                .WSAENETRESET => return error.ConnectionResetByPeer,
                .WSAENETUNREACH => return error.NetworkUnreachable,
                .WSAENOTCONN => return error.SocketNotConnected,
                .WSAESHUTDOWN => unreachable, // The socket has been shut down; it is not possible to WSASendTo on a socket after shutdown has been invoked with how set to SD_SEND or SD_BOTH.
                .WSAEWOULDBLOCK => return error.WouldBlock,
                .WSANOTINITIALISED => unreachable, // A successful WSAStartup call must occur before using this function.
                else => |err| return windows.unexpectedWSAError(err),
            },
            else => |rc| return @as(usize, @intCast(rc)),
        }
    }
    while (true) {
        const rc = system.sendto(sockfd, buf.ptr, buf.len, flags, dest_addr, addrlen);
        switch (errno(rc)) {
            .SUCCESS => return @as(usize, @intCast(rc)),

            .ACCES => return error.AccessDenied,
            .AGAIN => return error.WouldBlock,
            .ALREADY => return error.FastOpenAlreadyInProgress,
            .BADF => unreachable, // always a race condition
            .CONNRESET => return error.ConnectionResetByPeer,
            .DESTADDRREQ => unreachable, // The socket is not connection-mode, and no peer address is set.
            .FAULT => unreachable, // An invalid user space address was specified for an argument.
            .INTR => continue,
            .INVAL => return error.UnreachableAddress,
            .ISCONN => unreachable, // connection-mode socket was connected already but a recipient was specified
            .MSGSIZE => return error.MessageTooBig,
            .NOBUFS => return error.SystemResources,
            .NOMEM => return error.SystemResources,
            .NOTSOCK => unreachable, // The file descriptor sockfd does not refer to a socket.
            .OPNOTSUPP => unreachable, // Some bit in the flags argument is inappropriate for the socket type.
            .PIPE => return error.BrokenPipe,
            .AFNOSUPPORT => return error.AddressFamilyNotSupported,
            .LOOP => return error.SymLinkLoop,
            .NAMETOOLONG => return error.NameTooLong,
            .NOENT => return error.FileNotFound,
            .NOTDIR => return error.NotDir,
            .HOSTUNREACH => return error.NetworkUnreachable,
            .NETUNREACH => return error.NetworkUnreachable,
            .NOTCONN => return error.SocketNotConnected,
            .NETDOWN => return error.NetworkSubsystemFailed,
            else => |err| return unexpectedErrno(err),
        }
    }
}

pub fn recvfrom(
    sockfd: socket_t,
    buf: []u8,
    flags: u32,
    src_addr: ?*sockaddr,
    addrlen: ?*socklen_t,
) RecvFromError!usize {
    if (builtin.os.tag == .windows) {
        switch (windows.ws2_32.recvfrom(sockfd, buf.ptr, @as(i32, @intCast(buf.len)), @as(i32, @intCast(flags)), src_addr, @as(?*i32, @ptrCast(addrlen)))) {
            windows.ws2_32.SOCKET_ERROR => switch (windows.ws2_32.WSAGetLastError()) {
                .WSANOTINITIALISED => unreachable,
                .WSAECONNRESET => return error.ConnectionResetByPeer,
                .WSAEINVAL => return error.SocketNotBound,
                .WSAEMSGSIZE => return error.MessageTooBig,
                .WSAENETDOWN => return error.NetworkSubsystemFailed,
                .WSAENOTCONN => return error.SocketNotConnected,
                .WSAEWOULDBLOCK => return error.WouldBlock,
                // TODO: handle more errors
                else => |err| return windows.unexpectedWSAError(err),
            },
            else => |rc| return @as(usize, @intCast(rc)),
        }
    }
    while (true) {
        const rc = system.recvfrom(sockfd, buf.ptr, buf.len, flags, src_addr, addrlen);
        switch (errno(rc)) {
            .SUCCESS => return @as(usize, @intCast(rc)),
            .BADF => unreachable, // always a race condition
            .FAULT => unreachable,
            .INVAL => unreachable,
            .NOTCONN => return error.SocketNotConnected,
            .NOTSOCK => unreachable,
            .INTR => continue,
            .AGAIN => return error.WouldBlock,
            .NOMEM => return error.SystemResources,
            .CONNREFUSED => return error.ConnectionRefused,
            .CONNRESET => return error.ConnectionResetByPeer,
            else => |err| return unexpectedErrno(err),
        }
    }
}
