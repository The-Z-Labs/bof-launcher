///name: whoami
///description: "Print current user"
///author: Z-Labs
///tags: ['windows', 'linux','TA0007','T1033', 'z-labs']
///category: "SAL-BOF"
///OS: cross-platform
///sources:
///    - 'https://raw.githubusercontent.com/The-Z-Labs/bof-launcher/main/bofs/src/whoami.zig'
///examples: '
/// whoami
///'
const std = @import("std");
const w32 = @import("bof_api").win32;
const beacon = @import("bof_api").beacon;
const posix = @import("bof_api").posix;

const BofErrors = enum(u8) {
    OpenProcessTokenFailed = 1,
    GetTokenInformationFailed,
    ConvertSidToStringSidAFailed,
    GetUserNameExAFailed,
    UnknownError,
};

fn getTokenInfo(allocator: std.mem.Allocator, token_type: w32.TOKEN_INFORMATION_CLASS) ![]u8 {
    var token: w32.HANDLE = undefined;
    if (w32.OpenProcessToken(w32.GetCurrentProcess(), w32.TOKEN_READ, &token) == 0) {
        _ = beacon.printf(.err, "[getTokenInfo:OpenProcessToken] ERROR : %s\n", @tagName(w32.GetLastError()).ptr);
        return error.OpenProcessTokenFailed;
    }
    defer _ = w32.CloseHandle(token);

    var length: w32.DWORD = 0;
    _ = w32.GetTokenInformation(token, token_type, null, 0, &length);
    if (w32.GetLastError() != .INSUFFICIENT_BUFFER) {
        _ = beacon.printf(.err, "[getTokenInfo:GetTokenInformation] ERROR : %s\n", @tagName(w32.GetLastError()).ptr);
        return error.GetTokenInformationFailed;
    }

    const token_buf = try allocator.alignedAlloc(u8, .of(w32.TOKEN_USER), length);
    errdefer allocator.free(token_buf);
    if (w32.GetTokenInformation(token, token_type, @ptrCast(token_buf.ptr), length, &length) == 0) {
        _ = beacon.printf(.err, "[getTokenInfo:GetTokenInformation] ERROR : %s\n", @tagName(w32.GetLastError()).ptr);
        return error.GetTokenInformationFailed;
    }

    return token_buf;
}

fn getUserInfo(allocator: std.mem.Allocator, user_token: w32.TOKEN_USER) !void {
    var sid_str: [*:0]u8 = undefined;
    if (w32.ConvertSidToStringSidA(user_token.User.Sid, &sid_str) == 0) {
        _ = beacon.printf(.err, "[getUserInfo:ConvertSidToStringSidA] ERROR : %s\n", @tagName(w32.GetLastError()).ptr);
        return error.ConvertSidToStringSidAFailed;
    }
    defer _ = w32.LocalFree(sid_str);

    var length: w32.ULONG = 0;
    _ = w32.GetUserNameExA(.NameSamCompatible, null, &length);
    if (w32.GetLastError() != .MORE_DATA) {
        _ = beacon.printf(.err, "[getUserInfo:GetUserNameExA] ERROR : %s\n", @tagName(w32.GetLastError()).ptr);
        return error.GetUserNameExAFailed;
    }

    const user_name = try allocator.allocSentinel(u8, length - 1, 0);
    defer allocator.free(user_name);
    if (w32.GetUserNameExA(.NameSamCompatible, user_name, &length) == 0) {
        _ = beacon.printf(.err, "[getUserInfo:GetUserNameExA] ERROR : %s\n", @tagName(w32.GetLastError()).ptr);
        return error.GetUserNameExAFailed;
    }

    _ = beacon.printf(.output, "%s : %s", user_name.ptr, sid_str);
}

pub export fn go(adata: ?[*]u8, alen: i32) callconv(.c) u8 {
    @import("bof_api").init(adata, alen, .{});

    const allocator = std.heap.page_allocator;

    if (@import("builtin").os.tag == .windows) {
        const token_buf = getTokenInfo(allocator, .TokenUser) catch |err| switch (err) {
            error.OpenProcessTokenFailed => return @intFromEnum(BofErrors.OpenProcessTokenFailed),
            error.GetTokenInformationFailed => return @intFromEnum(BofErrors.GetTokenInformationFailed),
            else => return @intFromEnum(BofErrors.UnknownError),
        };
        defer allocator.free(token_buf);

        getUserInfo(allocator, std.mem.bytesToValue(w32.TOKEN_USER, token_buf)) catch |err| switch (err) {
            error.ConvertSidToStringSidAFailed => return @intFromEnum(BofErrors.ConvertSidToStringSidAFailed),
            error.GetUserNameExAFailed => return @intFromEnum(BofErrors.GetUserNameExAFailed),
            else => return @intFromEnum(BofErrors.UnknownError),
        };
    } else {
        const euid = posix.geteuid();
        const pwd = posix.getpwuid(euid);
        if (pwd) |p| {
            _ = beacon.printf(.output, "%s", p.name);
        }
    }

    return 0;
}
