const std = @import("std");
const beacon = @import("bof_api").beacon;
const posix = @import("bof_api").posix;

// BOF-specific error codes
const BofErrors = enum(u8) {
    AccessDenied = 0x1,
    AntivirusInterference,
    FileNotFound,
    FileBusy,
    UnknownError,
};

pub export fn go(adata: ?[*]u8, alen: i32) callconv(.c) u8 {
    @import("bof_api").init(adata, alen, .{});

    _ = beacon.printf(.output, "USER\tTTY\tLOGIN@\tIDLE\tJCPU\tPCPU\tWHAT\n");
    _ = posix.setutxent();

    var ut_entry = posix.getutxent();
    while (ut_entry) |ut| {
        if ((ut.ut_type == posix.USER_PROCESS) and ((ut.ut_user[0]) != 0)) {
            _ = beacon.printf(.output, "%s\t%s\n", &ut.ut_user, &ut.ut_line);
        }

        ut_entry = posix.getutxent();
    }
    _ = posix.endutxent();

    return 0;
}
