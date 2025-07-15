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

pub export fn go() callconv(.C) u8 {
    _ = beacon.printf.?(0, "USER\tTTY\tLOGIN@\tIDLE\tJCPU\tPCPU\tWHAT\n");
    _ = posix.setutxent();

    var ut_entry = posix.getutxent();
    while (ut_entry) |ut| {
        if ((ut.ut_type == posix.USER_PROCESS) and ((ut.ut_user[0]) != 0)) {
            _ = beacon.printf.?(0, "%s\t%s\n", &ut.ut_user, &ut.ut_line);
        }

        ut_entry = posix.getutxent();
    }
    _ = posix.endutxent();

    return 0;
}
