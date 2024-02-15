///name: hostname
///description: "Show system host name"
///author: Z-Labs
///tags: ['host-recon']
///OS: linux
///header: ['inline', '']
///sources:
///    - https://raw.githubusercontent.com/The-Z-Labs/bof-launcher/main/bofs/src/coreutils/hostname.zig
///usage: '
/// hostname
///'
///examples: '
/// hostname
///'
const std = @import("std");
const beacon = @import("bof_api").beacon;
const posix = @import("bof_api").posix;

pub export fn go() callconv(.C) u8 {
    var name: [posix.HOST_NAME_MAX + 1]u8 = undefined;
    const namelen: usize = posix.HOST_NAME_MAX;

    const ret = posix.gethostname(@as([*:0]u8, @ptrCast(&name)), namelen);
    if (ret != 0)
        return 1;

    _ = beacon.printf(0, "%s\n", &name);

    return 0;
}
