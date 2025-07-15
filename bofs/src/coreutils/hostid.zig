///name: hostid
///description: "Print the numeric identifier for the current host"
///author: Z-Labs
///tags: ['linux','host-recon','z-labs']
///OS: linux
///sources:
///    - 'https://raw.githubusercontent.com/The-Z-Labs/bof-launcher/main/bofs/src/coreutils/hostid.zig'
///examples: '
/// hostid
///'
const std = @import("std");
const beacon = @import("bof_api").beacon;
const posix = @import("bof_api").posix;

pub export fn go() callconv(.C) u8 {
    const id = posix.gethostid();
    _ = beacon.printf.?(0, "%08x\n", id);

    return 0;
}
