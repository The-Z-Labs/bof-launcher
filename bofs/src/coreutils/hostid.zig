///name: hostid
///description: "Print the numeric identifier for the current host"
///author: Z-Labs
///tags: ['linux','TA0007', 'T1016','z-labs']
///category: 'SAL-BOF'
///OS: Linux
///sources:
///    - 'https://raw.githubusercontent.com/The-Z-Labs/bof-launcher/main/bofs/src/coreutils/hostid.zig'
///examples: '
/// hostid
///'
const std = @import("std");
const beacon = @import("bof_api").beacon;
const posix = @import("bof_api").posix;

pub export fn go(adata: ?[*]u8, alen: i32) callconv(.c) u8 {
    @import("bof_api").init(adata, alen, .{});

    const id = posix.gethostid();
    _ = beacon.printf(.output, "%08x\n", id);

    return 0;
}
