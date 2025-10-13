///name: id
///description: "Print user and group information for each specified USER, or (when USER omitted) for the current process"
///author: Z-Labs
///tags: ['linux','host-recon','z-labs']
///OS: linux
///sources:
///    - 'https://raw.githubusercontent.com/The-Z-Labs/bof-launcher/main/bofs/src/coreutils/id.zig'
///examples: '
/// id
/// id root
///'
///arguments:
///- name: user
///  desc: "Prints user and group information for this user"
///  type: string
///  required: false
const std = @import("std");
const os = std.posix;
const c = std.c;
const mem = std.mem;
const beacon = @import("bof_api").beacon;
const posix = @import("bof_api").posix;

comptime {
    @import("bof_api").embedFunctionCode("__udivdi3");
    @import("bof_api").embedFunctionCode("__ashldi3");
    @import("bof_api").embedFunctionCode("__aeabi_uldivmod");
    @import("bof_api").embedFunctionCode("__aeabi_uidiv");
    @import("bof_api").embedFunctionCode("__aeabi_llsl");
}

// https://man7.org/linux/man-pages/man3/getgrouplist.3.html
pub extern fn getgrouplist(user: [*:0]const u8, group: c.gid_t, groups: [*]c.gid_t, ngroups: *i32) callconv(.c) i32;

const NGROUPS_MAX = 32;

pub export fn go(adata: ?[*]u8, alen: i32) callconv(.c) u8 {
    @import("bof_api").init(adata, alen, .{});

    const printf = beacon.printf;

    var ruid: c.uid_t = undefined;
    var rgid: c.gid_t = undefined;
    var euid: c.gid_t = undefined;
    var egid: c.gid_t = undefined;
    var ngroups: i32 = NGROUPS_MAX;

    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var groups_gids: [NGROUPS_MAX]c.gid_t = undefined;
    var groups_names = std.array_list.Managed([]const u8).init(allocator);
    defer groups_names.deinit();

    var pwd: ?*c.passwd = null;
    var grp: ?*posix.group = null;

    // no username provided
    if (alen == 0) {
        ruid = posix.getuid();
        rgid = posix.getgid();

        euid = posix.geteuid();
        egid = posix.getegid();

        pwd = posix.getpwuid(ruid);
        grp = posix.getgrgid(rgid);

        ngroups = posix.getgroups(NGROUPS_MAX, &groups_gids);
    } else {
        var parser = beacon.datap{};
        beacon.dataParse(&parser, adata, alen);
        const name = beacon.dataExtract(&parser, null);

        if (name) |n| {
            pwd = posix.getpwnam(@as([*:0]u8, @ptrCast(n)));
            if (pwd) |p| {
                ruid = p.uid;
                rgid = p.gid;

                if (getgrouplist(p.name.?, p.gid, &groups_gids, &ngroups) == -1)
                    return 1;
            } else return 1;
        } else return 1;
    }

    if (ngroups != -1) {
        var i: usize = 0;
        while (i < ngroups) {
            const g = posix.getgrgid(groups_gids[i]);

            const name = allocator.dupe(u8, mem.sliceTo(g.?.gr_name, 0)) catch return 1;
            groups_names.append(name) catch return 1;
            i = i + 1;
        }
    }

    if (pwd == null) {
        return 1;
    }

    _ = printf(.output, "uid=%d", ruid);
    if (pwd) |p|
        _ = printf(.output, "(%s)", p.name);

    _ = printf(.output, " gid=%d", rgid);
    grp = posix.getgrgid(rgid);
    if (grp) |gr|
        _ = printf(.output, "(%s)", gr.gr_name);

    if (alen == 0) {
        if (euid != ruid) {
            _ = printf(.output, " euid=%d", euid);
            pwd = posix.getpwuid(euid);
            if (pwd) |p| {
                _ = printf(.output, "(%s)", p.name);
            }
        }

        if (egid != rgid) {
            _ = printf(.output, " egid=%d", egid);
            grp = posix.getgrgid(egid);
            if (grp) |g| {
                _ = printf(.output, "(%s)", g.gr_name);
            }
        }
    }

    _ = printf(.output, " groups=");

    var i: usize = 0;
    for (groups_names.items) |name| {
        _ = printf(.output, "%d(%s)", groups_gids[i], name.ptr);

        if (i != groups_names.items.len - 1)
            _ = printf(.output, ",");

        i = i + 1;
        allocator.free(name);
    }
    _ = printf(.output, "\n");

    return 0;
}
