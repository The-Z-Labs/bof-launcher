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

// https://man7.org/linux/man-pages/man3/getgrouplist.3.html
pub extern fn getgrouplist(user: [*:0]const u8, group: c.gid_t, groups: [*]c.gid_t, ngroups: *i32) callconv(.C) i32;

const NGROUPS_MAX = 32;

pub export fn go(args: ?[*]u8, args_len: i32) callconv(.C) u8 {
    const printf = beacon.printf.?;

    var ruid: c.uid_t = undefined;
    var rgid: c.gid_t = undefined;
    var euid: c.gid_t = undefined;
    var egid: c.gid_t = undefined;
    var ngroups: i32 = NGROUPS_MAX;

    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var groups_gids: [NGROUPS_MAX]c.gid_t = undefined;
    var groups_names = std.ArrayList([]const u8).init(allocator);
    defer groups_names.deinit();

    var pwd: ?*c.passwd = null;
    var grp: ?*posix.group = null;

    // no username provided
    if (args_len == 0) {
        ruid = posix.getuid();
        rgid = posix.getgid();

        euid = posix.geteuid();
        egid = posix.getegid();

        pwd = posix.getpwuid(ruid);
        grp = posix.getgrgid(rgid);

        ngroups = posix.getgroups(NGROUPS_MAX, &groups_gids);
    } else {
        var parser = beacon.datap{};
        beacon.dataParse.?(&parser, args, args_len);
        const name = beacon.dataExtract.?(&parser, null);

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

    _ = printf(0, "uid=%d", ruid);
    if (pwd) |p|
        _ = printf(0, "(%s)", p.name);

    _ = printf(0, " gid=%d", rgid);
    grp = posix.getgrgid(rgid);
    if (grp) |gr|
        _ = printf(0, "(%s)", gr.gr_name);

    if (args_len == 0) {
        if (euid != ruid) {
            _ = printf(0, " euid=%d", euid);
            pwd = posix.getpwuid(euid);
            if (pwd) |p| {
                _ = printf(0, "(%s)", p.name);
            }
        }

        if (egid != rgid) {
            _ = printf(0, " egid=%d", egid);
            grp = posix.getgrgid(egid);
            if (grp) |g| {
                _ = printf(0, "(%s)", g.gr_name);
            }
        }
    }

    _ = printf(0, " groups=");

    var i: usize = 0;
    for (groups_names.items) |name| {
        _ = printf(0, "%d(%s)", groups_gids[i], name.ptr);

        if (i != groups_names.items.len - 1)
            _ = printf(0, ",");

        i = i + 1;
        allocator.free(name);
    }
    _ = printf(0, "\n");

    return 0;
}
