const std = @import("std");
const os = std.os;
const c = std.c;
const mem = std.mem;
const beacon = @import("bofapi").beacon;
const posix = @import("bofapi").posix;

// https://man7.org/linux/man-pages/man3/getgrouplist.3.html
pub extern fn getgrouplist(user: [*:0]const u8, group: c.gid_t, groups: [*]c.gid_t, ngroups: *i32) callconv(.C) i32;

const NGROUPS_MAX = 32;

pub export fn go(args: ?[*]u8, args_len: i32) callconv(.C) u8 {
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
        beacon.dataParse(&parser, args, args_len);
        const name = beacon.dataExtract(&parser, null);

        if (name) |n| {
            pwd = posix.getpwnam(@as([*:0]u8, @ptrCast(n)));
            if (pwd) |p| {
                ruid = p.pw_uid;
                rgid = p.pw_gid;

                if (getgrouplist(p.pw_name.?, p.pw_gid, &groups_gids, &ngroups) == -1)
                    return 1;
            } else return 1;
        } else return 1;
    }

    if (ngroups != -1) {
        var i: usize = 0;
        while (i < ngroups) {
            const g = posix.getgrgid(groups_gids[i]);

            const name = mem.Allocator.dupeZ(allocator, u8, mem.sliceTo(g.?.gr_name, 0)) catch return 1;
            groups_names.append(name) catch return 1;
            i = i + 1;
        }
    }

    if (pwd == null) {
        return 1;
    }

    _ = beacon.printf(0, "uid=%d", ruid);
    if (pwd) |p|
        _ = beacon.printf(0, "(%s)", p.pw_name);

    _ = beacon.printf(0, " gid=%d", rgid);
    grp = posix.getgrgid(rgid);
    if (grp) |gr|
        _ = beacon.printf(0, "(%s)", gr.gr_name);

    if (args_len == 0) {
        if (euid != ruid) {
            _ = beacon.printf(0, " euid=%d", euid);
            pwd = posix.getpwuid(euid);
            if (pwd) |p| {
                _ = beacon.printf(0, "(%s)", p.pw_name);
            }
        }

        if (egid != rgid) {
            _ = beacon.printf(0, " egid=%d", egid);
            grp = posix.getgrgid(egid);
            if (grp) |g| {
                _ = beacon.printf(0, "(%s)", g.gr_name);
            }
        }
    }

    _ = beacon.printf(0, " groups=");

    var i: usize = 0;
    for (groups_names.items) |name| {
        _ = beacon.printf(0, "%d(%s)", groups_gids[i], name.ptr);

        if (i != groups_names.items.len - 1)
            _ = beacon.printf(0, ",");

        i = i + 1;
        allocator.free(name);
    }
    _ = beacon.printf(0, "\n");

    return 0;
}
