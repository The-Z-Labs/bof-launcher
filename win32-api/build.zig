const std = @import("std");

pub fn build(b: *std.Build) void {
    const options = b.addOptions();
    options.addOption(
        bool,
        "bof",
        b.option(bool, "bof", "Enable LIBNAME$ prefix for each function (KERNEL32$VirtualAlloc())") orelse false,
    );

    const module = b.addModule("bof_launcher_win32", .{
        .root_source_file = b.path("src/root.zig"),
    });
    module.addOptions("options", options);
}
