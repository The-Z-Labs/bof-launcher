const beacon = @import("bofapi").beacon;
const w32 = @import("bofapi").win32;

pub export fn go(_: ?[*]u8, _: i32) callconv(.C) u8 {
    var version_info: w32.RTL_OSVERSIONINFOW = undefined;
    version_info.dwOSVersionInfoSize = @sizeOf(@TypeOf(version_info));

    if (w32.RtlGetVersion(&version_info) != .SUCCESS)
        return 1;

    _ = beacon.printf(
        0,
        "Windows version: %d.%d, OS build number: %d\n",
        version_info.dwMajorVersion,
        version_info.dwMinorVersion,
        version_info.dwBuildNumber,
    );
    return 0;
}
