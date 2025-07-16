const w32 = @import("bof_api").win32;
const beacon = @import("bof_api").beacon;

pub export fn go(_: ?[*]u8, _: i32) callconv(.c) u8 {
    var version_info: w32.OSVERSIONINFOW = undefined;
    version_info.dwOSVersionInfoSize = @sizeOf(@TypeOf(version_info));

    if (w32.RtlGetVersion.?(&version_info) != .SUCCESS)
        return 1;

    _ = beacon.printf.?(
        .output,
        "Windows version: %d.%d, OS build number: %d\n",
        version_info.dwMajorVersion,
        version_info.dwMinorVersion,
        version_info.dwBuildNumber,
    );
    return 0;
}
