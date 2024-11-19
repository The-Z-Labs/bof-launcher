const w32 = @import("bof_api").win32;
const beacon = @import("bof_api").beacon;

extern fn @"ntdll$RtlGetVersion"(
    lpVersionInformation: *w32.RTL_OSVERSIONINFOW,
) callconv(w32.WINAPI) w32.NTSTATUS;

const RtlGetVersion = if (@import("builtin").mode == .Debug)
    w32.RtlGetVersion
else
    @"ntdll$RtlGetVersion";

pub export fn go(_: ?[*]u8, _: i32) callconv(.C) u8 {
    var version_info: w32.OSVERSIONINFOW = undefined;
    version_info.dwOSVersionInfoSize = @sizeOf(@TypeOf(version_info));

    if (RtlGetVersion(&version_info) != .SUCCESS)
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
