#include <windows.h>
#include "beacon.h"

NTSYSAPI NTSTATUS NTAPI
#ifdef _DEBUG
RtlGetVersion
#else
ntdll$RtlGetVersion
#endif
(OSVERSIONINFOW* lpVersionInformation);

#ifndef _DEBUG
#define RtlGetVersion ntdll$RtlGetVersion
#endif

unsigned char go(unsigned char* arg_data, int arg_len) {
    OSVERSIONINFOW version_info;
    version_info.dwOSVersionInfoSize = sizeof(version_info);

    if (RtlGetVersion(&version_info) != 0)
        return 1;

    BeaconPrintf(
        0,
        "Windows version: %d.%d, OS build number: %d\n",
        version_info.dwMajorVersion,
        version_info.dwMinorVersion,
        version_info.dwBuildNumber
    );

#ifndef MY_DEFINE
    return 1;
#endif
    return 0;
}
