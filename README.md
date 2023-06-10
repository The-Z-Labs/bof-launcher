# bof-launcher

## Introduction

[Cobalt Strike 4.1](https://www.cobaltstrike.com/blog/cobalt-strike-4-1-the-mark-of-injection/) released on 25 June 2020, introduced a novel (for that time) capability of running so called [Beacon Object Files](https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/topics/beacon-object-files_main.htm) - *small post-ex capabilities that execute in [Beacon](https://www.cobaltstrike.com/), parse arguments, call a few Win32 APIs, report output, and exit*. Since that time BOFs became very popular and the demand to launch/execute them in other environments than [Cobalt Strike's Beacon](https://www.cobaltstrike.com/) has appeared. 

## Purpose

We at [Z-Labs](https://z-labs.eu) saw a big potential in BOFs and decided to extend its capabilities, versatility and usefulness even further. That's how this project came to live.

[bof-launcher](https://github.com/The-Z-Labs/bof-launcher) is an open-source library for loading, relocating and launching BOFs on Windows and UNIX/Linux systems. It's an alternative to Trustedsec's [COFFLoader](https://github.com/trustedsec/COFFLoader) and [ELFLoader](https://github.com/trustedsec/ELFLoader) with some very interesting features:

- Fully compatibile with [Cobalt Strike's Beacon](https://www.cobaltstrike.com/). Can compile and run every BOF available at [Cobalt Strike Community Kit](https://cobalt-strike.github.io/community_kit/) and every other open-source BOF that adheres to [generic BOF template](https://github.com/Cobalt-Strike/bof_template).
- Distributed as a fully standalone library with zero dependency (it does not even use `libc`).
- Fully integrable with programs written in C/C++ and/or [Zig](https://ziglang.org/) progamming languages.
- Adds capability to write BOFs in [Zig programming language](https://ziglang.org/) - which is a low-level langauge with a goal of being a "better C". All the features of the language and rich standard library can be used in BOFs (hash maps and other data structures, cross-platform OS layer, http, networking, threading, crypto and more).
- Asynchronous BOF execution - additional capability to launch more time-consuming BOFs in a separate thread. 
- Seamless support for either Windows COFF format and UNIX/Linux ELF format.
- ARM 64/32 support (in development).

## Building

Being a zero-dependency, drop-in C/C++ compiler that supports cross-compilation out-of-the-box, [Zig](https://ziglang.org/) can be used to build this project. To do so [Zig's tarball (master)](https://ziglang.org/download/) needs to be downloaded and dropped in the directory of choice. After adding that directory to the `PATH` environment variable, buliding the whole project is as easy as running:

    zig build

Build artifacts will show up in `zig-out/bin` and `zig-out/lib` folders.

To build the project for a specific target use `-Dtarget` option, for example:

    zig build -Dtarget=x86-windows-gnu
    zig build -Dtarget=x86_64-linux-gnu

To build and run test BOFs do:

    zig build test

To ease the whole process even more, the [zigupdate.sh](utils/zigupdate.sh) script can be used for getting Zig and building bof-launcher on Linux machines:

```
wget https://raw.githubusercontent.com/The-Z-Labs/bof-launcher/main/utils/zigupdate.sh
chmod +x zigupdate.sh; ./zigupdate.sh
<update PATH>
git clone https://github.com/The-Z-Labs/bof-launcher
cd bof-launcher
zig build
zig test
```

## Example BOFs

Below you can see the same BOF written in Zig and in C. When compiled, Zig version weights 860 bytes, C version weights 916 bytes.

For an example of larger and cross-platform BOF please see our [UDP port scanner](bofs/src/cUDPscan.zig).

To run a BOF you can use our [cli-bof-launcher](examples/launch-from-cli), for example:

    .\zig-out\bin\example-cli-launcher_win_x64.exe .\zig-out\bin\wWinver.coff.x64.o
    .\zig-out\bin\example-cli-launcher_win_x64.exe .\zig-out\bin\cUDPscan.coff.x64.o 162.159.200.1-5:123,88

```zig
const w32 = @import("bofapi").win32;
const beacon = @import("bofapi").beacon;

pub export fn go(_: ?[*]u8, _: i32) callconv(.C) u8 {
    var version_info: w32.OSVERSIONINFOW = undefined;
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
```

```c
#include <windows.h>
#include "beacon.h"

WINBASEAPI NTSTATUS WINAPI NTDLL$RtlGetVersion(OSVERSIONINFOW* lpVersionInformation);

unsigned char go(unsigned char* arg_data, int arg_len) {
    OSVERSIONINFOW version_info;
    version_info.dwOSVersionInfoSize = sizeof(version_info);

    if (NTDLL$RtlGetVersion(&version_info) != 0)
        return 1;

    BeaconPrintf(
        0,
        "Windows version: %d.%d, OS build number: %d\n",
        version_info.dwMajorVersion,
        version_info.dwMinorVersion,
        version_info.dwBuildNumber
    );
    return 0;
}
```

## BOF launcher library

We provide an open-source and standalone library that can be used to execute any BOF build with this project, it exposes both [C API](include/bof.h) and [Zig API](include/bof.zig). Library parses COFF/ELF object data, does the relocations, loads all needed symbols and handles BOF output for you. See the API and tests for details.

## Example usage scenarios

### Run BOF from disk

*Rapid launching, testing and debugging BOFs*

[cli-bof-launcher](examples/launch-from-cli) - standalone command line program for running BOFs. Handy during testing/verifying 3rd BOFs or during developing/debugging BOFs. Does not require [Cobalt Strike's Beacon](https://www.cobaltstrike.com/) and its aggresor scripts to run.

### Sample C application

*Integrating bof-launcher in program written in C*

[integration-with-c](examples/integration-with-c) - simple example showing how to integrate bof-launcher in a application written in C/C++.
