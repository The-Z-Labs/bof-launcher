# Beacon Object File (BOF) launcher

<p align="center">
  <img src="https://github.com/The-Z-Labs/bof-launcher/assets/4785347/990ad1fb-c35b-48cf-a0db-aed3c825d149" width="192" height="192" />
</p>

Z-Labs blog:
* [Write, debug and execute BOFs with bof-launcher (part 1)](https://blog.z-labs.eu/2024/12/02/write-debug-and-execute-bofs-part1.html)
* [Running BOFs with 'bof-launcher' library](https://blog.z-labs.eu/2024/02/08/bof-launcher.html)
* [Executing Cobalt Strike's BOFs on ARM-based Linux devices](https://blog.z-labs.eu/2024/05/10/bofs-on-arm-based-devices.html)

## Introduction

[Cobalt Strike 4.1](https://www.cobaltstrike.com/blog/cobalt-strike-4-1-the-mark-of-injection/) released on 25 June 2020, introduced a novel (for that time) capability of running so called [Beacon Object Files](https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/topics/beacon-object-files_main.htm) - *small post-ex capabilities that execute in [Beacon](https://www.cobaltstrike.com/), parse arguments, call a few Win32 APIs, report output, and exit*. Since that time BOFs became very popular and the demand to launch/execute them in other environments than [Cobalt Strike's Beacon](https://www.cobaltstrike.com/) has emerged.

## Purpose

We at [Z-Labs](https://z-labs.eu) saw a big potential in BOFs and decided to extend its capabilities, versatility and usefulness even further. That's how this project came to live.

[bof-launcher](bof-launcher/src/bof_launcher_api.h) is an open-source library written from scratch for loading and launching BOFs on Windows and UNIX/Linux systems. It's an alternative to Trustedsec's [COFFLoader](https://github.com/trustedsec/COFFLoader) and [ELFLoader](https://github.com/trustedsec/ELFLoader) with many additional features and clean [C API](bof-launcher/src/bof_launcher_api.h):

- Fully compatibile with [Cobalt Strike's Beacon](https://www.cobaltstrike.com/). Can compile and run every BOF available at [Cobalt Strike Community Kit](https://cobalt-strike.github.io/community_kit/) and every other open-source BOF that adheres to [generic BOF template](https://github.com/Cobalt-Strike/bof_template).
- Distributed as a fully standalone library with zero dependency (it does not even use `libc`).
- Fully integrable with programs written in C/C++ and/or [Zig](https://ziglang.org/) progamming languages.
- Adds capability to write BOFs in [Zig programming language](https://ziglang.org/) - which is a low-level langauge with a goal of being a "better C". All the features of the language and rich standard library can be used in BOFs (hash maps and other data structures, cross-platform OS layer, http, networking, threading, crypto and more).
- Capability to run asynchronous or long-running BOFs in a separate thread.
- Pattern for launching more risky BOFs (i.e. privilege escalation exploits) inside of a sacrificial process.
- Seamless support for either Windows COFF and UNIX/Linux ELF formats.
- ARM and AARCH64 support on Linux.
- Used in our [cli4bofs tool](https://github.com/The-Z-Labs/cli4bofs) that allows for running BOF files directly from a filesystem.
- Very flexible and efficient [API](bof-launcher/src/bof_launcher_api.h) allowing for so called BOF chaining.

## BOF launcher library

We provide open-source, standalone library that can be used to execute any BOF. On Windows we support x86 and x86_64 architectures, on Linux we support x86, x86_64, ARMv6+ and AArch64 architectures. Our library exposes both [C API](bof-launcher/src/bof_launcher_api.h) and [Zig API](bof-launcher/src/bof_launcher_api.zig). It parses COFF/ELF object data, does the relocations, loads all needed symbols and handles BOF output for you. See the API and tests for details.

Basic C API usage:
```c
// Load object file (COFF or ELF) and get a handle to it
BofObjectHandle bof_handle;
if (bofObjectInitFromMemory(obj_file_data, obj_file_data_size, &bof_handle) < 0) {
    // handle the error
}

// Execute
BofContext* context = NULL;
if (bofObjectRun(bof_handle, NULL, 0, &context) < 0) {
    // handle the error
}

// Get output
const char* output = bofContextGetOutput(context, NULL);
if (output) {
    // handle BOF output
}

bofContextRelease(context);
```

## Building project with Zig 0.13.0

Being a zero-dependency, drop-in C/C++ compiler that supports cross-compilation out-of-the-box, [Zig](https://ziglang.org/) can be used to build this project. To do so [Zig's tarball (0.13.0)](https://ziglang.org/download/#release-0.13.0) needs to be downloaded and dropped in the directory of choice. After adding that directory to the `PATH` environment variable, buliding the whole project is as easy as running:

    zig build

Above command will build all included BOFs, example programs and bof-launcher library for all supported platforms.
To build BOFs as a debuggable, standalone executables run:

    zig build -Doptimize=Debug

Build artifacts will show up in `zig-out/bin` and `zig-out/lib` folders.

To build and run test BOFs do:

    zig build test

To run tests on foreign CPU architectures, you can use [QEMU](https://www.qemu.org/) which is nicely integrated in Zig:

    zig build test -fqemu --glibc-runtimes /usr

## Z-Labs BOFs collection

In an addition to the bof-launcher library itself, we provide [a collection of BOFs](bofs/) that we have authored. We plan to gradually extend this collection. We focus on developing BOFs in Zig language but it is perfectly okay to implement it in C and add it to the collection. To do so, just drop your BOF to `bofs/src` directory and add an entry for it in [bofs/build.zig](https://github.com/The-Z-Labs/bof-launcher/blob/main/bofs/build.zig) file, like that:

    .{ .name = "YOUR_BOF_NAME", .formats = &.{.elf, .coff}, .archs = &.{ .x64, .x86 } },
    
The build system will figure out the file extension and will build it (for all specified architectures) using proper compiler. This way you could also build any 3rd party BOF of choice.

Below you can see one of our BOFs in two versions: one written in Zig and the second one written in C. When compiled, Zig version weights **only 574 bytes**, C version weights 923 bytes.

For an example of larger and cross-platform BOF please refer to our [UDP port sweeper](bofs/src/udpScanner.zig) or [TCP port scanner](bofs/src/tcpScanner.zig).

```zig
const w32 = @import("bof_api").win32;
const beacon = @import("bof_api").beacon;

extern fn @"ntdll$RtlGetVersion"(
    lpVersionInformation: *w32.RTL_OSVERSIONINFOW,
) callconv(w32.WINAPI) w32.NTSTATUS;

const RtlGetVersion = @"ntdll$RtlGetVersion";

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
```
```c
#include <windows.h>
#include "beacon.h"

NTSYSAPI NTSTATUS NTAPI NTDLL$RtlGetVersion(OSVERSIONINFOW* lpVersionInformation);

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

## Running BOFs from a filesystem

Often during the developemnt/debugging, testing or just playing with a new piece of BOF code it is convenient to run it directly from a filesystem. For that purpose we created [cli4bofs](https://github.com/The-Z-Labs/cli4bofs) tool. After downloading and building it you can run every BOF out there. Below, an example of running [our BOFs](bofs/src) is shown:

    cli4bofs.exe exec .\zig-out\bin\wWinver.coff.x64.o
    cli4bofs.exe exec .\zig-out\bin\udpScanner.coff.x64.o str:162.159.200.1-5:123,88

## Documenting your BOFs

We have also introduced a way for documenting BOFs with a simple yaml syntax within BOF's source code file. To document a BOF one can prefix each line containing the documentation with `///` at the top of BOF's source code file. By defualt during building the library with `zig build`, documentation from each BOF file will be concatenated to one common file `BOF-collection.yaml`. This file is ready to be used by our [cli4bofs tool](https://github.com/The-Z-Labs/cli4bofs). The yaml syntax for BOF documenting is shown below. An example of a BOF with complete documentation can be seen [here](https://github.com/The-Z-Labs/bof-launcher/blob/main/bofs/src/udpScanner.zig) and [here](https://github.com/The-Z-Labs/bof-launcher/blob/main/bofs/src/kmodLoader.zig) (for an example of BOF that exports API).

```
name: BOFname
description: string:"short description of a BOF"
author: BOFauthor 
tags: list of tags 
OS: string:linux|windows|cross
sources: list of URLs
entrypoint: optional:"go" 
api: optional:list of signatures of exported functions
examples: string:"usage examples of a BOF"
- arguments:
  - name: string:argName
    desc: string:"short description of an argument"
    type: string:"short|integer|string|stringW"
    required: bool
    api: optional:string:"api function name"
- errors:
  - name: errorName
    code: int
    message: string:"short description of the error"
```

## Example usage scenarios

### Minimal Windows-based C application that uses bof-launcher

*bof-launcher's "Hello world" program*

[bof-minimal_win_x64](https://github.com/The-Z-Labs/bof-minimal_win_x64) - if you're new to `bof-launcher`, be sure to check out this repo and read this [blog post](https://blog.z-labs.eu/2024/02/08/bof-launcher.html).

### Running BOFs from disk

*Rapid launching, prototyping and testing BOFs*

[cli4bofs](https://github.com/The-Z-Labs/cli4bofs) - standalone command line program for running BOFs directly from a filesystem. Handy also during testing/verifying 3rd BOFs or during developing BOFs. Does not require [Cobalt Strike's Beacon](https://www.cobaltstrike.com/) and its aggresor scripts to run.

### Examples of using bof-launcher in C

*Integrating bof-launcher in program written in C*

[integration-with-c](examples/integration-with-c) - simple example showing how to integrate bof-launcher in a application written in C/C++.

### Simple C2 solution with BOF execution capabilities

*Implementing custom, cross-platform C2 solutions capable of running BOFs*

[BOF-stager](examples/BOF-stager) - example of simple, cross-platform C2 implant that uses BOFs as its post-exploitation modules and communicates over HTTP with the C2 server.
