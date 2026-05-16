# Introduction

[Cobalt Strike 4.1](https://www.cobaltstrike.com/blog/cobalt-strike-4-1-the-mark-of-injection/) released on 25 June 2020, introduced a novel (for that time) capability of running so called [Beacon Object Files](https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/topics/beacon-object-files_main.htm) - *small post-ex capabilities that execute in [Beacon](https://www.cobaltstrike.com/), parse arguments, call a few Win32 APIs, report output, and exit*. Since that time BOFs became very popular and the demand to launch/execute them in other environments than [Cobalt Strike's Beacon](https://www.cobaltstrike.com/) has emerged.

This project provides:

1. [bof-launcher](#bof-launcher-library) - programming library for BOF management
2. [z-beacon](#z-beacon) - open adversary simulation toolkit
3. [Z-Labs BOFs collection](#z-Labs-bofs-collection) - 

# bof-launcher library

<p align="center">
  <img src="https://github.com/The-Z-Labs/bof-launcher/assets/4785347/990ad1fb-c35b-48cf-a0db-aed3c825d149" width="192" height="192" />
</p>

BOF launcher library is the engine behind the [z-beac0n](examples/implant) adversary simulation toolkit. 

It is a standalone programming library implemented in Zig and C that can be used to execute BOFs. On Windows it support x86 and x86_64 architectures, on Linux x86, x86_64, ARMv6+ and AArch64 architectures are supported. The library exposes either [C API](bof-launcher/src/bof_launcher_api.h) and [Zig API](bof-launcher/src/bof_launcher_api.zig).

Library features:

- Capable of running [BOFs](https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/topics/beacon-object-files_main.htm) that adhere to [Windows BOF template](https://github.com/Cobalt-Strike/bof_template) and [Linux BOF template](https://github.com/outflanknl/nix_bof_template).
- Fully integrable with programs written in C/C++/Zig/Go or Rust. See [examples](examples/) for sample integrations.
- Adds capability to write BOFs in [Zig programming language](https://ziglang.org/) - which is a low-level langauge with a goal of being a "better C".
- All the features of the language and rich standard library can be used in BOFs (hash maps and other data structures, cross-platform OS layer, http, networking, threading, crypto and more).
- Capability to implement cross-platform BOFs (see: [udpScanner]((bofs/src/udpScanner.zig)), [tcpScanner]((bofs/src/tcpScanner.zig)), [grep]((bofs/src/grep.zig)) and various other BOFs).
- Provides modern sleepmasking functionality.
- Capability to run asynchronous or long-running BOFs in a separate thread.
- Pattern for launching more risky BOFs (i.e. privilege escalation exploits) inside of a sacrificial process.
- Seamless support for either Windows COFF and UNIX/Linux ELF formats.
- ARM and AARCH64 support on Linux.
- Very flexible and efficient [API](bof-launcher/src/bof_launcher_api.h) allowing for so called BOF chaining.

bof-launcher C API:

```c
int bofLauncherInit(void);
void bofLauncherRelease(void);

int bofMemoryMaskKey(const unsigned char* key, int key_len);
int bofMemoryMaskWin32ApiCall(const char* win32_api_name, int masking_enabled);

int bofObjectInitFromMemory(const unsigned char* file_data_ptr, int file_data_len, BofObjectHandle* out_bof_handle);

void bofObjectRelease(BofObjectHandle bof_handle);
int bofObjectIsValid(BofObjectHandle bof_handle);

void* bofObjectGetProcAddress(BofObjectHandle bof_handle, const char* name);

int bofRun(const unsigned char* file_data_ptr, int file_data_len);
int bofObjectRun(BofObjectHandle bof_handle,
             unsigned char* arg_data_ptr,
             int arg_data_len,
             BofContext** out_context);
int bofObjectRunAsyncThread(BofObjectHandle bof_handle,
             unsigned char* arg_data_ptr,
             int arg_data_len,
             BofCompletionCallback completion_cb,
             void* completion_cb_context,
             BofContext** out_context);
int bofObjectRunAsyncProcess(BofObjectHandle bof_handle,
             unsigned char* arg_data_ptr,
             int arg_data_len,
             BofCompletionCallback completion_cb,
             void* completion_cb_context,
             BofContext** out_context);

void bofContextRelease(BofContext* context);
int bofContextIsRunning(BofContext* context);
void bofContextWait(BofContext* context);
unsigned char bofContextGetExitCode(BofContext* context);
const char* bofContextGetOutput(BofContext* context, int* out_output_len);
BofObjectHandle bofContextGetObjectHandle(BofContext* context);

int bofArgsInit(BofArgs** out_args);
int bofArgsInit(BofArgs** out_args);
void bofArgsRelease(BofArgs* args);
int bofArgsAdd(BofArgs* args, unsigned char* arg, int arg_len);
void bofArgsBegin(BofArgs* args);
void bofArgsEnd(BofArgs* args);
const char* bofArgsGetBuffer(BofArgs* args);
int bofArgsGetBufferSize(BofArgs* args);
```

# z-beac0n

For details see here: [z-beac0n - Open Adversary Simulation Toolkit](https://github.com/The-Z-Labs/bof-launcher/tree/main/examples/implant)

# Z-Labs BOFs collection

In an addition to the bof-launcher library itself, we provide [a collection of BOFs](bofs/) that we have authored. We plan to gradually extend this collection. We focus on developing BOFs in Zig language but it is perfectly okay to implement it in C and add it to the collection. To do so, just drop your BOF to `bofs/src` directory and add an entry for it in [bofs/build.zig](https://github.com/The-Z-Labs/bof-launcher/blob/main/bofs/build.zig) file, like that:

    .{ .name = "YOUR_BOF_NAME", .formats = &.{.elf, .coff}, .archs = &.{ .x64, .x86 } },
    
The build system will figure out the file extension and will build it (for all specified architectures) using proper compiler. This way you could also build any 3rd party BOF of choice.

Below you can see one of our BOFs in two versions: one written in Zig and the second one written in C. When compiled, Zig version weights 502 bytes, C version weights 562 bytes.

```zig
const w32 = @import("bof_api").win32;
const beacon = @import("bof_api").beacon;

pub export fn go(adata: ?[*]u8, alen: i32) callconv(.c) u8 {
    @import("bof_api").init(adata, alen, .{});

    var version_info: w32.OSVERSIONINFOW = undefined;
    version_info.dwOSVersionInfoSize = @sizeOf(@TypeOf(version_info));

    if (w32.RtlGetVersion(&version_info) != .SUCCESS)
        return 1;

    _ = beacon.printf(
        .output,
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
        CALLBACK_OUTPUT,
        "Windows version: %d.%d, OS build number: %d\n",
        version_info.dwMajorVersion,
        version_info.dwMinorVersion,
        version_info.dwBuildNumber
    );
    return 0;
}
```

# Building project with Zig 0.15.2

Being a zero-dependency, drop-in C/C++ compiler that supports cross-compilation out-of-the-box, [Zig](https://ziglang.org/) can be used to build this project. To do so [Zig's tarball (0.15.2)](https://ziglang.org/download/#release-0.15.2) needs to be downloaded and dropped in the directory of choice. After adding that directory to the `PATH` environment variable, buliding the whole project is as easy as running:

    zig build

Above command will build all included BOFs, example programs and bof-launcher library for all supported platforms.
To build BOFs as a debuggable, standalone executables run:

    zig build -Doptimize=Debug

Build artifacts will show up in `zig-out/bin` and `zig-out/lib` folders.

To build and run test BOFs do:

    zig build test

To run tests on foreign CPU architectures, you can use [QEMU](https://www.qemu.org/) which is nicely integrated in Zig:

    zig build test -fqemu --glibc-runtimes /usr
