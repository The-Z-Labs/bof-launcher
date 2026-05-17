# Introduction

[Cobalt Strike 4.1](https://www.cobaltstrike.com/blog/cobalt-strike-4-1-the-mark-of-injection/) released on 25 June 2020, introduced a novel (for that time) capability of running so called [Beacon Object Files](https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/topics/beacon-object-files_main.htm) - *small post-ex capabilities that execute in [Beacon](https://www.cobaltstrike.com/), parse arguments, call a few Win32 APIs, report output, and exit*. Since that time BOFs became very popular and the demand to launch/execute them in other environments than [Cobalt Strike's Beacon](https://www.cobaltstrike.com/) has emerged.

This project provides:

1. [bof-launcher](#bof-launcher-library) - programming library for BOF management
2. [z-beac0n](#z-beac0n) - a custom-written stage-1 (pre-C2) solution engineered with small footprint, stealth and modularity in mind
3. [Z-Labs BOFs collection](#z-Labs-bofs-collection) - growing collection of OS-specific and cross-platform BOFs handy to use during red teaming

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
- Access to [rich std library](https://ziglang.org/documentation/0.15.2/std/) during BOF development: lists, hash maps, cross-platform OS layer, http, networking, threading, crypto and compression.
- Capability to implement cross-platform BOFs (see: [udpScanner]((bofs/src/udpScanner.zig)), [tcpScanner]((bofs/src/tcpScanner.zig)), [grep]((bofs/src/grep.zig)) and various other BOFs).
- Provides modern sleepmasking functionality.
- Capability to run asynchronous or long-running BOFs in a separate thread.
- Pattern for launching more risky BOFs (i.e. privilege escalation exploits) inside of a sacrificial process.
- Seamless support for either Windows COFF and UNIX/Linux ELF formats.
- ARM and AARCH64 support on Linux.
- Flexible [API](bof-launcher/src/bof_launcher_api.h) allowing for BOF chaining (works like `Bash` pipes but purely in-memory) either on Linux and Windows.

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

![z-beac0n in action](https://github.com/The-Z-Labs/bof-launcher/blob/main/bin/ops.gif)

For details see here: [z-beac0n - Open Adversary Simulation Toolkit](https://github.com/The-Z-Labs/bof-launcher/tree/main/examples/implant)

# Z-Labs BOFs collection

## Cross-platform BOFs

| BOF name  | Description | Supported platforms | Example
| ------------- | ---------------------------------------------------- | --------------------------- | ------------------ |
| [z-beac0n core](src/z-beac0n-core.zig) | So called BOF zero (BOF0), BOF that operates as standalone implant, manages other loaded BOFs; capable of executing other BOFs | `Linux x86/x86_64/ARMv6+/AArch64`; `Windows x86/x86_64` | `z-beac0n` |
| [tcpScanner](src/tcpScanner.zig)  | TCP connect() port scanner  | `Linux x86/x86_64/ARMv6+/AArch64`; `Windows x86/x86_64` | `tcpScanner 4.3.2.1-255:22,80` |
| [udpScanner](src/udpScanner.zig) | UDP port sweeper | `Linux x86/x86_64/ARMv6+/AArch64`; `Windows x86/x86_64` | `udpScanner 4.3.2.1-255:5000-5010` |
| [whoami](src/whoami.zig) | On Linux: print effective user name; On Windows: output the current UserName and domain | `Linux x86/x86_64/ARMv6+/AArch64`; `Windows x86/x86_64` | `whoami` |
| [pwd](src/pwd.zig) | print name of current/working directory | `Linux x86/x86_64/ARMv6+/AArch64`; `Windows x86/x86_64` | `pwd` |
| [cd](src/cd.zig) | change working directory | `Linux x86/x86_64/ARMv6+/AArch64`; `Windows x86/x86_64` | `cd /` |
| [cat](src/cat.zig) | print content of a file | `Linux x86/x86_64/ARMv6+/AArch64`; `Windows x86/x86_64` | `cat /etc/passwd` |
| [zcat](src/zcat.zig) | print content of a gzip compressed file | `Linux x86/x86_64/ARMv6+/AArch64`; `Windows x86/x86_64` | `cat /boot/config.gz` |
| [ls](src/ls.zig) | list directory content | `Linux x86/x86_64/ARMv6+/AArch64`; `Windows x86/x86_64` | `ls /etc` |
| [whereami](src/whereami.zig) | print hypervisor vendor signature from CPUID | `Linux x86/x86_64`; `Windows x86/x86_64` | `whereami` |
| [grep](src/grep.zig) | Print lines that match patterns | `Linux x86/x86_64/ARMv6+/AArch64`; `Windows x86/x86_64` | `grep root /etc/passwd` |
| [find](src/find.zig) | Search for files in a directory hierarchy | `Linux x86/x86_64/ARMv6+/AArch64`; `Windows x86/x86_64` | `find /dev -type b` |

## Linux-only BOFs

| BOF name  | Description | Supported platforms | Example
| ------------- | ---------------------------------------------------- | --------------------------- | ------------------ |
| [dirtypipe](src/dirtypipe.zig) | Exploit for 'dirtypipe' vulnerability (CVE-2022-0847) implemented as a BOF | `Linux x86/x86_64/ARMv6+/AArch64` | `dirtypipe /etc/shadow 913 "backdoor:xxx:10123::::::"` |
| [kmodLoader](src/kmodLoader.zig) | API-style BOF; load/unload kernel module directly from memory (root privileges required) | `Linux x86/x86_64/ARMv6+/AArch64` | see docs |
| [lskmod](src/lskmod.zig) | list currently loaded kernel modules | `Linux x86/x86_64/ARMv6+/AArch64` | `lskmod` |
| [hostname](src/coreutils/hostname.zig) | show the system's host name | `Linux x86/x86_64/ARMv6+/AArch64` | `hostname` |
| [hostid](src/coreutils/hostid.zig) | print the numeric identifier for the current host | `Linux x86/x86_64/ARMv6+/AArch64` | `hostid` |
| [id](src/coreutils/id.zig) | print real and effective user and group IDs | `Linux x86/x86_64/ARMv6+/AArch64` | `id www-data` |
| [uname](src/coreutils/uname.zig) | print system information | `Linux x86/x86_64/ARMv6+/AArch64` | `uname -a` |
| [uptime](src/coreutils/uptime.zig) | show how long the system has been running | `Linux x86/x86_64/ARMv6+/AArch64` | `uptime` |
| [who](src/coreutils/who.zig) | print currently logged in users | `Linux x86/x86_64/ARMv6+/AArch64` | `who` |
| [ifconfig](src/net-tools/ifconfig.zig) | Display the status of the currently active network interfaces. With root privileges: also manipulate current state of the device | `Linux x86/x86_64/ARMv6+/AArch64` | `ifconfig eth0 promisc` |

## Windows-only BOFs

| BOF name  | Description | Supported platforms | Example
| ------------- | ---------------------------------------------------- | --------------------------- | ------------------ |
| [winver](src/wWinver.zig) | show the edition, version, and system type of Windows operating system | `Windows x86/x86_64` | `winver` |
| [processInjectionSrdi](src/wProcessInjectionSrdi.zig) | This BOF can inject any other BOF to any running process | `Windows x86/x86_64` | `cli4bofs inject file:abs_path_to_bof -i:<pid>` |

# Building all components

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
