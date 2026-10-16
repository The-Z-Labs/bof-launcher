# Introduction

[Cobalt Strike 4.1](https://www.cobaltstrike.com/blog/cobalt-strike-4-1-the-mark-of-injection/) released on 25 June 2020, introduced a novel (for that time) capability of running so called [Beacon Object Files](https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/topics/beacon-object-files_main.htm) - *small post-ex capabilities that execute in [Beacon](https://www.cobaltstrike.com/), parse arguments, call a few Win32 APIs, report output, and exit*. Since that time BOFs became very popular and the demand to launch/execute them in other environments than [Cobalt Strike's Beacon](https://www.cobaltstrike.com/) has emerged.

We at [Z-Labs](https://z-labs.eu) saw a big potential in BOFs and decided to extend its capabilities, versatility and usefulness even further. That's how the following projects came to live.

The repository provides:

1. [bof-launcher](#bof-launcher-library) - programming library for BOFs in-memory management (loading, keeping track of loaded BOFs, execution, masking).
2. [z-beac0n](#z-beac0n) - a custom-written stage-1 (aka pre-C2) solution featuring bof-launcher. Engineered with a small footprint, stealth and modularity in mind.
3. [Z-Labs BOFs collection](#z-Labs-bofs-collection) - growing collection of OS-specific and cross-platform BOFs for usage during a red team engagements.
4. ['bof' command line tool](examples/cli4bofs) - a swiss army knife tool for running, injecting and organizing your BOFs collection.


See [here](ROADMAP.md) for project's roadmap.

See [here](#building-all-components) for building instructions.

# bof-launcher library

<p align="center">
  <img src="https://github.com/The-Z-Labs/bof-launcher/assets/4785347/990ad1fb-c35b-48cf-a0db-aed3c825d149" width="192" height="192" />
</p>

BOF launcher library is the engine behind the [z-beac0n](examples/implant) adversary simulation toolkit. 

It is a standalone programming library implemented in Zig and C that can be used to execute BOFs. On Windows it support x86 and x86_64 architectures, on Linux x86, x86_64, ARMv6+ and AArch64 architectures are supported. The library exposes either [C API](bof-launcher/src/bof_launcher_api.h) and [Zig API](bof-launcher/src/bof_launcher_api.zig).

Library features:

- Capable of running [BOFs](https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/topics/beacon-object-files_main.htm) that adhere to [Windows BOF template](https://github.com/Cobalt-Strike/bof_template) and [Linux BOF template](https://github.com/outflanknl/nix_bof_template).
- Fully integrable with programs written in C/C++/Zig/Go or Rust. See [examples](examples/) for sample integrations.
- Adds capability to write BOFs in [Zig programming language](https://ziglang.org/) - which is a low-level language with a goal of being a "better C".
- Access to [rich std library](https://ziglang.org/documentation/0.15.2/std/) during BOF development: lists, hash maps, cross-platform OS layer, http, networking, threading, crypto and compression.
- Capability to implement cross-platform BOFs (see: [udpScanner]((bofs/src/udpScanner.zig)), [tcpScanner]((bofs/src/tcpScanner.zig)), [grep]((bofs/src/grep.zig)) and various other BOFs).
- Provides modern sleepmasking functionality.
- Capability to run asynchronous or long-running BOFs in a separate thread.
- Pattern for launching more risky BOFs (i.e. privilege escalation exploits) inside of a sacrificial process.
- Seamless support for either Windows COFF and UNIX/Linux ELF formats.
- ARM and AARCH64 support on Linux.
- Flexible [API](bof-launcher/src/bof_launcher_api.h) allowing for BOF chaining (works like `Bash` pipes but purely in-memory) both on Linux and Windows.

# z-beac0n

Extremely modular and versatile pre-C2 implant for Windows and Linux.

![z-beac0n in action](https://github.com/The-Z-Labs/bof-launcher/blob/main/bin/ops.gif)

For details see here: [z-beac0n - Open Adversary Simulation Toolkit](https://github.com/The-Z-Labs/bof-launcher/tree/main/examples/implant)

## Liability

This is an open source project meant to be used with authorization to assess the security posture and for research purposes.

# Z-Labs BOFs collection

In addition to `bof-launcher` and `z-beac0n` projects, we maintain growing collection of our BOFs in this repository. Main differentiator of these BOFs is that they are implemented in `Zig` programming language. This, among other advantages like (modern language syntax, access to rich std library), brings the capability to implement truly cross-platform BOFs. 

We have two types of BOFs here:

1. Conventional BOFs that are fully compatible with original `Cobalt Strike` BOFs and can be run in other red teaming toolboxes as well. Specifically, [Sliver](https://github.com/BishopFox/sliver), [AdaptixC2](https://github.com/Adaptix-Framework/AdaptixC2) and [Meterpreter](https://docs.metasploit.com/docs/using-metasploit/advanced/meterpreter/meterpreter-executebof-command.html) were [tested](bofs/socat).<br>

| Category  | Description | BOFs list | Documentation |
| ---------------- | ----------- | --------- | ------------- |
| SAL-BOF | Local Situational Awareness BOFs | [lskmod](bofs/src/lskmod.zig), [hostname](bofs/src/coreutils/hostname.zig), [hostid](bofs/src/coreutils/hostid.zig), [id](bofs/src/coreutils/id.zig), [uname](bofs/src/coreutils/uname.zig),<br>[uptime](bofs/src/coreutils/uptime.zig), [who](bofs/src/coreutils/who.zig), [ifconfig](bofs/src/net-tools/ifconfig.zig), [whoami](bofs/src/whoami.zig), [whereami](bofs/src/whereami.zig), [winver](bofs/src/wWinver.zig) | [SAL-BOF reference](bofs/SAL-BOF.md) |
| FS-BOF | Filesystem interaction BOFs | [pwd](bofs/src/pwd.zig), [cd](bofs/src/cd.zig), [cat](bofs/src/cat.zig), [zcat](bofs/src/zcat.zig), [ls](bofs/src/ls.zig), [grep](bofs/src/grep.zig), [find](bofs/src/find.zig) | [FS-BOF reference](bofs/FS-BOF.md) |
| NET-BOF | Networking BOFs | [socat](bofs/socat/) | [NET-BOF reference](bofs/NET-BOF.md) |
| SAR-BOF | Remote Situational Awareness BOFs | [tcpScanner](bofs/src/tcpScanner.zig), [udpScanner](bofs/src/udpScanner.zig) | [SAR-BOF reference](bofs/SAR-BOF.md) |
| Elevation-BOF | Context elevation BOFs | [dirtypipe](bofs/src/dirtypipe.zig) | [Elevation-BOF reference](bofs/Elevation-BOF.md) |
| Injection-BOF | Process injection BOFs | [processInjectionSrdi](bofs/src/wProcessInjectionSrdi.zig) | [Injection-BOF reference](bofs/Injection-BOF.md) |


2. Special purposes BOFs, that serve specifically as a buliding blocks for our `z-beac0n` implant.<br>

| Category  | Description | BOFs list | Documentation |
| --------- | ----------- | --------- | ------------- |
| BOF0 | So called `BOF zero`. Those ones operate as standalone implants, managing and executing other loaded BOFs (both conventional and API-style) | [z-beac0n core](bofs/src/z-beac0n-core.zig) | [BOF0 reference](bofs/BOF0.md) |
| C2-BOF | Special purpose API-style BOFs providing alternative C2 communication channels | [C2channelHTTPS](bofs/src/C2channelHTTPS.zig) | [C2-BOF reference](bofs/C2-BOF.md) |
| API-BOF | Misc API-style BOFs | [kmodLoader](bofs/src/kmodLoader.zig) | [API-BOF reference](bofs/API-BOF.md) |

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
