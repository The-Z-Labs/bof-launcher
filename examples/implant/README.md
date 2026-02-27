# z-beac0n - Open Adversary Simulation Toolkit

We follow DIY (do-it-yourself) philosophy when preparing C2 solution for a given mission objectives (i.e. professional adversary simulation engagements). Therefore we provide an open and flexible architectural solution together with reusable building blocks that can be quickly tailored to a given scenario.

The building blocks of the toolkit:

- [Architecture](#architecture)
- [z-beac0n implant](#implant)
- [backend components](#backend-components)
- [bof-launcher library](#bof-launcher-library)
- [Z-Labs BOFs collection](https://github.com/The-Z-Labs/bof-launcher/tree/main/bofs)
- [cli4bofs tool](#cli4bofs-tool)
- [Deployment](#deployment)

## Architecture

## Implant

z-beac0n implant is an example of software implant written with bof-launcher library, conceptually it looks like this:

![z-beac0n-arch](https://github.com/user-attachments/assets/da2a7b68-a246-4a01-bcf1-f051caf702cc)

It is composed of:

- [z-beac0n core BOF](../../bofs/src/z-beac0n-core.zig) (so called `BOF0`, i.e. initally executed BOF), it will take control over the implant and will manage its whole life-cycle (processing operator's commands, fetching additional BOFs, executing BOFs, uploading BOF's output to the operator, etc.);
- statically compiled [bof-launcher library](../../bof-launcher/src/bof_launcher_api.h);
- so called API-style BOF providing C2 communication protocol implementation. Thanks to implementing it as a BOF switching communication protocol implementation is possible during run-time (i.e. an implant is capable of fetching a BOF that provides alternative C2 communication implementation and re-attach it to "speak" with C2 server via other protocol!).
- arbitrary number of additional BOFs launched and managed by the z-beac0n core BOF.

Execution flow:

1. During the implant's startup self-contained `z-beac0n core BOF` is started using bof-launcher's `bofRun()` function. The control is then transferred to BOF0's `go()` entrypoint function.
2. `z-beac0n core BOF` has full access to bof-launcher's API so it is capable of launching other BOFs based on the operator's needs and requirements. BOFs could be launched using one of available routines: `bofObjectRun`. `bofObjectRunAsyncThread`. `bofObjectRunAsyncProcess`.
3. C2 server is queried for additional commands.

z-beac0n implant is currently available as a stageless payload in following forms: `elf executable`, `shellcode` and `shared library (so)`.

Example [stager.py](src/stager.py) script is available as a staging script that fetches over HTTP(S) an ELF executable payload and launches it in-memory in the context of Python's interpreter process;

## Backend components

On the server side following components are available:

- [stage-listener.py](src/stage-listener.py) - HTTP(S)-based payload serving listener compatible with ["meterpreter protocol"](https://github.com/rsmudge/metasploit-loader); 
- [serve_bofs.py](https://github.com/The-Z-Labs/bof-launcher/blob/main/utils/serve_bofs.py) - Command and control server for handling implant's beaconing.

## bof-launcher library

Of course working horse of z-beac0n implant is bof-launcher library it exposes following, well thought and efficient interface/API:

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

## cli4bofs tool

[cli4bofs](https://github.com/The-Z-Labs/cli4bofs) (i.e. command line interface for running BOFs) is a swiss army knife tool for running and mainataining collection of BOFs files. Allows for running any BOF from a filesystem and for conveniently passing arguments to it. Defines simple YAML schema for essential information about BOF files, like: description, URL(s) of the source code, supported arguments, usage examples, etc. Handy also for testing, prototyping and developing your own BOFs.

An example of complete YAML file for one of the BOFs:

```
name: cat
description: "Print content of a file"
author: Z-Labs
tags: ['windows', 'linux','host-recon','z-labs']
OS: cross
sources:
    - 'https://raw.githubusercontent.com/The-Z-Labs/bof-launcher/main/bofs/src/cat.zig'
examples: '
 cat /etc/passwd
 cat C:\Windows\System32\drivers\etc\hosts
'
arguments:
- name: file_path
  desc: "path to the file to be printed"
  type: string
  required: true
errors:
- name: AccessDenied
  code: 0x1
  message: "Failed to open provided file"
- name: FileNotFound
  code: 0x2
  message: "File not found"
- name: AntivirusInterference
  code: 0x3
  message: "Possible Antivirus Interference while opening the file"
- name: FileNotProvided
  code: 0x4
  message: "No file provided"
- name: StreamTooLong
  code: 0x5
  message: "File is very large"
- name: UnknownError
  code: 0x6
  message: "Unknown error"
```

## Deployment





