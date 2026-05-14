# z-beac0n - Open Adversary Simulation Toolkit

We follow DIY (do-it-yourself) philosophy when preparing C2 solution for a given mission objectives (i.e. professional adversary simulation engagements). Therefore we provide an open and flexible architectural solution together with reusable building blocks that can be quickly tailored to a given scenario.

- [Architecture](#architecture)
- [Deployment](#deployment)

The building blocks of the toolkit:

- [z-beac0n implant](#implant-internals)
- [backend components](#backend-components)
- [bof-launcher library](#bof-launcher-library)
- [Z-Labs BOFs collection](https://github.com/The-Z-Labs/bof-launcher/tree/main/bofs)
- [cli4bofs tool](#cli4bofs-tool)

## Architecture

<img width="699" height="273" alt="image" src="https://github.com/user-attachments/assets/441d23d5-15fc-4845-8bd3-f6b7fbfc59f5" />

For a description of implant's components depicted on the diagram see below: 

**BOF zero (BOF0)** - heart of z-beac0n implant, it has access to bof-launcher API so it is capable of launching other BOFs. BOF0 is executed right after implant's launch. It will take control over the implant and will manage its whole life-cycle (processing operator's commands, fetching additional BOFs, executing BOFs, uploading BOF's output to the operator, etc.);

**C2 Channel: API-style BOF** - initial implementation of the communication protocol with the C2 server. This essential BOF provides implementation of the following functions: `netInit`, `netConnect`, `netDisconnect`, `netExchange`, `netMasquerade`, and `netUnmasquerade` which are used by the implant to call home (i.e. C2 server) and obfuscate/mask generated network traffic. Notably an operator can provide alternative implementation of this BOF and re-attach it (during implant's runtime!) to cause the implant to "speak" with the C2 server in different language (i.e. using different communication protocol and/or modify traffic obfuscation/masking algorithm). Of course C2 server needs to act accordingly and prepare for "language" change.

**bof-launcher** - software component providing BOF management, BOF launching and BOF masking (in-memory evasion features) capabilities.

**additional in-memory BOFs** - arbitrary number of additional BOFs launched and managed by the BOF0. These BOFs could be launched using one of available routines: `bofObjectRun`, `bofObjectRunAsyncThread`, `bofObjectRunAsyncProcess` and could be short-lived (run and unload) or long-lived (run and stay in memory).

## Deployment

To run z-beac0n implant on o local machine for the testing/experimenting purposes, follow the steps below: 

1. Build all components

```
~/bof-launcher$ zig build
```

2. Prepare C2 server

Copy BOFs that will be served by the C2 server, you should put here binaries of every supported architecture. I copy our publicly available BOFs, you can add yours:

```
~/bof-launcher$ cd examples/implant
cp -r ../../zig-out/bin/bofs/ ./
```

It's time to launch the server (by default it will listen at `127.0.0.1:8000`):

    ~/bof-launcher/examples/implant$ python z-beac0n-C2.py

The server exposes two endpoints:

- `/tasking` - meant to be used by the operator to issue new tasks for the implant (`POST` request) and for retrieving output from completed tasks (`GET` request);
- `/heartbeat` - meant to be used by the implant to query for a new tasks (`GET` request) and to send back tasks' output (`POST` request);

Now, run the console. It will use those endpoints to contrl the implant:

    ~/bof-launcher/examples/implant$ python z-beac0n-console.py

You should see following hackish logo :) and the prompt:

```

             bb                             00000          
zzzzz        bb        eee    aa aa   cccc 00   00 nn nnn  
  zz  _____  bbbbbb  ee   e  aa aaa cc     00   00 nnn  nn 
 zz          bb   bb eeeee  aa  aaa cc     00   00 nn   nn 
zzzzz        bbbbbb   eeeee  aaa aa  ccccc  00000  nn   nn 
                                                           

z-beac0n>
```

3. Run z-beac0n implant

By default z-beac0n is being built for Linux:

 - as shellcode: `zig-out/bin/z-beac0n_lin_x64.bin`
 - as ELF executable: `zig-out/bin/z-beac0n_lin_x64.elf`
 - as shared library: `zig-out/lib/libz-beac0n_lin_x64.so`

For Windows:

 - as shellcode: `zig-out/bin/z-beac0n_win_{x86,x64}.bin`
 - as PE executable: `zig-out/bin/z-beac0n_win_{x86,x64}.exe`

In simplest case (for testing purposes) running the implant is a matter of executing the binary:

    ~/bof-launcher$ ./zig-out/bin/z-beac0n_lin_x64.elf

Verify the beaconing from the implant in the console:

```

             bb                             00000          
zzzzz        bb        eee    aa aa   cccc 00   00 nn nnn  
  zz  _____  bbbbbb  ee   e  aa aaa cc     00   00 nnn  nn 
 zz          bb   bb eeeee  aa  aaa cc     00   00 nn   nn 
zzzzz        bbbbbb   eeeee  aaa aa  ccccc  00000  nn   nn 
                                                           

z-beac0n> implant ls
Implant ID      First seen at         Last seen at       Implant identity string
================================================================================
Wxepb5bA     2026-05-14 17:40:16   2026-05-14 17:40:28   x86_64:linux:Wxepb5bA  

z-beac0n>
```

## Implant internals

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
- [z-beac0n-C2.py](z-beac0n-C2.py) - Command and control server for handling implant's beaconing.
- [z-beac0n-console.py](z-beac0n-console.py) - Operator's console.
- [icli.py](icli.py) - Console's dependency.
- [BOF-all.yaml](BOF-all.yaml) - BOFs' manuals.

## bof-launcher library

Of course working horse of z-beac0n implant is bof-launcher library. It exposes following, well thought and efficient interface/API:

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
