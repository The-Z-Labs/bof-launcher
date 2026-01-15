# z-beac0n - Open Adversary Simulation Toolkit

We follow DIY (do-it-yourself) philosophy when preparing C2 solution for a given mission objectives (i.e. professional adversary simulation engagement). Therefore we provide an open and flexible architectural solution together with reusable building blocks that can be quickly tailored to a given scenario.

## Implant

z-beac0n implant is an example of software implant written with bof-launcher library, conceptually it looks like this:

![z-beac0n-arch](https://github.com/user-attachments/assets/da2a7b68-a246-4a01-bcf1-f051caf702cc)

It is composed of:

- [z-beac0n core BOF](../../bofs/src/z-beac0n-core.zig) (so called `BOF0`, i.e. initally executed BOF), it will take control over the implant and will manage its whole life-cycle (processing operator's commands, downloading additional BOFs, executing BOFs, uploading BOF's output to the operator, etc.);
- statically compiled [bof-launcher library](../../bof-launcher/src/bof_launcher_api.h);
- arbitrary number of additional BOFs launched and managed by the z-beac0n core BOF.

## Backend components

On the server side following components are available:

- [stage-listener.py](src/stage-listener.py) - HTTP(S)-based payload serving listener compatible with ["meterpreter protocol"](https://github.com/rsmudge/metasploit-loader); 
- [stager.py](src/stager.py) - Python-based staging script that fetches over HTTP(S) a payload and execute it in-memory in the context of Python's interpreter process;
- [C2-https.py] - Command and control server for handling implant's beaconing.

## Execution flow

1. During the implant's startup self-contained `z-beac0n core BOF` is started using bof-launcher's `bofRun()` function. The control is then transferred to BOF0's `go()` entrypoint function.
2. `z-beac0n core BOF` has full access to bof-launcher's API so it is capable of launching other BOFs based on the operator's needs and requirements. BOFs could be launched using one of available routines: `bofObjectRun`. `bofObjectRunAsyncThread`. `bofObjectRunAsyncProcess`.
3. C2 server is queried for additional commands.

z-beac0n implant is currently available as a stageless payload in following forms: `elf executable`, `shellcode` and `shared library (so)`.



