# z-beac0n implant

z-beac0n is a Linux in-memory software implant. It is composed of:

- [z-beac0n core BOF](../../bofs/src/z-beac0n-core.zig) (also known as `BOF0`)
- statically compiled [bof-launcher library](../../bof-launcher/src/bof_launcher_api.h)
- arbitrary number of additional BOFs launched and managed by the z-beac0n core BOF.

Execution flow:

1. During the implant's startup self-contained `z-beac0n core BOF` is started using bof-launcher's `bofRun()` function. The control is then transferred to BOF0's `go()` entrypoint function.
2. `z-beac0n core BOF` has full access to bof-launcher's API so it is capable of launching other BOFs based on the operator's needs and requirements. BOFs could be launched using one of available routines: `bofObjectRun`. `bofObjectRunAsyncThread`. `bofObjectRunAsyncProcess`.
3. C2 server is queried for additional commands.

z-beac0n implant is currently available as a stageless payload in following forms: `elf executable`, `shellcode`, `shared library (so)`.



