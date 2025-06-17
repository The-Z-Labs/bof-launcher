# Z-Labs BOFs collection

### Cross-platform BOFs

| BOF name  | Description | Supported platforms | Example
| ------------- | ---------------------------------------------------- | --------------------------- | ------------------ |
| [tcpScanner](src/tcpScanner.zig)  | TCP connect() port scanner  | `Linux x86/x86_64/ARMv6+/AArch64`; `Windows x86/x86_64` | `tcpScanner 4.3.2.1-255:22,80` |
| [udpScanner](src/udpScanner.zig) | UDP port sweeper | `Linux x86/x86_64/ARMv6+/AArch64`; `Windows x86/x86_64` | `udpScanner 4.3.2.1-255:5000-5010` |
| [z-beac0n core](src/z-beac0n-core.zig) | So called BOF zero (BOF0). An example of a BOF that can operate as standalone implant | `Linux x86/x86_64/ARMv6+/AArch64`; `Windows x86/x86_64` | `z-beac0n` |

### GNU coreutils

*Implementation of chosen tools from [GNU coreutils](http://git.savannah.gnu.org/gitweb/?p=coreutils.git) as BOFs*

| BOF name  | Description | Supported platforms | Example
| ------------- | ---------------------------------------------------- | --------------------------- | ------------------ |
| [hostname](src/coreutils/hostname.zig) | show the system's host name | `Linux x86/x86_64/ARMv6+/AArch64` | `hostname` |
| [hostid](src/coreutils/hostid.zig) | print the numeric identifier for the current host | `Linux x86/x86_64/ARMv6+/AArch64` | `hostid` |
| [id](src/coreutils/id.zig) | print real and effective user and group IDs | `Linux x86/x86_64/ARMv6+/AArch64` | `id www-data` |
| [uname](src/coreutils/uname.zig) | print system information | `Linux x86/x86_64/ARMv6+/AArch64` | `uname -a` |
| [whoami](src/whoami.zig) | On Linux: print effective user name; On Windows: output the current UserName and domain | `Linux x86/x86_64/ARMv6+/AArch64`; `Windows x86/x86_64` | `whoami` |

### Net-tools

*Implementation of chosen tools from [net-tools package](https://salsa.debian.org/debian/net-tools) as BOFs*

| BOF name  | Description | Supported platforms | Example
| ------------- | ---------------------------------------------------- | --------------------------- | ------------------ |
| [ifconfig](src/net-tools/ifconfig.zig) | Display the status of the currently active network interfaces. With root privileges: also manipulate current state of the device | `Linux x86/x86_64/ARMv6+/AArch64` | `ifconfig eth0 promisc` |

### Linux-only BOFs

| BOF name  | Description | Supported platforms | Example
| ------------- | ---------------------------------------------------- | --------------------------- | ------------------ |
| [kmodLoader](src/kmodLoader.zig) | API-style BOF; load/unload kernel module directly from memory (root privileges required) | `Linux x86/x86_64/ARMv6+/AArch64` | see docs |
| [lskmod](src/lskmod.zig) | list currently loaded kernel modules | `Linux x86/x86_64/ARMv6+/AArch64` | `lskmod` |

### Windows-only BOFs

| BOF name  | Description | Supported platforms | Example
| ------------- | ---------------------------------------------------- | --------------------------- | ------------------ |
| [winver](src/wWinver.zig) | show the edition, version, and system type of Windows operating system | `Windows x86/x86_64` | `winver` |
