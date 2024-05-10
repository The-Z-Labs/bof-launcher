# Z-Labs BOFs collection

## BOFs written and maintained by [Z-Labs](https://z-labs.eu/)

| BOF name  | Description | Supported platforms | Example invoation
| ------------- | ------------------------------ | ---------------------- | ------------------ |
| [tcpScanner](src/tcpScanner.zig)  | TCP connect() port scanner  | `Windows x86/x86_64`;`Linux x86/x86_64/ARMv6+/AArch64` | `tcpScanner 4.3.2.1-255:22,80,443,8080-8089` |

[tcpScanner](src/tcpScanner.zig) - TCP connect() port scanner

[udpScanner](src/udpScanner.zig) - UDP port sweeper implemented as a cross-platform `BOF`. Example invocation: `udpScanner 4.3.2.1-255:161,427,5000-5010`. [cross-platform]

[winver](src/wWinver.zig) - show the edition, version, and system type of Windows operating system. [windows-based]

[net-tools](src/net-tools/) - Implementation of chosen tools from [net-tools package](https://salsa.debian.org/debian/net-tools) as `BOFs`.

[whoami](src/wWhoami.zig) - display the domain and user name of the person who is currently logged on to this computer. [windows-based]


### GNU coreutils

*Implementation of chosen tools from [GNU coreutils](http://git.savannah.gnu.org/gitweb/?p=coreutils.git) as BOFs*

[hostname](src/coreutils/hostname.zig) - show the system's host name. [linux-based]

[hostid](src/coreutils/hostid.zig) - print the numeric identifier for the current host. [linux-based]

[id](src/coreutils/id.zig) - print real and effective user and group IDs. [linux-based]

[uname](src/coreutils/uname.zig) - print system information. [linux-based]

### Net-tools

*Implementation of chosen tools from [net-tools package](https://salsa.debian.org/debian/net-tools) as BOFs*

[ifconfig](src/net-tools/ifconfig.zig) - Display the status of the currently active network interfaces. Manipulate current state of the device. Invocation example `ifconfig eth0 promisc`. [linux-based]

## YAML documentation for chosen 3rd party BOFs
