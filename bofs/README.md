# Z-Labs BOFs collection

## BOFs written and maintained by [Z-Labs](https://z-labs.eu/)

| BOF name  | Description | Supported platforms | Example
| ------------- | ---------------------------------------------------- | --------------------------- | ------------------ |
| [tcpScanner](src/tcpScanner.zig)  | TCP connect() port scanner  | `Linux x86/x86_64/ARMv6+/AArch64`; `Windows x86/x86_64` | `tcpScanner 4.3.2.1-255:22,80` |
| [udpScanner](src/udpScanner.zig) | UDP port sweeper | `Linux x86/x86_64/ARMv6+/AArch64`; `Windows x86/x86_64` | `udpScanner 4.3.2.1-255:5000-5010` |
| [winver](src/wWinver.zig) | show the edition, version, and system type of Windows operating system | `Windows x86/x86_64` | `winver` |
| [whoami](src/wWhoami.zig) | display the domain and user name of the person who is currently logged on to this computer | `Windows x86/x86_64` | `whoami` |


### GNU coreutils

*Implementation of chosen tools from [GNU coreutils](http://git.savannah.gnu.org/gitweb/?p=coreutils.git) as BOFs*

| BOF name  | Description | Supported platforms | Example
| ------------- | ---------------------------------------------------- | --------------------------- | ------------------ |
| [hostname](src/coreutils/hostname.zig) | show the system's host name | `Linux x86/x86_64/ARMv6+/AArch64` | `hostname` |
| [hostid](src/coreutils/hostid.zig) | print the numeric identifier for the current host | `Linux x86/x86_64/ARMv6+/AArch64` | `hostid` |
| [id](src/coreutils/id.zig) | print real and effective user and group IDs | `Linux x86/x86_64/ARMv6+/AArch64` | `id www-data` |
| [uname](src/coreutils/uname.zig) | print system information | `Linux x86/x86_64/ARMv6+/AArch64` | `uname -a` |

### Net-tools

*Implementation of chosen tools from [net-tools package](https://salsa.debian.org/debian/net-tools) as BOFs*

| BOF name  | Description | Supported platforms | Example
| ------------- | ---------------------------------------------------- | --------------------------- | ------------------ |
| [ifconfig](src/net-tools/ifconfig.zig) | Display the status of the currently active network interfaces. Manipulate current state of the device | `Linux x86/x86_64/ARMv6+/AArch64` | `ifconfig eth0 promisc` |

## Documentation for selected 3rd party BOFs

| BOF name  | Description | Supported platforms | Example | BOF usage | Author |
| ------------- | ---------------------------------------------------- | --------------------------- | ------------------- | ------------ | ----------- |
| [cat](https://raw.githubusercontent.com/trustedsec/ELFLoader/main/SA/src/cat.c) | Concatenate file to stdout | `Linux x86/x86_64/ARMv6+/AArch64` | `cat /etc/passwd` | [metadata](https://github.com/The-Z-Labs/bof-launcher/blob/main/BOFs-3rdparty-doc.yaml#L1) | [Trustedsec](https://github.com/trustedsec/ELFLoader)
