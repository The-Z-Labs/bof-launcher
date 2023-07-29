# cli4bofs 

Command line interface for BOFs.

## Description

Universal tool that allows to execute any BOF from filesystem and pass arguments to it. Handy for testing, prototyping and developing BOFs.

## Usage

```
Usage: ./zig-out/bin/cli4bofs_lin_x64 <BOF> [[prefix:]ARGUMENT]...

Execute given BOF from filesystem with provided ARGUMENTs.

ARGUMENTS:

ARGUMENT's data type can be specified using one of following prefix:
	short OR s	 - 16-bit signed integer.
	int OR i	 - 32-bit signed integer.
	str OR z	 - zero-terminated characters string.
	wstr OR Z	 - zer-terminated wide characters string.
	file OR b	 - special type followed by file path indicating that a pointer to a buffer filled with content of the file will be passed to BOF.

If prefix is ommited then ARGUMENT is treated as a zero-terminated characters string (str / z).

EXAMPLES:

cli4bofs uname -a
cli4bofs udpScanner 192.168.2.2-10:427
cli4bofs udpScanner z:192.168.2.2-10:427
cli4bofs udpScanner 192.168.2.2-10:427 file:/path/to/file/with/udpPayloads
```
