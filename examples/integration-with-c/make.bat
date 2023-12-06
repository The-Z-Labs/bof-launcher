@echo off

set CC=zig cc
set CFLAGS=-I../../include -I../../bof-launcher/src -std=c99 -fno-sanitize=undefined -c

%CC% %CFLAGS% ../../bof-launcher/src/beacon/stb_sprintf.c
%CC% %CFLAGS% ../../bof-launcher/src/beacon/beacon_impl.c
%CC% %CFLAGS% main.c

zig build-obj -O ReleaseSmall -fstrip ../../bof-launcher/src/bof_launcher.zig

%CC% -o bof_launcher.exe main.obj bof_launcher.obj beacon_impl.obj stb_sprintf.obj ole32.lib ws2_32.lib
