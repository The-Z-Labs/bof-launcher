@echo off

set CC=zig cc
set CFLAGS=-I../../include -std=c99 -fno-sanitize=undefined -c

%CC% %CFLAGS% ../../bof-launcher/src/beacon/stb_sprintf.c
%CC% %CFLAGS% ../../bof-launcher/src/beacon/beacon_impl.c
%CC% %CFLAGS% main.c

zig build-obj -O ReleaseSmall -fstrip ../../bof-launcher/src/bof_launcher.zig --mod bofapi::../../include/bofapi.zig --deps bofapi

%CC% -o bof_launcher main.obj bof_launcher.obj beacon_impl.obj stb_sprintf.obj
