@echo off

set CC=zig cc
set CFLAGS=-I../../bof-launcher/src -std=c99 -fno-sanitize=undefined -c

%CC% %CFLAGS% main.c

%CC% -o bof_launcher.exe ../../zig-out/lib/bof_launcher_win_x64.lib main.obj -lole32 -lws2_32
