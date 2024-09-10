CC=zig cc
CFLAGS=-std=c99 -fno-sanitize=undefined -c -I../../bof-launcher/src
ARCH := $(shell uname -m)

bof_launcher: main.o
        ifeq ($(ARCH),x86_64)
	$(CC) -o bof_launcher main.o ../../zig-out/lib/libbof_launcher_lin_x64.a
        else
	$(CC) -o bof_launcher main.o ../../zig-out/lib/libbof_launcher_lin_x86.a
        endif

main.o: main.c
	$(CC) $(CFLAGS) main.c

clean:
	-rm *.o bof_launcher
