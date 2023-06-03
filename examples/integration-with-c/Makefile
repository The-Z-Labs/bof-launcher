CC=zig cc
CFLAGS=-I../../include -std=c99 -fno-sanitize=undefined -c

bof_launcher: main.o bof_launcher.o bofapi.o stb_sprintf.o
	$(CC) -o bof_launcher main.o bof_launcher.o bofapi.o stb_sprintf.o

main.o: main.c
	$(CC) $(CFLAGS) main.c

bofapi.o: ../../bof-launcher/src/bofapi/bofapi.c
	$(CC) $(CFLAGS) ../../bof-launcher/src/bofapi/bofapi.c

stb_sprintf.o: ../../bof-launcher/src/bofapi/stb_sprintf.c
	$(CC) $(CFLAGS) ../../bof-launcher/src/bofapi/stb_sprintf.c

bof_launcher.o:
	zig build-obj -O ReleaseSmall ../../bof-launcher/src/bof_launcher.zig
