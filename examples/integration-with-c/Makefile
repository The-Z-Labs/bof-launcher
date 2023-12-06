CC=zig cc
CFLAGS=-I../../include -I../../bof-launcher/src -std=c99 -fno-sanitize=undefined -c

bof_launcher: main.o bof_launcher.o beacon_impl.o stb_sprintf.o
	$(CC) -o bof_launcher main.o bof_launcher.o beacon_impl.o stb_sprintf.o

main.o: main.c
	$(CC) $(CFLAGS) main.c

beacon_impl.o: ../../bof-launcher/src/beacon/beacon_impl.c
	$(CC) $(CFLAGS) ../../bof-launcher/src/beacon/beacon_impl.c

stb_sprintf.o: ../../bof-launcher/src/beacon/stb_sprintf.c
	$(CC) $(CFLAGS) ../../bof-launcher/src/beacon/stb_sprintf.c

bof_launcher.o:
	zig build-obj -O ReleaseSmall -fstrip ../../bof-launcher/src/bof_launcher.zig
