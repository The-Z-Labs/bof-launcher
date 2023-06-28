# baby-stager

## Description

Simple C2 solution that uses BOFs as its post-exploitation modules and communicates over HTTP with the C2 server.

## Usage

Configure backend (host and port) in `utils/serve_bofs.py` file:

```
if __name__ == '__main__':
    app.run(host='127.0.0.1',port=8000,debug=True)
```

Launch C2 server:

```
mkdir -p doc_root/bofs/
cp bof-launcher/utils/serve_bofs.py doc_root/

cp bof-launcher/zig-out/bin/uname.elf.x64.o doc_root/bofs/
cd doc_root/
python serve_bofs.py
```

Configuring and runnig the client:

```
$ head examples/baby-stager/src/main.zig 
const std = @import("std");
const assert = std.debug.assert;
const bof = @import("bofapi").bof;

const c2_host = "127.0.0.1:8000";
const c2_endpoint = "/endpoint";
const jitter = 3;

const stdout = std.io.getStdOut();

$ zig build

$ ./zig-out/bin/baby-stager_lin_x64
```

Tasking client to run `uname.elf.x64.o` BOF:

```
curl -H 'Content-Type: application/json' -d '{ "name" : "bof:uname", "header" : "inline:z" }' http://127.0.0.1:8000/tasking
```


