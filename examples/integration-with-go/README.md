
## Using bof-launcher in Go application

An example of simple `Go` application for executing provided BOF from a command line.

To build and run the tool prepare the following directory structure (`bof_launcher_api.h` and `libbof_launcher_lin_x64.a` are taken directly from bof-launcher):

```
bofsFromGo/
├── cgo.go
├── lib
│   ├── bof_launcher_api.h
│   └── libbof_launcher_lin_x64.a
└── uname.elf.x64.o
```

then build it:

```
go build -o bofsFromGo ./cgo.go
```

running it:

```
./bofsFromGo uname.elf.x64.o
```
