package main

/*

#cgo CFLAGS: -I./lib
#cgo LDFLAGS: ./lib/libbof_launcher_lin_x64.a
#include "bof_launcher_api.h"
*/
import "C"

import (
	"fmt"
	"os"
	"io"
	"unsafe"
)

func main() {

	if(len(os.Args) < 2) {
	    fmt.Printf("usage: %s <BOF>\n", os.Args[0])
	    return;
        }
	bof_file := os.Args[1]

	// init bof-launcher library
	C.bofLauncherInit();

	f, err := os.Open(bof_file)
	if err != nil {
            panic(err)
	}

	size, err := f.Seek(0, io.SeekEnd)
	if err != nil {
            panic(err)
	}
	f.Seek(0, io.SeekStart)

	fmt.Printf("Launching BOF file (size: %d): %s\n", size, bof_file)
	buf := make([]byte, size)

	file_len := 0
	for {
	    n, err := f.Read(buf)
	    if err != nil && err != io.EOF {
                panic(err)
	    }
	    if n == 0 {
	        break
	    }
	    file_len = file_len + n;
        }

	bof_handle := C.BofObjectHandle{}
	var bof_context *C.BofContext

	cbuf := (*C.uchar)(unsafe.Pointer(&buf[0]))
	if(C.bofObjectInitFromMemory(cbuf, (C.int)(file_len), &bof_handle) != 0) {
	    fmt.Println("bofObjectInitFromMemory failed")
	    return;
	}

	if(C.bofObjectRun(bof_handle, nil, 0, &bof_context) != 0) {
	    fmt.Println("bofObjectRun failed")
	    return;
        }

	if (bof_context == nil) {
	    fmt.Println("Creation of BofContext failed")
	    return;
        }

	bof_output := C.bofContextGetOutput(bof_context, nil)
	if(bof_output != nil) {
	    fmt.Printf("BOF output:\n%s", C.GoString(bof_output))
	    fmt.Printf("BOF exit code: %d\n", int(C.bofContextGetExitCode(bof_context)))
        }

	C.bofObjectRelease(bof_handle);
	C.bofContextRelease(bof_context);
	f.Close();
}
