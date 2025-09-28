Guessing srand(time(NULL))

```py
from pwn import *
import ctypes

libc = ctypes.CDLL("/lib/x86_64-linux-gnu/libc.so.6")

libc.time.restype = ctypes.c_long
libc.time.argtypes = [ctypes.c_void_p]

libc.srand.argtypes = [ctypes.c_uint]
libc.rand.restype = ctypes.c_int


p = process()
t = libc.time(None)
libc.srand(t)

v4 = libc.rand()
v5 = (libc.rand() << 31) | v4
v6 = v5 | (libc.rand() << 62)

v6 = (2**64-1) & v6

p.sendline(str(v6).encode())

p.interactive()
```
