# Baby Crypto
![image](https://github.com/user-attachments/assets/8c93fdf4-ebf5-45f0-b923-81e8f38c3cee)

# Challenge Interaction
![image](https://github.com/user-attachments/assets/0f936568-5a02-4b81-8a8d-abeeb8110f2f)

Challenge gives us *n*, *e*, and *ct* that is equal to $m^e$. We have to send some *Ciphertext (int)* to challenge and it replies by $ct^d$.
Unfortunately, sending given *ct* to challenge does not work.

![image](https://github.com/user-attachments/assets/03b35197-5757-4438-b921-a0f71c346090)

# Solution
We can send $2^e \times ct = 2^e \times m^e = (2 \times m)^e$. It gives us back $((2 \times m)^e)^d = 2 \times m$. Then we just divide the answer by 2.

# Script
```python
from pwn import *

p = process(["nc", "chals.bitskrieg.in", "7000"])


def get_info():
    p.recvuntil(b"n = ")
    n = int(p.recvuntil(b"\n")[:-1].decode())

    p.recvuntil(b"e = ")
    e = int(p.recvuntil(b"\n")[:-1].decode())

    p.recvuntil(b"ct = ")
    ct = int(p.recvuntil(b"\n")[:-1].decode())

    return n, e, ct

def int_to_str(number):
    return number.to_bytes((number.bit_length() + 7) // 8, byteorder='big').decode('utf-8')

def decrypt(n, e, ct):
    a = 1
    for i in range(e):
        a *= 2
        a %= n

    p.sendline(str(a*ct).encode())

    p.recvuntil(b"seek : ")
    res = int(p.recvuntil(b"\n")[:-1].decode())
    
    return int_to_str(res//2)

n, e, ct = get_info()

print(decrypt(n, e, ct))
```

# FLAG
BITSCTF{r54_0r4acl3_h4s_g0t_t0_b3_0n3_0f_7h3_3as13st_crypt0_1n_my_0p1n10n_74b15203}

