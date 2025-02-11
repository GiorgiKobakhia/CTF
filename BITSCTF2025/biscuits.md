# Biscuits
![image](https://github.com/user-attachments/assets/ed1aea62-8b2f-4347-aa34-8bf70462fdca)

## Description
Reverse main using IDA

![image](https://github.com/user-attachments/assets/13c7cc4d-54f3-43cc-add8-5d632ef9abda)

## Solution
This challenge forks connections. Let's create 101 connections which will have the same seed. Each connection leaks a cookie name that could be sent to the next connection. 
101-th connection sends all the cookie names to the challenge and receives flag.

## Script
```python
from pwn import *

ps = [0] * 101
for i in range(101):
    ps[i] = process(["nc", "20.244.40.210", "6000"])
    # ps[i] = remote("20.244.40.210", "6000")

answers = []

for i in range(100):
    print(i)
    for name in answers:
        ps[i].sendline(name)

    ps[i].sendline(b"gio")
    ps[i].recvuntil(b"I wanted was: ")
    res = ps[i].clean()[:-1]
    answers.append(res)
    print(res)

for name in answers:
    ps[100].sendline(name)

ps[100].interactive()
```
Note: **process** creates connection faster than **remote**

## Flag
BITSCTF{7h4nk5_f0r_4ll_0f_th3_c00ki3s_1_r34lly_enjoy3d_th3m_d31fa51e}
