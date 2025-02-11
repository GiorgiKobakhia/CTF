# Minesweeper2

![image](https://github.com/user-attachments/assets/0475e8a5-3d88-4ed4-b319-6ea72880a0ca)

## README.md
RULES:

In Minesweeper 2 you have board filled with hints about where the mines are and you have to clear or sweep them off, each tile shows the sum of the mines around it (4 adjacent neighbors).

Each tile may contain any number of mines.

Each move you must enter a coordinate, indexed with 0 0 in the top left. (ex: `1 2` or `22 13`)

If a mine is present at the coords it will clear it other wise print miss. If there are multiple mines in a tile you must clear all of them. The goal is to clear all mines in the moves remaining.

Beat all Levels to get the flag.

Good Luck!

## Challenge Interaction
![image](https://github.com/user-attachments/assets/76682ff1-e7e4-4079-9fd2-703d129d7e47)


## Solution
**Observation**: You can calculate number of mines in all the tiles, if you know the first row. So let's find those numbers by repeatedly sending coordinates (0, y) for every y, until it says "miss!".

## Script
```python
from pwn import *
import os

p = process(["nc", "chals.bitskrieg.in", "7006"])

move = 0
level = 1

def get_info():
    p.recvuntil(b"Level ")
    n = p.recvuntil(b"x")[3:-1]
    m = p.recvuntil(b"\n")[:-1]
    n = int(n.decode())
    m = int(m.decode())

    return n, m

def get_board(n, m):
    grid = []

    p.recvuntil(b"board:\n")

    res = p.recvuntil(b"E")[:-1]

    vals = res.decode().replace("\n"," ").split()
    vals = [int(x) for x in vals]

    for i in range(n):
        row = []
        for j in range(m):
            row.append(vals[i*m+j])
        grid.append(row)

    return grid


def guess_first_row(n, m, grid):
    row = []

    for j in range(m):
        i = 0
        if grid[i][j] != 0:
            row.append(0)
            continue
        
        x = 0
        payload = ""
        
        for _ in range(15):
            payload += f"{i} {j}\n"
        
        payload += "-1"
        p.sendline(payload.encode())

        res = p.recvuntil(b"Invalid move!\n")
        x = res.count(b"cleared")
        row.append(x)
    
    return row
    
def calculate_board(n, m, A, grid):
    for i in range(1, n):
        for j in range(m):
            if grid[i][j] != 0:
                continue
            sum = 0
            if i-2 >= 0:
                sum += A[i-2][j]
            if j-1 >= 0:
                sum += A[i-1][j-1]
            if j+1 < m:
                sum += A[i-1][j+1]
            A[i][j] = grid[i-1][j] - sum
    return A


def check_board(n, m, A, grid):
    for i in range(n):
        for j in range(m):
            sum = 0
            if i-1 >= 0:
                sum += A[i-1][j]
            if i+1 < n:
                sum += A[i+1][j]
            if j-1 >= 0:
                sum += A[i][j-1]
            if j+1 < m:
                sum += A[i][j+1]
            if sum != grid[i][j]:
                print(sum, grid[i][j])
                print("bad boooooooooy")
                exit(0)

def clear_level(n, m, A):
    for i in range(1, n):
        payload = ""
        for j in range(m):
            if A[i][j] > 0:
                for k in range(A[i][j]):
                    payload += f"{i} {j}\n"
        
        if i < n-1:
            payload += '-1\n'

        p.sendline(payload[:-1].encode())

        if i < n-1:
            res = p.recvuntil(b'valid')
    
    res = p.recvuntil(b"level")




for _ in range(7):
    print(level)
    
    n, m = get_info()

    print(n, m)
    
    grid = get_board(n, m)

    [print(row) for row in grid]

    A = [[0] * m for _ in range(n)]

    A[0] = guess_first_row(n, m, grid)

    A = calculate_board(n, m, A, grid)
    
    [print(row) for row in A]

    check_board(n, m, A, grid)

    clear_level(n, m, A)

    level += 1

p.interactive()
```

## FLAG
BITSCTF{D0_u_y34rn_f0R_th3_m1n3s?}
