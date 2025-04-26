## Solution For Coursera Crypto Course 
- Link: https://www.coursera.org/learn/crypto/assignment-submission/fofQp/week-2-programming-assignment-optional
```py
from Crypto.Cipher import AES
from Crypto.Util import Counter
from Crypto.Util.Padding import unpad


def xor(a, b):
    return bytes(x ^ y for x, y in zip(a, b))

def cbc_decrypt_manual(ct, cbc_key):
    aes = AES.new(cbc_key, AES.MODE_ECB)
    pt = b''

    iv = ct[:16]
    prev = iv
    for i in range(16, len(ct), 16):
        block = ct[i:i + 16]
        pt += xor(aes.decrypt(block), prev)
        prev = block

    pt = pt[:-pt[-1]]

    return pt.decode()  

def cbc_decrypt_auto(ct, cbc_key):
    iv = ct[:16]
    aes = AES.new(cbc_key, AES.MODE_CBC, iv)
    pt = unpad(aes.decrypt(ct[16:]), AES.block_size)
    return pt.decode()


# cbc decrypt 1
cbc_key = bytes.fromhex('140b41b22a29beb4061bda66b6747e14')
ct = bytes.fromhex('4ca00ff4c898d61e1edbf1800618fb2828a226d160dad07883d04e008a7897ee2e4b7465d5290d0c0e6c6822236e1daafb94ffe0c5da05d9476be028ad7c1d81')

print(cbc_decrypt_manual(ct, cbc_key))
print(cbc_decrypt_auto(ct, cbc_key))

# cbc decrypt 2
cbc_key = bytes.fromhex("140b41b22a29beb4061bda66b6747e14")
ct = bytes.fromhex("5b68629feb8606f9a6667670b75b38a5b4832d0f26e1ab7da33249de7d4afc48e713ac646ace36e872ad5fb8a512428a6e21364b0c374df45503473c5242a253")

print(cbc_decrypt_manual(ct, cbc_key))
print(cbc_decrypt_auto(ct, cbc_key))



################################################################################################################################################################################################################################
################################################################################################################################################################################################################################
################################################################################################################################################################################################################################


def ctr_decrypt_manual(ct, key):
    aes = AES.new(key, AES.MODE_ECB)
    iv = int.from_bytes(ct[:16], 'big')

    pt = b''
    for i in range(16, len(ct), 16):
        block = ct[i:i + 16]
        pt += xor(block, aes.encrypt(iv.to_bytes(16, 'big')))
        iv += 1

    return pt.decode()  


def ctr_decrypt_auto(ct, key):
    iv = int.from_bytes(ct[:16], 'big')
    ctr = Counter.new(128, initial_value=iv)
    aes = AES.new(key, AES.MODE_CTR, counter=ctr)
    pt = aes.decrypt(ct[16:])
    return pt.decode()

# ctr decrypt 1
ctr_key = bytes.fromhex("36f18357be4dbd77f050515c73fcf9f2")
ct = bytes.fromhex("69dda8455c7dd4254bf353b773304eec0ec7702330098ce7f7520d1cbbb20fc388d1b0adb5054dbd7370849dbf0b88d393f252e764f1f5f7ad97ef79d59ce29f5f51eeca32eabedd9afa9329")


print(ctr_decrypt_manual(ct, ctr_key))
print(ctr_decrypt_auto(ct, ctr_key))


# ctr decrypt 2
ctr_key = bytes.fromhex("36f18357be4dbd77f050515c73fcf9f2")
ct = bytes.fromhex("770b80259ec33beb2561358a9f2dc617e46218c0a53cbeca695ae45faa8952aa0e311bde9d4e01726d3184c34451")

print(ctr_decrypt_manual(ct, ctr_key))
print(ctr_decrypt_auto(ct, ctr_key))
```
