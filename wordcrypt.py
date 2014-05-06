#!/usr/bin/env python3
from Crypto import Random
from Crypto.Cipher import AES
from sys import stdin, stdout

# http://www.commx.ws/2013/10/aes-encryption-with-python/
def encrypt(message, key=None, key_size=128):
    def pad(s):
        x = AES.block_size - len(s) % AES.block_size
        return s + (bytes([x]) * x)
 
    padded_message = pad(message)
 
    if key is None:
        key = Random.OSRNG.posix.new().read(key_size // 8)
 
    iv = Random.OSRNG.posix.new().read(AES.block_size)
    cipher = AES.new(key, AES.MODE_CBC, iv)
 
    return (iv + cipher.encrypt(padded_message), key)

# http://www.commx.ws/2013/10/aes-encryption-with-python/
def decrypt(ciphertext, key):
    unpad = lambda s: s[:-s[-1]]
    iv = ciphertext[:AES.block_size]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = unpad(cipher.decrypt(ciphertext))[AES.block_size:]
 
    return plaintext

if __name__ == '__main__':
    message = 'hello'
    encrypted = encrypt(message.encode("utf-8"))
    decrypted = decrypt(*encrypted).decode("utf-8")
    print(decrypted)
 
    assert decrypted == message