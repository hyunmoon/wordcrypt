#!/usr/bin/env python2
from sys import stdin, stdout
from Crypto.Cipher import AES
import hashlib, os, re

def keygen(passphrase):
  SALT = "Go Hokies!"
  passphrase = SALT + passphrase
  key = hashlib.md5(passphrase.encode('utf-8')).hexdigest()
  return key

def AESencrypt(password, plaintext, base64=False):
    SALT_LENGTH = 32
    DERIVATION_ROUNDS=1337
    BLOCK_SIZE = 16
    KEY_SIZE = 32
    MODE = AES.MODE_CBC
     
    salt = os.urandom(SALT_LENGTH)
    iv = os.urandom(BLOCK_SIZE)
     
    paddingLength = 16 - (len(plaintext) % 16)
    paddedPlaintext = plaintext+chr(paddingLength)*paddingLength
    derivedKey = password
    for i in range(0,DERIVATION_ROUNDS):
        derivedKey = hashlib.sha256(derivedKey+salt).digest()
    derivedKey = derivedKey[:KEY_SIZE]
    cipherSpec = AES.new(derivedKey, MODE, iv)
    ciphertext = cipherSpec.encrypt(paddedPlaintext)
    ciphertext = ciphertext + iv + salt
    if base64:
        import base64
        return base64.b64encode(ciphertext)
    else:
        return ciphertext.encode("hex")
 
def AESdecrypt(password, ciphertext, base64=False):
    SALT_LENGTH = 32
    DERIVATION_ROUNDS=1337
    BLOCK_SIZE = 16
    KEY_SIZE = 32
    MODE = AES.MODE_CBC
     
    if base64:
        import base64
        decodedCiphertext = base64.b64decode(ciphertext)
    else:
        decodedCiphertext = ciphertext.decode("hex")
    startIv = len(decodedCiphertext)-BLOCK_SIZE-SALT_LENGTH
    startSalt = len(decodedCiphertext)-SALT_LENGTH
    data, iv, salt = decodedCiphertext[:startIv], decodedCiphertext[startIv:startSalt], decodedCiphertext[startSalt:]
    derivedKey = password
    for i in range(0, DERIVATION_ROUNDS):
        derivedKey = hashlib.sha256(derivedKey+salt).digest()
    derivedKey = derivedKey[:KEY_SIZE]
    cipherSpec = AES.new(derivedKey, MODE, iv)
    plaintextWithPadding = cipherSpec.decrypt(data)
    paddingLength = ord(plaintextWithPadding[-1])
    plaintext = plaintextWithPadding[:-paddingLength]
    return plaintext

if __name__ == '__main__':
  password = 'password'
  text = stdin.read()
  encrypted = AESencrypt(password, text)
  print(encrypted)
  decrypted = AESdecrypt(password, encrypted)
  print(decrypted)
  
  
  keystr = 'two'
  count = text.count(keystr);
  for x in range(0, count):
    encrypted_keystr = AESencrypt(password, keystr)
    text = text.replace('two', '__[' + encrypted_keystr + ']__', 1)
    
  print(text)
  
  m = None
  m = re.search('__\[(.*?)\]__', text)
  print('Decrypt:')
  while (m is not None):
    decrypted_keystr = AESdecrypt(password, m.group(1))
    text = text.replace('__['+m.group(1)+']__', decrypted_keystr, 1)
    m = re.search('__\[(.*?)\]__', text)
    
  print(text)