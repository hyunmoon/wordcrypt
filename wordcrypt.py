#!/usr/bin/env python2
from sys import stdin, stdout
from Crypto.Cipher import AES
import hashlib, os, re
import getpass
import argparse
import sys

def keygen(passphrase):
  SALT = "Go Hokies!"
  passphrase = SALT + passphrase
  key = hashlib.md5(passphrase.encode('utf-8')).hexdigest()
  return key

# http://www.floyd.ch/?p=293
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

# http://www.floyd.ch/?p=293
def AESdecrypt(password, ciphertext, base64=False):
    SALT_LENGTH = 32
    DERIVATION_ROUNDS=1337
    BLOCK_SIZE = 16
    KEY_SIZE = 32
    MODE = AES.MODE_CBC
    
    # assert ciphertext in hex
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

def PrintHelp():
    print ""
    print "Usage: python wordcrypt.py [Option1] [] [File ...]\n"
    print " -h  help"
    print ""
  
def GetPassphrase():
  pprompt = lambda: (getpass.getpass('Type password: ' ), getpass.getpass('Type password again: '))
  p1, p2 = pprompt()
  count = 0
  while p1 != p2:
    #count += 1
    #if (count >= 5):
      #print 'Error occured while obtaining password. Program exits.'
      #sys.exit(1)
    print('Passwords do not match. Try again')
    p1, p2 = pprompt()
    
  return p1
  
if __name__ == '__main__':
  # these two will come from command
  password = 'password'
  keystr = 'two'
  # need command line parser to hadle
  # -e -s "str1" "str2" "stre3"....   (Encrypt every line that has str[])
  # -e                                (Encrypt entire text)
  # -d                                (Decrypt entire text)
  # -p PASSPHRASE                     (Provide passphrase)
  #                                    If passhrase is empty, either
  #                                    use it empty or prompt user 
  #
  # Order of switches:
  # -(e),d -p PASSPHRASE (-a,l)
  # () : optional
 
  text = ""
  parser = argparse.ArgumentParser(description = "Decrpyt or encrypt text files. Omit -p if command history is logged")
  group = parser.add_mutually_exclusive_group()
  group.add_argument("-d","--decrypt", help="decrypt encypted text", action = "store_true")
  group.add_argument("-e","--encrypt",help="help encrypt entire input", action = "store_true")
  parser.add_argument("-s","--strings", help="encrypt strings listed ", nargs = "+")
  parser.add_argument("-p","--password", help="password for encryption and decryption")

  parser.add_argument("-i","--input", help="name input text file to be encrypted or decrypted")
  parser.add_argument("-o","--output", help="name output text file containing decrypted or encrypted text")

  args = parser.parse_args()

  if args.input == None:
     text = stdin.read()
  else:
     try:
       input_file = open(args.input, 'r')
       text = input_file.read()
     except IOError:
        sys.stderr.write("Error: Input file \"{0}\" not found\n".format(args.input))
  	sys.exit(1)

  if args.encrypt or (not args.encrypt and not args.decrypt):
    pw = ""
    if args.password == None:
      pw = GetPassphrase()
    else:
      pw = args.password
 
    if args.strings == None:
      encrypted = AESencrypt(pw, text.strip())
      print(encrypted)
      sys.exit(0)
    else:
          # Partial encryption (only the matches of input strings)
          count = text.count(keystr);
          pw = GetPassphrase()
          for x in range(0, count):
            encrypted_keystr = AESencrypt(pw, keystr.strip())
            text = text.replace(keystr, '__[' + encrypted_keystr + ']__', 1)
          print(text.strip())
          sys.exit(0)
 

  elif args.decrypt:
    pw = ""
    if args.password == None:
      pw = GetPassphrase()
    else:
      pw = args.password
    if args.strings == None:
      pw = getpass.getpass('Type password: ' )
      decrypted = AESdecrypt(pw, text.strip())
      print(decrypted)
      sys.exit(0)
    else: 
      # Partial decryption (only the matches of input strings)
      m = None
      m = re.search('__\[(.*?)\]__', text)
      while (m is not None):
        decrypted_keystr = AESdecrypt(pw, m.group(1).strip())
        text = text.replace('__['+m.group(1)+']__', decrypted_keystr, 1)
        m = re.search('__\[(.*?)\]__', text)
    
      print(text.strip())
      sys.exit(0)
      #
