#!/usr/bin/env python2
from Crypto.Cipher import AES # www.dlitz.net/software/pycrypto
from sys import stdin, stdout
import sys
import hashlib, os, re
import getpass, argparse

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
  
def GetPassword():
  pprompt = lambda: (getpass.getpass('Type password: ' ), getpass.getpass('Re-type password: '))
  p1, p2 = pprompt()
  while p1 != p2:
    print('Passwords do not match. Try again')
    p1, p2 = pprompt()
    
  return p1

def printToWhere(filename, text):
   if filename != None:
     output_file = open(filename,"w") 
     output_file.write(text)


if __name__ == '__main__':
  
  parser = argparse.ArgumentParser(description = "Decrpyt or encrypt text files. Omit -p if command history is logged")
  group = parser.add_mutually_exclusive_group()

  group.add_argument("-d","--decrypt", help="decrypt encypted text", action = "store_true")
  group.add_argument("-e","--encrypt",help="encrypt entire input", action = "store_true")

  group2 = parser.add_mutually_exclusive_group()
  group2.add_argument("-s","--strings", help="encrypt strings in regular text", nargs = "+")
  group2.add_argument("-l","--lines", help="encrypt entire lines in regular text containing argument strings", nargs = "+")

  parser.add_argument("-o","--output", help="output file to encrypted or decrypted text")
  parser.add_argument("-i","--input", help="input file to encrypt or decrypt")
  parser.add_argument("-p","--password", help="password for encryption and decryption")

  args = parser.parse_args()
  text = ""
  pw = ""
  if args.input == None:
     text = stdin.read()
  else:
     try:
       input_file = open(args.input, 'r')
       text = input_file.read().strip()
     except IOError:
        sys.stderr.write("Error: Input file \"{0}\" not found\n".format(args.input))
  	sys.exit(1)
  
  # ENCRYPT -------------------------------------------------
  if args.encrypt  or (not args.encrypt and not args.decrypt):
    if args.password == None:
      pw = GetPassword()
    else:
      pw = args.password

    if args.strings == None and args.lines == None:
      encrypted_str = AESencrypt(pw, text.strip())
      text = text.replace(text, '__[' + encrypted_str + ']__', 1)
    elif args.lines != None: # Encrypt entire lines that contain particular strings
      nText = ""
      strCt = len(args.lines)

      for i in range(0, strCt):
	keystr = args.lines[i].strip()
	for line in text.splitlines():
	  if keystr in line:
	    encrypted_keystr = AESencrypt(pw, line)
	    text = text.replace(line, '__[' + encrypted_keystr + ']__', 1) 
    else:
      # Encrypt only the particular strings
      strCt = len(args.strings)
      for i in range(0, strCt):
	keystr = args.strings[i].strip()
	numMatch = text.count(keystr);
	for x in range(0, numMatch):
	  encrypted_keystr = AESencrypt(pw, keystr.strip())
	  text = text.replace(keystr, '__[' + encrypted_keystr + ']__', 1)
	
  # DECRYPT -------------------------------------------------
  elif args.decrypt:
    if args.lines != None or args.strings != None:
      print sys.stderr.write("Error: Cannot decrypt specific strings or lines\n")
      sys.exit(1)
    if args.password == None:
      pw = getpass.getpass('Type password: ' )
    else:
      pw = args.password
    m = re.search('__\[(.*?)\]__', text)
    while (m is not None):
      try:
	decrypted_keystr = AESdecrypt(pw.strip(), m.group(1).strip())
      except TypeError:
	decrypted_keystr = '[ERROR_DAMAGED_DATA]'
      text = text.replace('__['+m.group(1)+']__', decrypted_keystr, 1)
      m = re.search('__\[(.*?)\]__', text)
      
  if args.output == None:
    print(text.strip())
    sys.exit(0)
  else:
    output_file = open(args.output,'w')
    output_file.write(text)