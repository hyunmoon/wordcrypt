ECE2524 SP14
Final Project - WordCrypt  

## Introduction
Wordcrypt is a simple yet powerful string encrypting tool.  
It is capable of encrypting or decrypting only certain strings or lines in the text 

## Required library
In order to run wordcrypt, you need PyCrypto library.  
Linux:  
    `$ sudo apt-get install python-crypto`
    
Windows:  
    1. Go to http://www.voidspace.org.uk/python/modules.shtml#pycrypto  
    2. Download and install "PyCrypto 2.6 for Python 2.6 32bit" or "64bit"  

## Usage

Usage: python wordcrypt.py [Option1] [] [File ...]  

Option:  
    1. `-e : Encrypt (default)`  
    2. `-d : Decrypt`  
    3. `-p : Provide password (If no -p switch, user will be prompted to type password)`  
    4. `-s : Encrypt only the specific strings                ex) -s "str1" "str2" "str3"`  
    5. `-l : Encrypt the lines containing the specific string ex) -l "str1" "str2" "str3"`  
    6. `-i : Input file (if no -i switch, the program will read from the standard input)`  
    7. `-o : Outout file (if no -o switch, the program will write to the standard output)`  
	
     
## Useful Commands:
To highlight the encrypted part, add the following at the end of command line after a space  
    `| grep '\\\_\\\_\\\[.*\\\]\\\_\\\_'`  
      
To save the result in clipboard, add the following at the end of the command line after a space  
    `| xsel -ib`  
    (This requires xsel. To install, type ` sudo apt-get install xsel `)  

	
## Note:
This project has been inspired by a scene in the movie "Inception"

![alt tag](https://lh6.googleusercontent.com/-0Y3geyRNkno/U2llsZB5_sI/AAAAAAAAAjE/g10k74Zp2hc/w587-h450-no/Resizedd_capture_001.png)


There are many tools out there that encrypts the file itself  
But, what if you want to encrypt only the key pieces of information?  

Wordcrypt uses AES-128 encryption algorithm which is known to be one of the safest and strongest encryption algorithm.  
Also, even if there are multiple occurences of the strings, each will have different encrypted string so that it is  
difficult to guess the word by reading it.  

In this project, we tried to show some design philosopy of UNIX including:  

1. Rule of Comosition (can interact with other programs through pipe)  
2. Rule of Least Surprise (simple command line interface)  
3. Rule of Silence (it does not print unnecessary output)  

## Contributor:
Contributor to this project:  
hyunmoon@vt.edu  
kpeng16@vt.edu  