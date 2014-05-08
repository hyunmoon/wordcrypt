## WordCrypt - ECE2524 Final Project

Wordcrypt is a simple yet powerful string encryption tool for text files.  
It can encrypt or decrypt some specific words, lines or the entire text in a text file.  

This project has been inspired by a scene in the movie "Inception"  
![alt tag](https://lh6.googleusercontent.com/-0Y3geyRNkno/U2llsZB5_sI/AAAAAAAAAjE/g10k74Zp2hc/w587-h450-no/Resizedd_capture_001.png)

Wordcrypt uses AES-128 encryption algorithm which is known to be one of the safest  
and strongest way to encrypt. It will come handy when maintaining a confidential document.

---

## Requirement
In order to run wordcrypt, you need Python v2.x and PyCrypto library installed.  
To install PyCrypto libarary,  
Linux - Ubuntu based:  
    `$ sudo apt-get install python-crypto`
    
Linux - RedHat based:  
    `$ sudo yum install python-crypto`
    
Windows:  
    1. Go to http://www.voidspace.org.uk/python/modules.shtml#pycrypto  
    2. Download and install "PyCrypto 2.6 for Python 2.6 32bit" or "64bit"  

## Usage

Usage: python wordcrypt.py [Option1] [] [File ...]  

Option:  
    1. `-e : Encrypt (program defaults to -e if user does not input -e or -d), mutually exclusive with -d`  
    2. `-d : Decrypt, mutually exclusive with -e`  
    3. `-p : Provide password (If no -p switch, user will be prompted to type password)`  
    4. `-s : Encrypt only the specific strings                ex) -s "str1" "str2" "str3"`  
    5. `-l : Encrypt the lines containing the specific strings ex) -l "str1" "str2" "str3"`  
    6. `-i : Input file (if no -i switch, the program will read from the standard input)`  
    7. `-o : Outout file (if no -o switch, the program will write to the standard output)`  

    
For example,  
If you would like to encrypt some specific phone numbers contained in a text file you can do:  
`python wordcrypt.py -s "540-9876-5432" "571-1111-2222" -i sample.txt`

If you would like to encrypt every line that contains phone numbers you can do:  
`python wordcrypt.py -l "Phone" -i sample.txt`


## Useful Commands
To save the result in clipboard, add the following at the end of the command line after a space  
    `| xsel -ib`  
    
It requires installation of xsel. To install,  
Linux - Ubuntu based:  
    `$ sudo apt-get install xsel`    
Linux - RedHat based:  
    `$ sudo yum install xsel`

  
  
To check the encrypted strings, add the following at the end of command line after a space  
    `| grep '\_\_\[.*\]\_\_'`  
      
	
## Design Philosophy

In this project, we tried to show some design philosopy of UNIX including:  

1. Rule of Composition (can easily interact with other programs through pipe)  
2. Rule of Silence (does not print unnecessary output)  

## Contributor
Contributors to this project:  
hyunmoon@vt.edu  
kpeng16@vt.edu (Fork:https://github.com/PengK/wordcrypt-1)  
