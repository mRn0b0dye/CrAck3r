#!/usr/bin/env python

from pwn import *
import optparse
import sys

class colors():
    Red = '\033[1;31m'
    Yellow = '\033[1;33m'
    Magenta = '\033[1;35m'
    Cyan = '\033[1;36m'
    Blue = '\033[1;34m'
    Reset = '\033[0m'

def banner():
    baner = """{}
\t\t\t      _       _  
\t\t\t     / \_____/ \           C  r  A  c  k  e  r 
\t\t\t    /   \___/   \         /|\/|\|/|\|/|\|/|\| \ 
\t\t\t   ( o )     ( o )       / | \| | \| | \| | \| \  
\t\t\t    \|     ^    /       //\\|  \|  \|  \|| \| / \   
\t\t\t     \___----__/       //|/\|  \|  \|  \|  \| /| \           
\t\t\t      \       /       // |\|  \|  \|  \|  \| | \  \ 
\t\t\t       \_____/       /  \|  \|  \|  \|  \| | \  \| \
  
    {}""".format(colors.Red, colors.Reset)
    return baner

def hash_table():
    hash_mode = """
                            {}HASH__TABLE

                 _______________________________________                                 
                |  Suported_HASH     ||      #(type)    |
                |--------------------++-----------------|
                |      SHA1          ||       100       |
                |      SHA256        ||      2560       |   
                |      SHA384        ||      3840       |  
                |      SHA512        ||      5120       |   
                |      SHA224        ||      2240       |
                |      SHA3_256      ||      3256       | 
                |      SHA3_384      ||      3384       |
                |      SHA3_512      ||      3512       |
                |      SHA3_224      ||      3224       |
                |      BLAKE2b       ||       200       |
                |      BLAKE2bs      ||      2200       |
                |      MD5           ||       400       |   
                -----------------------------------------{}
    
    """.format(colors.Red, colors.Reset)
    return hash_mode

def help_menu():
    Usage = "python {} [ -H <hash> or -f <hash_file> ] options".format(sys.argv[0])
    arg = optparse.OptionParser(usage= Usage)
    arg.add_option("-H", "--hash", dest= "hash", help= "Enter Hash")
    arg.add_option("-f", "--hash-file", dest= "hash_file", help= "Enter Hash file")
    arg.add_option("-w", "--wordlist", dest= "wordlist", help= "Enter wordlist path")
    arg.add_option("-t", "--hash-type", dest= "hash_type", help= "Enter Hash Type{}".format(hash_table()))
    (options, arguments) = arg.parse_args()
    return options
    
def cracker_single_hash(hash, hash_type, wordlist):
    attempts = 0
    with log.progress('{}CRACKING..\n{}{}'.format(colors.Blue, hash, colors.Reset)) as p:
        with open(wordlist, 'r', encoding= 'latin-1') as word:
            for password in word:
                password = password.strip('\n').encode('latin-1')
                hash_type = int(hash_type)
                if hash_type == 2560:
                    password_hash = sha256sum(password)
                elif hash_type == 100:
                    password_hash = sha1sumhex(password)
                elif hash_type == 2240:
                    password_hash = sha224sumhex(password)
                elif hash_type == 400:
                    password_hash = md5sumhex(password)
                elif hash_type == 3840:
                    password_hash = sha384sumhex(password)
                elif hash_type == 3384:
                    password_hash = sha3_384sumhex(password)
                elif hash_type == 3224:
                    password_hash = sha3_224sumhex(x)
                elif hash_type == 3256:
                    password_hash = sha3_256sumhex(x)
                elif hash_type == 3512:
                    password_hash = sha3_512sumhex(x)                
                elif hash_type == 5120:
                    password_hash = sha512sumhex(password)
                elif hash_type == 200:
                    password_hash = blake2bsumhex(password)
                elif hash_type == 2200:
                    password_hash = blake2ssumhex(password)
                p.status('{}{}{}'.format(colors.Yellow, password.decode('latin-1'), colors.Reset))
                attempts = attempts + 1
                if password_hash == hash:
                    p.success('\n{}Password: {}\nAttempts: {}{}'.format(colors.Magenta, password.decode('latin-1'), attempts, colors.Reset))
                    exit()
            if password_hash != hash:
                p.failure('\n{}Password Not Found!!{}'.format(colors.Blue, colors.Reset))

def cracker_multiple_hashs(hash_file, hash_type, wordlist):
    attempts = 0
    with open(hash_file, 'r') as hash_line:
        for hash in hash_line:
            hash = hash.strip('\n')
            with log.progress('{}CRACKING..\n{}{}'.format(colors.Blue, hash, colors.Reset)) as p:
                with open(wordlist, 'r', encoding= 'latin-1') as word:
                    for password in word:
                        password = password.strip('\n').encode('latin-1')
                        hash_type = int(hash_type)
                        if hash_type == 2560:
                            password_hash = sha256sum(password)
                        elif hash_type == 100:
                            password_hash = sha1sumhex(password)
                        elif hash_type == 2240:
                            password_hash = sha224sumhex(password)
                        elif hash_type == 400:
                            password_hash = md5sumhex(password)
                        elif hash_type == 3840:
                            password_hash = sha384sumhex(password)
                        elif hash_type == 3384:
                            password_hash = sha3_384sumhex(password)
                        elif hash_type == 3224:
                            password_hash = sha3_224sumhex(x)
                        elif hash_type == 3256:
                            password_hash = sha3_256sumhex(x)
                        elif hash_type == 3512:
                            password_hash = sha3_512sumhex(x)                
                        elif hash_type == 5120:
                            password_hash = sha512sumhex(password)
                        elif hash_type == 200:
                            password_hash = blake2bsumhex(password)
                        elif hash_type == 2200:
                            password_hash = blake2ssumhex(password)
                        p.status('{}{}{}'.format(colors.Yellow, password.decode('latin-1'), colors.Reset))
                        attempts = attempts + 1
                        if password_hash == hash:
                            p.success('\n{}hash: {}\nPassword: {}{}'.format(colors.Magenta, hash, password.decode('latin-1'), colors.Reset))
                    if password_hash != hash:
                        p.failure('\n{}Password Not Found!!{}'.format(colors.Blue, colors.Reset))

def main():
    options = help_menu()
    try:
        if (sys.argv[1] == '-H' or sys.argv[1] == '--hash'):
            print(banner())
            cracker_single_hash(options.hash, options.hash_type, options.wordlist)
        elif (sys.argv[1] == '-f' or sys.argv[1] == '--hash-file'):
            print(banner())
            cracker_multiple_hashs(options.hash_file, options.hash_type, options.wordlist)
        # elif (sys.argv[1] == '-h'):
    except KeyboardInterrupt:
        print("{}[+]{}Exiting Program{}".format(colors.Yellow, colors.Red, colors.Reset))
        sys.exit()
    
if __name__ == '__main__':
    main()

