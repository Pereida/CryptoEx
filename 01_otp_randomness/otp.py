#!/usr/bin/env python
import os, sys       # do not use any other imports/libraries
# The total time of resolution was around 4.5 hours
# Cesar Pereida

def bytestring_to_int(s):
    # initialize i to 0
    i = 0

    # we store the first string in i
    i = ord(s[0])

    # loop through the whole byte strings, shifting and xoring to create a big integer
    for x in s:
        i = i << 8
        i = i | ord(x)

    # return the big int number
    return i

def int_to_bytestring(i, length):
    # initialize the s string
    s = ''

    # loop through the integer in chunks of bytes
    for x in range(0, length):
        s = chr(i & 255) + s
        i = i >> 8

    # return the string
    return s


def encrypt(pfile, kfile, cfile):
    # open the file and read it
    with open(pfile) as p:
        ptext = p.read()    #open(pfile).read()
    p.close()

    # get the len of the file
    pfile_len = len(ptext)

    # create a random string the same size as the pfile
    ktext = os.urandom(pfile_len)

    # convert plaintext and ciphertext byte strings to one big integer
    ptint = bytestring_to_int(ptext)
    kint = bytestring_to_int(ktext)

    # XOR the plaintext and key to generate ciphertext
    cint = ptint ^ kint

    # conver the cipher int to cipher byte string
    ctext = int_to_bytestring(cint, pfile_len)

    # create key file, write to it and close it 
    with open(kfile, 'w+') as k:
        k.write(ktext)
    k.close()

    # create ciphertext file, write to it and close it
    with open(cfile, 'w+') as c:
        c.write(ctext)
    c.close()

    # print ctext

    pass
    

def decrypt(cfile, kfile, pfile):
    
    # open cfile, read it and close it
    with open(cfile) as c:
        ctext = c.read()
    c.close()

    # open kfile, read it and close it
    with open(kfile) as k:
        ktext = k.read()
    k.close()

    # convert the ciphertext and key from byte string to int
    cint = bytestring_to_int(ctext)
    kint = bytestring_to_int(ktext)

    # xor the ciphertext int and key int
    ptint = cint ^ kint

    # convert the plaintext int to byte string
    ptext = int_to_bytestring(ptint, len(ktext))

    # create and open plaintext file, write to it and close it
    with open(pfile, 'w+') as p:
        p.write(ptext)
    p.close()

    # print ptext
    pass

def usage():
    print "Usage:"
    print "encrypt <plaintext file> <output key file> <ciphertext output file>"
    print "decrypt <ciphertext file> <key file> <plaintext output file>"
    sys.exit(1)

if len(sys.argv) != 5:
    usage()
elif sys.argv[1] == 'encrypt':
    encrypt(sys.argv[2], sys.argv[3], sys.argv[4])
elif sys.argv[1] == 'decrypt':
    decrypt(sys.argv[2], sys.argv[3], sys.argv[4])
else:
    usage()