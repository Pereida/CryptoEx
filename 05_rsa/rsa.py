#!/usr/bin/env python

import hashlib, os, sys # do not use any other imports/libraries
from pyasn1.codec.der import decoder

def int_to_base128_bytestring(i):
    # i - arbitrary integer (of type 'int' or 'long')
    # returns the byte string representation of int in base 128

    first_remainder = True  # flag indicate first (right most) remainder for each i
    s = ''                  # string with the base 128 representation
    quotient = i
    remainder = 0

    while quotient:
        remainder = quotient % 128  # calculate mod 128
        quotient = quotient // 128  # quotient div 128
        if first_remainder: 
            # dont add 1 to msb
            s = chr(remainder) + s  # add to the string
            first_remainder = False
        else:
            # add 1 to msb (number | 128)
            s = chr(128 | remainder) + s # add to the string
    return s

def asn1_null():
    # returns DER encoding of NULL
    return chr(0x05) + chr(0x00)

def asn1_len(content):
    # helper function - should be used in other functions to calculate length octet(s)
    # content - bytestring that contains TLV content octet(s)
    # returns length (L) octet(s) for TLV
    
    # if the length is less than 128
    if len(content) < 128:
        return chr(len(content))
    else:                               # else calculate the length in DER
        len_content = len(content)      # int length of the content
        len_bytes = int_to_bytestring(len_content)
        return chr(128 | len(len_bytes)) + len_bytes

def asn1_integer(i):
    # i - arbitrary integer (of type 'int' or 'long')
    # returns DER encoding of INTEGER

    # i is converted to bytestring
    val = int_to_bytestring(i)
    
    if not i:                           # if i == 0 return 0x02 0x01 0x00
        return chr(0x02) + asn1_len(chr(0x00)) + chr(0x00)
    elif (i >> ((len(val) * 8) - 1)):   # if the msb of the MSB is 1, left pad with 0x00 byte
        return chr(0x02) + asn1_len(chr(0x00) + val) + chr(0x00) + val
    else:                               # otherwise return the TLV of i
        return chr(0x02) + asn1_len(val) + val

def asn1_sequence(der):
    # der - DER bytestring to encapsulate into sequence
    # returns DER encoding of SEQUENCE
    return chr(0x30) + asn1_len(der) + der

def asn1_objectidentifier(oid):
    # oid - list of integers representing OID (e.g., [1,2,840,123123])
    # returns DER encoding of OBJECTIDENTIFIER
    
    first_octet_string = int_to_bytestring(40 * oid[0] + oid[1]) 

    val = ''

    for i in oid[2:]:
        val += int_to_base128_bytestring(i)

    return chr(0x06) + asn1_len(first_octet_string + val) + first_octet_string + val

def asn1_octetstring(octets):
    # octets - arbitrary byte string (e.g., "abc\x01")
    # returns DER encoding of OCTETSTRING

    return chr(0x04) + asn1_len(octets) + octets

def int_to_bytestring(i):
    # i - arbitrary integer (of type 'int' or 'long')
    # returns the byte string representation of int
    s = ''          # initialize the s string
    if not i:
        return chr(0x00)
    else:
        while i > 0:    # loop through i in chunks of bytes
            s = chr(i & 255) + s
            i = i >> 8
        return s    # return the string

def bytestring_to_int(s):
    # converts bytestring to integer
    i = 0
    for char in s:
        i <<= 8
        i |= ord(char) 
    return i

def pem_to_der(content):
    # converts PEM content (if it is PEM) to DER
    pem = ''

    if 'BEGIN PUBLIC KEY' in content:   # pem pub key
        print '+ Processing PEM public key...'
        pem = content[27:]
        pem = pem[:-26]
        # print pem
        der = pem.decode('base64')
        # print der
        return der 
    elif 'BEGIN RSA PRIVATE KEY' in content: # pem private key
        print '+ Processing PEM private key...'
        pem = content[32:]
        pem = pem[:-31]
        # print pem
        der = pem.decode('base64')
        # print der
        return der 
    else:
        print '+ Processing DER key...'
        return content

def get_pubkey(filename):
    # reads public key file and returns (n, e)
    pubkey = []    # store the modulus n and exp e

    pub_pem = '' # string to store the pem
    pub_der = '' # string to store the der

    # read keyfile
    with open(filename, 'r') as k:
        pub_pem = k.read()
        # print pub_pem
    k.close()

    # check if it's PEM or DER and recieve DER
    pub_der = pem_to_der(pub_pem)
    
    # get bitstring (tuple) of pub key
    bitstring = decoder.decode(pub_der)[0][1]

    # convert from bitstring (tuple) to string
    pub_string = ''.join('%s' % i for i in bitstring)
    # print pub_string

    # convert from string to int and then to raw bytestring der
    pub_int = int(pub_string, 2)
    pub_bytestring = int_to_bytestring(pub_int)

    # get n and e from der bitstring (bytestring) and append to pubkey
    pubkey.append(decoder.decode(pub_bytestring)[0][0]) # n
    pubkey.append(decoder.decode(pub_bytestring)[0][1]) # e

    return int(pubkey[0]), int(pubkey[1])

def get_privkey(filename):
    # reads private key file and returns (n, d)
    privkey = []
    priv_der = ''
    priv_pem = ''

    # read key file
    with open(filename, 'r') as k:
        priv_pem = k.read()
    k.close()

    # check if it's PEM or DER and recieve DER
    priv_der = pem_to_der(priv_pem)

    priv_der = decoder.decode(priv_der)
    # print priv_der

    privkey.append(priv_der[0][1]) # n
    privkey.append(priv_der[0][3]) # d

    return int(privkey[0]), int(privkey[1])

def pkcsv15pad_encrypt(plaintextfile, n):
    # pad plaintext for encryption according to PKCS#1 v1.5
    padded_plaintext = ''
    plaintext = ''
    # calculate byte size of the modulus n
    n_len = len(int_to_bytestring(n))

    with open(plaintextfile, 'r') as p:
        plaintext = p.read()
    p.close()

    plaintext_len = len(plaintext)
    # print plaintext_len

    # plaintext must be at least 11 bytes smaller than modulus
    if plaintext_len > n_len - 11:
        print '- Please try again with a smaller file...'
        sys.exit(1)
    else:
        ps = n_len - (plaintext_len + 3)    # number bytes padding
        # print ps
        padding = os.urandom(ps)    # generate random padding

        while chr(0x00) in padding: # regenerate if padding contains 0x00
            padding = os.urandom(ps)

        padded_plaintext = chr(0x00) + chr(0x02) + padding + chr(0x00) + plaintext
        # print len(padded_plaintext)
    
    # generate padding bytes
    return padded_plaintext

def pkcsv15pad_sign(plaintext, n):
    # pad plaintext for signing according to PKCS#1 v1.5
    padded_plaintext = ''
    
    # calculate byte size of the modulus n
    n_len = len(int_to_bytestring(n))
    # print n_len

    # plaintext must be at least 3 bytes smaller than modulus
    plaintext_len = len(plaintext)
    # print plaintext_len

    if plaintext_len > n_len - 3:
        print '- Could not sign, something went wrong...'
        sys.exit(1)
    else:
        ps = n_len - (plaintext_len + 3)    # number bytes padding
        # print ps
        padding = chr(0xFF) * ps

        padded_plaintext = chr(0x00) + chr(0x01) + padding + chr(0x00) + plaintext
        # print len(padded_plaintext)
    
    # generate padding bytes
    return padded_plaintext

def pkcsv15pad_remove(plaintext):
    # removes PKCS#1 v1.5 padding
    index = plaintext.find(chr(0x00))
    plaintext = plaintext[1:]
    # print plaintext[index:]
    return plaintext[index:]

def encrypt(keyfile, plaintextfile, ciphertextfile):

    # print '*************** ENCRYPTION ********************'

    # get the n and e from keyfile
    pubkey = get_pubkey(keyfile)
    
    # get the plaintext padded according to PKCS#1 v1.5
    plaintext_padded = pkcsv15pad_encrypt(plaintextfile, pubkey[0])
    
    # convert plaintext padded to int
    m = bytestring_to_int(plaintext_padded)
    
    print '+ Encrypting...'
    # calculate ciphertext: c = me mod n
    ciphertext = pow(m, pubkey[1], pubkey[0])
    
    # convert ciphertext to bytestring
    ciphertext = int_to_bytestring(ciphertext)
    
    # write ciphertext to file
    with open(ciphertextfile, 'w+') as f:
        f.write(ciphertext)
    f.close()

    # check file creation
    if os.path.isfile(ciphertextfile):
        print '+ Encryption successful on', ciphertextfile
    else:
        print '- Something went wrong...'

    pass

def decrypt(keyfile, ciphertextfile, plaintextfile):

    c = ''
    m = ''
    privkey = []

    # convert ciphertext to integer
    with open(ciphertextfile, 'r') as f:
        c = f.read()
    f.close()

    c = bytestring_to_int(c)

    # get d and n from private key
    privkey = get_privkey(keyfile)

    print '+ Decrypting...'
    # Calculate decryption: m = cd mod n
    m = pow(c, privkey[1], privkey[0])

    # convert m integer to bytestring
    m = int_to_bytestring(m)

    # remove padding
    m = pkcsv15pad_remove(m)

    # write plaintext to file
    with open(plaintextfile, 'w+') as f:
        f.write(m)
    f.close()

    # check file creation
    if os.path.isfile(plaintextfile):
        print '+ Decryption successful on', plaintextfile
    else:
        print '- Something went wrong...'

    pass

def digestinfo_der(filename):
    # returns ASN.1 DER encoded DigestInfo structure containing SHA1 digest of file
    der = ''
    # hash algorithm used SHA-1
    digestinfoHash = hashlib.sha1()

    # read file by chunks and add to the hmac
    with open(filename, 'r') as f:
        for chunk in read_by_chunks(f):
            digestinfoHash.update(chunk)
    f.close()

    # generate DER structure of digest info
    der = asn1_sequence(asn1_sequence(asn1_objectidentifier([1,3,14,3,2,26]) + asn1_null()) + asn1_octetstring(digestinfoHash.digest()))

    # with open('digestinfo', 'w+') as f:
    #     f.write(der)
    # f.close()

    return der

def read_by_chunks(fileobject, size=1024):
    while True:
        data = fileobject.read(size)
        if not data:
            break
        yield data

def sign(keyfile, filetosign, signaturefile):

    s = ''
    digestinfo = ''
    plaintext = ''
    privkey = []

    # get private key n, d
    privkey = get_privkey(keyfile)

    # get digest info structure in der
    digestinfo = digestinfo_der(filetosign)

    # pkcsv15pad to digest info
    plaintext = pkcsv15pad_sign(digestinfo, privkey[0])

    # convert padded bytestring to int
    plaintext = bytestring_to_int(plaintext)

    # compute signature s = md mod n
    s = pow(plaintext, privkey[1], privkey[0])

    # convert signature int to bytestring
    s = int_to_bytestring(s)

    # check len of resulting bytestring and compare to modulus n
    n_len = len(int_to_bytestring(privkey[0]))

    # print len(s)
    if len(s) < n_len:
        s = chr(0x00) * (n_len - len(s)) + s

    # write to signature file
    with open(signaturefile, 'w+') as f:
        f.write(s)
    f.close()

    # check file creation
    if os.path.isfile(signaturefile):
        print '+ File signed successfully...'
    else:
        print '- File not signed!'

    pass

def verify(keyfile, signaturefile, filetoverify):
    # prints "Verified OK" or "Verification Failure"
    s = ''
    m = ''
    pubkey = []

    # get public key n and e
    pubkey = get_pubkey(keyfile)

    # convert signature bytestring to int
    with open(signaturefile) as f:
        s = f.read()
    f.close()

    s = bytestring_to_int(s)

    # calculate decryption m = se mod n
    m = pow(s, pubkey[1], pubkey[0])

    # convert from int to bytestring
    m = int_to_bytestring(m)

    # remove padding
    m = pkcsv15pad_remove(m)

    # get digest from der structure
    digestinfo = decoder.decode(m)[0][1]

    # calculate digest of the file to verify
    hhash = hashlib.sha1()

    with open(filetoverify, 'r') as f:
        for chunk in read_by_chunks(f):
            hhash.update(chunk)
    f.close()

    digestinfo_calculated = hhash.digest()

    print '+ Verifying signature...'
    if digestinfo == digestinfo_calculated:
        print 'Verified OK'
    else:
        print 'Verification Failure'

    pass

def usage():
    print "Usage:"
    print "encrypt <public key file> <plaintext file> <output ciphertext file>"
    print "decrypt <private key file> <ciphertext file> <output plaintext file>"
    print "sign <private key file> <file to sign> <signature output file>"
    print "verify <public key file> <signature file> <file to verify>"
    sys.exit(1)

if len(sys.argv) != 5:
    usage()
elif sys.argv[1] == 'encrypt':
    encrypt(sys.argv[2], sys.argv[3], sys.argv[4])
elif sys.argv[1] == 'decrypt':
    decrypt(sys.argv[2], sys.argv[3], sys.argv[4])
elif sys.argv[1] == 'sign':
    sign(sys.argv[2], sys.argv[3], sys.argv[4])
elif sys.argv[1] == 'verify':
    verify(sys.argv[2], sys.argv[3], sys.argv[4])
else:
    usage()
