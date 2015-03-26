#!/usr/bin/python

import datetime, os, sys
from pyasn1.codec.der import decoder

# $ sudo apt-get install python-crypto
sys.path = sys.path[1:] # removes script directory from aes.py search path
from Crypto.Cipher import AES          # https://www.dlitz.net/software/pycrypto/api/current/Crypto.Cipher.AES-module.html
from Crypto.Protocol.KDF import PBKDF2 # https://www.dlitz.net/software/pycrypto/api/current/Crypto.Protocol.KDF-module.html#PBKDF2
from Crypto.Util.strxor import strxor  # https://www.dlitz.net/software/pycrypto/api/current/Crypto.Util.strxor-module.html#strxor
import hashlib, hmac # do not use any other imports/libraries


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

def read_chunk(start_position, file_object, chunk_size):
    # start_position - starting position to read file
    # file_object - object of type file to read
    # chunk_size - the amount of data we want to read from file
    file_object.seek(start_position)
    while True:
        data = file_object.read(chunk_size) # read data by chunks
        if not data:    # no data
            break       # break out of the while
        yield data      # return data and continue where it left

def read_chunk_aes(file_object, chunk_size = 16):
    # file_object - object of type file to read
    # chunk_size - the amount of data we want to read from file in bytes
    still_data = True

    while True:
        data = file_object.read(chunk_size)
        padding = chunk_size - len(data) 
        # print len(data)
        if not still_data:
            break
        elif padding > 0 and padding < 16:
            data = data + (chr(padding) * padding)
            still_data = False
            # print data.encode('hex')
        elif not data:
            data = chr(16) * 16
            still_data = False
            # print data.encode('hex')
        yield data

def cbc_encrypt(iv, aes_key, pfile):
    # iv - 16 random generated iv
    # aes_key - 16 byte key derived from user pass
    # pfile - string file name to read in chunks (in bytes)
    # return the ciphertext

    ciphertext = ''
    xoring = ''

    # create cipher object with key
    cipher = AES.new(aes_key)

    with open(pfile, 'r') as f:
        for chunk in read_chunk_aes(f): # read chunk by chunk
            xoring = strxor(iv, chunk)  # xor iv and plaintext
            iv = cipher.encrypt(xoring) # encrypt the xor of iv and chunk
            ciphertext += cipher.encrypt(xoring) # encrypt the xor of iv and chunk
    f.close()

    # print ciphertext
    return ciphertext

def cbc_decrypt(iv, aes_key, cfile, start_position):
    # iv - string 16 byte random generated iv
    # aes_key - int 16 byte key derived from user pass
    # cfile - string name of the file to read in chunks (in bytes)
    # start_position - int position start encryption in cfile
    # return the plaintext
    plaintext = ''
    ciphertext = ''
    padding = ''

    # create cipher object with key
    cipher = AES.new(aes_key)

    with open(cfile, 'r') as f:
        for chunk in read_chunk(start_position, f, 16): # read file starting position by chunks of 16 bytes
            ciphertext = chunk  # each chunk is copied to ciphertext
            # print len(ciphertext)
            decryption = cipher.decrypt(ciphertext) # decrypt the ciphertext with the key
            plaintext += strxor(iv, decryption)     # xor iv and decryption
            iv = ciphertext                         # assign ciphertext to iv
    f.close()

    padding = plaintext[-1] # obtain the last byte of plaintext (padding)
    padding = ord(padding)  # int value of the padding

    return plaintext[:-padding] # return the plaintext minus the padding

# this function benchmarks how many PBKDF2 iterations
# can be performed in one second on the machine it is executed
def benchmark():

    # measure time for performing 10000 iterations
    start = datetime.datetime.now()

    key = PBKDF2('qwertyui', '12345678', 16, 100000)

    stop = datetime.datetime.now()
    time = (stop-start).total_seconds()

    # extrapolate to 1 second
    iter = 100000 // time

    print "[+] Benchmark: %s PBKDF2 iterations in 1 second" % (iter)

    return iter # returns number of iterations that can be performed in 1 second

def encrypt(pfile, cfile):

    try:
        # benchmarking
        iter = benchmark()

        # asking for password
        print "[?] Enter password:",
        password = raw_input()

        # derieving key

        iv = os.urandom(16)     # generate random iv value
        salt = os.urandom(8)    # generate random salt
        PBKDF2_keylen = 36

        master_key = PBKDF2(password, salt, PBKDF2_keylen, int(iter))

        aes_key = master_key[:16]
        hmac_key = master_key[16:]

        # encryption
        cypher = cbc_encrypt(iv, aes_key, pfile)

        # writing ciphertext in temporary file and calculating HMAC digest
        with open('/tmp/.tmp.aes', 'w+') as f:
            f.write(cypher)
        f.close()

        m = hmac.new(hmac_key, None, hashlib.sha1) # key, message, algorithm

        with open('/tmp/.tmp.aes', 'r') as f:
            for chunk in read_chunk(0, f, 512):
                m.update(chunk)
        f.close()

        # writing DER structure in cfile
        der = asn1_sequence(asn1_sequence(asn1_octetstring(salt) + asn1_integer(int(iter)) + asn1_integer(PBKDF2_keylen)) +
                            asn1_sequence(asn1_objectidentifier([2,16,840,1,101,3,4,1,2]) + asn1_octetstring(iv)) +
                            asn1_sequence(asn1_sequence(asn1_objectidentifier([1,3,14,3,2,26]) + asn1_null()) + 
                            asn1_octetstring(m.digest())))

        with open(cfile, 'w+') as f:
            f.write(der)
            # append temporary ciphertext file to cfile
            with open('/tmp/.tmp.aes', 'r') as infile:
                for line in infile:
                    f.write(line)
            infile.close()
        f.close() 

        # deleting temporary ciphertext file
        if os.path.isfile('/tmp/.tmp.aes'):
            os.remove('/tmp/.tmp.aes')
            # print 'Temp file removed successfully!'

        if os.path.isfile(cfile):
            print "[+] Sucessful encryption: ", cfile

    except IOError as e:
        print "I/O error({0}): ({1})".format(e.errno, e.strerror)
    except:
        print "Unexpected error:", sys.exc_info()[0]
        raise

def decrypt(cfile, pfile):

    # reading DER structure
    try:
        with open(cfile, 'r') as c:
            raw = c.read(90)
        c.close()

        # print decoder.decode(raw)

        iv = str(decoder.decode(raw)[0][1][1])
        salt = str(decoder.decode(raw)[0][0][0])
        PBKDF2_keylen = int(decoder.decode(raw)[0][0][2])
        iter = int(decoder.decode(raw)[0][0][1])
        digest = decoder.decode(raw)[0][2][1]

        # print digest

        iter_bytes = ord(asn1_len(asn1_integer(iter)))   # get number of bytes used for iterations
        cypher_start = 83 + iter_bytes                   # 83 fixed for all other params + iterations

        # asking for password
        print "[?] Enter password:",
        password = raw_input()

        # derieving key
        master_key = PBKDF2(password, salt, PBKDF2_keylen, int(iter))

        aes_key = master_key[:16]
        hmac_key = master_key[16:]

        # first pass over ciphertext to calculate and verify HMAC
        m = hmac.new(hmac_key, None, hashlib.sha1)

        with open(cfile, 'r') as c:
            for chunk in read_chunk(cypher_start , c, 512):
                m.update(chunk)
        c.close()

        digest_calc = m.digest()

        if digest_calc != digest:
            print "[-] HMAC verification failure: wrong password or modified ciphertext!"
        else:
            print '[+] HMAC-SHA1 digest: ' + digest_calc.encode('hex')
            print "[+] Hashes match! Continue with decryption..."

            # second pass over ciphertext to decrypt
            plaintext = cbc_decrypt(iv, aes_key, cfile, cypher_start)

            with open(pfile, 'w+') as f:
                f.write(plaintext)
            f.close()

            if os.path.isfile(pfile):
                print "[+] Sucessful decryption: ", pfile

    except IOError as e:
        print "I/O error({0}): ({1})".format(e.errno, e.strerror)
    except:
        print "Unexpected error:", sys.exc_info()[0]
        raise

def usage():
    print "Usage:"
    print "-encrypt <plaintextfile> <ciphertextfile>"
    print "-decrypt <ciphertextfile> <plaintextfile>"
    sys.exit(1)


if len(sys.argv) != 4:
    usage()
elif sys.argv[1] == '-encrypt':
    encrypt(sys.argv[2], sys.argv[3])
elif sys.argv[1] == '-decrypt':
    decrypt(sys.argv[2], sys.argv[3])
else:
    usage()
