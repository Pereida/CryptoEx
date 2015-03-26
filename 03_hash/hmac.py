#!/usr/bin/python

import hashlib, sys
from pyasn1.codec.der import decoder

sys.path = sys.path[1:] # removes script directory from hmac.py search path
import hmac # do not use any other imports/libraries

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

def read_chunk(file_object, chunk_size = 512):
    # file_object - object of type file to read
    # chunk_size - the amount of data we want to read from file
    while True:
        data = file_object.read(chunk_size) # read data by chunks
        if not data:    # no data
            break       # break out of the while
        yield data      # return data and continue where it left

def calculate_digest(filename, h):
    # filename - name of the file we are calculating the hash
    # h - hash algorithm used to calculate hmac
    # return the digest in string format
    try: 
        print "[?] Enter key:",
        key = raw_input()

        m = hmac.new(key, None, h)  # new instance of hmac with key and algorithm

        with open(filename, 'r') as f:
            for piece in read_chunk(f):
                m.update(piece)     # we read and add the data in chunks
        f.close()

        return m.digest()   # generate and return the digest

    except IOError as e:
        print "I/O error({0}): ({1})".format(e.errno, e.strerror)
    except:
        print "Unexpected error:", sys.exc_info()[0]
        raise

def verify(filename):
    # filename - name of the file to verify
    # print the result of comparing digest in file and digest calculated
    print "[+] Reading HMAC DigestInfo from", filename+".hmac"

    digest_calculated = ''

    try:
        with open(filename+".hmac", 'r') as f:
            raw = f.read()  # read the whole .hmac file
        f.close()
    
        hmacOID = decoder.decode(raw)[0][0][0]  # obtain the Hash algorithm OID from der
        digest = str(decoder.decode(raw)[0][1]) # obtain the digest from der

        if str(hmacOID) == '1.2.840.113549.2.5':    # MD5
            print '[+] HMAC-MD5 digest:' + digest.encode('hex')
            digest_calculated = calculate_digest(filename, hashlib.md5)
            print '[+] Calculated HMAC-MD5:' + digest_calculated.encode('hex')
        elif str(hmacOID) == '1.3.14.3.2.26':       # SHA1
            print '[+] HMAC-SHA1 digest:' + digest.encode('hex')
            digest_calculated = calculate_digest(filename, hashlib.sha1)
            print '[+] Calculated HMAC-SHA1:' + digest_calculated.encode('hex')
        elif str(hmacOID) == '2.16.840.1.101.3.4.2.1': #SHA256
            print '[+] HMAC-SHA256 digest:' + digest.encode('hex')
            digest_calculated = calculate_digest(filename, hashlib.sha256)
            print '[+] Calculated HMAC-SHA256:' + digest_calculated.encode('hex')
        else:
            print "[-] Unsupported Hash Function!"

        if digest_calculated != digest:
            print "[-] Wrong key or message has been manipulated!"
        else:
            print "[+] HMAC verification successful!"

    except IOError as e:
        print "I/O error({0}): ({1})".format(e.errno, e.strerror)
    except:
        print "Unexpected error:", sys.exc_info()[0]
        raise

def mac(filename):
    # filename - name of the file used to generate the hmac
    # print the resulting file containing the hmac
    try:
        print "[?] Enter key:",
        key = raw_input()

        m = hmac.new(key, None, hashlib.sha256) # key, message, algorithm

        with open(filename, 'r') as f:
            for piece in read_chunk(f):
                m.update(piece)
        f.close()

        # generate the asn1 structure for sha256
        asn1_digest = asn1_sequence(asn1_sequence(asn1_objectidentifier([2,16,840,1,101,3,4,2,1]) + asn1_null()) + asn1_octetstring(m.digest()))

        with open(filename+".hmac", 'w+') as f:
            f.write(asn1_digest)    # write the digest in asn1 encoding to filename.hmac
        f.close()

        print "[+] Writing HMAC DigestInfo to", filename+".hmac"

    except IOError as e:
        print "I/O error({0}): ({1})".format(e.errno, e.strerror)
    except:
        print "Unexpected error:", sys.exc_info()[0]
        raise


def usage():
    print "Usage:"
    print "-verify <filename>"
    print "-mac <filename>"
    sys.exit(1)

if len(sys.argv) != 3:
    usage()
elif sys.argv[1] == '-mac':
    mac(sys.argv[2])
elif sys.argv[1] == '-verify':
    verify(sys.argv[2])
else:
    usage()
