#!/usr/bin/env python
import sys   # do not use any other imports/libraries
# Cesar Pereida
# It took around 9 hours of work

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
        return s	# return the string

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

def asn1_len(content):
    # helper function - should be used in other functions to calculate length octet(s)
    # content - bytestring that contains TLV content octet(s)
    # returns length (L) octet(s) for TLV
    
    # if the length is less than 128
    if len(content) < 128:
        return chr(len(content))
    else:		                        # else calculate the length in DER
        len_content = len(content)      # int length of the content
        len_bytes = int_to_bytestring(len_content)
        return chr(128 | len(len_bytes)) + len_bytes

def asn1_boolean(bool):
    # BOOLEAN encoder has been implemented for you
    if bool:
        bool = chr(0xff)
    else:
        bool = chr(0x00)
    return chr(0x01) + asn1_len(bool) + bool

def asn1_null():
    # returns DER encoding of NULL
    return chr(0x05) + chr(0x00)

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

def asn1_bitstring(bitstr):
    # bitstr - bytestring containing bitstring (e.g., "10101")
    # returns DER encoding of BITSTRING

    if bitstr == '':    # if bitstr == '' return 0x03 0x01 0x00
        return chr(0x03) + asn1_len(chr(0x00)) + chr(0x00)
    else:
        # len of the bitstr is the num of bits used
        bitstr_len = len(bitstr)
        
        # declare padding to 0
        padding = 0
        
        # if len modulo 8 is 0, no padding required
        if (bitstr_len % 8):
            # padding is the substraction 
            padding = 8 - (bitstr_len % 8)
        
        # convert the bitstr to int
        bitstr_bin = int(bitstr, 2)
    
        # convert from int padded to bytestring 
        bitstr_bin = int_to_bytestring(bitstr_bin << padding)

        # print test
        # print "Padding: " + chr(padding).encode('hex')
        # print "Bitstring: " + bitstr_bin.encode('hex')
        # print "Both: " + chr(padding).encode('hex') + " " + bitstr_bin.encode('hex')

        # return type, len and value
        return chr(0x03) + asn1_len(chr(padding) + bitstr_bin) + chr(padding) + bitstr_bin

def asn1_octetstring(octets):
    # octets - arbitrary byte string (e.g., "abc\x01")
    # returns DER encoding of OCTETSTRING

    return chr(0x04) + asn1_len(octets) + octets

def asn1_objectidentifier(oid):
    # oid - list of integers representing OID (e.g., [1,2,840,123123])
    # returns DER encoding of OBJECTIDENTIFIER
    
    first_octet_string = int_to_bytestring(40 * oid[0] + oid[1]) 

    val = ''

    for i in oid[2:]:
        val += int_to_base128_bytestring(i)

    return chr(0x06) + asn1_len(first_octet_string + val) + first_octet_string + val

def asn1_sequence(der):
    # der - DER bytestring to encapsulate into sequence
    # returns DER encoding of SEQUENCE
    return chr(0x30) + asn1_len(der) + der

def asn1_set(der):
    # der - DER bytestring to encapsulate into set
    # returns DER encoding of SET
    return chr(0x31) + asn1_len(der) + der

def asn1_printablestring(string):
    # string - bytestring containing printable characters (e.g., "foo")
    # returns DER encoding of PrintableString
    return chr(0x13) + asn1_len(string) + string

def asn1_utctime(time):
    # time - bytestring containing timestamp in UTCTime format (e.g., "121229010100Z")
    # returns DER encoding of UTCTime
    return chr(0x17) + asn1_len(time) + time

def asn1_tag_explicit(der, tag):
    # der - DER encoded bytestring
    # tag - tag value to specify in the type octet
    # returns DER encoding of original DER that is encapsulated in tag type 
    return chr(0xa0 | tag) + asn1_len(der) + der

def usage():
    print "Usage:"
    print "asn1_task.py <output key file>"
    sys.exit(1)

# figure out what to put in '...' by looking on ASN.1 structure required
asn1 = asn1_tag_explicit(asn1_sequence(
                            asn1_set(asn1_integer(5) + 
                            asn1_tag_explicit(
                                asn1_integer(200), 2) + 
                            asn1_tag_explicit(
                                asn1_integer(65407), 11)
                            ) 
                            + asn1_boolean(True) 
                            + asn1_bitstring("110") 
                            + asn1_octetstring('\x00\x01\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02'+
                                                '\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02'+
                                                '\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02') 
                            + asn1_null() 
                            + asn1_objectidentifier([1,2,840,113549,1]) 
                            + asn1_printablestring('hello.') 
                            + asn1_utctime('150223010900Z'))
                        , 0)

if len(sys.argv) != 2:
    usage()
else:
    # ouput file
    open(sys.argv[1], 'w').write(asn1)