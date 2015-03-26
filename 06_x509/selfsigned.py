#!/usr/bin/env python

import argparse, hashlib, os, sys # do not use any other imports/libraries
from pyasn1.codec.der import decoder

# parse arguments
parser = argparse.ArgumentParser(description='generate self-signed X.509 CA certificate', add_help=False)
parser.add_argument("private_key_file", help="Private key file (in PEM or DER form)")
parser.add_argument("output_cert_file", help="File to store self-signed CA certificate (PEM form)")
args = parser.parse_args()

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
        # print '+ Processing PEM public key...'
        pem = content[27:-26]
        # print pem
        der = pem.decode('base64')
        # print der
        return der 
    elif 'BEGIN RSA PRIVATE KEY' in content: # pem private key
        # print '+ Processing PEM private key...'
        pem = content[32:-31]
        # print pem
        der = pem.decode('base64')
        # print der
        return der
    else:
        # print '+ Processing DER key...'
        return content

def get_pubkey(filename):
    # reads private key file and returns (n, e)
    pubkey_der = ''

    # read the keyfile
    with open(filename, 'r') as f:
        pubkey_der = f.read()
    f.close()

    # assume the key is on PEM
    pubkey_der = pem_to_der(pubkey_der)

    # decode the der structure
    pubkey_der = decoder.decode(pubkey_der)

    return int(pubkey_der[0][1]), int(pubkey_der[0][2])

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

def digestinfo_der(data):
    # returns ASN.1 DER encoded DigestInfo structure containing SHA1 digest of file
    der = ''
    # hash algorithm used SHA-1
    digestHash = hashlib.sha1()
    digestHash.update(data)
    # generate DER structure of digest info
    der = asn1_sequence(asn1_sequence(asn1_objectidentifier([1,3,14,3,2,26]) + asn1_null()) + asn1_octetstring(digestHash.digest()))

    return der

def sign(keyfile, data):

    s = ''
    digestinfo = ''
    plaintext = ''
    privkey = []

    # get private key n, d
    privkey = get_privkey(keyfile)
    # print '*************** PRIVATE KEY ********************'
    # print privkey

    # get digest info structure in der
    digestinfo = digestinfo_der(data)
    # print '*************** DIGESTINFO STRUCTURE ********************'
    # print digestinfo

    # pkcsv15pad to digest info
    plaintext = pkcsv15pad_sign(digestinfo, privkey[0])
    # print '*************** DIGESTINFO STRUCTURE + PADDING ********************'
    # print plaintext

    # convert padded bytestring to int
    plaintext = bytestring_to_int(plaintext)
    # print '*************** MESSAGE IN INTEGER ********************'
    # print plaintext

    # compute signature s = md mod n
    s = pow(plaintext, privkey[1], privkey[0])
    # print '*************** SIGNATURE IN INTEGER ********************'
    # print s

    # convert signature int to bytestring
    s = int_to_bytestring(s)
    # print '*************** SIGNATURE IN BYTESTRING ********************'
    # print s

    # check len of resulting bytestring and compare to modulus n
    n_len = len(int_to_bytestring(privkey[0]))

    # print len(s)
    if len(s) < n_len:
        s = chr(0x00) * (n_len - len(s)) + s

    # return the signature
    return s

def x509_name(country, organization, ou, cn):
    # country, organization, ou, cn string values
    # return the der structure of the issuer
    issuer = ''
    issuerCountry = asn1_sequence(asn1_objectidentifier([2,5,4,6]) + asn1_printablestring(country))
    issuerOrganization = asn1_sequence(asn1_objectidentifier([2,5,4,10]) + asn1_printablestring(organization))
    issuerOU = asn1_sequence(asn1_objectidentifier([2,5,4,11]) + asn1_printablestring(ou))
    issuerCN = asn1_sequence(asn1_objectidentifier([2,5,4,3]) + asn1_printablestring(cn))
    issuer = asn1_sequence(asn1_set(issuerCountry + issuerOrganization + issuerOU + issuerCN))
    return issuer

def x509_time():
    # return a time 
    # hardcoded here but can be calculated with import datetime
    time = ''
    notBefore = '150101000000Z' 
    notAfter =  '160101000000Z'
    time = asn1_sequence(asn1_utctime(notBefore) + asn1_utctime(notAfter))

    return time

def selfsigned(privkey, certfile):
    # create x509v3 self-signed CA root certificate
    pem = ''
    der = ''
    certificate = ''

    # get public key (n, e) from private key file
    n, e = get_pubkey(privkey)
    # print n, e

    # construct subjectPublicKeyInfo from public key values (n, e)
    # create n, e bitstring DER structure 
    SubPubKeyInfoBitstring = asn1_sequence(asn1_integer(n) + asn1_integer(e))
    # create bitstring of past structure
    SubPubKeyInfoBitstring = ''.join('{:08b}'.format(ord(x), 'b') for x in SubPubKeyInfoBitstring)
    SubjectPublicKeyInfo = asn1_sequence(asn1_sequence(asn1_objectidentifier([1,2,840,113549,1,1,1]) + asn1_null()) + asn1_bitstring(str(SubPubKeyInfoBitstring)))

    # construct tbsCertificate structure
    version = asn1_tag_explicit(asn1_integer(2), 0)
    serialNumber = asn1_integer(1)
    signature = asn1_sequence(asn1_objectidentifier([1,2,840,113549,1,1,5]) + asn1_null())
    issuer = x509_name('MX', 'University of Tartu', 'IT dep', 'Cesar Root CA')
    validity = x509_time()
    subject = x509_name('MX', 'University of Tartu', 'IT dep', 'Cesar Root CA')
    # extension - basic constraints
    basicConstraints = asn1_sequence(asn1_boolean(True))
    basicConstraints_ext = asn1_sequence(asn1_objectidentifier([2,5,29,19]) + asn1_boolean(True) + asn1_octetstring(basicConstraints))
    # extension - key usage
    keyUsage = '00000110'
    keyUsage = asn1_bitstring(keyUsage)
    keyUsage_ext = asn1_sequence(asn1_objectidentifier([2,5,29,15]) + asn1_boolean(True) + asn1_octetstring(keyUsage))
    # create extension structure
    extension = asn1_sequence(basicConstraints_ext + keyUsage_ext)
    extensions = asn1_tag_explicit(extension , 3)

    # TBSCertificate structure
    tbsCertificate = asn1_sequence(version + serialNumber + signature + issuer + validity + subject + SubjectPublicKeyInfo + extensions)

    # sign tbsCertificate structure
    signature = sign(privkey, tbsCertificate)
    signatureValue = ''.join('{:08b}'.format(ord(x) , 'b') for x in signature)
    signatureValue = asn1_bitstring(signatureValue)

    # signature algorithm
    signatureAlg = asn1_sequence(asn1_objectidentifier([1,2,840,113549,1,1,5]) + asn1_null())

    # construct final X.509 DER
    certificate = asn1_sequence(tbsCertificate + signatureAlg + signatureValue)

    # convert to PEM by .encode('base64') and adding PEM headers
    pem = '-----BEGIN CERTIFICATE-----\n' + certificate.encode('base64') + '-----END CERTIFICATE-----\n'

    # write PEM certificate to file
    with open(certfile, 'w+') as f:
        f.write(pem)
    f.close()

selfsigned(args.private_key_file, args.output_cert_file)
