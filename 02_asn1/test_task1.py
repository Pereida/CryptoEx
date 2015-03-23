#!/usr/bin/env python
import sys, os, hashlib

### must be executed from directory where asn1_task1.py resides

error = 0
asn1name = "asn1.der.produced"

try:
    os.remove(asn1name)
except:
    pass


dername = "asn1.der.expected"

# write DER structure that we expect to obtain
der = """
a07230703110020105a204020200c8ab05020300ff7f0101ff030205c00433
00010202020202020202020202020202020202020202020202020202020202
0202020202020202020202020202020202020202050006072a864886f70d01
130668656c6c6f2e170d3135303232333031303930305a
"""
open(dername, 'w').write(der.replace("\n","").decode('hex'))

sys.argv = ["", asn1name]
from asn1_task1 import *

# check if output DER created
if not os.path.isfile(asn1name):
    print "[-] No output DER produced!"
    error = 1
else:
    # check if matches expected
    digest_produced = hashlib.sha1(open(asn1name).read()).digest().encode('hex')
    digest_expected = hashlib.sha1(open(dername).read()).digest().encode('hex')
    if digest_produced != digest_expected:
        print "[-] Produced DER file does not match expected!"
        os.system("dumpasn1 " + dername + " > der.expect")
        os.system("dumpasn1 " + asn1name + " > der.produced")
        os.system("diff -u der.expect der.produced")
        error = 1


def test_der(fname, args, expected):
    global error
    try:
        der = globals()[fname](*args)
        derhex = der.encode('hex')
        if derhex != expected:
            print "[-] %s(%s): Expected '%s' got '%s'" % (fname, repr(args)[:40], expected, derhex)
            error = 1
        return der
    except:
        print "[-] Failed to execute: %s(%s)" % (fname, repr(args)[:40])
        error = 1


test_der("asn1_len", [""], "00")
test_der("asn1_len", ["1"], "01")
test_der("asn1_len", ["   126"*21], "7e")
test_der("asn1_len", [" 128"*32], "8180")
test_der("asn1_len", ["     65540"*6554], "83010004")

test_der("asn1_boolean", [True], "0101ff")
test_der("asn1_boolean", [False], "010100")
test_der("asn1_octetstring", ["\x00hohoho"], "040700686f686f686f")
test_der("asn1_null", [], "0500")
test_der("asn1_sequence", [asn1_null()], "30020500")
test_der("asn1_set", [asn1_null()], "31020500")
test_der("asn1_printablestring", ["foo"], "1303666f6f")
test_der("asn1_utctime", ["120929010100Z"], "170d3132303932393031303130305a")
test_der("asn1_tag_explicit", [asn1_null(), 0], "a0020500")
test_der("asn1_tag_explicit", [asn1_null(), 4], "a4020500")
test_der("asn1_tag_explicit", [asn1_null(), 30], "be020500")
test_der("asn1_integer", [0], "020100")
test_der("asn1_integer", [1], "020101")
test_der("asn1_integer", [127], "02017f")
test_der("asn1_integer", [128], "02020080")
test_der("asn1_integer", [255], "020200ff")
test_der("asn1_integer", [256], "02020100")
test_der("asn1_integer", [32767], "02027fff")
test_der("asn1_integer", [32768], "0203008000")
#test_der("asn1_integer", [-1], "0201ff")
#test_der("asn1_integer", [-2], "0201fe")
#test_der("asn1_integer", [-128], "020180")
#test_der("asn1_integer", [-129], "0202ff7f")
#test_der("asn1_integer", [-130], "0202ff7e")
#test_der("asn1_integer", [-1000000], "0203f0bdc0")
test_der("asn1_objectidentifier", [[1,2]], "06012a")
test_der("asn1_objectidentifier", [[1,2,840]], "06032a8648")
test_der("asn1_objectidentifier", [[1,2,840,5,1000000]], "06072a864805bd8440")
test_der("asn1_objectidentifier", [[1,2,840,5,127,128,129]], "06092a8648057f81008101")
test_der("asn1_bitstring", [""], "030100")
test_der("asn1_bitstring", ["0"], "03020700")
test_der("asn1_bitstring", ["1"], "03020780")
test_der("asn1_bitstring", ["101010"], "030202a8")
test_der("asn1_bitstring", ["0011111111"], "0303063fc0")
test_der("asn1_bitstring", ["0011111111000000"], "0303003fc0")

if error:
    print "[-] Some of the tests failed!"
else:
    print "[+] All tests succeeded!"

sys.exit(error)