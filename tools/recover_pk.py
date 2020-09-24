#!/usr/bin/env python3

# @doegox -- 2020

import sslcrypto
import binascii
import sys

debug = False

def recover(data, signature):
    recovered = set()
    alghash = None
    if len(signature) == 32:
        curve = sslcrypto.ecc.get_curve("secp128r1")
        recoverable = False
    elif len(signature) == 33:
        curve = sslcrypto.ecc.get_curve("secp128r1")
        recoverable = True
    elif len(signature) == 56:
        curve = sslcrypto.ecc.get_curve("secp224r1")
        recoverable = False
    elif len(signature) == 57:
        curve = sslcrypto.ecc.get_curve("secp224r1")
        recoverable = True
    else:
        print("Unsupported signature size %i" % len(signature))
        exit(1)

    if (recoverable):
        try:
            pk = curve.recover(signature, data, hash=alghash)
            recovered.add(pk)
            if debug:
                print("Possible Pk:    ", binascii.hexlify(pk))
        except:
            pass
    else:
        for i in range(2):
            # Brute force RECID
            recid = bytes([27+i])
            try:
                pk = curve.recover(recid + signature, data, hash=alghash)
                recovered.add(pk)
                if debug:
                    print("Possible Pk:    ", binascii.hexlify(pk))
            except:
                pass
    return recovered

if len(sys.argv) < 3 or len(sys.argv) % 2 == 0:
    print("Usage:   \n%s UID SIGN [UID SIGN] [...]" % sys.argv[0])
    print("Example: \n%s 04ee45daa34084 ebb6102bff74b087d18a57a54bc375159a04ea9bc61080b7f4a85afe1587d73b" % sys.argv[0])
    exit(1)

recovered = set()
for i in range(1, len(sys.argv), 2):
    data = binascii.unhexlify(sys.argv[i])
    if debug:
        print("UID       (%2i): " %  len(data), binascii.hexlify(data))
    signature = binascii.unhexlify(sys.argv[i+1])
    if debug:
        print("Signature (%2i): " % len(signature), binascii.hexlify(signature))
    recovered_tmp = recover(data, signature)
    if i == 1:
        if recovered_tmp == set():
            break
        else:
            recovered = recovered_tmp
    else:
        recovered &= recovered_tmp

print("Possible uncompressed Pk(s):")
for pk in list(recovered):
    print(binascii.hexlify(pk).decode('utf8'))
