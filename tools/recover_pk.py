#!/usr/bin/env python3

# @doegox -- 2020

import sslcrypto
import binascii
import sys

debug = False

def recover(data, signature, alghash=None):
    recovered = set()
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

def recover_multiple(uids, sigs, alghash=None):
    recovered = set()
    assert len(uids) == len(sigs)
    for i in range(len(uids)):
        data = binascii.unhexlify(uids[i])
        if debug:
            print("UID       (%2i): " %  len(data), binascii.hexlify(data))
        signature = binascii.unhexlify(sigs[i])
        if debug:
            print("Signature (%2i): " % len(signature), binascii.hexlify(signature))
        recovered_tmp = recover(data, signature, alghash)
        if i == 0:
            if recovered_tmp == set():
                break
            else:
                recovered = recovered_tmp
        else:
            recovered &= recovered_tmp
    return recovered

if len(sys.argv) < 3 or len(sys.argv) % 2 == 0:
    print("Usage:   \n%s UID SIGN [UID SIGN] [...]" % sys.argv[0])
    print("Example: \n%s 04ee45daa34084 ebb6102bff74b087d18a57a54bc375159a04ea9bc61080b7f4a85afe1587d73b" % sys.argv[0])
    exit(1)

print("Assuming no hash was used in the signature generation:")
recovered = recover_multiple(sys.argv[1:][::2], sys.argv[1:][1::2])
print("Possible uncompressed Pk(s):")
for pk in list(recovered):
    print(binascii.hexlify(pk).decode('utf8'))
print("Assuming SHA-256 was used in the signature generation:")
recovered = recover_multiple(sys.argv[1:][::2], sys.argv[1:][1::2], alghash="sha256")
print("Possible uncompressed Pk(s):")
for pk in list(recovered):
    print(binascii.hexlify(pk).decode('utf8'))
