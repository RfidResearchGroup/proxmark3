# Requirements:
# python3 -m pip install pyamiibo

import sys
from amiibo import AmiiboDump, AmiiboMasterKey

def main():
    if(len(sys.argv) != 5):
        print("""
    \t{0} - helper script for integrating with PyAmiibo

    Usage: {0} <uid> <infile> <outfile> <keyfile>

    Example:

    \t{0} 04123456789ABC my_amiibo_original.bin my_amiibo_with_new_uid.bin keyfile.bin

    \n""".format(sys.argv[0]))
        return 1

    uid = sys.argv[1]
    infile = sys.argv[2]
    outfile = sys.argv[3]
    keyfile = sys.argv[4]

    if len(uid) != 14:
        print('expecting 7 byte UID')
        return 1

    with open(keyfile, 'rb') as keybin:
        master_key = AmiiboMasterKey.from_combined_bin(keybin.read())

    with open(infile, 'rb') as fin, open(outfile, 'wb') as fout:
        dump = AmiiboDump(master_key, fin.read(), is_locked=True)
        dump.unlock()
        dump.uid_hex = uid
        dump.lock()
        fout.write(dump.data)

    return 0

if __name__ == "__main__":
    sys.exit(main())

