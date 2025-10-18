#!/usr/bin/env python3

# Library of the SUNCMAC recovery script.
# Compute, verify and brute-force SUNCMAC using AES-128 CMAC.
#
# Requirements:
#   pip install cryptography
#
# doegox & noproto, 2025
# cf "BREAKMEIFYOUCAN!: Exploiting Keyspace Reduction and Relay Attacks in 3DES and AES-protected NFC Technologies"
# for more info

import sys
import time
import multiprocessing
import queue
from itertools import combinations
from math import comb

try:
    from cryptography.hazmat.primitives.cmac import CMAC
    from cryptography.hazmat.primitives.ciphers import algorithms
except ImportError:
    print("\n\nERROR: Due to a limitation of the Proxmark3 client, this script can be run only once.")
    print("Please restart the Proxmark3 client")
    sys.exit(1)


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


def count_words_with_k_bits_set(n_bits, max_bits_set, mask=0):
    """Count all n-bit words with up to max_bits_set bits set, respecting a mask."""

    non_masked_positions = [pos for pos in range(n_bits) if not (mask & (1 << pos))]
    n_available = len(non_masked_positions)

    count = 1  # Count the zero word
    for k in range(1, min(max_bits_set + 1, n_available + 1)):
        count += comb(n_available, k)

    return count


def sliced_enumerate_words_with_k_bits_set(n_bits, max_bits_set, slice_index=0, total_slices=1, mask=0):
    """Generate slice idx over tot slices of all n-bit words with up to max_bits_set bits set, respecting a mask."""
    non_masked_positions = [pos for pos in range(n_bits) if not (mask & (1 << pos))]
    n = 0
    if n % total_slices == slice_index:
        yield 0
    for k in range(1, max_bits_set + 1):
        for bits in combinations(non_masked_positions, k):
            n += 1
            value = 0
            for pos in bits:
                value |= (1 << pos)
            if n % total_slices == slice_index:
                yield value


def compute_suncmac(key, uid, counter):
    """Compute SUNCMAC over data using a 16-byte key.

    Returns the 8-byte SUNCMAC tag.
    """
    # 7-byte UID
    # 3-byte NFC counter value
    # 5-byte Tag Tamper information (only for StatusDetect IC version)
    # => 8-byte SUNCMAC

    key = bytes.fromhex(key)
    uid = bytes.fromhex(uid)
    counter = bytes.fromhex(counter)
    if len(key) != 16:
        raise ValueError("Key must be 16 bytes for AES-128")
    c = CMAC(algorithms.AES(key))
    c.update(uid + counter)
    return f"{uid.hex().upper()}x{counter.hex().upper()}x{c.finalize()[1::2].hex().upper()}"


def verify_suncmac(key, msg):
    """Verify SUNCMAC over ASCII msg using a 16-byte key."""
    if type(key) is str:
        key = bytes.fromhex(key)
    elif type(key) is int:
        key = key.to_bytes(16, byteorder='big')
    if len(key) != 16:
        raise ValueError("Key must be 16 bytes for AES-128")
    msg = msg.split("x")
    if len(msg) == 4:
        msg[2] = msg[2][:2].replace("C", "3").replace("O", "F").replace("I", "9") + msg[2][2:]
    data = bytes.fromhex(''.join(msg))
    their_tag = data[-8:]
    c = CMAC(algorithms.AES(key))
    c.update(data[:-8])
    my_tag = c.finalize()[1::2]
    return their_tag == my_tag


def bruteforce_suncmac(start_key, msg, segment, xor=False, candidates=2**32):
    """Bruteforce SUNCMAC over ASCII msg over one full segment."""

    def worker_task(task_queue, start_key, result, result_index, stop_flag):
        while not stop_flag.value:
            try:
                start, end = task_queue.get_nowait()
            except queue.Empty:
                return
            for i in range(start, end):
                if stop_flag.value:
                    return
                candidate = start_key ^ (i << (32 * (3 - segment)))
                candidate = candidate.to_bytes(16, byteorder='big')
                c = CMAC(algorithms.AES(candidate))
                c.update(data)
                if c.finalize()[1::2] == their_tag:
                    with result.get_lock():
                        result.value = i
                    with result_index.get_lock():
                        result_index.value = i - start
                    with stop_flag.get_lock():
                        stop_flag.value = True
                    return

    def parallel_bruteforce(start_key, num_processes):
        chunk_size = 2**20  # Define a smaller chunk size
        result = multiprocessing.Value('I', 0xFFFFFFFF)
        result_index = multiprocessing.Value('I', 0xFFFFFFFF)
        stop_flag = multiprocessing.Value('b', False)
        task_queue = multiprocessing.Queue()

        # Populate the task queue with chunks
        print(f"Adding {candidates} candidates to the task queue in {candidates // chunk_size} chunks of {chunk_size}")
        for i in range(0, candidates, chunk_size):
            task_queue.put((i, min(i + chunk_size, candidates)))

        # Start worker processes
        processes = []
        for _ in range(num_processes):
            process = multiprocessing.Process(target=worker_task,
                                              args=(task_queue, start_key, result, result_index, stop_flag))
            processes.append(process)
            process.start()

        for process in processes:
            process.join()

        # Ensure the queue is emptied
        while not task_queue.empty():
            task_queue.get_nowait()
        task_queue.close()
        task_queue.join_thread()

        return (result.value, result_index.value) if result.value != 0xFFFFFFFF else (None, None)

    if type(start_key) is str:
        start_key = int(start_key, 16)
    elif type(start_key) is bytes:
        start_key = int.from_bytes(start_key, byteorder='big')
    msg = msg.split("x")
    if len(msg) == 4:
        msg[2] = msg[2][:2].replace("C", "3").replace("O", "F").replace("I", "9") + msg[2][2:]
    msg = bytes.fromhex(''.join(msg))
    their_tag = msg[-8:]
    data = msg[:-8]
    num_processes = multiprocessing.cpu_count()
    print(f"Using {num_processes} processes for bruteforce")
    if not xor:
        # Erase segment in start_key
        start_key &= ~((0xFFFFFFFF) << (32 * (3 - segment)))
    start_time = time.perf_counter()
    result, result_index = parallel_bruteforce(start_key, num_processes)
    end_time = time.perf_counter()
    if result is not None:
        key = start_key ^ (result << (32 * (3 - segment)))
        print(f"Found matching tag for k={key:032X}")
    else:
        print("No matching tag found")
    if result_index is None:
        result_index = candidates // num_processes
    print(f"Execution time: {end_time - start_time:.2f} seconds")
    print(f"Average execution time on one segment (2**31): "
          f"{(end_time - start_time)/result_index/num_processes*2**31/60:.2f} minutes")


def bruteforce_suncmac_low_hw(start_key, msg, segment, n_bits=32, bitflips=7, quiet=False):
    """Bruteforce SUNCMAC over ASCII msg over one segment, starting with low hw candidates."""

    if verify_suncmac(start_key, msg):
        return start_key, 1

    def worker_task(slice_index, start_key, result, result_index, stop_flag):
        for n, i in enumerate(sliced_enumerate_words_with_k_bits_set(n_bits, bitflips, slice_index,
                                                                     num_processes, mask=0)):
            if stop_flag.value:
                return
            candidate = start_key ^ (i << (32 * (3 - segment)))
            candidate = candidate.to_bytes(16, byteorder='big')
            c = CMAC(algorithms.AES(candidate))
            c.update(data)
            if c.finalize()[1::2] == their_tag:
                with result.get_lock():
                    result.value = i
                with result_index.get_lock():
                    result_index.value = n
                with stop_flag.get_lock():
                    stop_flag.value = True
                return

    def parallel_bruteforce(start_key, num_processes):
        result = multiprocessing.Value('I', 0xFFFFFFFF)
        result_index = multiprocessing.Value('I', 0xFFFFFFFF)
        stop_flag = multiprocessing.Value('b', False)

        # Start worker processes
        processes = []
        for slice_index in range(num_processes):
            process = multiprocessing.Process(target=worker_task,
                                              args=(slice_index, start_key, result, result_index, stop_flag))
            processes.append(process)
            process.start()

        for process in processes:
            process.join()

        return (result.value, result_index.value) if result.value != 0xFFFFFFFF else (None, None)

    if type(start_key) is str:
        start_key = int(start_key, 16)
    elif type(start_key) is bytes:
        start_key = int.from_bytes(start_key, byteorder='big')
    msg = msg.split("x")
    if len(msg) == 4:
        msg[2] = msg[2][:2].replace("C", "3").replace("O", "F").replace("I", "9") + msg[2][2:]
    msg = bytes.fromhex(''.join(msg))
    their_tag = msg[-8:]
    data = msg[:-8]
    num_processes = multiprocessing.cpu_count()
    if not quiet:
        print(f"Using {num_processes} processes for bruteforce")
    start_time = time.perf_counter()
    result, result_index = parallel_bruteforce(start_key, num_processes)
    end_time = time.perf_counter()
    if not quiet:
        print(f"Execution time: {end_time - start_time:.2f} seconds")
    if result is not None and result_index is not None:
        key = start_key ^ (result << (32 * (3 - segment)))
        if not quiet:
            print(f"Found matching tag for k={key:032X} at distance {hamming_distance(key, start_key):d}")
            print(f"Average speed: "
                  f"{(result_index + 1) * num_processes / (end_time - start_time):.2f} keys/second")
        return key, (result_index + 1) * num_processes
    else:
        if not quiet:
            print("No matching tag found")
        return None, count_words_with_k_bits_set(n_bits, bitflips, mask=0)


if __name__ == "__main__":
    print("Running self-tests...")
    n_bits, max_bits_set, mask = 32, 5, 0
    assert len(list(enumerate_words_with_k_bits_set(n_bits, max_bits_set, mask=mask))) == \
        count_words_with_k_bits_set(n_bits, max_bits_set, mask=mask)
    n_bits, max_bits_set, mask = 32, 5, 0b1100110011001100110011001100110011001100110011001100110011001100
    assert len(list(enumerate_words_with_k_bits_set(n_bits, max_bits_set, mask=mask))) == \
        count_words_with_k_bits_set(n_bits, max_bits_set, mask=mask)

    # Test vectors from AN12998
    key = "00000000000000000000000000000000"
    uid = "04AA2BD2335780"
    counter = "000001"
    assert compute_suncmac(key, uid, counter) == "04AA2BD2335780x000001xB188AC6F69140B92"
    assert verify_suncmac(key, "04AA2BD2335780x000001xB188AC6F69140B92")
    uid = "04C767F2066180"
    counter = "000003"
    assert compute_suncmac(key, uid, counter) == "04C767F2066180x000003x3779793DFE592188"
    assert verify_suncmac(key, "04C767F2066180x000003x3779793DFE592188")

    # change third segment
    key = "2b7e151628aed2a6abf7158809cf4f3c"
    msg = compute_suncmac(key, uid, counter)
    assert verify_suncmac(key, msg)
    start_key = "2b7e151628aed2a6abf7158809caffff"
    bruteforce_suncmac(start_key, msg, segment=3, xor=True)
    start_key = "2b7e151628aed2a6abf7158848cf6efd"
    bruteforce_suncmac_low_hw(start_key, msg, segment=3)

    # NTAG 223 StatusDetect, real tag
    # Set mirror config
    # hf 14a raw -skc a229803D043C
    # hf 14a raw -c a22a83000000
    # Read mirror
    # hf 14a raw -sc 3a0410
    # => 046910EA841390x000000xCO00000000x146F1F74FFB89569
    key = "00000000000000000000000000000000"
    msg = "046910EA841390x000000xCO00000000x146F1F74FFB89569"
    assert verify_suncmac(key, msg)
    # Set mirror config: don't show CTT/STORED_TT/ACT_TT data in mirror
    # hf 14a raw -skc a229803C043C
    # hf 14a raw -c a22a80000000
    # hf 14a raw -sc 3a0410
    # => 046910EA841390x000000x0000000000x887DBC0298EF2755
    msg = "046910EA841390x000000x0000000000x887DBC0298EF2755"
    assert verify_suncmac(key, msg)
    # Set default key
    # hf 14a raw -skc a2343c4fcf09
    # hf 14a raw -kc a2358815f7ab
    # hf 14a raw -kc a236a6d2ae28
    # hf 14a raw -c a23716157e2b
    # hf 14a raw -sc 3a0410
    # => 046910EA841390x000000x0000000000x17B5B634CAAA9BB8
    key = "2b7e151628aed2a6abf7158809cf4f3c"
    msg = "046910EA841390x000000x0000000000x17B5B634CAAA9BB8"
    assert verify_suncmac(key, msg)
    start_key = "2b7e151628aed2a6abf7158809caffff"
    bruteforce_suncmac(start_key, msg, segment=3, xor=True)

    # Preparing NDEF http://www.foo.bar?uid=
    # hf 14a raw -skc a2040342d101
    # hf 14a raw -kc a2053e550166
    # hf 14a raw -kc a2066F6F2E62
    # hf 14a raw -kc a20761723F75
    # hf 14a raw -kc a20869643D00
    # CFG_0: CFG_B0=MIRROR_EN|MIRROR_BYTE=3 TT MIRROR_PAGE=8 AUTH0
    # hf 14a raw -kc a229983C083C
    # CFG_1: CFG_B1=PROT
    # hf 14a raw -kc a22a80000000
    # Key default AES
    # hf 14a raw -kc a2343c4fcf09
    # hf 14a raw -kc a2358815f7ab
    # hf 14a raw -kc a236a6d2ae28
    # hf 14a raw -c a23716157e2b
    # hf mfu ndefread
    # http://www.foo.bar?uid=048A0FEA841390x000000x0000000000x1A797B9096B03021
    # hf 14a raw -sc 3a1114
    # 31 41 37 39 37 42 39 30 39 36 42 30 33 30 32 31
    # 1A797B9096B03021
    key = "2b7e151628aed2a6abf7158809cf4f3c"
    msg = "048A0FEA841390x000000x0000000000x1A797B9096B03021"
    assert verify_suncmac(key, msg)
