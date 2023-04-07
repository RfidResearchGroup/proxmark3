#!/usr/bin/env python3

'''

# pm3_online_check.py
# Christian Herrmann, Iceman,  <iceman@icesql.se> 2020
# version = 'v1.0.5'
#
#  This code is copyright (c) Christian Herrmann, 2020, All rights reserved.
#  For non-commercial use only, the following terms apply - for all other
#  uses, please contact the author:
#
#    This code is free software; you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation; either version 3 of the License, or
#    (at your option) any later version.
#
#    This code is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#
# Dependencies:
#
# pip3 install pexpect ansicolors
#
'''
import pexpect
from colors import color
import requests
import string
import re
import time
import argparse

def pm3_flashbootrom():
    flbootrom = pexpect.spawnu('./pm3-flash-bootrom')
    flbootrom.expect(pexpect.EOF)
    msg = escape_ansi(str(flbootrom.before))
    if 'Have a nice day!'.lower() in msg:
        print("Flashing bootrom ", color('[OK]', fg='green'))
    else:
        print("Flashing bootrom ", color('[FAIL]', fg='red'))

    time.sleep(20)

def pm3_flashfullimage():
    flimage = pexpect.spawnu('./pm3-flash-fullimage')
    flimage.expect(pexpect.EOF)
    msg = escape_ansi(str(flimage.before))
    if 'Have a nice day!'.lower() in msg:
        print("Flashing fullimage ", color('[OK]', fg='green'))
    else:
        print("Flashing fullimage ", color('[FAIL]', fg='red'))

    time.sleep(20)

def escape_ansi(line):
    ansi_escape = re.compile(r'(\x9B|\x1B\[)[0-?]*[ -/]*[@-~]')
    return ansi_escape.sub('', str(line)).lower()

def pm3_initrdv4(child):
    child.sendline('script run init_rdv4')
    i = child.expect('pm3 --> ')

    msg = escape_ansi(str(child.before))
    if 'finished init_rdv4'.lower() in msg:
        print("Init RDV4 ", color('[OK]', fg='green'))
    else:
        print("Init RDV4 ", color('[FAIL]', fg='red'))

# LF T55x7 wipe/clone/read/wipe test
def pm3_lf_t55xx(child):

    try:
        print("[=] starting lf t55xx tests...")

        # wipe t55xx
        child.sendline('lf t55xx wipe')
        i = child.expect('pm3 --> ')

        msg = escape_ansi(str(child.before))
        if 'Writing page 0  block: 07  data: 0x00000000'.lower() in msg:
            print("[+] LF T55XX WIPE ", color('[OK]', fg='green'))
        else:
            print("[-] LF T55XX WIPE ", color('[FAIL]', fg='red'))

        # clone HID
        child.sendline('lf hid clone -r 2006ec0c86')
        i = child.expect('pm3 --> ')

        msg = escape_ansi(str(child.before))
        if 'Done'.lower() in msg:
            print("[+] LF HID CLONE ", color('[OK]', fg='green'))
        else:
            print("[-] LF HID CLONE ", color('[FAIL]', fg='red'))

        # read HID
        child.sendline('lf hid read')
        i = child.expect('pm3 --> ')

        msg = escape_ansi(str(child.before))
        if "HID H10301 26-bit;  FC: 118  CN: 1603    parity: valid".lower() in msg:
            print("[+] LF HID READ ", color('[OK]', fg='green'))
        else:
            print("[-] LF HID READ ", color('[FAIL]', fg='red'))

        # wipe t55xx
        child.sendline('lf t55xx wipe')
        i = child.expect('pm3 --> ')
        return True

    except:
        print(color("[!] exception for LF T55XX", fg='red'))
        msg = escape_ansi(str(child.before))
        print(msg)
        child.sendline('quit')
        child.expect(pexpect.EOF)
        return False

def pm3_flash_sm(child):
    try:
        print("[+] Updating smart card fw")
        child.sendline('smart upgrade -f sim013.bin')
        i = child.expect('pm3 --> ')
        msg = escape_ansi(str(child.before))
        print("================")
        print(" smart card upgrade")
        print("==== msg ========")
        print(msg)
        if "successful" in msg:
            print("[+] Smart card firmware upgrade ", color('[OK]', fg='green'))
            return True
        else:
            print("[-] Smart card firmware upgrade ", color('[FAIL]', fg='red'))
            return False
    except:
        print(color("[!] exception for SMART UPGRADE", fg='red'))
        msg = escape_ansi(str(child.before))
        print(msg)
        child.sendline('quit')
        child.expect(pexpect.EOF)
        return False

def main():

    parser = argparse.ArgumentParser()
    parser.add_argument("--flash", help="flash bootrom & fullimage", action="store_true")
    parser.add_argument("--init", help="run init rdv4 script", action="store_true")
    parser.add_argument("-y", help="automatic yes to prompts", action="store_true")
    args = parser.parse_args()

    print("-----------", color('Proxmark3 online test script v1.0.3', fg='cyan'), "------------")
    print("This script will run some series of test against a connected Proxmark3 device")
    print("Steps:");
    print(" 1. flash bootrom, fullimage");
    print(" 2. init_rdv4 / flash smartcard");
    print(" 3. check device mismatch message");
    print(" 4. check smart card fw,  flash memory");
    print("    if needed, flash flash smartcard reader firmware");
    print(" 5. check antenna tuning");
    print(" 6. check LF T55x7 functionality");
    print(" 7. check HF search");
    print(" 8. check SPIFFS");
    print(" 9. check HF iCLASS functionality");
    print("\n");

    # result
    res = 0
    total_tests = 12
    must_update_fw = 0
    msg = ''

    if args.flash:
        print("-----------------------", color('Flashing phase', fg='cyan'), "---------------------")
        print("flashing bootrom - don't touch the device or cables")
        pm3_flashbootrom()

        print("flashing fullimage - don't touch the device or cables")
        pm3_flashfullimage()
        print("\n")

    # start pm3
    child = pexpect.spawnu('./pm3')
    i = child.expect('pm3 --> ')
    print("[+] Proxmark3 client open")

    if args.init:
        print("------------------------", color('Init phase', fg='cyan'), "------------------------")
        print("Running init rdv4 script - don't touch the device or cables")
        pm3_initrdv4(child)
        print("flashing smartcard  - don't touch the device or cables")
        pm3_flash_sm(child)
        print("\n")

    print("------------------------", color('Test phase', fg='cyan'), "------------------------")


    # check device mismatch
    signature_msg = "device.................... RDV4".lower()

    # check flashmemory
    flash_mem = "baudrate................24 mhz".lower()

    # check smartcard fw version
    sm_version = "version.................v4.12".lower()

    # check LF
    lf_search = "valid hid prox id found!".lower()

    # check HF
    hf_search = "Valid iCLASS tag / PicoPass tag found".lower()

    # mem spiffs info
    mem_spiffs = "max path length............32 chars".lower()

    # lf antenna tuning
    lf_tune = "LF antenna is OK".lower()

    # hf antenna tuning
    hf_tune = "HF antenna is OK".lower()

    try:
        # HW VERSION checks
        child.sendline('hw version')
        i = child.expect('pm3 --> ')
        msg = escape_ansi(str(child.before))

        if signature_msg in msg:
            print("[+] RDV4 signature ", color('[OK]', fg='green'))
            res += 1
        else:
            print("[-] RDV4 signature ", color('[FAIL]', fg='red'))


        # HW STATUS checks
        child.sendline('hw status')
        i = child.expect('pm3 --> ')
        msg = escape_ansi(str(child.before))

        if sm_version in msg:
            print("[+] Smart card firmware version ", color('[OK]', fg='green'))
            res += 1
        else:
            print("[-] Smart card firmware version ", color('[FAIL]', fg='red'), " will upgrade fw in the next step")
            must_update_fw = 1

        if flash_mem in msg:
            print("[+] Flash memory accessible ", color('[OK]', fg='green'))
            res += 1
        else:
            print("[-] Flash memory accessible ", color('[FAIL]', fg='red'))

        # extract slow clock and verify its OK...
        # slow clock check:
        # Slow clock..............30057 Hz
        for line in msg.splitlines():
            match_slow = line.find('slow clock..............')

            if match_slow > -1:
                match = re.search(r'\d+', line)
                if match:
                    clock = int(match[0])
                    if clock < 29000:
                        print("[-] Warning, Slow clock too slow (%d Hz)" % (clock), color('[FAIL]', fg='red'))
                    elif clock > 33000:
                        print("[-] Warning, Slow clock too fast (%d Hz)" % (clock), color('[FAIL]', fg='red'))
                    else:
                        print("[+] Slow clock within acceptable range (%d Hz)" % (clock), color('[OK]', fg='green'))
                        res += 1
    except:
        print(color("[!] exception for HW STATUS", fg='red'))
        msg = escape_ansi(str(child.before))
        print(msg)
        child.sendline('quit')
        child.expect(pexpect.EOF)
        return

    if must_update_fw == 1:
        if pm3_flash_sm(child):
            res += 1

    try:
        print("[=] starting antenna tune tests,  this takes some time and plot window will flash up...")
        # HW TUNE checks
        child.sendline('hw tune')
        i = child.expect('pm3 --> ')

        msg = escape_ansi(str(child.before))
        if lf_tune in msg:
            print("[+] LF antenna tuning ", color('[OK]', fg='green'))
            res += 1
        else:
            print("[-] LF antenna tuning ", color('[FAIL]', fg='red'))

        if hf_tune in msg:
            print("[+] HF antenna tuning ", color('[OK]', fg='green'))
            res += 1
        else:
            print("[-] HF antenna tuning ", color('[FAIL]', fg='red'))

    except:
        print(color("[!] exception for hw tune", fg='red'))
        msg = escape_ansi(str(child.before))
        print(msg)
        child.sendline('quit')
        child.expect(pexpect.EOF)
        return

    # hide plot window again
    child.sendline('data hide')
    i = child.expect('pm3 --> ')

    ans = ''

    while ans != 'y' and args.y == False:

        ans = (input(color('>>> Put LF card and HF card on Proxmark3 antenna', fg='yellow') + '   [Y/n/q] ') or "y")

        if ans == 'q':
            child.sendline('quit')
            child.expect(pexpect.EOF)
            print('[!] Aborted all tests ', color('[USER ABORTED]', fg='red'))
            return

    # LF T55X7 WIPE/CLONE/READ TESTS
    if pm3_lf_t55xx(child):
        res += 1

    # HF SEARCH TESTS
    try:
        print("[=] starting HF SEARCH tests...")

        # HF SEARCH Test
        child.sendline('hf search')
        i = child.expect('pm3 --> ')

        msg = escape_ansi(str(child.before))
        if hf_search in msg:
            print("[+] HF SEARCH ", color('[OK]', fg='green'))
            res += 1
        else:
            print("[-] HF SEARCH ", color('[FAIL]', fg='red'))

    except:
        print(color("[!] exception for HF SEARCH", fg='red'))
        msg = escape_ansi(str(child.before))
        print(msg)
        child.sendline('quit')
        child.expect(pexpect.EOF)
        return

    # MEM Tree test
    child.sendline('mem spiffs info')
    i = child.expect('/', timeout=10)

    msg = escape_ansi(str(child.before))
    if mem_spiffs in msg:
        print("[+] MEM SPIFFS INFO ", color('[OK]', fg='green'))
        res += 1
    else:
        print("[-] MEM SPIFFS INFO ", color('[FAIL]', fg='red'))


    ans = ''
    while ans != 'y' and args.y == False:

        ans = (input(color('>>> Put iCLASS legacy card on Proxmark3 antenna', fg='yellow') + '   [Y/n/q] ') or "y")

        if ans == 'q':
            child.sendline('quit')
            child.expect(pexpect.EOF)
            print('[!] Aborted all tests ', color('[USER ABORTED]', fg='red'))
            return

    # iCLASS read/write test
    try:
        print("[=] starting iCLASS info/read/write tests...")
        child.sendline('hf iclass info')
        i = child.expect('pm3 --> ')

        # iclass info / read / write checks
        iclass_info = 'Credential... iCLASS legacy'.lower()

        iclass_ok = False
        msg = escape_ansi(str(child.before))
        if iclass_info in msg:
            print("[+] HF ICLASS INFO ", color('[OK]', fg='green'))
            res += 1
            iclass_ok = True
        else:
            print("[-] HF ICLASS INFO ", color('[FAIL]', fg='red'))

        if iclass_ok:

            child.sendline('hf iclass rdbl -b 10 --ki 0')
            i = child.expect('pm3 --> ')
            msg = escape_ansi(str(child.before))
            for line in msg.splitlines():
                iclass_read = 'block 10'.lower()
                if iclass_read in line:
                    res += 1
                    print("[+] HF ICLASS RDBL ", color('[OK]', fg='green'))
                    old_b10 = line[16:].replace(" ","")

                    child.sendline('hf iclass wrbl -b 10 --ki 0 -d 0102030405060708')
                    i = child.expect('pm3 --> ')
                    msg = escape_ansi(str(child.before))
                    iclass_write = 'wrote block 10 successful'.lower()
                    if iclass_write in msg:
                        res += 1
                        print("[+] HF ICLASS WRBL ", color('[OK]', fg='green'))
                        child.sendline('hf iclass wrbl -b 10 --ki 0 -d %s' % (old_b10))
                        i = child.expect('pm3 --> ')
                    else:
                        print("[-] HF ICLASS WRBL ", color('[FAIL]', fg='red'))

                    break;

        else:
            print("[-] skipping iclass read/write")

    except:
        print(color("[!] exception iCLASS read/write", fg='red'))
        msg = escape_ansi(str(child.before))
        print(msg)
        child.sendline('quit')
        child.expect(pexpect.EOF)
        return


    # exit Proxmark3 client
    child.sendline('quit')
    i = child.expect(pexpect.EOF)

    print("[+] PM3 client closed\n")

    # validate test results

    print("-------------------------", color('Results', fg='cyan'), "-------------------------")
    if res == total_tests:
        print('[+] Passed ',  color('[OK]', fg='green'))
    else:
        print('[-] failed test ',  color('[FAIL]', fg='red'), '(%d / %d tests)' % (res, total_tests))
    print("")

if __name__ == "__main__":
    main()
