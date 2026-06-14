#! /usr/bin/env python3.6
# -*- coding: utf-8 -*-
#
#  VULNERS OPENSOURCE
#  __________________
#
#  Vulners Project [https://vulners.com]
#  All Rights Reserved.
#
#  Author: Kir [isox@vulners.com]
#  Credits: Dennis Goh [dennis@rfidresearchgroup.com]
#
# This helper script is made for wiping S50 7byte UID cards with Gen2 magic commands from restored state to blank one.
#
# Scenario:
# You want to clone 7byte Mifare 1k card using RfidResearchGroup Proxmark3 RDV4.0
#
# Step 1: Dumping original card and making a Mifare 7byte UID clone using S50 7byte UID
#
# Place original card to the reader.
# Dump data and recover keys
#
# hf mf autopwn
#
# You will get data, EML and key file. Backup this file, you will need them to wipe the card back to blank state.
# Place blank S50 card to the reader.
#
# Get first line from EML file (block0) and write it down using command
#
#                                      Place it here
#                                            |
#                                            |
#                                            v
# hf mf wrbl --blk 0 -b -k FFFFFFFFFFFF -d 046E46AAA53480084400120111003113
#
# Now restore all the data using built-in restore command
#
# hf mf restore
#
# Step 2: Recovering S50 7byte UID card to the blank state
#
# Find current card data files from Step 1 in your backup or if you lost them create them again using 'hf mf autopwn' command.
# Place them in current working directory.
#
# Read hf-mf-CARD_UID-data.eml file and copy it content with CTRL-C.
# Place it to the eml variable in this script.
#
# Check execution command and check device and command name: 'proxmark3 -c "%s" /dev/tty.usbmodemiceman1'
#
# Run script and review key blocks returning to default FFFFFFFFFFFF state.
# Be patient! It is executing aprox 3 minutes.
# Success one result looks like:
#
# Block 0: Success: isOk:01
# Block 3: Success: isOk:01
# Block 7: Success: isOk:01
# Block 11: Success: isOk:01
# Block 15: Success: isOk:01
# Block 19: Success: isOk:01
# Block 23: Success: isOk:01
# Block 27: Success: isOk:01
# Block 31: Success: isOk:01
# Block 35: Success: isOk:01
# Block 39: Success: isOk:01
# Block 43: Success: isOk:01
# Block 47: Success: isOk:01
# Block 51: Success: isOk:01
# Block 55: Success: isOk:01
# Block 59: Success: isOk:01
# Block 63: Success: isOk:01
#
# That's it! Your S50 7byte UID card is wiped back. Now you can return back to Step 1 of this manual.
#
#

import subprocess

# EML data var te get keys of
EML_FILE_DATA = """PLACE RAW hf-mf-CARD_UID-dump.eml FILE CONTENT OF CURRENTLY LOADED CARD HERE"""
# Change your device name here if it differs from the default Proxmark3 RDV4.0
PROXMARK_BIN_EXEC_STRING = './pm3 -c "%s"'
# Constants
DEFAULT_ACCESS_BLOCK = "FFFFFFFFFFFFFF078000FFFFFFFFFFFF"
F12_KEY = "FFFFFFFFFFFF"

def exec_proxmark_cmd(command, retry = 2, input=""):
    exec_ok = False
    retry_c = 0
    while not exec_ok and retry_c < retry:
        sh_command = PROXMARK_BIN_EXEC_STRING % command
        rst = subprocess.run(sh_command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, input=input.encode("utf-8"))

        proxmark_reply = rst.stdout.decode("utf-8")
        proxmark_status = proxmark_reply.splitlines()[-1:][0].strip()
        if proxmark_status == "ok":
            return True, "Success: " + proxmark_status
        retry_c += 1
    return False, "Error: %s , status %s" % (proxmark_reply.splitlines()[-2:][0], proxmark_status)


def chunk(iterable,n):
    """assumes n is an integer>0
    """
    iterable=iter(iterable)
    while True:
        result=[]
        for i in range(n):
            try:
                a=next(iterable)
            except StopIteration:
                break
            else:
                result.append(a)
        if result:
            yield result
        else:
            break

sector_array = [sector for sector in chunk(EML_FILE_DATA.splitlines(), 4)]
block = 0
block_success = {}

for sector in sector_array:
    key_A = sector[3][:12]
    key_B = sector[3][-12:]
    for _block in range(0,4):
        if sector_array.index(sector) == 0 and block == 0:
            write_status, verbose = exec_proxmark_cmd("hf mf wrbl --blk %s -b -k %s -d %s" % (block, key_B, sector[0]))
            if not write_status:
                write_status, verbose = exec_proxmark_cmd("hf mf wrbl --blk %s -a -k %s -d %s" % (block, key_A, sector[0]))
            if not write_status:
                write_status, verbose = exec_proxmark_cmd("hf mf wrbl --blk %s -a -k %s -d %s" % (block, F12_KEY, sector[0]))
            block_success[block] = verbose

        elif _block == 3:
            write_status, verbose = exec_proxmark_cmd("hf mf wrbl --blk %s -b -k %s -d %s" % (block, key_B, DEFAULT_ACCESS_BLOCK))
            if not write_status:
                write_status, verbose = exec_proxmark_cmd("hf mf wrbl --blk %s -a -k %s -d %s" % (block, key_A, DEFAULT_ACCESS_BLOCK))
            if not write_status:
                write_status, verbose = exec_proxmark_cmd("hf mf wrbl --blk %s -a -k %s -d %s" % (block, F12_KEY, DEFAULT_ACCESS_BLOCK))
            block_success[block] = verbose

        _block += 1
        block += 1

for block in block_success:
    print("Block %s: %s" % (block ,block_success[block]))
