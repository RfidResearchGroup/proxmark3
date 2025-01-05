#!/usr/bin/env python3

# ------------------------------------------------------------------------------
# Imports
#
import re
import os
import sys
import argparse
import pm3
import struct
import json

from fm11rf08s_recovery import recovery

author = "@csBlueChip"
script_ver = "1.4.0"

# Copyright @csBlueChip

# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# See LICENSE.txt for the text of the license.

# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

# The original version of this script can be found at:
# https://github.com/csBlueChip/Proxmark_Stuff/tree/main/MiFare_Docs/Fudan_RF08S/PM3_Script
# The original version is released with an MIT Licence.
# Or please reach out to me [BlueChip] personally for alternative licenses.


# optional color support .. `pip install ansicolors`
try:
    from colors import color
except ModuleNotFoundError:
    def color(s, fg=None):
        _ = fg
        return str(s)


def initlog():
    """Print and Log: init globals

globals:
- logbuffer (W)
- logfile (W)
"""
    global logbuffer
    global logfile
    logbuffer = ''
    logfile = None


def startlog(uid, dpath, append=False):
    """Print and Log: set logfile and flush logbuffer

globals:
- logbuffer (RW)
- logfile (RW)
"""
    global logfile
    global logbuffer

    logfile = f"{dpath}hf-mf-{uid.hex().upper()}-log.txt"
    if append is False:
        with open(logfile, 'w'):
            pass
    if logbuffer != '':
        with open(logfile, 'a') as f:
            f.write(logbuffer)
        logbuffer = ''


def lprint(s='',  end='\n', flush=False, prompt="[" + color("=", fg="yellow") + "] ", log=True):
    """Print and Log

globals:
- logbuffer (RW)
- logfile (R)
"""

    s = f"{prompt}" + f"\n{prompt}".join(s.split('\n'))
    print(s, end=end, flush=flush)

    if log is True:
        global logbuffer
        if logfile is not None:
            with open(logfile, 'a') as f:
                f.write(s + end)
        else:
            # buffering
            logbuffer += s + end


def main():
    """== MAIN ==

globals:
- p (W)
"""
    global p
    p = pm3.pm3()  # console interface
    initlog()

    if not checkVer():
        return
    dpath = getPrefs()
    args = parseCli()

    # No logfile name yet
    lprint("Fudan FM11RF08S full card recovery")
    lprint("\nDump folder... " + color(f"{dpath}", fg="yellow"))

    # FIXME: script is announced as for RF08 and for RF08S but it comprises RF32N key
    # and if RF08 is supported, all other NXP/Infineon with same backdoor can be treated
    # by the same script (once properly implemented, see other FIXME)
    bdkey, blk0 = getBackdoorKey()
    if bdkey is None:
        return
    uid = getUIDfromBlock0(blk0)
    startlog(uid, dpath, append=False)
    decodeBlock0(blk0)
    fudanValidate(blk0, args.validate)

    mad = False
    keyfile = f"{dpath}hf-mf-{uid.hex().upper()}-key.bin"

    # FIXME: nr of sectors depend on the tag. RF32N is 40, RF32 is 64, RF08 is 16, RF08S is 16+1
    # Currently loadKeys is hardcoded for RF08S
    if args.force or (key := loadKeys(keyfile)) is None:
        if args.recover is False:
            s = color("--recover", fg="yellow")
            lprint(f" Keys not loaded, use {s} to run recovery script [slow]", prompt="[" + color("!", fg="red") + "]")
        else:
            # FIXME: recovery() is only for RF08S. TODO for the other ones with a "darknested" attack
            keyfile = recoverKeys(uid=uid, kdf=[["Bambu v1", kdfBambu1]])
            if keyfile == False:
                lprint("Script failed - aborting")
                return
            key = loadKeys(keyfile)

    if key is not None:
        ret, mad, key = verifyKeys(key)
        if ret is False:
            if args.nokeys is False:
                s = color("--nokeys", fg="yellow")
                lprint(f" Use {s} to keep going past this point", prompt="[" + color("!", fg="red") + "]")
                return

    # FIXME: nr of blocks depend on the tag. RF32 is 256, RF08 is 64, RF08S is 64+8
    # Currently readBlocks is hardcoded for RF08S
    data, blkn = readBlocks(bdkey, args.fast)
    data = patchKeys(data, key)

    dump18 = diskDump(data, uid, dpath)  # save it before you do anything else

    dumpData(data, blkn)

    # FIXME: nr of blocks depend on the tag. RF32 is 256, RF08 is 64, RF08S is 64+8,
    # Currently dumpAcl is hardcoded for RF08S
    dumpAcl(data)

    if (mad is True) or (args.mad is True):
        dumpMad(dump18)

    if (args.bambu is True) or (detectBambu(data) is True):
        dumpBambu(data)

    lprint("\nTadah!")

    return


def getPrefs():
    """Get PM3 preferences

globals:
- p (R)
"""
    p.console("prefs show --json")
    prefs = json.loads(p.grabbed_output)
    dpath = prefs['file.default.dumppath'] + os.path.sep
    return dpath


def checkVer():
    """Assert python version"""
    required_version = (3, 8)
    if sys.version_info < required_version:
        print(f"Python version: {sys.version}")
        print(f"The script needs at least Python v{required_version[0]}.{required_version[1]}. Abort.")
        return False
    return True


def parseCli():
    """Parse the CLi arguments"""
    parser = argparse.ArgumentParser(description='Full recovery of Fudan FM11RF08S cards.')

    parser.add_argument('-n', '--nokeys',   action='store_true', help='extract data even if keys are missing')
    parser.add_argument('-r', '--recover',  action='store_true', help='run key recovery script if required')
    parser.add_argument('-f', '--force',    action='store_true', help='force recovery of keys')
    parser.add_argument('-b', '--bambu',    action='store_true', help='force Bambu tag decode')
    parser.add_argument('-m', '--mad',      action='store_true', help='force M.A.D. decode')
    parser.add_argument('-v', '--validate', action='store_true', help='check Fudan signature (requires internet)')
    parser.add_argument('--fast', action='store_true', help='use ecfill for faster card transactions')

    args = parser.parse_args()

    if args.force is True:
        args.recover = True
    return args


def getBackdoorKey():
    """Find backdoor key
[=]   # | sector 00 / 0x00                                | ascii
[=] ----+-------------------------------------------------+-----------------
[=]   0 | 5C B4 9C A6 D2 08 04 00 04 59 92 25 BF 5F 70 90 | \\........Y.%._p.

globals:
- p (R)
"""

    #          FM11RF08S        FM11RF08        FM11RF32
    dklist = ["A396EFA4E24F", "A31667A8CEC1", "518b3354E760"]

    lprint("\nTrying known backdoor keys...")

    bdkey = ""
    for k in dklist:
        cmd = f"hf mf rdbl -c 4 --key {k} --blk 0"
        lprint(f"\n`{cmd}`", end='', flush=True)
        res = p.console(cmd)
        for line in p.grabbed_output.split('\n'):
            if " | " in line and "# | s" not in line:
                blk0 = line[10:56+1]
        if res == 0:
            s = color('ok', fg='green')
            lprint(f"     ( {s} )", prompt='')
            bdkey = k
            break
        s = color('fail', fg='yellow')
        lprint(f"     ( {s} ) [{res}]", prompt='')

    if bdkey == "":
        lprint("\n Unknown key, or card not detected.", prompt="[" + color("!", fg="red") + "]")
        return None, None
    return bdkey, blk0


def getUIDfromBlock0(blk0):
    """Extract UID from block 0"""
    uids = blk0[0:11]                            # UID string  : "11 22 33 44"
    uid = bytes.fromhex(uids.replace(' ', ''))   # UID (bytes) : 11223344
    return uid


def decodeBlock0(blk0):
    """Extract data from block 0"""
    lprint()
    lprint("             UID         BCC         ++---- RF08* ID -----++")
    lprint("             !           !  SAK      !!                   !!")
    lprint("             !           !  !  ATQA  !!     Fudan Sig     !!")
    lprint("             !---------. !. !. !---. VV .---------------. VV")
    #                              0           12 15 18    24 27                45
    #                              !           !  !  !     !  !                 !
    #                              00 11 22 33 44 55 66 77 88 99 AA BB CC DD EE FF
    lprint(f"  Block 0  : {blk0}")

    # --- decode block 0 ---

    uid = getUIDfromBlock0(blk0)
    bcc = int(blk0[12:14], 16)                  # BCC
    chk = 0                                     # calculate checksum
    for h in uid:
        chk ^= h

    sak = int(blk0[15:17], 16)                  # SAK
    atqa = int(blk0[18:23].replace(' ', ''), 16)  # 0x7788

    fida = int(blk0[24:26], 16)                  # Fudan ID 0x88
    fidb = int(blk0[45:47], 16)                  # Fudan ID 0xFF
    # fid = (fida<<8)|fidb                         # Fudan ID 0x88FF

    hash = blk0[27:44]                           # Fudan hash "99 AA BB CC DD EE"

    is08S = False

    type = f"[{fida:02X}:{fidb:02X}]"            # type/name
    if fidb == 0x90:
        if fida == 0x01 or fida == 0x03 or fida == 0x04:
            type += " - Fudan FM11RF08S"
            is08S = True

    elif fidb == 0x1D:
        if fida == 0x01 or fida == 0x02 or fida == 0x03:
            type += " - Fudan FM11RF08"

    elif fidb == 0x91 or fidb == 0x98:
        type += " - Fudan FM11RF08 (never seen in the wild)"

    else:
        type += " - Unknown (please report)"

    # --- show results ---

    lprint()

    if bcc == chk:
        desc = "verified"
    else:
        desc = f"fail. Expected {chk:02X}"
    lprint(f"  UID/BCC  : {uid.hex().upper()}/{bcc:02X} - {desc}")

    if sak == 0x01:
        desc = "NXP MIFARE TNP3xxx 1K"
    elif sak == 0x08:
        desc = "NXP MIFARE CLASSIC 1k | Plus 1k | Ev1 1K"
    elif sak == 0x09:
        desc = "NXP MIFARE Mini 0.3k"
    elif sak == 0x10:
        desc = "NXP MIFARE Plus 2k"
    elif sak == 0x18:
        desc = "NXP MIFARE Classic 4k | Plus 4k | Ev1 4k"
    else:
        desc = "{unknown}"
    lprint(f"  SAK      : {sak:02X} - {desc}")
    lprint(f"  ATQA     : {atqa:04X}")   # show ATQA
    lprint(f"  Fudan ID : {type}")       # show type
    lprint(f"  Fudan Sig: {hash}")       # show ?Partial HMAC?

    if not is08S:
        lprint("\n  This script is only for the RF08S cards")
        lprint("  Other cards can be cracked with `hf mf autopwn`")
        sys.exit(13)


def fudanValidate(blk0, live=False):
    """Fudan validation"""
    url = "https://rfid.fm-uivs.com/nfcTools/api/M1KeyRest"
    hdr = "Content-Type: application/text; charset=utf-8"
    post = f"{blk0.replace(' ', '')}"

    lprint(f"\n  Validator:\n`wget -q -O -"
           f" --header=\"{hdr}\""
           f" --post-data \"{post}\""
           f" {url}"
           " | json_pp`")

    if live:
        # Warning, this import causes a "double free or corruption" crash if the script is called twice...
        # So for now we limit the import only when really needed
        try:
            import requests
        except ModuleNotFoundError:
            s = color("not found", fg="red")
            lprint(f"Python module 'requests' {s}, please install!", prompt="[" + color("!", fg="red") + "] ")
            return
        lprint("\nCheck Fudan signature (requires internet)...")

        headers = {"Content-Type": "application/text; charset=utf-8"}
        resp = requests.post(url, headers=headers, data=post)

        if resp.status_code != 200:
            lprint(f"HTTP Error {resp.status_code} - check request not processed")

        else:
            r = json.loads(resp.text)
            if r['data'] is not None:
                desc = f" {{{r['data']}}}"
            else:
                desc = ""
            lprint(f"The man from Fudan, he say: {r['code']} - {r['message']}{desc}")
    else:
        s = color('--validate', fg="yellow")
        lprint(f'\n Use {s} to perform Fudan signature check automatically', prompt='[?]')


def loadKeys(keyfile):
    """Load keys from file

If keys cannot be loaded AND --recover is specified, then run key recovery
"""
    key = [[b'' for _ in range(2)] for _ in range(17)]  # create a fresh array

    lprint("\nLoad keys from file... " + color(f"{keyfile}", fg="yellow"))

    try:
        with (open(keyfile, "rb")) as fh:
            for ab in [0, 1]:
                for sec in range((16+2)-1):
                    key[sec][ab] = fh.read(6)

    except IOError:
        return None

    return key


def recoverKeys(uid, kdf=[[]]):
    """Run key recovery script"""
    badrk = 0     # 'bad recovered key' count (ie. not recovered)

    keys = False
    lprint(f"\nTrying KDFs:");
    for fn in kdf:
        lprint(f"  {fn[0]:s}", end='')
        keys = fn[1](uid)
        if keys != False:
            lprint(" .. Success", prompt='')
            break
        lprint(" .. Fail", prompt='')

    lprint("\nRunning recovery script, ETA: Less than 30 minutes")

    lprint('\n`-._,-\'"`-._,-"`-._,-\'"`-._,-\'"`-._,-\'"`-._,-\'"`-._,-\'"`-._,-\'"`-._,')
    r = recovery(quiet=False, keyset=keys)
    lprint('`-._,-\'"`-._,-"`-._,-\'"`-._,-\'"`-._,-\'"`-._,-\'"`-._,-\'"`-._,-\'"`-._,')

    if r == False:
        return False

    keyfile = r['keyfile']
    rkey = r['found_keys']
    # fdump = r['dumpfile']
    # rdata = r['data']

    for k in range(0, 16+1):
        for ab in [0, 1]:
            if rkey[k][ab] == "":
                if badrk == 0:
                    lprint("Some keys were not recovered: ", end='')
                else:
                    lprint(", ", end='', prompt='')
                badrk += 1

                kn = k
                if kn > 15:
                    kn += 16
                lprint(f"[{kn}/", end='', prompt='')
                lprint("A]" if ab == 0 else "B]", end='', prompt='')
    if badrk > 0:
        lprint("", prompt='')
    return keyfile

def kdfBambu1(uid):
    from Cryptodome.Protocol.KDF import HKDF
    from Cryptodome.Hash         import SHA256

    # Generate all keys
    try:
        # extracted from Bambu firmware
        salt = bytes([0x9a,0x75,0x9c,0xf2,0xc4,0xf7,0xca,0xff,0x22,0x2c,0xb9,0x76,0x9b,0x41,0xbc,0x96])
        keyA = HKDF(uid, 6, salt, SHA256, 16, context=b"RFID-A\0")
        keyB = HKDF(uid, 6, salt, SHA256, 16, context=b"RFID-B\0")
    except Exception as e:
        print(f"{e}")
        return False

    # --- Grab block 13 (in sector 3) ---
    cmd = f"hf mf rdbl -c 0 --key {keyA[3].hex()} --blk 12"
    #lprint(f"  `{cmd}`", flush=True, log=False, end='')
    for retry in range(5):
        p.console(cmd)

        found = False
        for line in p.grabbed_output.split('\n'):
            if " | " in line and "# | s" not in line:
                lsub = line[4:76]
                found = True
        if found:
            break
    if not found:
        return False

    # --- Try to decode it as a bambu date string ---
    try:
        dl = bytes.fromhex(lsub[6:53]).decode('ascii').rstrip('\x00')
    except Exception:
        return False

    # dl    2024_03_22_16_29
    #       yy y    y     m    m     d    d     h    h     m    m
    exp = r"20[2-3][0-9]_[0-1][0-9]_[0-3][0-9]_[0-2][0-9]_[0-5][0-9]"
    if not re.search(exp, dl):
        return False

    # --- valid date string, we are confident this is a bambu card ---
    keys = []
    for i in range(0, 15+1):
        keys.append([keyA[i].hex(), keyB[i].hex()])

    return keys

def verifyKeys(key):
    """Verify keys

globals:
- p (R)
"""

    badk = 0
    mad = False

    lprint("Checking keys...")

    for sec in range(0, 16+1):  # 16 normal, 1 dark
        sn = sec
        if (sn > 15):
            sn = sn + 16

        for ab in [0, 1]:
            bn = (sec * 4) + 3
            if bn >= 64:
                bn += 64

            cmd = f"hf mf rdbl -c {ab} --key {key[sec][ab].hex()} --blk {bn}"
            lprint(f"  `{cmd}`", end='', flush=True)

            res = p.console(cmd, capture=False)
            lprint(" " * (3-len(str(bn))), end='', prompt='')
            if res == 0:
                s = color("ok", fg="green")
                lprint(f" ( {s} )", end='', prompt='')
            else:
                s = color("fail", fg="red")
                lprint(f" ( {s} )", end='', prompt='')
                badk += 1
                key[sec][ab] = b''

            # check for Mifare Application Directory
            if (sec == 0) and (ab == 0) \
               and (key[0][0] == b'\xa0\xa1\xa2\xa3\xa4\xa5'):
                mad = True
                lprint(" - MAD Key", prompt='')
            else:
                lprint("", prompt='')

    if badk > 0:
        s = color(f'{badk}', fg="red")
        e = "s exist" if badk != 1 else " exists"
        lprint(f" {s} bad key{e}", prompt="[" + color("!", fg="red") + "]")
        rv = False, mad, key

    else:
        lprint("All keys verified")
        rv = True, mad, key

    if mad is True:
        lprint("MAD key detected")

    return rv


def readBlocks(bdkey, fast=False):
    """
Read all block data - INCLUDING advanced verification blocks

[=]   # | sector 00 / 0x00                                | ascii
[=] ----+-------------------------------------------------+-----------------
[=]   0 | 5C B4 9C A6 D2 08 04 00 04 59 92 25 BF 5F 70 90 | \\........Y.%._p.

globals:
- p (R)
"""
    data = []
    blkn = list(range(0, 63 + 1)) + list(range(128, 135 + 1))

    lprint("\nLoad blocks {0..63, 128..135}[64 + 8 = 72] from the card")

    blkn_todo = blkn
    if fast:
        # Try fast dump first
        # The user   uses keyhole #0 (-a)
        # The vendor uses keyhole #1 (-b)
        # The thief  uses keyhole #4 (backdoor)
        #                    |___
        cmd = f"hf mf ecfill -c 4 --key {bdkey}"
        lprint(f"`{cmd}`", flush=True, log=False)
        p.console(cmd)
        for line in p.grabbed_output.split('\n'):
            if "ok" in line:
                cmd = "hf mf eview"
                lprint(f"`{cmd}`", flush=True, log=False)
                p.console(cmd)
                for line in p.grabbed_output.split('\n'):
                    if " | " in line and "sec | blk | data" not in line:
                        lsub = line[11:83]
                        data.append(lsub)
                        blkn_todo = list(range(128, 135+1))

    bad = 0
    for n in blkn_todo:
        cmd = f"hf mf rdbl -c 4 --key {bdkey} --blk {n}"
        lprint(f"  `{cmd}`", flush=True, log=False, end='')

        for retry in range(5):
            p.console(cmd)

            found = False
            for line in p.grabbed_output.split('\n'):
                if " | " in line and "# | s" not in line:
                    lsub = line[4:76]
                    data.append(lsub)
                    found = True
            if found:
                break

        s = color("ok", fg="green")
        if not found:
            data.append(f"{n:3d} | -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- | ----------------")
            bad += 1
            s = color("fail", fg="red")

        lprint(" " * (3 - len(str(n))), flush=True, log=False, end='', prompt='')
        lprint(f' ( {s} )', flush=True, log=False, prompt='')

    s = color("ok", fg="green")
    if bad > 0:
        s = color("fail", fg="red")

    lprint(f'Loading ( {s} )', log=False)
    return data, blkn


def patchKeys(data, key):
    """Patch keys in to data
  3 | 00 00 00 00 00 00 87 87 87 69 00 00 00 00 00 00 | .........i......
"""
    lprint("\nPatching keys in to data")

    for sec in range(0, 16 + 1):
        blk = (sec * 4) + 3  # find "trailer" for this sector
        if key is not None:
            if key[sec][0] == b'':
                keyA = "-- -- -- -- -- -- "
            else:
                kstr = key[sec][0].hex()
                keyA = "".join([kstr[i:i+2] + " " for i in range(0, len(kstr), 2)])

            if key[sec][1] == b'':
                keyB = "-- -- -- -- -- -- "
            else:
                kstr = key[sec][1].hex()
                keyB = "".join([kstr[i:i+2] + " " for i in range(0, len(kstr), 2)])

            data[blk] = data[blk][:6] + keyA + data[blk][24:36] + keyB

        else:
            data[blk] = data[blk][:6] + "-- -- -- -- -- -- " + data[blk][24:36] + "-- -- -- -- -- --"
    return data


def dumpData(data, blkn):
    """Dump data"""
    lprint()
    lprint("===========")
    lprint(" Card Data")
    lprint("===========")
    lprint()

    cnt = 0
    for n in blkn:
        sec = (cnt // 4)
        if sec > 15:
            sec = sec + 16

        if (n % 4 == 0):
            lprint(f"{sec:2d}:{data[cnt]}")
        else:
            lprint(f"  :{data[cnt]}")

        cnt += 1
        if (cnt % 4 == 0) and (n != blkn[-1]):  # Space between sectors
            lprint()


def detectBambu(data):
    """Let's try to detect a Bambu card by the date strings..."""
    try:
        dl = bytes.fromhex(data[12][6:53]).decode('ascii').rstrip('\x00')
        dls = dl[2:13]
        ds = bytes.fromhex(data[13][6:41]).decode('ascii').rstrip('\x00')
    except Exception:
        return False

    # ds      24_03_22_16
    # dl    2024_03_22_16_29
    #       yy y    y     m    m     d    d     h    h     m    m
    exp = r"20[2-3][0-9]_[0-1][0-9]_[0-3][0-9]_[0-2][0-9]_[0-5][0-9]"

    if re.search(exp, dl) and (ds == dls):
        lprint("\nBambu date strings detected.")
        return True
    else:
        lprint("\nBambu date strings not detected.")
        return False


def dumpBambu(data):
    """Dump bambu details

https://github.com/Bambu-Research-Group/RFID-Tag-Guide/blob/main/README.md

       6           18          30          42         53
       |           |           |           |          |
   3 | 00 00 00 00 00 00 87 87 87 69 00 00 00 00 00 00 | .........i......
"""
    try:
        lprint()
        lprint("===========")
        lprint(" Bambu Tag")
        lprint("===========")
        lprint()
        lprint("Decompose as Bambu tag .. ", end='')

        MaterialVariantIdentifier_s = bytes.fromhex(data[1][6:29]).decode('ascii').rstrip('\x00')
        UniqueMaterialIdentifier_s = bytes.fromhex(data[1][30:53]).decode('ascii').rstrip('\x00')  # [**] 8not16

        FilamentType_s = bytes.fromhex(data[2][6:53]).decode('ascii').rstrip('\x00')

        DetailedFilamentType_s = bytes.fromhex(data[4][6:53]).decode('ascii').rstrip('\x00')

        Colour_rgba = int(data[5][6:17].replace(' ', ''), 16)
        SpoolWeight_g = int(data[5][21:23] + data[5][18:20], 16)
        Block5_7to8 = data[5][24:29]
        FilamentDiameter_mm = struct.unpack('f', bytes.fromhex(data[5][30:41].replace(' ', '')))[0]
        Block5_12to15 = data[5][42:50]

        DryingTemperature_c = int(data[6][9:11] + data[6][6:8], 16)
        DryingTime_h = int(data[6][15:17] + data[6][12:14], 16)
        BedTemperatureType_q = int(data[6][21:23] + data[6][18:20], 16)
        BedTemperature_c = int(data[6][27:29] + data[6][24:26], 16)
        MaxTemperatureForHotend_c = int(data[6][33:35] + data[6][30:32], 16)
        MinTemperatureForHotend_c = int(data[6][39:41] + data[6][36:38], 16)
        Block6_12to15 = data[6][42:50]

        # XCamInfo_x = bytes.fromhex(data[8][6:41].replace(' ', ''))
        XCamInfo_x = data[8][6:41]
        NozzleDiameter_q = struct.unpack('f', bytes.fromhex(data[8][42:53].replace(' ', '')))[0]

        # TrayUID_s = bytes.fromhex(data[9][6:53]).decode('ascii').rstrip('\x00') #[**] !ascii
        TrayUID_s = data[9][6:53]

        Block10_0to3 = data[10][6:17]
        SpoolWidth_um = int(data[10][21:23] + data[14][18:20], 16)
        Block10_6to15 = data[10][24:50]

        ProductionDateTime_s = bytes.fromhex(data[12][6:53]).decode('ascii').rstrip('\x00')

        ShortProductionDateTime_s = bytes.fromhex(data[13][6:53]).decode('ascii').rstrip('\x00')

        # Block14_0to3 = data[14][6:17]
        FilamentLength_m = int(data[14][21:23] + data[14][18:20], 16)
        # Block14_6to15 = data[14][24:51]

        # (16blocks * 16bytes = 256) * 8bits = 2048 bits
        hblk = [42,
                44, 45, 46,
                48, 49, 50,
                52, 53, 54,
                56, 57, 58,
                60, 61, 62]
        Hash = []
        for b in hblk:
            Hash.append(data[b][6:53])

        lprint("[offset:length]", prompt='')
        lprint("  Block 1:")
        lprint(f"    [ 0: 8] MaterialVariantIdentifier_s = \"{MaterialVariantIdentifier_s}\"")
        lprint(f"    [ 8: 8] UniqueMaterialIdentifier_s = \"{UniqueMaterialIdentifier_s}\"")
        lprint("  Block 2:")
        lprint(f"    [ 0:16] FilamentType_s = \"{FilamentType_s}\"")
        lprint("  Block 4:")
        lprint(f"    [ 0:16] DetailedFilamentType_s = \"{DetailedFilamentType_s}\"")
        lprint("  Block 5:")
        lprint(f"    [ 0: 4] Colour_rgba = 0x{Colour_rgba:08X}")
        lprint(f"    [ 4: 2] SpoolWeight_g = {SpoolWeight_g}g")
        lprint(f"    [ 6: 2] Block5_7to8 = {{{Block5_7to8}}}")
        lprint(f"    [ 8: 4] FilamentDiameter_mm = {FilamentDiameter_mm}mm")
        lprint(f"    [12: 4] Block5_12to15 = {{{Block5_12to15}}}")
        lprint("  Block 6:")
        lprint(f"    [ 0: 2] DryingTemperature_c = {DryingTemperature_c}^C")
        lprint(f"    [ 2: 2] DryingTime_h = {DryingTime_h}hrs")
        lprint(f"    [ 4: 4] BedTemperatureType_q = {BedTemperatureType_q}")
        lprint(f"    [ 6: 2] BedTemperature_c = {BedTemperature_c}^C")
        lprint(f"    [ 8: 2] MaxTemperatureForHotend_c = {MaxTemperatureForHotend_c}^C")
        lprint(f"    [10: 2] MinTemperatureForHotend_c = {MinTemperatureForHotend_c}^C")
        lprint(f"    [12: 4] Block6_12to15 = {{{Block6_12to15}}}")
        lprint("  Block 8:")
        lprint(f"    [ 0:12] XCamInfo_x = {{{XCamInfo_x}}}")
        lprint(f"    [12: 4] NozzleDiameter_q = {NozzleDiameter_q:.6f}__")
        lprint("  Block 9:")
        # lprint(f"    [ 0:16] TrayUID_s = \"{TrayUID_s}\"")
        lprint(f"    [ 0:16] TrayUID_s = {{{TrayUID_s}}}  ; not ASCII")
        lprint("  Block 10:")
        lprint(f"    [ 0: 4] Block10_0to3 = {{{Block10_0to3}}}")
        lprint(f"    [ 4: 2] SpoolWidth_um = {SpoolWidth_um}um")
        lprint(f"    [ 6:10] Block10_6to15 = {{{Block10_6to15}}}")
        lprint("  Block 12:")
        lprint(f"    [ 0:16] ProductionDateTime_s = \"{ProductionDateTime_s}\"")
        lprint("  Block 13:")
        lprint(f"    [ 0:16] ShortProductionDateTime_s = \"{ShortProductionDateTime_s}\"")
        lprint("  Block 14:")
        lprint(f"    [ 0: 4] Block10_0to3 = {{{Block10_0to3}}}")
        lprint(f"    [ 4: 2] FilamentLength_m = {FilamentLength_m}m")
        lprint(f"    [ 6:10] Block10_6to15 = {{{Block10_6to15}}}")
        lprint(f"\n  Blocks {hblk}:")
        for i in range(0, len(hblk)):
            lprint(f"    [ 0:16] HashBlock[{i:2d}] =  {{{Hash[i]}}}   // #{hblk[i]:2d}")

    except Exception as e:
        lprint(prompt='')
        lprint(f"Failed: {e}")


# +=============================================================================
# Dump ACL
#
#  ,-------------------.
# (  2.2 : ACCESS BITS  )
#  `-------------------'

#     The Access bits on both (used) Sectors is the same:  78 77 88

#     Let's reorganise that according to the official spec Fig 9.
#          Access        C1 C2 C3
#      ========== ===========
#         78 77 88  -->  78 87 87
#         ab cd ef  -->  cb fa ed

#     The second nybble of each byte is the inverse of the first nybble.
#     It is there to trap tranmission errors, so we can just ignore it/them.

#     So our Access Control value is : {c, f, e} == {7, 8, 8}

#     Let's convert those nybbles to binary
#         (c) 7 --> 0111
#         (f) 8 --> 1000
#         (e) 8 --> 1000
#                   |||| ...and transpose them:
#                   ||||
#                   |||`--- 100 - Block 0 Access bits
#                   ||`---- 100 - Block 1 Access bits
#                   |`----- 100 - Block 2 Access bits
#                   `------ 011 - Block 3 Access bits [Sector Trailer]

#     Now we can use the lookup table [Table 3] to work out what we can do
#     with the Sector Trailer (Block(S,3)):

#               |    Key A     | | Access Bits  | |    Key B     |
#               | read ¦ write | | read ¦ write | | read ¦ write |
#               +------¦-------+ +------¦-------+ +------¦-------+
#         000 : |  --  ¦ KeyA  | | KeyA ¦  --   | | KeyA ¦ KeyA  |
#         001 : |  --  ¦ KeyA  | | KeyA ¦ KeyA  | | KeyA ¦ KeyA  | Transport Mode
#         010 : |  --  ¦  --   | | KeyA ¦  --   | | KeyA ¦  --   |

#         011 : |  --  ¦ KeyB  | | A+B  ¦ KeyB  | |  --  ¦ KeyB  | <-- Our Card!

#         100 : |  --  ¦ KeyB  | | A+B  ¦ --    | |  --  ¦ KeyB  |
#         101 : |  --  ¦  --   | | A+B  ¦ KeyB  | |  --  ¦  --   |
#         110 : |  --  ¦  --   | | A+B  ¦  --   | |  --  ¦  --   | }__
#         111 : |  --  ¦  --   | | A+B  ¦  --   | |  --  ¦  --   | }   The Same!?

#     Our card uses 011, for (both of) the (used) Sector Trailer(s). So:
#         Both Key A and Key B can READ the Access Bits
#         Key B can (additionally) WRITE to Key A, Key B (itself), and the Access Bits

#     Then we can do a similar lookup for the 3 data Blocks (in this Sector)
#     This time using [Table 4]

#               |    Data      |   Counter   |
#               | read ¦ write | Inc  ¦ Dec  |
#               +------¦-------+------¦------+
#         000 : | A+B  ¦  A+B  | A+B  ¦  A+B | Transport Mode
#         001 : | A+B  ¦  --   |  --  ¦  A+B |
#         010 : | A+B  ¦  --   |  --  ¦  --  |
#         011 : | KeyB ¦  KeyB |  --  ¦  --  |

#         100 : | A+B  ¦  KeyB |  --  ¦  --  | <-- Our Card!

#         101 : | KeyB ¦  --   |  --  ¦  --  |
#         110 : | A+B  ¦  KeyB | KeyB ¦  A+B |
#         111 : | --   ¦  --   |  --  ¦  --  |

#     Our card uses 100, for all of the (used) Sectors. So:
#         Both Key A and Key B can READ the Block
#         Only Key B can WRITE to the Block
#         The block cannot be used as a "counter" because:
#             Neither key can perform increment nor decrement commands

#     WARNING:
#         IF YOU PLAN TO CHANGE ACCESS BITS, RTFM, THERE IS MUCH TO CONSIDER !
# ==============================================================================
def dumpAcl(data):
    """Dump ACL

       6           18    24 27 30 33       42         53
       |           |     |  |  |  |        |          |
   3 | 00 00 00 00 00 00 87 87 87 69 00 00 00 00 00 00 | .........i......
                         ab cd ef
"""
    aclkh = []      # key header
    aclk = [""] * 8  # key lookup
    aclkx = []      # key output

    lprint()
    lprint("=====================")
    lprint(" Access Control List")
    lprint("=====================")
    lprint()

    aclkh.append(" _______________________________________________________ ")
    aclkh.append("|        |                Sector Trailers               |")
    aclkh.append("|        |----------------------------------------------|")
    aclkh.append("| Sector |____Key_A_____||_Access_Bits__||____Key_B_____|")
    aclkh.append("|        | read ¦ write || read ¦ write || read ¦ write |")
    aclkh.append("|--------+------¦-------++------¦-------++------¦-------|")
    #            "|   xx   |  --  ¦ KeyA  || KeyA ¦  --   || KeyA ¦ KeyA  |"
    aclk[0] =             "|  --  ¦ KeyA  || KeyA ¦  --   || KeyA ¦ KeyA  | [000]"  # noqa: E222
    aclk[1] =             "|  --  ¦ KeyA  || KeyA ¦ KeyA  || KeyA ¦ KeyA  | [001]"  # noqa: E222
    aclk[2] =             "|  --  ¦  --   || KeyA ¦  --   || KeyA ¦  --   | [010]"  # noqa: E222
    aclk[3] =             "|  --  ¦ KeyB  || A+B  ¦ KeyB  ||  --  ¦ KeyB  | [011]"  # noqa: E222
    aclk[4] =             "|  --  ¦ KeyB  || A+B  ¦ --    ||  --  ¦ KeyB  | [100]"  # noqa: E222
    aclk[5] =             "|  --  ¦  --   || A+B  ¦ KeyB  ||  --  ¦  --   | [101]"  # noqa: E222
    aclk[6] =             "|  --  ¦  --   || A+B  ¦  --   ||  --  ¦  --   | [110]"  # noqa: E222  # yes, the same!?
    aclk[7] =             "|  --  ¦  --   || A+B  ¦  --   ||  --  ¦  --   | [111]"  # noqa: E222  # ...

    acldh = []       # data header
    acld = [""] * 8  # data lookup
    acldx = []       # data output

    acldh.append(" _____________________________________ ")
    acldh.append("|       |          Data Blocks        |")
    acldh.append("|       |-----------------------------|")
    acldh.append("| Block |    Data      ||   Counter   |")
    acldh.append("|       | read ¦ write || Inc  ¦ Dec  |")
    acldh.append("|-------+------¦-------++------¦------+")
    #            "|  xxx  | A+B  ¦  A+B  || A+B  ¦  A+B | "
    acld[0] =            "| A+B  ¦  A+B  || A+B  ¦  A+B | [000]"  # noqa: E222
    acld[1] =            "| A+B  ¦  --   ||  --  ¦  A+B | [001]"  # noqa: E222
    acld[2] =            "| A+B  ¦  --   ||  --  ¦  --  | [010]"  # noqa: E222
    acld[3] =            "| KeyB ¦  KeyB ||  --  ¦  --  | [011]"  # noqa: E222
    acld[4] =            "| A+B  ¦  KeyB ||  --  ¦  --  | [100]"  # noqa: E222
    acld[5] =            "| KeyB ¦  --   ||  --  ¦  --  | [101]"  # noqa: E222
    acld[6] =            "| A+B  ¦  KeyB || KeyB ¦  A+B | [110]"  # noqa: E222
    acld[7] =            "| --   ¦  --   ||  --  ¦  --  | [111]"  # noqa: E222

    idx = [[]] * (16+2)

    # --- calculate the ACL indices for each sector:block ---
    for d in data:
        bn = int(d[0:3], 10)

        if ((bn % 4) == 3):
            sn = (bn // 4)
            sec = sn if sn < 16 else sn - 16

            c = int(d[27], 16)
            f = int(d[31], 16)
            e = int(d[30], 16)
            r0 = ((c & (2**0)) << 2) | ((f & (2**0)) << 1) | ((e & (2**0))     )  # noqa: E202
            r1 = ((c & (2**1)) << 1) | ((f & (2**1))     ) | ((e & (2**1)) >> 1)  # noqa: E202
            r2 = ((c & (2**2))     ) | ((f & (2**2)) >> 1) | ((e & (2**2)) >> 2)  # noqa: E202
            r3 = ((c & (2**3)) >> 1) | ((f & (2**3)) >> 2) | ((e & (2**3)) >> 3)  # noqa: E221
            idx[sec] = [r0, r1, r2, r3]

    # --- build the ACL conversion table ---
    for d in data:
        bn = int(d[0:3], 10)
        sn = (bn // 4)
        sec = sn if sn < 16 else sn - 16

        if ((bn % 4) == 3):
            aclkx.append(f"|   {sn:2d}   " + aclk[idx[sec][bn % 4]]
                         + f"  {{{d[24:32]}}} -> {{{d[27]}{d[31]}{d[30]}}}")
        else:
            acldx.append(f"|  {bn:3d}  " + acld[idx[sec][bn % 4]])

    # --- print it all out ---
    for line in aclkh:
        lprint(f"  {line}")
    i = 0
    for line in aclkx:
        lprint(f"  {line}")
        if (i % 4) == 3:
            lprint("  |        |      ¦       ||      ¦       ||      ¦       |")
        i += 1

    lprint()

    for line in acldh:
        lprint(f"  {line}")
    i = 0
    for line in acldx:
        lprint(f"  {line}")
        if (i % 3) == 2:
            lprint("  |       |      ¦       ||      ¦      |")
        i += 1


def diskDump(data, uid, dpath):
    """Full Dump"""
    dump18 = f'{dpath}hf-mf-{uid.hex().upper()}-dump18.bin'

    lprint(f'\nDump card data to file... ' + color(dump18, fg='yellow'))

    bad = False
    try:
        with open(dump18, 'wb') as f:
            for d in data:
                if '--' in d[6:53]:
                    bad = True
                b = bytes.fromhex(d[6:53].replace(' ', '').replace('--', 'FF'))
                f.write(b)
        if bad:
            lprint('Bad data exists, and has been saved as 0xFF')

        s = color('ok', fg='green')
        lprint(f' Save file operations ( {s} )', prompt='[+]')

    except Exception as e:
        s = color('fail', fg='red')
        lprint(f' Save file operations: {e} ( {s} )', prompt='[!]')

    return dump18


def dumpMad(dump18):
    """Dump MAD

globals:
- p (R)
"""

    lprint()
    lprint("====================================")
    lprint(" MiFare Application Directory (MAD)")
    lprint("====================================")
    lprint()

    cmd = f"hf mf mad --force --verbose --file {dump18}"
    lprint(f"`{cmd}`", log=False)

    lprint('\n`-._,-\'"`-._,-"`-._,-\'"`-._,-\'"`-._,-\'"`-._,-\'"`-._,-\'"`-._,-\'"`-._,\n')

    p.console(cmd)

    for line in p.grabbed_output.split('\n'):
        lprint(line, prompt='')

    lprint('`-._,-\'"`-._,-"`-._,-\'"`-._,-\'"`-._,-\'"`-._,-\'"`-._,-\'"`-._,-\'"`-._,')


if __name__ == "__main__":
    main()
