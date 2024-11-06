#!/usr/bin/env python3

#------------------------------------------------------------------------------
# Revision log:
#------------------------------------------------------------------------------
'''
1.1.0 - BC  - Major refactor
1.0.0 - BC  - Initial release
'''
script_ver = "1.1.0"

'''
This was originally created for my local defcon chapter to aid teaching NFC.
We wanted a realistic challenge which could NOT be resolved by typing `autopwn`.
Enter FM11RF08S tags ... which (currently) don't get autopwn'ed.

We decided the flag would be: The MD5 of the card data,
but this had to include all 8 documented Dark blocks AND all 32+2=34 Keys.
Not rocket surgery if you know what you're doing, but non-trivial for someone
who is still struggling to spell `autoporn` <-- yes, this happened!

Ultimately we needed a tool by which to demo everything.
This is it; and this is me proffering it to the wider community.

BlueChip
'''

#------------------------------------------------------------------------------
# Imports
#
import re
import os
import sys
import time
import argparse
import pm3
import struct
import json
import requests

from fm11rf08s_recovery import recovery

# optional color support .. `pip install ansicolors`
try:
	from colors import color
except ModuleNotFoundError:
	def color(s, fg=None):
		_ = fg
		return str(s)

#+=============================================================================
# Print and Log
# >> "logfile"
#==============================================================================
def startlog(uid,  append = False):
	global  logfile

	logfile = f"{dpath}hf-mf-{uid:08X}-log.txt"
	if append == False:
		with open(logfile, 'w'):   pass

#+=========================================================
def lprint(s,  end='\n', flush=False):
	print(s, end=end, flush=flush)

	if logfile is not None:
		with open(logfile, 'a') as f:
			f.write(s + end)

#++============================================================================
#                                  == MAIN ==
# >> "prompt"
# >> p. [console handle]
# >> "keyfile"
#==============================================================================
def main():
	global  prompt
	global  p

	prompt = "[bc]"
	p      = pm3.pm3()  # console interface

	getPrefs()
	checkVer()
	parseCli()

	print(f"{prompt} Fudan FM11RF08[S] full card recovery")
	print(f"{prompt} (C)Copyright BlueChip 2024")
	print(f"{prompt} Licence: MIT (\"Free as in free.\")")

	print(prompt)
	print(f"{prompt} Dump folder: {dpath}")

	getDarkKey()
	decodeBlock0()

	global  keyfile
	global  mad

	mad     = False
	keyfile = f"{dpath}hf-mf-{uid:08X}-key.bin"
	keyok   = False

	if args.force == False and loadKeys() == True:
		keyok = True
	else:
		if args.recover == False:
			lprint(f"{prompt} * Keys not loaded, use --recover to run recovery script [slow]")
		else:
			recoverKeys()
			if loadKeys() == True:  keyok = True

	if keyok == True:
		if verifyKeys() == False:
			if args.nokeys == False:
				lprint(f"{prompt} ! Use --nokeys to keep going past this point")
				exit(101)

	readBlocks()
	patchKeys(keyok)

	diskDump()  # save it before you do anything else

	dumpData()
	dumpAcl()

	if mad == True:  dumpMad()

	if (args.bambu == True) or (detectBambu() == True):
		dumpBambu()

	lprint(prompt)
	lprint(f"{prompt} Tadah!")

	return

#+=============================================================================
# Get PM3 preferences
# >> "dpath"
#==============================================================================
def getPrefs():
	global  dpath

	p.console("prefs show --json")
	prefs = json.loads(p.grabbed_output)
	dpath = prefs['file.default.dumppath'] + os.path.sep

#+=============================================================================
# Assert python version
#==============================================================================
def checkVer():
	required_version = (3, 8)
	if sys.version_info < required_version:
		print(f"Python version: {sys.version}")
		print(f"The script needs at least Python v{required_version[0]}.{required_version[1]}. Abort.")
		exit()

#+=============================================================================
# Parse the CLi arguments
# >> args.
#==============================================================================
def parseCli():
	global  args

	parser = argparse.ArgumentParser(description='Full recovery of Fudan FM11RF08* cards.')

	parser.add_argument('-n', '--nokeys',   action='store_true', help='extract data even if keys are missing')
	parser.add_argument('-r', '--recover',  action='store_true', help='run key recovery script if required')
	parser.add_argument('-f', '--force',    action='store_true', help='force recovery of keys')
	parser.add_argument('-b', '--bambu',    action='store_true', help='force Bambu tag decode')
	parser.add_argument('-v', '--validate', action='store_true', help='check Fudan signature (requires internet)')

	args   = parser.parse_args()

	if args.force == True:  args.recover = True

#+=============================================================================
# Find backdoor key
# >> "dkey"
# >> "blk0"
'''
[=]   # | sector 00 / 0x00                                | ascii
[=] ----+-------------------------------------------------+-----------------
[=]   0 | 5C B4 9C A6 D2 08 04 00 04 59 92 25 BF 5F 70 90 | \........Y.%._p.
'''
#==============================================================================
def getDarkKey():
	global  dkey
	global  blk0

	#          FM11RF08S        FM11RF08        FM11RF32
	dklist = ["A396EFA4E24F", "A31667A8CEC1", "518b3354E760"]

	print(prompt)
	print(f"{prompt} Trying known backdoor keys...")

	dkey = ""
	for k in dklist:
		cmd = f"hf mf rdbl -c 4 --key {k} --blk 0"
		print(f"{prompt} `{cmd}`", end='', flush=True)
		res = p.console(f"{cmd}", capture=False)
		if res == 0:
			print(" - success")
			dkey = k;
			break;
		print(f" - fail [{res}]")

	if dkey == "":
		print(f"{prompt}")
		print(f"{prompt} ! Unknown key, or card not detected.")
		exit(1)

	for line in p.grabbed_output.split('\n'):
		if " | " in line and "# | s" not in line:
			blk0 = line[10:56+1]

#+=============================================================================
# Extract data from block 0
# >> "uid"
# >> "uids"
#==============================================================================
def decodeBlock0():
	global  uid
	global  uids

	# We do this early so we can name the logfile!
	uids = blk0[0:11]                            # UID string  : "11 22 33 44"
	uid  = int(uids.replace(' ', ''), 16)        # UID (value) : 0x11223344
	startlog(uid, append=False)

	lprint(prompt)
	lprint(f"{prompt}              UID         BCC         ++----- RF08 ID -----++")
	lprint(f"{prompt}              !           !  SAK      !!                   !!")
	lprint(f"{prompt}              !           !  !  ATQA  !!     Fudan Sig     !!")
	lprint(f"{prompt}              !---------. !. !. !---. VV .---------------. VV")
	#                              0           12 15 18    24 27                45
	#                              !           !  !  !     !  !                 !
	#                              00 11 22 33 44 55 66 77 88 99 AA BB CC DD EE FF
	lprint(f"{prompt}   Block 0  : {blk0}")

	# --- decode block 0 ---

	bcc  = int(blk0[12:14], 16)                  # BCC
	chk  = 0                                     # calculate checksum
	for h in uids.split():
		chk ^= int(h, 16)

	sak  = int(blk0[15:17], 16)                  # SAK
	atqa = int(blk0[18:23].replace(' ',''), 16)  # 0x7788

	fida = int(blk0[24:26], 16)                  # Fudan ID 0x88
	fidb = int(blk0[45:47], 16)                  # Fudan ID 0xFF
	fid  = (fida<<8)|fidb                        # Fudan ID 0x88FF

	hash = blk0[27:44]                           # Fudan hash "99 AA BB CC DD EE"

	type = f"[{fida:02X}:{fidb:02X}]"            # type/name
	if fidb == 0x90:
		if fida == 0x01 or fida == 0x03 or fida == 0x04:
			type += " - Fudan FM11RF08S"

	elif fidb == 0x1D:
		if fida == 0x01 or fida == 0x02 or fida == 0x03:
			type += " - Fudan FM11RF08"

	elif fidb == 0x91 or fidb == 0x98:
		type += " - Fudan FM11RF08 (never seen in the wild)"

	else:
		type += " - Unknown (please report)"

	# --- show results ---

	lprint(prompt)

	lprint(f"{prompt}   UID/BCC  : {uid:08X}/{bcc:02X} - ", end='')
	if bcc == chk:  lprint("verified")
	else:           lprint(f"fail. Expected {chk:02X}")

	lprint(f"{prompt}   SAK      : {sak:02X} - ", end='')
	if   sak == 0x01:  lprint("NXP MIFARE TNP3xxx 1K")
	elif sak == 0x08:  lprint("NXP MIFARE CLASSIC 1k | Plus 1k | Ev1 1K")
	elif sak == 0x09:  lprint("NXP MIFARE Mini 0.3k")
	elif sak == 0x10:  lprint("NXP MIFARE Plus 2k")
	elif sak == 0x18:  lprint("NXP MIFARE Classic 4k | Plus 4k | Ev1 4k")
	else:              lprint("{unknown}")

	lprint(f"{prompt}   ATQA     : {atqa:04X}")   # show ATQA
	lprint(f"{prompt}   Fudan ID : {type}")       # show type
	lprint(f"{prompt}   Fudan Sig: {hash}")       # show ?Partial HMAC?
	lprint(f"{prompt}   Dark Key : {dkey}")       # show key

#+=============================================================================
# Fudan validation
# >> "blk0"
#==============================================================================
def fudanValidate():
	global  blk0

	url  = "https://rfid.fm-uivs.com/nfcTools/api/M1KeyRest"
	hdr  = "Content-Type: application/text; charset=utf-8"
	post = f"{blk0.replace(' ','')}"

	lprint(prompt)
	lprint(f"{prompt}   Validator: `wget -q  -O -"
	       f"  --header=\"{hdr}\""
	       f"  --post-data \"{post}\""
	       f"  {url}"
	       "  | json_pp`")

	if args.validate:
		lprint(prompt)
		lprint(f"{prompt} Check Fudan signature (requires internet)...")

		headers = { "Content-Type" : "application/text; charset=utf-8" }
		resp = requests.post(url, headers=headers, data=post)

		if resp.status_code != 200:
			lprint(f"{prompt} HTTP Error {resp.status_code} - check request not processed")

		else:
			r = json.loads(resp.text)
			lprint(f"{prompt} The man from Fudan, he say: {r['code']} - {r['message']}", end='')
			if r['data'] is not None:
				lprint(f" {{{r['data']}}}")
			else:
				lprint("")
	else:
		lprint(prompt)
		lprint(f"{prompt}   ...Use --validate to perform Fudan signature check automatically")

#+=============================================================================
# Load keys from file
# If keys cannot be loaded AND --recover is specified, then run key recovery
# >> "keyfile"
# >> "key[17][2]"
#==============================================================================
def loadKeys():
	global  keyfile
	global  key

	key = [[0 for _ in range(2)] for _ in range(17)]  # create a fresh array

	lprint(prompt)
	lprint(f"{prompt} Load Keys from file: |{keyfile}|")

	try:
		with (open(keyfile, "rb")) as fh:
			for ab in [0, 1]:
				for sec in range((16+2)-1):
					key[sec][ab] = fh.read(6)

	except IOError as e:
		return False

	return True

#+=============================================================================
# Run key recovery script
# >> "keyfile"
#==============================================================================
def recoverKeys():
	global  keyfile

	badrk   = 0     # 'bad recovered key' count (ie. not recovered)

	lprint(prompt)
	lprint(f"{prompt} Running recovery script, ETA: Less than 30 minutes")

	lprint(prompt)
	lprint(f'{prompt} `-._,-\'"`-._,-"`-._,-\'"`-._,-\'"`-._,-\'"`-._,-\'"`-._,-\'"`-._,-\'"`-._,')

	r = recovery(quiet=False)
	keyfile = r['keyfile']
	rkey    = r['found_keys']
	fdump   = r['dumpfile']
	rdata   = r['data']

	lprint(f'{prompt} `-._,-\'"`-._,-"`-._,-\'"`-._,-\'"`-._,-\'"`-._,-\'"`-._,-\'"`-._,-\'"`-._,')

	for k in range(0, 16+1):
		for ab in [0, 1]:
			if rkey[k][ab] == "":
				if badrk == 0:  lprint(f"{prompt} Some keys were not recovered: ", end='')
				else:           lprint(f", ", end='')
				badrk += 1

				kn = k
				if kn > 15:  kn += 16
				lprint(f"[{kn}/", end='')
				lprint("A]" if ab == 0 else "B]", end='')
	if badrk > 0:  lprint("")

#+=============================================================================
# Verify keys
# >> "key[][]"
# >> mad!
#==============================================================================
def verifyKeys():
	global  key
	global  mad

	badk = 0

	lprint(f"{prompt} Check keys..")

	for sec in range (0,16+1):  # 16 normal, 1 dark
		sn = sec
		if (sn > 15):  sn = sn + 16

		for ab in [0, 1]:
			bn  = (sec * 4) + 3
			if bn >= 64:  bn += 64

			cmd = f"hf mf rdbl -c {ab} --key {key[sec][ab].hex()} --blk {bn}"
			lprint(f"{prompt}   `{cmd}`", end='', flush=True)

			res = p.console(f"{cmd}", capture=False)
			lprint(" " * (3-len(str(bn))), end="")
			if res == 0:
				lprint(" ... PASS", end="")
			else:
				lprint(" ... FAIL", end="")
				badk += 1
				key[sec][ab] = ""

			# check for Mifare Application Directory
			if (sec == 0) and (ab == 0) \
			   and (key[0][0] == b'\xa0\xa1\xa2\xa3\xa4\xa5'):
				mad = True
				lprint(" - MAD Key")
			else:
				lprint("")

	if badk > 0:
		lprint(f"{prompt} ! {badk} bad key", end='')
		lprint("s exist" if badk != 1 else " exists")
		rv = False

	else:
		lprint(f"{prompt} All keys verified OK")
		rv = True

	if mad == True:
		lprint(f"{prompt} MAD key detected")

	return rv

#+=============================================================================
# Read all block data - INCLUDING Dark blocks
# >> blkn
# >> "data[]"
'''
[=]   # | sector 00 / 0x00                                | ascii
[=] ----+-------------------------------------------------+-----------------
[=]   0 | 5C B4 9C A6 D2 08 04 00 04 59 92 25 BF 5F 70 90 | \........Y.%._p.
'''
#==============================================================================
def readBlocks():
	global  data
	global  blkn

	data = []
	blkn = list(range(0, 63+1)) + list(range(128, 135+1))

	# The user   uses keyhole #1 (-a)
	# The vendor uses keyhole #2 (-b)
	# The thief  uses keyhole #4 (backdoor)
	#                   |___
	rdbl = f"hf mf rdbl -c 4 --key {dkey} --blk"

	lprint(prompt)
	lprint(prompt + " Load blocks {0..63, 128..135}[64+8=72] from the card")

	bad = 0
	for n in blkn:
		cmd = f"{rdbl} {n}"
		print(f"\r{prompt} `{cmd}`", end='', flush=True)

		for retry in range(5):
			p.console(f"{cmd}")

			found = False
			for line in p.grabbed_output.split('\n'):
				if " | " in line and "# | s" not in line:
					l = line[4:76]
					data.append(l)
					found = True
			if found:  break

		if not found:
			data.append(f"{n:3d} | -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- | ----------------")
			bad += 1

	print(" .. OK")

#+=============================================================================
# Patch keys in to data
# >> "key[][]"
# >> "data[]"
# >> keyok!
'''
  3 | 00 00 00 00 00 00 87 87 87 69 00 00 00 00 00 00 | .........i......
'''
#==============================================================================
def patchKeys(keyok):
	global  key
	global  data

	lprint(prompt)
	lprint(f"{prompt} Patch keys in to data")

	for sec in range(0, 16+1):
		blk = (sec * 4) +3  # find "trailer" for this sector
		if keyok:
			if key[sec][0] == "":
				keyA = "-- -- -- -- -- -- "
			else:
				kstr = key[sec][0].hex()
				keyA = "".join([kstr[i:i+2] + " " for i in range(0, len(kstr), 2)])

			if key[sec][1] == "":
				keyB = "-- -- -- -- -- -- "
			else:
				kstr = key[sec][1].hex()
				keyB = "".join([kstr[i:i+2] + " " for i in range(0, len(kstr), 2)])

			data[blk] = data[blk][:6] + keyA + data[blk][24:36] + keyB

		else:
			data[blk] = data[blk][:6] + "-- -- -- -- -- -- " + data[blk][24:36] + "-- -- -- -- -- --"

#+=============================================================================
# Dump data
# >> blkn
# >> "data[]"
#==============================================================================
def dumpData():
	global  blkn
	global  data

	lprint(prompt)
	lprint(f"{prompt} ===========")
	lprint(f"{prompt}  Card Data")
	lprint(f"{prompt} ===========")
	lprint(f"{prompt}")

	cnt = 0
	for n in blkn:
		sec = (cnt // 4)
		if sec > 15:  sec = sec + 16

		if (n % 4 == 0):
			lprint(f"{prompt} {sec:2d}:{data[cnt]}")
		else:
			lprint(f"{prompt}   :{data[cnt]}")

		cnt += 1
		if (cnt % 4 == 0) and (n != blkn[-1]):  # Space between sectors
			lprint(prompt)

#+=============================================================================
# Let's try to detect a Bambu card by the date strings...
#==============================================================================
def detectBambu():
	try:
		dl  = bytes.fromhex(data[12][ 6:53]).decode('ascii').rstrip('\x00')
		dls = dl[2:13]
		ds  = bytes.fromhex(data[13][ 6:41]).decode('ascii').rstrip('\x00')
	except Exception as e:
		return False

	# ds      24_03_22_16
	# dl    2024_03_22_16_29
	#       yy y    y     m    m     d    d     h    h     m    m
	exp = r"20[2-3][0-9]_[0-1][0-9]_[0-3][0-9]_[0-2][0-9]_[0-5][0-9]"

	lprint(f"{prompt}")
	if re.search(exp, dl) and (ds == dls):
		lprint(f"{prompt} Bambu date strings detected.")
		return True
	else:
		lprint(f"{prompt} Bambu date strings not detected.")
		return False


#+=============================================================================
# Dump bambu details
# https://github.com/Bambu-Research-Group/RFID-Tag-Guide/blob/main/README.md
# >> "data[]"
'''
      6           18          30          42         53
      |           |           |           |          |
  3 | 00 00 00 00 00 00 87 87 87 69 00 00 00 00 00 00 | .........i......
'''
#+=============================================================================
def dumpBambu():
	global  data

	try:
		lprint(f"{prompt}")
		lprint(f"{prompt} ===========")
		lprint(f"{prompt}  Bambu Tag")
		lprint(f"{prompt} ===========")
		lprint(f"{prompt}")
		lprint(f"{prompt} Decompose as Bambu tag .. ", end='')

		MaterialVariantIdentifier_s = bytes.fromhex(data[1][ 6:29]).decode('ascii').rstrip('\x00')
		UniqueMaterialIdentifier_s  = bytes.fromhex(data[1][30:53]).decode('ascii').rstrip('\x00')  #[**] 8not16

		FilamentType_s              = bytes.fromhex(data[2][ 6:53]).decode('ascii').rstrip('\x00')

		DetailedFilamentType_s      = bytes.fromhex(data[4][ 6:53]).decode('ascii').rstrip('\x00')

		Colour_rgba                 = int(data[5][ 6:17].replace(' ',''), 16)
		SpoolWeight_g               = int(data[5][21:23] + data[5][18:20], 16)
		Block5_7to8                 = data[5][24:29]
		FilamentDiameter_mm         = struct.unpack('f', bytes.fromhex(data[5][30:41].replace(' ','')))[0]
		Block5_12to15               = data[5][42:50]

		DryingTemperature_c         = int(data[6][ 9:11] + data[6][ 6: 8], 16)
		DryingTime_h                = int(data[6][15:17] + data[6][12:14], 16)
		BedTemperatureType_q        = int(data[6][21:23] + data[6][18:20], 16)
		BedTemperature_c            = int(data[6][27:29] + data[6][24:26], 16)
		MaxTemperatureForHotend_c   = int(data[6][33:35] + data[6][30:32], 16)
		MinTemperatureForHotend_c   = int(data[6][39:41] + data[6][36:38], 16)
		Block6_12to15               = data[6][42:50]

#		XCamInfo_x                  = bytes.fromhex(data[8][ 6:41].replace(' ',''))
		XCamInfo_x                  = data[8][ 6:41]
		NozzleDiameter_q            = struct.unpack('f', bytes.fromhex(data[8][42:53].replace(' ','')))[0]

#		TrayUID_s                   = bytes.fromhex(data[9][ 6:53]).decode('ascii').rstrip('\x00') #[**] !ascii
		TrayUID_s                   = data[9][ 6:53]

		Block10_0to3                = data[10][ 6:17]
		SppolWidth_um               = int(data[10][21:23] + data[14][18:20], 16)
		Block10_6to15               = data[10][24:50]

		ProductionDateTime_s        = bytes.fromhex(data[12][ 6:53]).decode('ascii').rstrip('\x00')

		ShortProductionDateTime_s   = bytes.fromhex(data[13][ 6:53]).decode('ascii').rstrip('\x00')

		Block14_0to3                = data[14][ 6:17]
		FilamentLength_m            = int(data[14][21:23] + data[14][18:20], 16)
		Block14_6to15               = data[14][24:51]

		# (16blocks * 16bytes = 256) * 8bits = 2048 bits
		hblk = [42, 44,45,46, 48,49,50, 52,53,54, 56,57,58, 60,61,62]
		Hash = []
		for b in hblk:
			Hash.append(data[b][6:53])

		lprint("[offset:length]")
		lprint(f"{prompt}   Block 1:")
		lprint(f"{prompt}     [ 0: 8] MaterialVariantIdentifier_s = \"{MaterialVariantIdentifier_s}\"")
		lprint(f"{prompt}     [ 8: 8] UniqueMaterialIdentifier_s  = \"{UniqueMaterialIdentifier_s}\"")
		lprint(f"{prompt}   Block 2:")
		lprint(f"{prompt}     [ 0:16] FilamentType_s              = \"{FilamentType_s}\"")
		lprint(f"{prompt}   Block 4:")
		lprint(f"{prompt}     [ 0:16] DetailedFilamentType_s      = \"{DetailedFilamentType_s}\"")
		lprint(f"{prompt}   Block 5:")
		lprint(f"{prompt}     [ 0: 4] Colour_rgba                 = 0x{Colour_rgba:08X}")
		lprint(f"{prompt}     [ 4: 2] SpoolWeight_g               = {SpoolWeight_g}g")
		lprint(f"{prompt}     [ 6: 2] Block5_7to8                 = {{{Block5_7to8}}}")
		lprint(f"{prompt}     [ 8: 4] FilamentDiameter_mm         = {FilamentDiameter_mm}mm")
		lprint(f"{prompt}     [12: 4] Block5_12to15               = {{{Block5_12to15}}}")
		lprint(f"{prompt}   Block 6:")
		lprint(f"{prompt}     [ 0: 2] DryingTemperature_c         = {DryingTemperature_c}^C")
		lprint(f"{prompt}     [ 2: 2] DryingTime_h                = {DryingTime_h}hrs")
		lprint(f"{prompt}     [ 4: 4] BedTemperatureType_q        = {BedTemperatureType_q}")
		lprint(f"{prompt}     [ 6: 2] BedTemperature_c            = {BedTemperature_c}^C")
		lprint(f"{prompt}     [ 8: 2] MaxTemperatureForHotend_c   = {MaxTemperatureForHotend_c}^C")
		lprint(f"{prompt}     [10: 2] MinTemperatureForHotend_c   = {MinTemperatureForHotend_c}^C")
		lprint(f"{prompt}     [12: 4] Block6_12to15               = {{{Block6_12to15}}}")
		lprint(f"{prompt}   Block 8:")
		lprint(f"{prompt}     [ 0:12] XCamInfo_x                  = {{{XCamInfo_x}}}")
		lprint(f"{prompt}     [12: 4] NozzleDiameter_q            = {NozzleDiameter_q:.6f}__")
		lprint(f"{prompt}   Block 9:")
#		lprint(f"{prompt}     [ 0:16] TrayUID_s                   = \"{TrayUID_s}\"")
		lprint(f"{prompt}     [ 0:16] TrayUID_s                   = {{{TrayUID_s}}}  ; not ASCII")
		lprint(f"{prompt}   Block 10:")
		lprint(f"{prompt}     [ 0: 4] Block10_0to3                = {{{Block10_0to3}}}")
		lprint(f"{prompt}     [ 4: 2] SppolWidth_um               = {SppolWidth_um}um")
		lprint(f"{prompt}     [ 6:10] Block10_6to15               = {{{Block10_6to15}}}")
		lprint(f"{prompt}   Block 12:")
		lprint(f"{prompt}     [ 0:16] ProductionDateTime_s        = \"{ProductionDateTime_s}\"")
		lprint(f"{prompt}   Block 13:")
		lprint(f"{prompt}     [ 0:16] ShortProductionDateTime_s   = \"{ShortProductionDateTime_s}\"")
		lprint(f"{prompt}   Block 14:")
		lprint(f"{prompt}     [ 0: 4] Block10_0to3                = {{{Block10_0to3}}}")
		lprint(f"{prompt}     [ 4: 2] FilamentLength_m            = {FilamentLength_m}m")
		lprint(f"{prompt}     [ 6:10] Block10_6to15               = {{{Block10_6to15}}}")
		lprint(f"{prompt}")
		lprint(f"{prompt}   Blocks {hblk}:")
		for i in range(0, len(hblk)):
			lprint(f"{prompt}     [ 0:16] HashBlock[{i:2d}]  =  {{{Hash[i]}}}   // #{hblk[i]:2d}")

	except Exception as e:
		lprint(f"Failed: {e}")

#+=============================================================================
# Dump ACL
# >> "data[][]"
'''
      6           18    24 27 30 33       42         53
      |           |     |  |  |  |        |          |
  3 | 00 00 00 00 00 00 87 87 87 69 00 00 00 00 00 00 | .........i......
                        ab cd ef
'''
'''
 ,-------------------.
(  2.2 : ACCESS BITS  )
 `-------------------'

	The Access bits on both (used) Sectors is the same:  78 77 88

	Let's reorganise that according to the official spec Fig 9.
	     Access        C1 C2 C3
	   ==========     ===========
	    78 77 88  -->  78 87 87
	    ab cd ef  -->  cb fa ed

	The second nybble of each byte is the inverse of the first nybble.
	It is there to trap tranmission errors, so we can just ignore it/them.

	So our Access Control value is : {c, f, e} == {7, 8, 8}

	Let's convert those nybbles to binary
		(c) 7 --> 0111
		(f) 8 --> 1000
		(e) 8 --> 1000
		          |||| ...and transpose them:
		          ||||
		          |||`--- 100 - Block 0 Access bits
		          ||`---- 100 - Block 1 Access bits
		          |`----- 100 - Block 2 Access bits
		          `------ 011 - Block 3 Access bits [Sector Trailer]

	Now we can use the lookup table [Table 3] to work out what we can do
	with the Sector Trailer (Block(S,3)):
	
		      |    Key A     | | Access Bits  | |    Key B     |
		      | read ¦ write | | read ¦ write | | read ¦ write |
		      +------¦-------+ +------¦-------+ +------¦-------+
		000 : |  --  ¦ KeyA  | | KeyA ¦  --   | | KeyA ¦ KeyA  |
		001 : |  --  ¦ KeyA  | | KeyA ¦ KeyA  | | KeyA ¦ KeyA  | Transport Mode
		010 : |  --  ¦  --   | | KeyA ¦  --   | | KeyA ¦  --   |

		011 : |  --  ¦ KeyB  | | A+B  ¦ KeyB  | |  --  ¦ KeyB  | <-- Our Card!

		100 : |  --  ¦ KeyB  | | A+B  ¦ --    | |  --  ¦ KeyB  |
		101 : |  --  ¦  --   | | A+B  ¦ KeyB  | |  --  ¦  --   |
		110 : |  --  ¦  --   | | A+B  ¦  --   | |  --  ¦  --   | }__ 
		111 : |  --  ¦  --   | | A+B  ¦  --   | |  --  ¦  --   | }   The Same!?
		
	Our card uses 011, for (both of) the (used) Sector Trailer(s). So: 
		Both Key A and Key B can READ the Access Bits
		Key B can (additionally) WRITE to Key A, Key B (itself), and the Access Bits

	Then we can do a similar lookup for the 3 data Blocks (in this Sector)
	This time using [Table 4]

		      |    Data      |   Counter   |
		      | read ¦ write | Inc  ¦ Dec  |
		      +------¦-------+------¦------+
		000 : | A+B  ¦  A+B  | A+B  ¦  A+B | Transport Mode
		001 : | A+B  ¦  --   |  --  ¦  A+B |
		010 : | A+B  ¦  --   |  --  ¦  --  |
		011 : | KeyB ¦  KeyB |  --  ¦  --  |

		100 : | A+B  ¦  KeyB |  --  ¦  --  | <-- Our Card!

		101 : | KeyB ¦  --   |  --  ¦  --  |
		110 : | A+B  ¦  KeyB | KeyB ¦  A+B |
		111 : | --   ¦  --   |  --  ¦  --  |

	Our card uses 100, for all of the (used) Sectors. So: 
		Both Key A and Key B can READ the Block
		Only Key B can WRITE to the Block
		The block cannot be used as a "counter" because:
			Neither key can perform increment nor decrement commands

	WARNING: 
		IF YOU PLAN TO CHANGE ACCESS BITS, RTFM, THERE IS MUCH TO CONSIDER !
'''
#==============================================================================
def dumpAcl():
	global  blkn

	aclkh = []      # key header
	aclk  = [0] * 8 # key lookup
	aclkx = []      # key output

	lprint(f"{prompt}")
	lprint(f"{prompt} =====================")
	lprint(f"{prompt}  Access Control List")
	lprint(f"{prompt} =====================")

	aclkh.append(" _______________________________________________________ ")
	aclkh.append("|        |                Sector Trailers               |")
	aclkh.append("|        |----------------------------------------------|")
	aclkh.append("| Sector |____Key_A_____||_Access_Bits__||____Key_B_____|")
	aclkh.append("|        | read ¦ write || read ¦ write || read ¦ write |")
	aclkh.append("|--------+------¦-------++------¦-------++------¦-------|")
	#            "|   xx   |  --  ¦ KeyA  || KeyA ¦  --   || KeyA ¦ KeyA  |"
	aclk[0] =             "|  --  ¦ KeyA  || KeyA ¦  --   || KeyA ¦ KeyA  | [000]"
	aclk[1] =             "|  --  ¦ KeyA  || KeyA ¦ KeyA  || KeyA ¦ KeyA  | [001]"
	aclk[2] =             "|  --  ¦  --   || KeyA ¦  --   || KeyA ¦  --   | [010]"
	aclk[3] =             "|  --  ¦ KeyB  || A+B  ¦ KeyB  ||  --  ¦ KeyB  | [011]"
	aclk[4] =             "|  --  ¦ KeyB  || A+B  ¦ --    ||  --  ¦ KeyB  | [100]"
	aclk[5] =             "|  --  ¦  --   || A+B  ¦ KeyB  ||  --  ¦  --   | [101]"
	aclk[6] =             "|  --  ¦  --   || A+B  ¦  --   ||  --  ¦  --   | [110]"  # yes, the same!?
	aclk[7] =             "|  --  ¦  --   || A+B  ¦  --   ||  --  ¦  --   | [111]"  # ...

	acldh = []       # data header
	acld  = [0] * 8  # data lookup
	acldx = []       # data output

	acldh.append(" _____________________________________ ")
	acldh.append("|       |          Data Blocks        |")
	acldh.append("|       |-----------------------------|")
	acldh.append("| Block |    Data      ||   Counter   |")
	acldh.append("|       | read ¦ write || Inc  ¦ Dec  |")
	acldh.append("|-------+------¦-------++------¦------+")
	#            "|  xxx  | A+B  ¦  A+B  || A+B  ¦  A+B | "
	acld[0] =            "| A+B  ¦  A+B  || A+B  ¦  A+B | [000]"
	acld[1] =            "| A+B  ¦  --   ||  --  ¦  A+B | [001]"
	acld[2] =            "| A+B  ¦  --   ||  --  ¦  --  | [010]"
	acld[3] =            "| KeyB ¦  KeyB ||  --  ¦  --  | [011]"
	acld[4] =            "| A+B  ¦  KeyB ||  --  ¦  --  | [100]"
	acld[5] =            "| KeyB ¦  --   ||  --  ¦  --  | [101]"
	acld[6] =            "| A+B  ¦  KeyB || KeyB ¦  A+B | [110]"
	acld[7] =            "| --   ¦  --   ||  --  ¦  --  | [111]"

	idx = [0] * (16+2)

	# --- calculate the ACL indices for each sector:block ---
	for d in data:
		bn = int(d[0:3], 10)

		if ((bn % 4) == 3):
			sn = (bn // 4)
			sec = sn if sn < 16 else sn -16

			c = int(d[27], 16)
			f = int(d[31], 16)
			e = int(d[30], 16)
			r0 = ((c & (2**0)) << 2) | ((f & (2**0)) << 1) | ((e & (2**0))     )
			r1 = ((c & (2**1)) << 1) | ((f & (2**1))     ) | ((e & (2**1)) >> 1)
			r2 = ((c & (2**2))     ) | ((f & (2**2)) >> 1) | ((e & (2**2)) >> 2)
			r3 = ((c & (2**3)) >> 1) | ((f & (2**3)) >> 2) | ((e & (2**3)) >> 3)
			idx[sec] = [r0, r1, r2, r3]

	# --- build the ACL conversion table ---
	for d in data:
		bn = int(d[0:3], 10)
		sn = (bn // 4)
		sec = sn if sn < 16 else sn -16

		if ((bn%4) == 3):
			aclkx.append(f"|   {sn:2d}   " + aclk[idx[sec][bn%4]] 
			             + f"  {{{d[24:32]}}} -> {{{d[27]}{d[31]}{d[30]}}}")
		else:
			acldx.append(f"|  {bn:3d}  "   + acld[idx[sec][bn%4]])

	# --- print it all out ---
	for l in aclkh:
		lprint(f"{prompt}   {l}")
	i = 0
	for l in aclkx:
		lprint(f"{prompt}   {l}")
		if (i % 4) == 3:  lprint(f"{prompt}   |        |      ¦       ||      ¦       ||      ¦       |")
		i += 1

	lprint(f"{prompt}")

	for l in acldh:
		lprint(f"{prompt}   {l}")
	i = 0
	for l in acldx:
		lprint(f"{prompt}   {l}")
		if (i % 3) == 2:  lprint(f"{prompt}   |       |      ¦       ||      ¦      |")
		i += 1

#+=============================================================================
# Full Dump
# >> "uid"
# >> "dump18"
#==============================================================================
def diskDump():
	global  uid
	global  dump18

	dump18 = f"{dpath}hf-mf-{uid:08X}-dump18.bin"

	lprint(prompt)
	lprint(f"{prompt} Dump Card Data to file: {dump18}")

	bad = False
	with open(dump18, 'wb') as f:
		for d in data:
			if "--" in d[6:53]:  bad = True
			b = bytes.fromhex(d[6:53].replace(" ", "").replace("--","FF"))
			f.write(b)
	if bad:  lprint(f"{prompt} Bad data exists, and has been saved as 0xFF")

#+=============================================================================
# Dump MAD
# >> "dump18"
#==============================================================================
def dumpMad():
	global  dump18

	lprint(f"{prompt}")
	lprint(f"{prompt} ====================================")
	lprint(f"{prompt}  MiFare Application Directory (MAD)")
	lprint(f"{prompt} ====================================")
	lprint(f"{prompt}")

	cmd=f"hf mf mad --verbose --file {dump18}"
	print(f"{prompt} `{cmd}`")

	lprint(f"{prompt}")
	lprint(f'{prompt} `-._,-\'"`-._,-"`-._,-\'"`-._,-\'"`-._,-\'"`-._,-\'"`-._,-\'"`-._,-\'"`-._,')

	lprint("")
	res = p.console(f"{cmd}")

	for line in p.grabbed_output.split('\n'):
		lprint(line)

	lprint(f'{prompt} `-._,-\'"`-._,-"`-._,-\'"`-._,-\'"`-._,-\'"`-._,-\'"`-._,-\'"`-._,-\'"`-._,')

#++============================================================================
if __name__ == "__main__":
	main()
