### Crappy helper script for USCUID-UL, v0.2.4.2
## Written and tested by Eltrick
# It is recommended that you are able to backdoor read main blocks
# in case changing from one type to another messes up keys/pwd
# unless you know what you're doing.

## For the uninitiated, the keys are stored in the following locations
## per the corresponding datasheets
# UL11     - PWD - page 18d
# UL21     - PWD - page 39d
# UL-C     - KEY - pages 44d to 47d
# NTAG 213 - PWD - page 43d
# NTAG 215 - PWD - page 133d
# NTAG 216 - PWD - page 229d

import argparse
import pm3

try:
    # pip install ansicolors
    from colors import color
except ModuleNotFoundError:
    def color(s, fg=None):
        _ = fg
        return str(s)

HEX_DIGITS = "0123456789ABCDEF"
MEMORY_CONFIG = { "C3": "UL11", "3C": "UL21", "00": "UL-C", "A5": "NTAG 213", "5A": "NTAG 215", "AA": "NTAG 216", "55": "Unknown IC with 238 pages" }
KNOWN_CONFIGS = ["C30004030101000B03", "3C0004030101000E03", "000000000000000000", "A50004040201000F03", "5A0004040201001103", "AA0004040201001303"]

parser = argparse.ArgumentParser(description='A script to help with raw USCUID-UL commands. Out of everything until -s, only one functionality can be used at a time, prioritised in order listed below.')
parser.add_argument('-r', '--read', action='store_true', help='Read and parse config from card')
parser.add_argument('-t', '--type', help='Type to change to: 1-UL11; 2-UL21; 3-UL-C; 4-NTAG213; 5-NTAG215; 6-NTAG216')
parser.add_argument('-c', '--cfg', help='Config to write')
parser.add_argument('-p', '--parse', help='Config to parse')
parser.add_argument('-b', '--bdr', help='Page num to read with backdoor')
parser.add_argument('-w', '--wbd', help='First page num to write with backdoor')
parser.add_argument('-u', '--uid', help='New UID to write')
parser.add_argument('-d', '--data', help='Page data to write if using -w, multiple of 4 bytes')
parser.add_argument('-s', '--sig', help='Signature to write with backdoor')
parser.add_argument('--gen1a', action='store_true', help='Use gen1a (40/43) magic wakeup')
parser.add_argument('--gdm', action='store_true', help='Use gdm alt (20/23) magic wakeup')

args = parser.parse_args()
card_config = args.read
ul_type = args.type
config = args.cfg
parse = args.parse
backdoor_block = args.bdr
write_backdoor = args.wbd
data = args.data
signature = args.sig
gen1a = args.gen1a
alt = args.gdm
uid = args.uid

field_on = False
p = pm3.pm3()

ERROR = "[" + color("-", "red") + "] "
SUCCESS = "[" + color("+", "green") + "] "

def verify_config(config: str) -> bool:
    if len(config) != 32:
        print(ERROR + "Configuration data must be 16 bytes.")
        return False
    if set(config) > set(HEX_DIGITS):
        print(ERROR + "Configuration data must be in hex.")
        return False
    return True

def parse_config(config: str):
    print(SUCCESS + "" + config)
    cfg_magic_wup = config[0:4]
    cfg_wup_style = config[4:6]
    cfg_regular_available = config[6:8]
    cfg_auth_type = config[8:10]
    cfg_cuid = config[12:14]
    cfg_memory_config = config[14:16]

    log_magic_wup = "Magic wakeup " + ("en" if cfg_magic_wup != "8500" else "dis") + "abled" + (" with config access" if cfg_magic_wup == "7AFF" else "")
    log_wup_style = "Magic wakeup style " + ("Gen1a 40(7)/43" if cfg_wup_style == "00" else ("GDM 20(7)/23" if cfg_wup_style == "85" else "unknown"))
    log_regular_available = "Config " + ("" if cfg_regular_available == "A0" else "un") + "available in regular mode"
    log_auth_type = "Auth type " + ("1B - PWD" if cfg_auth_type == "00" else "1A - 3DES")
    log_cuid = "CUID " + ("dis" if cfg_cuid == "A0" else "en") + "abled"
    log_memory_config = "Maximum memory configuration: " + (MEMORY_CONFIG[cfg_memory_config] if cfg_memory_config in MEMORY_CONFIG.keys() else "unknown")

    print(SUCCESS + "^^^^............................ " + log_magic_wup)
    print(SUCCESS + "....^^.......................... " + log_wup_style)
    print(SUCCESS + "......^^........................ " + log_regular_available)
    print(SUCCESS + "........^^...................... " + log_auth_type)
    print(SUCCESS + "..........^^.................... unknown")
    print(SUCCESS + "............^^.................. " + log_cuid)
    print(SUCCESS + "..............^^................ " + log_memory_config)
    print(SUCCESS + "................^^^^^^^^^^^^^^^^ version info")

def try_auth_magic(enforced = False):
    if enforced and not (gen1a | alt):
        print(ERROR + "Magic wakeup required. Please select one.")
        exit()
    if gen1a ^ alt:
        p.console("hf 14a raw -akb 7 " + ("40" if gen1a else "20"))
        p.console("hf 14a raw -k " + ("43" if gen1a else "23"))

def write_config(config: str):
    try_auth_magic()
    for i in range(4):
        p.console("hf 14a raw -" + ("s" if (i == 0 and not (gen1a or alt)) else "") + ("k" if i != 3 else "") + "c" + f" E2{i:02x}" + config[8*i:8*i+8], False, False)

def grab_config() -> str:
    try_auth_magic()
    p.console("hf 14a raw -c" + ("s" if not (gen1a or alt) else "") + " E050")
    out = p.grabbed_output
    if out == "":
        return out
    return out.split("\n")[-2][4:-9].replace(" ", "")

if gen1a and alt:
    print(ERROR + "Please only choose one magic wakeup type.")
    exit()

if card_config:
    config_grab = grab_config()
    if not verify_config(config_grab):
        print(ERROR + "Failed to grab config data from card.")
        exit()
    parse_config(config_grab)

elif ul_type != None:
    ul_type_num = int(ul_type) - 1
    if ul_type_num < 0 or ul_type_num >= len(KNOWN_CONFIGS):
        print(ERROR + "Type specified is non-existent.")
        exit()
    old_config = grab_config()
    new_config = old_config[0:8] + ("0A" if ul_type_num == 2 else "00") + old_config[10:14] + KNOWN_CONFIGS[ul_type_num]
    write_config(new_config)

elif config != None:
    config = config.upper()
    if not verify_config(config):
        exit()
    write_config(config)

elif parse != None:
    parse = parse.upper()
    if not verify_config(parse):
        exit()
    parse_config(parse)

elif backdoor_block != None:
    block = int(backdoor_block)
    try_auth_magic(True)
    p.console(f"hf 14a raw -c 30{block:02x}")
    print(p.grabbed_output.split("\n")[-2][4:-9].replace(" ", ""))

elif write_backdoor != None:
    write_backdoor_num = int(write_backdoor)
    if data == None:
        print(ERROR + "Specify data to write to the block.")
        exit()
    if len(data) % 8 != 0:
        print(ERROR + "Data must be a multiple of 4 bytes.")
        exit()

    try_auth_magic(True)
    for i in range(len(data) // 8):
        p.console("hf 14a raw -" + ("k" if i != (len(data) // 8 - 1) else "") + f"c A2{(write_backdoor_num + i):02x}{data[8*i:8*i+8]}", False, False)

elif uid != None:
    if len(uid) != 14:
        print(ERROR + "UID must be 7 bytes.")
        exit()
    try_auth_magic()
    p.console(f"hf 14a raw -kc" + ("s" if not (gen1a or alt) else "") + " 3002")
    block_2 = p.grabbed_output.split("\n")[-2][4:-9].replace(" ", "")[:8]
    uid_bytes = [int(uid[2*x:2*x+2], 16) for x in range(7)]

    bcc_0 = 0x88 ^ uid_bytes[0] ^ uid_bytes[1] ^ uid_bytes[2]
    new_block_0 = ""
    for i in range(3):
        new_block_0 += f"{uid_bytes[i]:02x}"
    new_block_0 += f"{bcc_0:02x}"

    bcc_1 = uid_bytes[3] ^ uid_bytes[4] ^ uid_bytes[5] ^ uid_bytes[6]
    new_block_1 = uid[6:]
    new_block_2 = f"{bcc_1:02x}" + block_2[2:]
    p.console("hf 14a raw -kc A200" + new_block_0, False, False)
    p.console("hf 14a raw -kc A201" + new_block_1, False, False)
    p.console("hf 14a raw -c A202" + new_block_2, False, False)

elif signature != None:
    if len(signature) != 64:
        print(ERROR + "Signature must be 32 bytes.")
        exit()
    try_auth_magic(True)
    signature_pages = [signature[8*x:8*x+8] for x in range(8)]
    for i in range(8, 16):
        p.console("hf 14a raw -c" + ("k" if i != 15 else "") + f" A2F{i:01x}{signature_pages[i - 8]}", False, False)

# Always try to HALT
p.console("hf 14a raw -c 5000")
