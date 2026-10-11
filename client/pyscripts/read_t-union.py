#!/usr/bin/env python3
# -*- coding: utf-8 -*-

#   Contributed by klks84 (https://github.com/klks)
#   Run with ./pm3 -c "script run read_t-union.py"
#
#   Script to read China T-Union cards, based on the work of SocialSisterYi
#   See LICENSE.txt for the text of the license.

import sys
from typing import Optional, List, Tuple, Any
import pm3

#References
# https://github.com/SocialSisterYi/T-Union_Master/blob/main/src/protocol/t_union_poller_i.c
# https://wiki.nfc.im/books/%E6%99%BA%E8%83%BD%E5%8D%A1%E6%89%8B%E5%86%8C/page/%E4%BA%A4%E9%80%9A%E8%81%94%E5%90%88%E5%8D%A1%EF%BC%88t-union%EF%BC%89

# optional color support .. `pip install ansicolors`
try:
    from colors import color  # type: ignore
except ModuleNotFoundError:
    def color(s, fg=None):
        _ = fg
        return str(s)

# Constants
DEBUG = False
MAX_CARD_POLL_TRIES = 5
MAX_TRANSACTION_RECORDS = 10
MAX_TRAVEL_RECORDS = 30
FILE_ID_TRANSACTION = 0x18
FILE_ID_TRAVEL = 0x1E
AID_PBOC_DEBIT_CREDIT = "A00000000386980701"
AID_TUNION_TRANSIT = "A000000632010105"
DDF_PPSE = b"2PAY.SYS.DDF01"

class BridgePM3:
    """Bridge class for communicating with Proxmark3 device."""

    def __init__(self, hw_debug: bool, pm3: Any = None):
        self._debug = hw_debug
        if pm3 is None:
            raise ValueError("Need a pm3 instance")
        self.pm3 = pm3
        self.recv_buff: Optional[str] = None

    def recv(self) -> bytes:
        """Receive data from PM3."""
        if self.recv_buff is None:
            raise ValueError("No data in receive buffer")

        ret_buff = bytes.fromhex(self.recv_buff)

        if self._debug:
            if ret_buff[-2:] == b"\x90\x00":
                print(f"[{color('+', fg='green')}] PM3 <= {self.recv_buff}")
            else:
                print(f"[{color('-', fg='red')}] PM3 <= {self.recv_buff}")

        return ret_buff

    def hw_reset(self) -> None:
        """Reset the Proxmark3 hardware."""
        self.pm3.console("hw reset")

    def send(self, data: bytes, select: bool = False) -> None:
        """Send APDU command to card via PM3."""

        exec_cmd = "hf 14a apdu -k"

        if select:
            exec_cmd += "s"  # activate field and select card

        exec_cmd += "d "  # full APDU package

        # Convert bytearray to string
        exec_cmd += bytearray(data).hex()

        if self._debug:
            print(f"[{color('+', fg='green')}] PM3 => exec_cmd = {color(exec_cmd, fg='yellow')}")

        self.pm3.console(exec_cmd)
        self.recv_buff = self.extract_ret(self.pm3.grabbed_output.split('\n'))

    def extract_ret(self, ret: List[str]) -> Optional[str]:
        """Extract response data from PM3 output."""
        for line in ret:
            if "<<< " in line:
                parts = line.split(" ")
                if len(parts) > 2:
                    return parts[2]
        return None

    def sendToNfc(self, data: bytes) -> None:
        """Send data to NFC card, auto-detecting SELECT commands."""
        enable_select = False
        if len(data) > 5 and data[0] == 0x00 and data[1] == 0xA4 and (data[2] == 0x00 or data[2] == 0x04) and data[3] == 0x00:
            enable_select = True
        self.send(data, select=enable_select)

    def nfcFindCard(self) -> str:
        """Check if a card is present."""
        self.pm3.console("hf 14a info")

        for line in self.pm3.grabbed_output.split("\n"):
            if "UID:" in line:
                return line
        return "noCard"

    def nfcGetRecData(self) -> bytes:
        """Get received data from PM3."""
        recvdata = self.recv()
        if recvdata is None:
            raise ValueError("Did not receive any data from PM3")
        return recvdata

    def waitForCard(self, max_tries: int = MAX_CARD_POLL_TRIES) -> bool:
        """Poll for a card up to max_tries. Return True if found, else False."""
        tries = 0
        while self.nfcFindCard() == 'noCard':
            print('No card detected, retrying...')
            tries += 1
            if tries >= max_tries:
                break

        if tries >= max_tries:
            print(f"No card found after {max_tries} attempts")
            return False
        return True

def assert_success(ret: bytes) -> None:
    """Assert that a response has SW=0x9000 and abort with message otherwise."""
    if len(ret) < 2:
        raise ValueError("Response too short to contain status word")
    assert ret[-2:] == b"\x90\x00", f"Aborting execution, SW1_SW2 = {bytes_to_hexstr(ret[-2:])}"

def parse_return_code(ret_code: Optional[bytes], console_print: bool = True) -> Optional[str]:
    """Parse ISO 7816-4 status words and return description."""
    if ret_code is None:
        if console_print:
            print("Return code empty")
        return None

    if len(ret_code) < 2:
        if console_print:
            print(f"Insufficient length of ret_code: {len(ret_code)}")
        return None

    ret_string = "Unknown return code"

    match ret_code[0]:
        case 0x62:
            if ret_code[1] >= 2 and ret_code[1] <= 0x80:
                ret_string = "Triggering by the card"
            match ret_code[1]:
                case 0x81:
                    ret_string = "Part of returned data may be corrupted"
                case 0x82:
                    ret_string = "End of file or record reached before reading Ne bytes"
                case 0x83:
                    ret_string = "Selected file deactivated"
                case 0x84:
                    ret_string = "File control information not formatted"
                case 0x85:
                    ret_string = "Selected file in termination state"
                case 0x86:
                    ret_string = "No input data available from a sensor on the card"

        case 0x63:
            if ret_code[1] == 0x81:
                ret_string = "File filled up by the last write"
            elif (ret_code[1] & 0xF0) == 0xC0:
                ret_string = "Counter from 0 to 15 encoded by 'X'(SW2&0xF)"

        case 0x64:
            if ret_code[1] >= 2 and ret_code[1] <= 0x80:
                ret_string = "Triggering by the card"
            elif ret_code[1] == 1:
                ret_string = "Immediate response required by the card"

        case 0x65:
            if ret_code[1] == 0x81:
                ret_string = "Memory failure"

        case 0x67:
            if ret_code[1] == 0x00:
                ret_string = "Invalid length"

        case 0x68:
            match ret_code[1]:
                case 0x81:
                    ret_string = "Logical channel not supported"
                case 0x82:
                    ret_string = "Secure messaging not supported"
                case 0x83:
                    ret_string = "Last command of the chain expected"
                case 0x84:
                    ret_string = "Command chaining not supported"

        case 0x69:
            match ret_code[1]:
                case 0x81:
                    ret_string = "Command incompatible with file structure"
                case 0x82:
                    ret_string = "Security status not satisfied"
                case 0x83:
                    ret_string = "Authentication method blocked"
                case 0x84:
                    ret_string = "Reference data not usable"
                case 0x85:
                    ret_string = "Conditions of use not satisfied"
                case 0x86:
                    ret_string = "Command not allowed (no current EF)"
                case 0x87:
                    ret_string = "Expected secure messaging data objects missing"
                case 0x88:
                    ret_string = "Incorrect secure messaging data objects"

        case 0x6A:
            match ret_code[1]:
                case 0x80:
                    ret_string = "Incorrect parameters in the command data field"
                case 0x81:
                    ret_string = "Function not supported"
                case 0x82:
                    ret_string = "File or application not found"
                case 0x83:
                    ret_string = "Record not found"
                case 0x84:
                    ret_string = "Not enough memory space in the file"
                case 0x85:
                    ret_string = "Nc inconsistent with TLV structure"
                case 0x86:
                    ret_string = "Incorrect parameters P1-P2"
                case 0x87:
                    ret_string = "Nc inconsistent with parameters P1-P2"
                case 0x88:
                    ret_string = "Referenced data or reference data not found"
                case 0x89:
                    ret_string = "File already exists"
                case 0x8A:
                    ret_string = "DF name already exists"

        case 0x6D:
            match ret_code[1]:
                case 0x00:
                    ret_string = "Invalid INS parameter"

        case 0x6E:
            match ret_code[1]:
                case 0x00:
                    ret_string = "Invalid CLA parameter"

        case 0x93:
            match ret_code[1]:
                case 0x02:
                    ret_string = "Invalid MAC"

        case 0x94:
            match ret_code[1]:
                case 0x01:
                    ret_string = "The amount is insufficient"
                case 0x03:
                    ret_string = "Key indexes are not supported"

        case 0x90:
            if ret_code[1] == 0:
                ret_string = "Operation Successful"

    if console_print:
        print(f"[{color('=', fg='yellow')}] SW1_SW2 <= {bytes_to_hexstr(ret_code)} => {ret_string}")

    return ret_string


def parse_tlv(data: bytes, tag_length: int) -> List[Tuple[bytes, bytes]]:
    """
    Parse TLV (Tag-Length-Value) structure.

    Args:
        data: bytes or bytearray containing TLV data
        tag_length: int, number of bytes for the tag field (must be > 0)

    Returns:
        list of tuples: [(tag, value), (tag, value), ...]
    """
    if tag_length <= 0:
        raise ValueError(f"Invalid tag_length: {tag_length}, must be > 0")

    result = []
    offset = 0

    while offset < len(data):
        # Check if we have enough bytes for tag and length
        if offset + tag_length + 1 > len(data):
            break

        # Extract tag
        tag = data[offset:offset + tag_length]
        offset += tag_length

        # Extract length (assuming 1 byte for length)
        length = data[offset]
        offset += 1

        # Check if we have enough bytes for value
        if offset + length > len(data):
            break

        # Extract value
        value = data[offset:offset + length]
        offset += length

        result.append((tag, value))

    return result

# https://github.com/SocialSisterYi/T-Union_Master/blob/857ffec87d67413e759c5e055e6a410a93536b2e/src/protocol/t_union_poller_i.c#L88
def parse_tunion_meta(level: int, tlv_data: bytes) -> None:
    """Parse T-Union card metadata from TLV data."""
    if len(tlv_data) < 0x1C:
        raise ValueError(f"TLV data too short: {len(tlv_data)} bytes, expected at least 28")

    card_type = tlv_data[0]
    city_id = int.from_bytes(tlv_data[1:3], byteorder='big')
    card_number = tlv_data[10:20].hex().upper()

    issued_year = tlv_data[20:22].hex().upper()
    issued_month = tlv_data[22:23].hex().upper()
    issued_day = tlv_data[23:24].hex().upper()

    exp_year = tlv_data[24:26].hex().upper()
    exp_month = tlv_data[26:27].hex().upper()
    exp_day = tlv_data[27:28].hex().upper()

    print(" " * level + f"Card Type = {color(card_type, fg='green')}")
    print(" " * level + f"City ID = {color(city_id, fg='green')}")
    print(" " * level + f"Card Number = {color(card_number, fg='green')}")
    issued_date = f"{issued_year}-{issued_month}-{issued_day}"
    exp_date = f"{exp_year}-{exp_month}-{exp_day}"
    print(" " * level + f"Issued Date = {color(issued_date, fg='green')}")
    print(" " * level + f"Expiration Date = {color(exp_date, fg='green')}")

# https://github.com/SocialSisterYi/T-Union_Master/blob/857ffec87d67413e759c5e055e6a410a93536b2e/src/protocol/t_union_poller_i.c#L114
def decode_transaction(data: bytes) -> None:
    """Decode and display transaction record."""
    if len(data) < 23:
        raise ValueError(f"Transaction data too short: {len(data)} bytes, expected at least 23")

    sequence = int.from_bytes(data[0:2], byteorder='big')
    money = int.from_bytes(data[5:9], byteorder='big')
    trans_type = data[9]
    type_str = "Unknown"
    match trans_type:
        case 0x01 | 0x02:
            type_str = "Load"
        case 0x05 | 0x06:
            type_str = "Purchase"
        case 0x09:
            type_str = "CompoundPurchase"
    terminal_id = data[10:16].hex().upper()
    year = data[16:18].hex().upper()
    month = data[18:19].hex().upper()
    day = data[19:20].hex().upper()
    hour = data[20:21].hex().upper()
    minute = data[21:22].hex().upper()
    second = data[22:23].hex().upper()
    print(f"\nSequence: {color(sequence, fg='green')}")
    money_str = f"{money/100:.2f} CNY"
    print(f"Amount: {color(money_str, fg='green')}")
    print(f"Type: {color(trans_type, fg='green')} ({color(type_str, fg='green')})")
    print(f"Terminal ID: {color(terminal_id, fg='green')}")
    transaction_date = f"{year}-{month}-{day} {hour}:{minute}:{second}"
    print(f"Transaction Date: {color(transaction_date, fg='green')}")
    print("")

# https://github.com/SocialSisterYi/T-Union_Master/blob/857ffec87d67413e759c5e055e6a410a93536b2e/src/protocol/t_union_poller_i.c#L136
def decode_travel(data: bytes) -> None:
    """Decode and display travel record."""
    if len(data) < 42:
        raise ValueError(f"Travel data too short: {len(data)} bytes, expected at least 42")

    travel_type = data[0]
    terminal_id = data[1:9].hex().upper()
    sub_type = data[9]
    station_id = data[10:17].hex().upper()
    money = int.from_bytes(data[17:21], byteorder='big')
    balance = int.from_bytes(data[21:25], byteorder='big')
    year = data[25:27].hex().upper()
    month = data[27:28].hex().upper()
    day = data[28:29].hex().upper()
    hour = data[29:30].hex().upper()
    minute = data[30:31].hex().upper()
    second = data[31:32].hex().upper()
    city_id = data[32:34].hex().upper()
    institution_id = data[34:42].hex().upper()

    print(f"\nType: {color(travel_type, fg='green')}")
    print(f"Terminal ID: {color(terminal_id, fg='green')}")
    print(f"Sub Type: {color(sub_type, fg='green')}")
    print(f"Station ID: {color(station_id, fg='green')}")
    travel_cost_str = f"{money/100:.2f} CNY"
    card_balance_str = f"{balance/100:.2f} CNY"
    print(f"Travel Cost: {color(travel_cost_str, fg='green')}")
    print(f"Card Balance: {color(card_balance_str, fg='green')}")
    travel_date = f"{year}-{month}-{day} {hour}:{minute}:{second}"
    print(f"Transaction Date: {color(travel_date, fg='green')}")
    print(f"City ID: {color(city_id, fg='green')}")
    print(f"Institution ID: {color(institution_id, fg='green')}")
    print("")

# TLV data decoded with https://emvlab.org/tlvutils/
def decode_tlv(level: int, tlv_data: bytes, tag_length: int) -> None:
    """Recursively decode and print TLV structure."""
    parsed_tlv = parse_tlv(tlv_data, tag_length)

    for p_tag, p_value in parsed_tlv:
        match p_tag:
            case b"\x6f":
                print("6F File Control Information (FCI) Template")
                decode_tlv(level+1, p_value, 1)
            case b"\x84":
                try:
                    df_name = p_value.decode('utf-8')
                except (UnicodeDecodeError, AttributeError):
                    df_name = p_value.hex().upper()
                print(" " * level + f"84 Dedicated File (DF) Name = {color(df_name, fg='green')}")
            case b"\xA5":
                print(" " * level + "A5 File Control Information (FCI) Proprietary Template")
                decode_tlv(level+1, p_value, 2)
            case b"\xbf\x0c":
                print(" " * level + "BF0C File Control Information (FCI) Issuer Discretionary Data")
                decode_tlv(level+1, p_value, 1)
            case b"\x61":
                print(" " * level + "61 Application Template")
                decode_tlv(level+1, p_value, 1)
            case b"\x4f":
                aid = p_value.hex().upper()
                print(" " * level + f"4F Application Identifier (AID) = {color(aid, fg='green')}")
            case b"\x50":
                app_label = p_value.decode('utf-8', errors='ignore')
                print(" " * level + f"50 Application Label = {color(app_label, fg='green')}")
            case b"\x87":
                app_priority = p_value.hex().upper()
                print(" " * level + f"87 Application Priority Indicator = {app_priority}")
            case b"\x9f\x08":
                app_ver = p_value.hex().upper()
                print(" " * level + f"9F08 Application Version Number = {app_ver}")
            case b"\x9f\x0c":
                print(" " * level + "9F0C File Control Information (FCI) Issuer Discretionary Data")
                parse_tunion_meta(level+1, p_value)
            case _:
                print(f"Unable to parse tag {level=}, {p_tag=}, {p_value=}")

def process_tlv(tlv_data: bytes) -> None:
    """Process TLV data after checking status word."""
    if DEBUG:
        print(f"[{color('+', fg='green')}] Calling: {sys._getframe(0).f_code.co_name}")

    if len(tlv_data) < 2:
        raise ValueError("TLV data too short")

    SW1_SW2 = tlv_data[-2:]
    answer = tlv_data[:-2]

    if SW1_SW2 == b"\x90\x00":
        decode_tlv(0, answer, 1)
    else:
        raise ValueError(f"Failed to parse TLV, SW={bytes_to_hexstr(SW1_SW2)}")

def bytes_to_hexstr(inp: bytes) -> str:
    """Convert bytes-like to space-separated hex, e.g., b"\x01\x02" -> "01 02"."""
    return ' '.join(format(ch, "02X") for ch in inp)

def strToint16(hex_str: str) -> List[int]:
    """Parse hex string into list of 1-byte ints grouped by two chars per byte.

    Example: "3F00" -> [0x3F, 0x00]
    """
    if len(hex_str) % 2 != 0:
        raise ValueError(f"Hex string must have even length, got {len(hex_str)}")

    return [int(hex_str[i:i+2], 16) for i in range(0, len(hex_str), 2)]

def GetRecData(pm3_conn: BridgePM3) -> bytes:
    """Get received data from PM3 connection."""
    nfcdata = pm3_conn.nfcGetRecData()

    if DEBUG:
        print(f"[{color('=', fg='yellow')}] RECV <= " + bytes_to_hexstr(nfcdata))

    parse_return_code(nfcdata[-2:], DEBUG)
    return nfcdata

def sendCommand(pm3_conn: BridgePM3, cla: int, ins: int, p1: int, p2: int,
                Data: Optional[bytes] = None, le: Optional[int] = None) -> bytes:
    """Send APDU command and receive response."""
    context = [cla, ins, p1, p2]
    if Data is not None:
        lc = len(Data)
        context = context + [lc] + list(Data)
    else:
        lc = None

    if le is not None:
        context = context + [le]

    if lc is None and le is None:
        context = context + [0x00]

    if DEBUG:
        print(f"[{color('=', fg='yellow')}] SEND => {bytes_to_hexstr(bytes(context))}")

    pm3_conn.sendToNfc(bytes(context))
    recdata = GetRecData(pm3_conn)
    return recdata

def cmd_select(pm3_conn: BridgePM3, fileID: Optional[str] = None, name: Optional[bytes] = None) -> bytes:
    """Send SELECT command to card."""
    if DEBUG:
        print(f"[{color('+', fg='green')}] Calling: {sys._getframe(0).f_code.co_name}")

    if fileID is None and name is None:
        raise ValueError("fileID or name cannot be empty")

    cla = 0x00
    ins = 0xA4
    p2 = 0x00

    if name:
        p1 = 0x04
        ret = sendCommand(pm3_conn, cla=cla, ins=ins, p1=p1, p2=p2, Data=name)
    else:
        p1 = 0x00
        fileIDlist = bytes(strToint16(fileID))
        ret = sendCommand(pm3_conn, cla=cla, ins=ins, p1=p1, p2=p2, Data=fileIDlist, le=0x00)

    if DEBUG:
        print(f"[{color('=', fg='yellow')}] SELECT => {bytes_to_hexstr(ret)}\n")

    if ret[-2:] == b"\x90\x00":
        process_tlv(ret)

    return ret

def cmd_get_balance(pm3_conn: BridgePM3) -> bytes:
    """Get card balance."""
    if DEBUG:
        print(f"[{color('+', fg='green')}] Calling: {sys._getframe(0).f_code.co_name}")

    cla = 0x80
    ins = 0x5C
    p1 = 0x00
    p2 = 0x02

    ret = sendCommand(pm3_conn, cla=cla, ins=ins, p1=p1, p2=p2, le=4)
    if DEBUG:
        print(f"[{color('=', fg='yellow')}] GET_BALANCE => {bytes_to_hexstr(ret)}\n")
    return ret

def cmd_read_record(pm3_conn: BridgePM3, record_number: int, file_id: int) -> bytes:
    """Read a record from a file on the card."""
    if DEBUG:
        print(f"[{color('+', fg='green')}] Calling: {sys._getframe(0).f_code.co_name}")

    cla = 0x00
    ins = 0xB2
    p1 = record_number
    p2 = ((file_id & 0x1F) << 3) | 4

    ret = sendCommand(pm3_conn, cla, ins, p1, p2, Data=None, le=0)
    assert ret[-2:] == b"\x90\x00", f"Card did not return success"

    if DEBUG:
        print(f"[{color('=', fg='yellow')}] READ_RECORD => {bytes_to_hexstr(ret)}\n")
    return ret

def process_tunion_transit_card(pm3_conn: BridgePM3) -> None:
    """Process T-Union transit card - read balance, transactions, and travel records."""
    print("\nReading Balance...")
    ret = cmd_get_balance(pm3_conn)
    assert_success(ret)
    balance = int.from_bytes(ret[0:4], byteorder='big')
    balance_str = f"{balance/100:.2f} CNY"
    print(f"Balance = {color(balance_str, fg='green')}")

    print("\nReading Transactions...")
    for i in range(MAX_TRANSACTION_RECORDS):
        print(f"Reading Transaction Record {i+1}...", end="")
        try:
            ret = cmd_read_record(pm3_conn, record_number=i+1, file_id=FILE_ID_TRANSACTION)
            assert_success(ret)
            if all(b == 0x00 for b in ret[0:-2]):
                print(" Empty")
            else:
                decode_transaction(ret[0:-2])
        except (AssertionError, ValueError) as e:
            print(f" Error: {e}")
            break

    print("\nReading Travel Records...")
    for i in range(MAX_TRAVEL_RECORDS):
        print(f"Reading Travel Record {i+1}...", end="")
        try:
            ret = cmd_read_record(pm3_conn, record_number=i+1, file_id=FILE_ID_TRAVEL)
            assert_success(ret)
            if all(b == 0x00 for b in ret[0:-2]):
                print(" Empty")
            else:
                decode_travel(ret[0:-2])
        except (AssertionError, ValueError) as e:
            print(f" Error: {e}")
            break

def main() -> None:
    """Main entry point for T-Union card reader."""
    try:
        p = pm3.pm3()
        pm3_conn = BridgePM3(hw_debug=DEBUG, pm3=p)

        if not pm3_conn.waitForCard():
            raise ValueError("Unable to find card...")

        print("\nSelecting DDF...")
        ret = cmd_select(pm3_conn, name=DDF_PPSE)
        assert_success(ret)

        for aidl in [AID_PBOC_DEBIT_CREDIT, AID_TUNION_TRANSIT]:
            print(f"\nSelecting AID: {aidl}")
            ret = cmd_select(pm3_conn, name=bytes.fromhex(aidl))
            assert_success(ret)

            match aidl:
                case "A00000000386980701":  # PBOC Debit/Credit
                    print("PBOC Debit/Credit card detected - implementation pending")
                    # TODO: Implement PBOC card processing
                case "A000000632010105":  # T-Union Transit
                    process_tunion_transit_card(pm3_conn)
                case _:
                    print(f"Unknown AID: {aidl}, please report!")

    except Exception as e:
        print(f"\nError: {e}")
        raise
    finally:
        # Reset device to known good state
        if 'pm3_conn' in locals():
            pm3_conn.hw_reset()

if __name__ == "__main__":
    main()
