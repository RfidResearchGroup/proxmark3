#!/usr/bin/env python3
"""Proxmark Reader App

Cross-platform (Windows, Linux, macOS)
It performs the same legacy Reader-SAM PACS extraction used by ``hf iclass
sam`` and ``hf seos sam``, but moves the SAM from the Proxmark SIM slot to a
PC/SC reader such as an ACR39.  The Proxmark is used only as the HF
antenna/reader.

Requires Python 3.10+, pyserial and pyscard:
``python -m pip install -r pyserial pyscard``

Examples:
  python proxmark_reader_pyscard.py --list
  python proxmark_reader_pyscard.py iclass --sam ACR39
  python proxmark_reader_pyscard.py seos --pm3 /dev/ttyACM0 --sam ACR39 -v
  python proxmark_reader_pyscard.py --decode 0632829cc0
"""

from __future__ import annotations

import argparse
import struct
import time
from dataclasses import dataclass
from typing import Optional

try:
    import serial
    from serial.tools import list_ports
    from smartcard.System import readers
except ImportError as exc:
    raise SystemExit("pyserial and pyscard are required: "
                     "python -m pip install -r pyserial pyscard") from exc


# --- Proxmark3 PacketCommandNG over USB CDC --------------------------------

CMD_PREAMBLE_MAGIC = 0x61334D50
CMD_POSTAMBLE_MAGIC = 0x3361
RESP_PREAMBLE_MAGIC = 0x62334D50
CMD_PING = 0x0109
CMD_CAPABILITIES = 0x0112
CMD_WTX = 0x0116
CMD_HF_ISO14443A_READER = 0x0385
CMD_HF_ICLASS_RAW = 0x039F
CMD_HF_DROPFIELD = 0x0430
PM3_SUCCESS = 0
PM3_USB_IDS = {(0x9AC4, 0x4B8F), (0x2D2D, 0x504D), (0x502D, 0x502D)}


class ReaderError(RuntimeError):
    """A safe, read-only Reader-SAM or Proxmark operation failed."""


@dataclass
class Pm3Response:
    cmd: int
    status: int
    reason: int
    data: bytes


def find_pm3_port() -> Optional[str]:
    for port in list_ports.comports():
        if (getattr(port, "vid", None), getattr(port, "pid", None)) in PM3_USB_IDS:
            return port.device
    return None


class Proxmark:
    """Minimal, read-only PM3 transport used for the external-SAM relay."""

    def __init__(self, port: Optional[str], verbose: bool = False):
        self.port = port or find_pm3_port()
        if not self.port:
            raise ReaderError("no Proxmark3 USB serial port found; pass --pm3-port COMx")
        self.verbose = verbose
        self.ser: Optional[serial.Serial] = None

    def open(self) -> int:
        self.ser = serial.Serial(self.port, 115200, timeout=2, bytesize=serial.EIGHTBITS,
                                 parity=serial.PARITY_NONE, stopbits=serial.STOPBITS_ONE,
                                 rtscts=False, dsrdtr=False)
        ping = bytes(range(32))
        self.send_ng(CMD_PING, ping)
        reply = self.wait(CMD_PING, 10)
        if reply.data[:32] != ping:
            raise ReaderError("PING echo mismatch; selected port is not a Proxmark3")
        self.send_ng(CMD_CAPABILITIES)
        reply = self.wait(CMD_CAPABILITIES, 2)
        if reply.status != PM3_SUCCESS or not reply.data:
            raise ReaderError("Proxmark capabilities handshake failed")
        return reply.data[0]

    def close(self) -> None:
        if self.ser is not None:
            try:
                self.ser.close()
            finally:
                self.ser = None

    def _log(self, message: str) -> None:
        if self.verbose:
            print(f"[pm3] {message}")

    def _write(self, cmd: int, data: bytes) -> None:
        if self.ser is None:
            raise ReaderError("Proxmark port is not open")
        if len(data) > 512:
            raise ReaderError("Proxmark payload exceeds 512 bytes")
        length = len(data) | 0x8000  # the NG bit; MIX frames are no longer supported
        frame = struct.pack("<IHH", CMD_PREAMBLE_MAGIC, length, cmd & 0xFFFF)
        self.ser.write(frame + data + struct.pack("<H", CMD_POSTAMBLE_MAGIC))
        self.ser.flush()
        self._log(f"TX {cmd:04x}: {data.hex()}")

    def send_ng(self, cmd: int, data: bytes = b"") -> None:
        self._write(cmd, data)

    def _read_exact(self, size: int, deadline: float) -> bytes:
        if self.ser is None:
            raise ReaderError("Proxmark port is not open")
        out = b""
        while len(out) < size:
            if time.monotonic() > deadline:
                raise ReaderError("timeout reading from Proxmark")
            part = self.ser.read(size - len(out))
            if part:
                out += part
        return out

    def _read_frame(self, deadline: float) -> Pm3Response:
        magic = struct.pack("<I", RESP_PREAMBLE_MAGIC)
        window = b""
        while window != magic:
            if time.monotonic() > deadline:
                raise ReaderError("timeout waiting for Proxmark response")
            if self.ser is None:
                raise ReaderError("Proxmark port is not open")
            part = self.ser.read(1)
            if part:
                window = (window + part)[-4:]
        length_ng, status, reason, cmd = struct.unpack("<HbbH", self._read_exact(6, deadline))
        data = self._read_exact(length_ng & 0x7FFF, deadline) if length_ng & 0x7FFF else b""
        self._read_exact(2, deadline)
        self._log(f"RX {cmd:04x} status={status}: {data.hex()}")
        return Pm3Response(cmd, status, reason, data)

    def wait(self, command: int, timeout: float) -> Pm3Response:
        deadline = time.monotonic() + timeout
        while True:
            reply = self._read_frame(deadline)
            if reply.cmd == CMD_WTX:
                if len(reply.data) >= 2:
                    deadline = max(deadline, time.monotonic() + int.from_bytes(reply.data[:2], "little") / 1000)
                continue
            if reply.cmd == command:
                return reply

    def drop_field(self) -> None:
        try:
            self.send_ng(CMD_HF_DROPFIELD)
        except ReaderError:
            pass


# --- Proxmark HF reader commands -------------------------------------------

ISO14A_CONNECT = 1 << 0
ISO14A_NO_DISCONNECT = 1 << 1
ISO14A_APDU = 1 << 2
ISO14A_RAW = 1 << 3
ISO14A_APPEND_CRC = 1 << 5
ISO14A_CLEARTRACE = 1 << 17


@dataclass
class Card14a:
    uid: bytes
    atqa: bytes
    sak: int


@dataclass
class IclassCard:
    csn: bytes


class HfReader:

    def __init__(self, pm3: Proxmark):
        self.pm3 = pm3

    def _reader14a(self, flags: int, data: bytes = b"",
                   timeout: float = 5) -> tuple[int, int, bytes]:
        """Send an iso14a_raw_cmd_t and unpack the iso14a_raw_resp_t reply.

        Returns (length, sel, payload). `sel` is the select status on a CONNECT,
        `length` the number of payload bytes otherwise.
        """
        # iso14a_raw_cmd_t: u32 flags, u32 timeout, u32 wait_us, u16 len, u16 lenbits
        req = struct.pack("<IIIHH", flags, 0, 0, len(data), 0) + data
        self.pm3.send_ng(CMD_HF_ISO14443A_READER, req)
        reply = self.pm3.wait(CMD_HF_ISO14443A_READER, timeout)
        # iso14a_raw_resp_t: u16 len, u8 sel, u8 rfu, u8 data[]
        if len(reply.data) < 4:
            return 0, 0, b""
        length, sel, _rfu = struct.unpack("<HBB", reply.data[:4])
        return length, sel, reply.data[4:]

    def select_seos(self) -> Card14a:
        _len, sel, data = self._reader14a(ISO14A_CONNECT | ISO14A_CLEARTRACE | ISO14A_NO_DISCONNECT)
        if sel == 0 or len(data) < 15:
            raise ReaderError("no ISO14443-A / SEOS card in the Proxmark field")
        uid_len = data[10]
        if uid_len not in (4, 7, 10) or len(data) < 15 + data[14]:
            raise ReaderError("invalid ISO14443-A selection response")
        uid, atqa, sak = bytes(data[:uid_len]), bytes(data[11:13]), data[13]
        if sel == 2:  # card did not supply ATS; enter T=CL explicitly
            self._reader14a(ISO14A_RAW | ISO14A_APPEND_CRC | ISO14A_NO_DISCONNECT, b"\xe0\x80")
        return Card14a(uid, atqa, sak)

    def transceive_seos(self, apdu: bytes) -> bytes:
        length, _sel, data = self._reader14a(ISO14A_APDU | ISO14A_NO_DISCONNECT, apdu, 10)
        if length <= 2 or len(data) < length:
            return b""
        return bytes(data[:length - 2])  # PM3 payload includes the T=CL CRC.

    def _iclass_raw(self, flags: int, frame: bytes = b"", timeout: float = 5) -> Pm3Response:
        self.pm3.send_ng(CMD_HF_ICLASS_RAW, struct.pack("<BH", flags, len(frame)) + frame)
        return self.pm3.wait(CMD_HF_ICLASS_RAW, timeout)

    def select_iclass(self) -> IclassCard:
        reply = self._iclass_raw(0x01)  # fork reader command: select and keep the field active
        if reply.status != PM3_SUCCESS or len(reply.data) < 8:
            raise ReaderError("no iCLASS SE/SR card in the Proxmark field")
        return IclassCard(bytes(reply.data[:8]))

    def transceive_iclass(self, frame: bytes) -> bytes:
        reply = self._iclass_raw(0, frame, 10)
        return bytes(reply.data) if reply.status == PM3_SUCCESS else b""


# --- PC/SC via pyscard (Windows, Linux, macOS) -----------------------------


class Pcsc:
    """Cross-platform PC/SC client for a Reader SAM in an ACR39.

    Uses only pyscard's stable core API -- ``readers()``, ``createConnection()``,
    ``connect()``, ``transmit()``, ``getATR()`` and ``disconnect()`` -- so that it
    behaves the same on the Windows, pcsc-lite and macOS PC/SC backends.  The
    bare ``connect()`` negotiates T=0/T=1, matching the ``T0|T1`` mask the
    Windows build passes to ``SCardConnectW``.
    """

    def __init__(self, reader_substring: str):
        self.reader_substring = reader_substring
        self.connection = None
        self.reader_name = ""

    @staticmethod
    def _readers() -> list:
        try:
            return list(readers())
        except Exception as exc:  # pyscard raises backend-specific errors
            raise ReaderError(f"could not enumerate PC/SC readers: {exc}") from exc

    def list_readers(self) -> list[str]:
        return [str(reader) for reader in self._readers()]

    def connect(self) -> bytes:
        available = self._readers()
        matches = [r for r in available if self.reader_substring.lower() in str(r).lower()]
        if not matches:
            names = [str(r) for r in available]
            raise ReaderError(f"no PC/SC reader matches {self.reader_substring!r}; found: {names}")
        self.reader_name = str(matches[0])
        connection = matches[0].createConnection()
        try:
            connection.connect()
        except Exception as exc:
            raise ReaderError(f"could not connect to {self.reader_name}: {exc}") from exc
        self.connection = connection
        try:
            return bytes(connection.getATR())
        except Exception:
            return b""

    def transmit(self, apdu: bytes) -> bytes:
        if self.connection is None:
            raise ReaderError("PC/SC reader is not connected")
        try:
            data, sw1, sw2 = self.connection.transmit(list(apdu))
        except Exception as exc:
            raise ReaderError(f"PC/SC exchange failed: {exc}") from exc
        return bytes(data) + bytes((sw1, sw2))

    def close(self) -> None:
        if self.connection is not None:
            try:
                self.connection.disconnect()
            except Exception:
                pass
            self.connection = None


# --- Grace Reader-SAM protocol and legacy-card relay -----------------------

HOST, SAM, HF = 0x44, 0x0A, 0x14
GET_PACS = bytes.fromhex("a013be11800104840c2b0601040181e43801010204")


@dataclass
class Route:
    source: int
    destination: int
    reply_to: int
    sc_flag: int = 0

    def bytes(self) -> bytes:
        return bytes((self.source, self.destination, self.reply_to, 0, 0, self.sc_flag))

    @classmethod
    def parse(cls, data: bytes) -> "Route":
        if len(data) < 6 or data[3:5] != b"\0\0":
            raise ReaderError(f"malformed Grace routing header: {data[:6].hex()}")
        return cls(data[0], data[1], data[2], data[5])

    def hf_reply(self) -> "Route":
        return Route(self.destination, self.source, self.destination, self.sc_flag)


def ber_length(data: bytes, offset: int) -> tuple[int, int]:
    if offset >= len(data):
        raise ReaderError("truncated BER length")
    first = data[offset]
    if first < 0x80:
        return first, 1
    if first in (0x81, 0x82) and offset + (first & 0x7f) < len(data):
        count = first & 0x7f
        return int.from_bytes(data[offset + 1:offset + 1 + count], "big"), count + 1
    raise ReaderError("unsupported or malformed BER length")


def tlv(data: bytes, offset: int = 0) -> tuple[int, bytes, int]:
    if offset + 1 >= len(data):
        raise ReaderError("truncated BER TLV")
    length, width = ber_length(data, offset + 1)
    begin, end = offset + 1 + width, offset + 1 + width + length
    if end > len(data):
        raise ReaderError("BER length exceeds message")
    return data[offset], data[begin:end], end


def enc_len(size: int) -> bytes:
    if size < 0x80:
        return bytes((size,))
    if size <= 0xff:
        return bytes((0x81, size))
    return bytes((0x82, size >> 8, size & 0xff))


def wrap(tag: int, value: bytes) -> bytes:
    return bytes((tag,)) + enc_len(len(value)) + value


def parse_card_api(body: bytes) -> tuple[str, bytes, Optional[int]]:
    """Classify an A1 Reader-SAM card request as scan, transceive, or RF state."""
    tag, outer, _ = tlv(body)
    if tag != 0xA1 or not outer:
        raise ReaderError(f"not a Reader-SAM card API request: {body.hex()}")
    inner_tag, inner, _ = tlv(outer)
    if inner_tag in (0x82, 0x83):
        return ("rf", b"", inner_tag)
    fields = []
    offset = 0
    while offset < len(inner):
        field_tag, value, offset = tlv(inner, offset)
        fields.append((field_tag, value))
    if not fields or fields[0][0] != 0x80:
        raise ReaderError(f"unrecognised Reader-SAM card request: {body.hex()}")
    if inner_tag == 0xA0:
        return ("scan", fields[0][1], None)
    if inner_tag == 0xA1:
        return ("transceive", fields[0][1], None)
    raise ReaderError(f"unrecognised Reader-SAM card request: {body.hex()}")


def card_info_response(route: Route, protocol: int, ident: bytes,
                       atqa: bytes = b"", sak: Optional[int] = None) -> bytes:
    info = wrap(0x80, protocol.to_bytes(2, "big")) + wrap(0x81, ident)
    if atqa:
        info += wrap(0x82, atqa)
    if sak is not None:
        info += wrap(0x83, bytes((sak,)))
    selected = wrap(0xA1, wrap(0x81, bytes((HF,))) + wrap(0xA2, info))
    return wrap(0xBD, wrap(0xA0, selected))


def card_response(data: bytes) -> bytes:
    # Exact legacy shape: BD { A0 { A0 { 80 <card response>, 81 00 00 } } }.
    inner = wrap(0x80, data) + b"\x81\x02\x00\x00"
    return wrap(0xBD, wrap(0xA0, wrap(0xA0, inner)))


def iclass_crc(data: bytes) -> bytes:
    crc = 0xE012
    for byte in data:
        crc ^= byte
        for _ in range(8):
            crc = (crc >> 1) ^ 0x8408 if crc & 1 else crc >> 1
    return bytes((crc & 0xff, crc >> 8))


class LegacyReaderSam:
    """External PC/SC implementation of the legacy `hf * sam` read path."""

    def __init__(self, pcsc: Pcsc, hf: HfReader, verbose: bool = False):
        self.pcsc, self.hf, self.verbose = pcsc, hf, verbose
        self.card_kind = ""
        self.card14: Optional[Card14a] = None
        self.card_iclass: Optional[IclassCard] = None

    def _log(self, message: str) -> None:
        if self.verbose:
            print(f"[sam] {message}")

    def exchange(self, route: Route, payload: bytes) -> tuple[Route, bytes]:
        frame = route.bytes() + payload
        apdu = b"\xa0\xda\x02\x63\x00" + len(frame).to_bytes(2, "big") + frame + b"\x00\x00"
        self._log(f"TX route={route.bytes().hex()} body={payload.hex()}")
        response = self.pcsc.transmit(apdu)
        if len(response) < 8:
            raise ReaderError(f"Reader SAM response too short: {response.hex()}")
        if response[-2:] != b"\x90\x00":
            raise ReaderError(f"Reader SAM APDU failed: SW={response[-2:].hex()} data={response[:-2].hex()}")
        reply_route, body = Route.parse(response[:-2]), response[6:-2]
        self._log(f"RX route={reply_route.bytes().hex()} body={body.hex()}")
        return reply_route, body

    def _set_detected_card(self) -> None:
        if self.card_kind == "iclass":
            assert self.card_iclass is not None
            payload = bytes.fromhex("a012ad10a00e800200048108") + self.card_iclass.csn
        else:
            assert self.card14 is not None
            details = wrap(0x80, b"\x00\x02") + wrap(0x81, self.card14.uid)
            details += wrap(0x82, self.card14.atqa) + wrap(0x83, bytes((self.card14.sak,)))
            payload = wrap(0xA0, wrap(0xAD, wrap(0xA0, details)))
        _route, body = self.exchange(Route(HOST, SAM, HOST), payload)
        if not body.startswith(b"\xbd"):
            raise ReaderError(f"Reader SAM rejected card selection: {body.hex()}")

    def _handle_card_request(self, route: Route, body: bytes) -> tuple[Route, bytes]:
        action, data, rf_tag = parse_card_api(body)
        if action == "rf":
            if rf_tag == 0x82:
                self.hf.pm3.drop_field()
            return self.exchange(route.hf_reply(), b"\xbd\x02\x8a\x00")
        if action == "scan":
            # The legacy flow has already selected the card, but safely answer a
            # ScanFieldForCard request if this Reader SAM emits one.
            if self.card_kind == "iclass":
                assert self.card_iclass is not None
                payload = card_info_response(route, 4, self.card_iclass.csn)
            else:
                assert self.card14 is not None
                payload = card_info_response(route, 2, self.card14.uid, self.card14.atqa, self.card14.sak)
            return self.exchange(route.hf_reply(), payload)
        if self.card_kind == "iclass":
            # Match `hf iclass sam -p`: never allow a read to decrement/update
            # the e-purse.  The SAM expects a synthetic read-back + iCLASS CRC.
            if len(data) >= 10 and data[:2] == b"\x87\x02":
                reply = data[6:10] + data[:4]
                reply += iclass_crc(reply)
            else:
                reply = self.hf.transceive_iclass(data)
        else:
            reply = self.hf.transceive_seos(data)
        if not reply:
            raise ReaderError("card did not answer the Reader SAM transceive")
        return self.exchange(route.hf_reply(), card_response(reply))

    def read(self, kind: str) -> bytes:
        self.card_kind = kind
        if kind == "iclass":
            self.card_iclass = self.hf.select_iclass()
        else:
            self.card14 = self.hf.select_seos()
        self._set_detected_card()

        route, body = self.exchange(Route(HOST, SAM, HOST), GET_PACS)
        while body.startswith(b"\xa1"):
            route, body = self._handle_card_request(route, body)
        # `_handle_card_request` acknowledges the terminal RF-off request using
        # the exact HF-interface route.  That acknowledgement already returns
        # the final GetContentElement/PACS response.  Sending a second legacy
        # acknowledgement here leaves the SAM with only ISO7816 ``90 00`` and
        # discards the PACS that was just received.
        return extract_pacs(body)


def extract_pacs(body: bytes) -> bytes:
    """Extract the physicalAccessBits PACS value from legacy SAM response TLVs."""
    tag, value, _ = tlv(body)
    if tag != 0xBD:
        raise ReaderError(f"Reader SAM returned no PACS content element: {body.hex()}")
    inner_tag, inner, _ = tlv(value)
    if inner_tag == 0x8A:
        access_tag, pacs, _ = tlv(inner)
        if access_tag != 0x03:
            raise ReaderError(f"unexpected legacy PACS element: {inner.hex()}")
    elif inner_tag == 0xB3:
        app_tag, fields, _ = tlv(inner)
        if app_tag != 0xA0:
            raise ReaderError(f"unexpected SIO response: {inner.hex()}")
        offset, pacs = 0, b""
        while offset < len(fields):
            field_tag, field_value, offset = tlv(fields, offset)
            if field_tag == 0x80:
                pacs = field_value
                break
        if not pacs:
            raise ReaderError("Reader SAM returned SIO content without PACS access bits")
    else:
        raise ReaderError(f"unexpected Reader-SAM response: {body.hex()}")
    if len(pacs) < 2 or pacs[0] > 7:
        raise ReaderError(f"invalid PACS value: {pacs.hex()}")
    return pacs


# --- PACS display / Wiegand decoding --------------------------------------

class WiegandMessage:
    """The PM3 Top/Mid/Bot bit model, retained for its exact parity logic."""

    def __init__(self, length: int):
        self.length, self.top, self.mid, self.bot = length, 0, 0, 0

    def set_bit(self, position: int, value: int) -> None:
        shift = self.length - position - 1
        if shift > 63:
            self.top = (self.top | (value << (shift - 64))) if value else self.top & ~(1 << (shift - 64))
        elif shift > 31:
            self.mid = (self.mid | (value << (shift - 32))) if value else self.mid & ~(1 << (shift - 32))
        else:
            self.bot = (self.bot | (value << shift)) if value else self.bot & ~(1 << shift)

    def get_bit(self, position: int) -> int:
        shift = self.length - position - 1
        if shift > 63:
            return (self.top >> (shift - 64)) & 1
        if shift > 31:
            return (self.mid >> (shift - 32)) & 1
        return (self.bot >> shift) & 1

    def linear(self, first: int, size: int) -> int:
        result = 0
        for position in range(first, first + size):
            result = (result << 1) | self.get_bit(position)
        return result


def parity(value: int) -> int:
    return value.bit_count() & 1


def odd_parity(value: int) -> int:
    return parity(value) ^ 1


def decode_wiegand(pacs: bytes) -> list[tuple[str, int, int, bool]]:
    pad, packed = pacs[0], pacs[1:]
    length = len(packed) * 8 - pad
    if length <= 0:
        return []
    message = WiegandMessage(length)
    for pos in range(length):
        message.set_bit(pos, (packed[pos // 8] >> (7 - pos % 8)) & 1)
    if length == 26:
        cn, fc = (message.bot >> 1) & 0xffff, (message.bot >> 17) & 0xff
        ok = (odd_parity((message.bot >> 1) & 0xfff) == (message.bot & 1)
              and parity((message.bot >> 13) & 0xfff) == ((message.bot >> 25) & 1))
        return [("H10301", fc, cn, ok)]
    if length == 37:
        parity_ok = (message.get_bit(0) == parity(message.linear(1, 18))
                     and message.get_bit(36) == odd_parity(message.linear(18, 18)))
        return [("H10302", 0, message.linear(1, 35), parity_ok),
                ("H10304", message.linear(1, 16), message.linear(17, 19), parity_ok)]
    if length == 34:
        ok = (message.get_bit(0) == parity(message.linear(1, 16))
              and message.get_bit(33) == odd_parity(message.linear(17, 16)))
        return [("H10306", message.linear(1, 16), message.linear(17, 16), ok)]
    if length == 35:
        cn = (message.bot >> 1) & 0xfffff
        fc = ((message.mid & 1) << 11) | (message.bot >> 21)
        ok = (parity((message.mid & 1) ^ (message.bot & 0xb6db6db6)) == ((message.mid >> 1) & 1)
              and odd_parity((message.mid & 3) ^ (message.bot & 0x6db6db6c)) == (message.bot & 1)
              and odd_parity((message.mid & 3) ^ (message.bot & 0xffffffff)) == ((message.mid >> 2) & 1))
        return [("C1k35s", fc, cn, ok)]
    if length == 48:
        cn = (message.bot >> 1) & 0x7fffff
        fc = ((message.mid & 0x3fff) << 8) | (message.bot >> 24)
        ok = (parity((message.mid & 0x1b6d) ^ (message.bot & 0xb6db6db6)) == ((message.mid >> 14) & 1)
              and odd_parity((message.mid & 0x36db) ^ (message.bot & 0x6db6db6c)) == (message.bot & 1)
              and odd_parity((message.mid & 0x7fff) ^ (message.bot & 0xffffffff)) == ((message.mid >> 15) & 1))
        return [("C1k48s", fc, cn, ok)]
    if length == 33:
        ok = (message.get_bit(0) == parity(message.linear(1, 16))
              and message.get_bit(32) == odd_parity(message.linear(16, 16)))
        return [("D10202", message.linear(1, 7), message.linear(8, 24), ok)]
    return []


def render_pacs(pacs: bytes) -> None:
    bit_string = "".join(f"{byte:08b}" for byte in pacs[1:])
    bit_string = bit_string[:-pacs[0]] if pacs[0] else bit_string
    print(f"PACS : {pacs.hex()}  (pad {pacs[0]})")
    print(f"Bits : {bit_string}  ({len(bit_string)} bits)")
    decoded = decode_wiegand(pacs)
    if not decoded:
        print("Format: no supported Wiegand format matches this bit length")
    for name, fc, cn, parity_ok in decoded:
        status = "parity OK" if parity_ok else "parity check unavailable/failed"
        if name == "H10302":
            print(f"Format: {name}  CN={cn}  ({status})")
        else:
            print(f"Format: {name}  FC={fc}  CN={cn}  ({status})")


def main() -> int:
    parser = argparse.ArgumentParser(description="External Reader-SAM PACS reader proof of concept")
    parser.add_argument("card", nargs="?", choices=("iclass", "seos"),
                        help="card family to read")
    parser.add_argument("--pm3", help="Proxmark USB serial port (auto-detected if omitted)")
    parser.add_argument("--sam", default="ACR39", help="PC/SC reader-name substring (default: ACR39)")
    parser.add_argument("--list", action="store_true", help="list PC/SC readers and exit")
    parser.add_argument("--decode", metavar="HEX", help="offline PACS decoder; no hardware needed")
    parser.add_argument("-v", "--verbose", action="store_true", help="show PM3 and Reader-SAM exchanges")
    args = parser.parse_args()

    if args.decode:
        try:
            pacs = bytes.fromhex(args.decode)
            if len(pacs) < 2 or pacs[0] > 7:
                raise ValueError("must be <pad 00-07><packed Wiegand bytes>")
            render_pacs(pacs)
            return 0
        except ValueError as exc:
            print(f"[-] invalid PACS: {exc}")
            return 2

    pcsc = Pcsc(args.sam)
    if args.list:
        try:
            readers = pcsc.list_readers()
            print("PC/SC readers:" if readers else "No PC/SC readers found.")
            for reader in readers:
                print(f"  {reader}")
            return 0
        finally:
            pcsc.close()
    if not args.card:
        parser.error("choose a card family: iclass or seos")

    pm3: Optional[Proxmark] = None
    try:
        pm3 = Proxmark(args.pm3, args.verbose)
        caps = pm3.open()
        print(f"[+] Proxmark: {pm3.port} (capabilities v{caps})")
        atr = pcsc.connect()
        print(f"[+] Reader SAM: {pcsc.reader_name}  ATR={atr.hex() or '(unavailable)'}")
        print(f"[+] Reading {args.card.upper()} via the legacy Reader-SAM flow...")
        pacs = LegacyReaderSam(pcsc, HfReader(pm3), args.verbose).read(args.card)
        print("[+] Read complete")
        render_pacs(pacs)
        return 0
    except ReaderError as exc:
        print(f"[-] {exc}")
        return 1
    finally:
        if pm3 is not None:
            pm3.drop_field()
            pm3.close()
        pcsc.close()


if __name__ == "__main__":
    raise SystemExit(main())
