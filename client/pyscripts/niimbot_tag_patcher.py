#!/usr/bin/env python3
# Licensed at MIT license

# Tool to analyze and patch Niimbot label printers RFID tags or clone them into other tags.
# Tag contents (NTAG) are encrypted are contain a security record computed from card UUID,
# therefore cloning a card contents to another one will not work and such tag will be rejected by a printer.

# You need a Proxmark3 card dump in PM3 bin or json file. Patching will modify this dump so you need to 
# upload it again to a card.

# Note that Niimbot mobile app keeps copy of those values on their servers so resetting the tag print counter
# may not work in the long term.


# Usage:

# python3 niimbot_tag_patcher.py --help
# python3 niimbot_tag_patcher.py analyze -i tag-dump.json -f pm3-json

# Patch the print counter, set it back to 0 and write the file to patched.json
# (format of the pached file is always the same as input file)

# python3 niimtag.py patch -i tag-dump.json -f pm3-json --print-counter 0 -w patched.json


# (C) 2026 PhaseLoop

import argparse
import binascii
import json
from ctypes import c_uint32 as uint32
from dataclasses import dataclass, field
from struct import pack, unpack
from typing import Self

CRYPTO_KEY = bytes(
    [
        0xA1,
        0xCC,
        0x00,
        0x00,
        0xB7,
        0x72,
        0x00,
        0x00,
        0x58,
        0x67,
        0x00,
        0x00,
        0xC9,
        0x65,
        0x00,
        0x00,
    ]
)

# from Proxmark3 bin dump file format
PM3_MFU_DUMP_PREFIX_LENGTH = 56

# Tag research and structures based on open research here:
# https://printers.niim.blue/other/rfig-tags/
# security check value at 0x08 presented there is computed wrong


# tea_decrypt and tea_encrypt shamelessly stolen from
# https://github.com/devsli/tea_cipher/tree/master
# licensed as MIT license.
# Modified to unpack/pack integers as little endian to match
# ARM architecture in printers


def tea_decrypt(ciphertext, key, delta=0x9E3779B9):
    """
    Decrypt a ciphertext using TEA algorithm.

    ciphertext: 64 bits length bytes-like object.
    key: 128 bits length bytes-like object.

    Return a 64 bits length bytes object.
    """

    v0, v1 = map(uint32, unpack("<2I", ciphertext))
    k0, k1, k2, k3 = map(uint32, unpack("<4I", key))
    sm, delta = uint32(0xC6EF3720), uint32(delta)

    for i in range(32):
        v1.value -= (
            ((v0.value << 4) + k2.value)
            ^ (v0.value + sm.value)
            ^ ((v0.value >> 5) + k3.value)
        )
        v0.value -= (
            ((v1.value << 4) + k0.value)
            ^ (v1.value + sm.value)
            ^ ((v1.value >> 5) + k1.value)
        )
        sm.value -= delta.value

    return pack("<2I", v0.value, v1.value)


def tea_encrypt(plaintext, key, delta=0x9E3779B9):
    """
    Encrypt a plaintext using TEA algorithm.

    plaintext: 64 bits length bytes-like object.
    key: 128 bits length bytes-like object.

    Return a 64 bits length bytes object.
    """

    v0, v1 = map(uint32, unpack("<2I", plaintext))
    k0, k1, k2, k3 = map(uint32, unpack("<4I", key))
    sm, delta = uint32(0), uint32(delta)

    for i in range(32):
        sm.value += delta.value
        v0.value += (
            ((v1.value << 4) + k0.value)
            ^ (v1.value + sm.value)
            ^ ((v1.value >> 5) + k1.value)
        )
        v1.value += (
            ((v0.value << 4) + k2.value)
            ^ (v0.value + sm.value)
            ^ ((v0.value >> 5) + k3.value)
        )

    return pack("<2I", v0.value, v1.value)


class CardLoadError(Exception): ...


class LabelValueError(Exception): ...


class CLIError(Exception): ...


@dataclass
class LabelTag:

    PRINT_COUNTER_OFFSET = 0x02  # 16 bit LE
    PRINT_COUNTER_CRC32_OFFSET = 0x04
    LABEL_SECURITY_RECORD_OFFSET = 0x08
    LABEL_SECURITY_RECORD_LENGTH = 7

    VENDOR_DATA_OFFSET = 0x14
    VENDOR_DATA_LENGTH = 0x78

    SERIAL_OFFSET = 0x10
    SERIAL_FIELD_SIZE = 16

    BARCODE_OFFSET = 0x28
    BARCODE_FIELD_SIZE = 13

    NAME_OFFSET = 0x46
    NAME_FIELD_SIZE = 20

    PAPER_WIDTH_OFFSET = 0x5A
    PAPER_HEIGHT_OFFSET = 0x5B
    PRINT_LIMIT_OFFSET = 0x5C

    card_data: bytearray = field(
        default_factory=bytearray
    )  # full NTAG card data, starting from sector 0
    encrypted_data: bytearray = field(
        default_factory=bytearray
    )  # encrypted data, sectors 5-34
    vendor_data: bytearray = field(
        default_factory=bytearray
    )  # decrypted data from sectors 5-34

    def field_to_uint8(self, offset) -> int:
        return unpack(
            "<B",
            bytes(self.vendor_data[offset : offset + 1]),
        )[0]

    def uint8_to_field(self, offset, value: int) -> None:
        assert 0 <= value <= 255, "value must be between 0 and 255"

        field_value = pack("<B", value)
        self.vendor_data[offset : offset + 1] = field_value

    def uint32_to_field(self, offset, value: int) -> None:    
        field_value = pack("<I", value)
        self.vendor_data[offset : offset + 4] = field_value

    def field_to_text(self, offset, max_size) -> str:
        text = ""

        for i in range(max_size):
            char_byte = self.vendor_data[offset + i]
            if char_byte == 0x00:  # end of string
                break
            else:
                text += bytes([char_byte]).decode("utf-8")
        return text

    def text_to_field(self, offset: int, max_size: int, value: str) -> None:
        encoded_text = value.encode("utf-8")
        # cut text to match max_size - 1 byte to keep \0 termination
        encoded_text = bytes(encoded_text[0 : max_size - 1])

        # zeroed buffer is filled with encoded text minus one so string is always terminated with \0
        # it will probably break unicode if it gets cut in the middle of a 16/32 bit value
        buffer = bytearray(max_size)
        buffer[0 : len(encoded_text)] = encoded_text

        self.vendor_data[offset:offset+max_size] = buffer

    @property
    def barcode(self) -> str:
        barcode_text = ""
        for i in range(self.BARCODE_FIELD_SIZE):
            char_byte = self.vendor_data[self.BARCODE_OFFSET + i]
            if char_byte == 0x00:  # end of string
                break
            else:
                barcode_text += bytes([char_byte]).decode("utf-8")

        return barcode_text

    @property
    def name(self) -> str:
        return self.field_to_text(self.NAME_OFFSET, self.NAME_FIELD_SIZE)

    @name.setter
    def name(self, value) -> None:
        self.text_to_field(self.NAME_OFFSET, self.NAME_FIELD_SIZE, value)

    @property
    def paper_width(self) -> int:
        return self.field_to_uint8(self.PAPER_WIDTH_OFFSET)

    @paper_width.setter
    def paper_width(self, value: int) -> None:
        self.uint8_to_field(self.PAPER_WIDTH_OFFSET, value)

    @property
    def paper_height(self) -> int:
        return self.field_to_uint8(self.PAPER_HEIGHT_OFFSET)

    @paper_height.setter
    def paper_height(self, value: int) -> None:
        self.uint8_to_field(self.PAPER_HEIGHT_OFFSET, value)

    @property
    def print_counter(self) -> int:
        print_count = unpack(
            "<H",
            bytes(
                self.vendor_data[
                    self.PRINT_COUNTER_OFFSET : self.PRINT_COUNTER_OFFSET + 2
                ]
            ),
        )
        return print_count[0]

    @print_counter.setter
    def print_counter(self, value:int):
        self.uint8_to_field(self.PRINT_COUNTER_OFFSET, value)

    @property
    def print_counter_crc32(self) -> int:
        print_counter_crc32 = unpack(
            "<I",
            bytes(
                self.vendor_data[
                    self.PRINT_COUNTER_CRC32_OFFSET : self.PRINT_COUNTER_CRC32_OFFSET
                    + 4
                ]
            ),
        )
        return print_counter_crc32[0]

    @print_counter_crc32.setter
    def print_counter_crc32(self, value:int):
        return self.uint32_to_field(self.PRINT_COUNTER_CRC32_OFFSET, value)
        

    @property
    def print_limit(self) -> int:
        print_limit = unpack(
            "<B",
            bytes(
                self.vendor_data[self.PRINT_LIMIT_OFFSET : self.PRINT_LIMIT_OFFSET + 1]
            ),
        )
        return print_limit[0]

    @property
    def reencrypted_data(self) -> bytes:
        # reencrypt card data using current "vendor_data" buffer which may have been
        # modified by us

        buffer = bytearray()

        # encrypt self.vendor_data in 8 byte increments (because that's how TEA works)
        for vendor_block in (
            self.vendor_data[pos : pos + 8]
            for pos in range(0, len(self.encrypted_data), 8)
        ):
            buffer += bytearray(tea_encrypt(vendor_block, CRYPTO_KEY))

        assert len(buffer) == len(
            self.vendor_data
        ), f"Internal error - vendor data len {len(buffer)} != ciphertext len ({len(self.vendor_data)})"

        return bytes(buffer)

    @property
    def security_record(self) -> bytes:
        return bytes(
            self.vendor_data[
                self.LABEL_SECURITY_RECORD_OFFSET : self.LABEL_SECURITY_RECORD_OFFSET
                + self.LABEL_SECURITY_RECORD_LENGTH
            ]
        )

    @security_record.setter
    def security_record(self, value: bytes) -> None:
        assert len(value) == self.LABEL_SECURITY_RECORD_LENGTH
        self.vendor_data[
            self.LABEL_SECURITY_RECORD_OFFSET : self.LABEL_SECURITY_RECORD_OFFSET
            + self.LABEL_SECURITY_RECORD_LENGTH
        ] = bytearray(value)

    @property
    def serial(self) -> str:
        return self.field_to_text(self.SERIAL_OFFSET, self.SERIAL_FIELD_SIZE)

    @property
    def uuid(self) -> str:
        return bytes(self.card_data[0:8]).hex().upper()

    def compute_security_record(self, card_uuid: bytes | None = None) -> bytes:
        # note that UUID byte with index 3 is skipped

        record_uuid = card_uuid or bytes(self.card_data[0:7])

        return bytes(
            [
                0x88,
                record_uuid[0],
                record_uuid[1],
                record_uuid[2],
                record_uuid[4],
                record_uuid[5],
                record_uuid[6],
            ]
        )

    def compute_print_counter_crc32(self) -> int:
        data = self.vendor_data[
            0:4
        ]  # CRC32 is computed over first 4 bytes of a card - unknown field and a 16 bit print counter
        return binascii.crc32(data)

    def process_card_data(self):
        # copy vendor data to encrypted_data array
        self.encrypted_data = self.card_data[
            self.VENDOR_DATA_OFFSET : self.VENDOR_DATA_OFFSET + self.VENDOR_DATA_LENGTH
        ]

        # decrypt encrypted_data into vendor_data in 8 byte increments (because that's how TEA works)
        for encrypted_block in (
            self.encrypted_data[pos : pos + 8]
            for pos in range(0, len(self.encrypted_data), 8)
        ):
            self.vendor_data += bytearray(tea_decrypt(encrypted_block, CRYPTO_KEY))

        assert len(self.vendor_data) == len(
            self.encrypted_data
        ), "Internal error - vendor data len != ciphertext len"

    @classmethod
    def validate_pm3json_dump(cls, dump: dict):
        if not "Created" in dump and not "blocks" in dump:
            raise CardLoadError(
                "File does not look like Proxmark3-compatible json dump"
            )

        if dump.get("FileType") != "mfu":
            raise CardLoadError("File is not an mfu card dump")

        if not isinstance(dump["blocks"], dict):
            raise CardLoadError(
                "'blocks' object in file is not a list, probably wrong file format"
            )

        if len(dump["blocks"]) < int(
            (cls.VENDOR_DATA_LENGTH + cls.VENDOR_DATA_OFFSET) / 4
        ):
            raise CardLoadError(
                "card dump does not look like Niimbot RFID card - size too small"
            )

    @classmethod
    def from_pm3json(cls, input: str) -> Self:
        dump = json.loads(input)
        cls.validate_pm3json_dump(dump)
        tag = cls()

        for block_num in range(35):
            block_hex = dump["blocks"].get(f"{block_num}")

            if block_hex is None:
                raise CardLoadError(f"No block {block_num} found in loaded card dump")

            block = bytes.fromhex(block_hex)
            tag.card_data += bytearray(block)

        tag.process_card_data()
        return tag

    def patch_pm3json(self, input: str) -> str:
        # we can't really generate PM3 dump from scratch so we just load the same dump
        # and replace vendor sectors with updated ones
        dump = json.loads(input)
        self.validate_pm3json_dump(dump)

        start_block = int(self.VENDOR_DATA_OFFSET / 4)
        number_of_blocks = int(self.VENDOR_DATA_LENGTH / 4)

        encrypted_data = self.reencrypted_data

        for block_num in range(start_block, start_block + number_of_blocks):
            # beginning of encrypted data is block 5 in a card dump so when accessing it by block_num we need to offset that
            new_block = bytes(encrypted_data[(block_num-start_block) * 4 : ((block_num-start_block) * 4) + 4]).hex().upper()
            dump["blocks"][str(block_num)] = new_block

        return json.dumps(dump, indent=2)

    @classmethod
    def from_pm3bin(cls, input: bytes) -> Self:

        if len(input) < PM3_MFU_DUMP_PREFIX_LENGTH + (
            cls.VENDOR_DATA_LENGTH + cls.VENDOR_DATA_OFFSET
        ):
            raise CardLoadError(
                "card dump does not look like Niimbot RFID card - size too small"
            )

        tag = cls()
        tag.card_data = bytearray(input[PM3_MFU_DUMP_PREFIX_LENGTH:])
        tag.process_card_data()
        return tag


def load_tag(args: argparse.Namespace) -> LabelTag:
    open_mode = "r"

    if args.file_format == "pm3-bin":
        open_mode += "b"

    tag_contents = None

    with open(args.input_file, open_mode) as tag_file:
        tag_contents = tag_file.read()

    if args.file_format == "pm3-json":
        return LabelTag.from_pm3json(tag_contents)
    elif args.file_format == "pm3-bin":
        return LabelTag.from_pm3bin(tag_contents)
    else:
        raise CLIError("Unknown file format specified")


def save_tag(args: argparse.Namespace, tag: LabelTag) -> None:
    open_mode_read = "r"
    open_mode_write = "w"

    if args.file_format == "pm3-bin":
        open_mode_read += "b"
        open_mode_write += "b"

    with open(args.input_file, open_mode_read) as input_tag_file:
        tag_contents = input_tag_file.read()

    if args.file_format == "pm3-json":
        patched_tag = tag.patch_pm3json(tag_contents)
    elif args.file_format == "pm3-bin":
        raise CLIError("bin not yet supported for patching")
    else:
        raise CLIError("Unknown file format specified")

    with open(args.write_file, open_mode_write) as output_tag_file:
        output_tag_file.write(patched_tag)


def tag_analyze(args: argparse.Namespace) -> None:

    tag = load_tag(args)

    print("==== Decoded RFID tag contents: ====")
    print(f"Card UUID: {tag.uuid}")
    print(f"Tag name: {tag.name}")
    print(f"Label print counter: {tag.print_counter}")
    print(f"Label paper width: {tag.paper_width}")
    print(f"Label paper width: {tag.paper_height}")
    print(f"Label print limit: {tag.print_limit}")
    print(f"Label serial number: {tag.serial}")
    print(f"Label barcode: {tag.barcode}")

    print()

    if tag.compute_security_record() == tag.security_record:
        print("Security record value valid")
    else:
        print("Security record value INVALID")

    print(
        f"Security record field value computed for current card UUID: {tag.compute_security_record().hex()}"
    )
    print(f"Security record field retrieved from dump: {tag.security_record.hex()}")

    if tag.compute_print_counter_crc32() == tag.print_counter_crc32:
        print("Print counter CRC32 checksum valid")
    else:
        print("Print counter CRC32 checksum INVALID")


def tag_patch(args: argparse.Namespace) -> None:

    if not args.write_file:
        raise CLIError("You need specify a file to write the patched RFID dump.")

    tag = load_tag(args)

    if args.name is not None:
        tag.name = args.name

    if args.width is not None:
        if args.width < 0 or args.width > 255:
            raise LabelValueError("Paper width must be between 0 and 255 mm")
        tag.paper_width = args.width

    if args.height is not None:
        if args.height < 0 or args.height > 255:
            raise LabelValueError("Paper height must be between 0 and 255 mm")
        tag.paper_heigth = args.height

    if args.print_counter is not None:
        tag.print_counter = args.print_counter
        tag.print_counter_crc32 = tag.compute_print_counter_crc32()

    if args.fix_security_record:
        card_uuid = bytes.fromhex(args.uuid) if args.uuid else None
        tag.security_record = tag.compute_security_record(card_uuid=card_uuid)

    save_tag(args, tag)


def main():
    parser = argparse.ArgumentParser(
        prog="ProgramName", description="Analyze and patch Niimbot label RFID chips"
    )

    parser.add_argument(
        "-i", "--input-file", help="RFID dump file to read", required=True
    )
    parser.add_argument(
        "-f",
        "--file-format",
        help="RFID dump file format",
        choices=["pm3-json", "pm3-bin"],
        required=True,
    )
    parser.add_argument(
        "-w", "--write-file", help="RFID dump file to write (same format as input)"
    )

    parser.add_argument("--name", "--name", help="set roll name")

    parser.add_argument("--width", "--width", help="set paper width (in mm)", type=int)

    parser.add_argument(
        "--height", "--height", help="set paper height (in mm)", type=int
    )

    parser.add_argument(
        "--print-counter",
        "--print-counter",
        help="set label print counter (counter of already printed labels) <0, 255>",
        type=int,
    )

    parser.add_argument(
        "--print-limit",
        "--print-limit",
        help="set label print limit <0, 255>",
        type=int,
    )

    parser.add_argument(
        "--fix-security-record",
        "--fix-security-record",
        help="fix security record to match card UUID",
        action='store_true',
    )
    parser.add_argument(
        "--uuid",
        "--uuid",
        help="use this card UUID instead of one in dump file to calculate security check",
        type=str,
    )

    parser.add_argument(
        "command", help="Command to execute", choices=["analyze", "patch"]
    )

    args = parser.parse_args()
    if args.command == "analyze":
        return tag_analyze(args)
    elif args.command == "patch":
        return tag_patch(args)
    else:
        print(f"Unknown command: {args.command}")


if __name__ == "__main__":
    main()
