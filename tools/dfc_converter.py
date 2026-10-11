#!/usr/bin/env python3
"""Convert DESFire credentials between DFC v4 and Proxmark3 mfdes v1 JSON.

DFC is the interchange format used by the DESFire Compatible app for Flipper
Zero and Chameleon Ultra. Proxmark3 loads the JSON result with `hf mfdes eload`.
Only features represented by both formats are converted.
"""

import argparse
import json
import pathlib
import re
import sys


class ConversionError(ValueError):
    """Input cannot be represented in the destination format."""


FILE_TYPES = {
    "Standard Data": (0, "standard"),
    "Backup Data": (1, "backup"),
    "Value": (2, "value"),
    "Linear Record": (3, "linear_record"),
    "Cyclic Record": (4, "cyclic_record"),
}
FILE_TYPES_BY_RAW = {raw: (name, token) for name, (raw, token) in FILE_TYPES.items()}
COMM_BY_RAW = {0: "plain", 1: "mac", 2: "plain_rfu", 3: "encrypt"}
COMM_BY_TOKEN = {token: raw for raw, token in COMM_BY_RAW.items()}
STORAGE_CODES = {2048: 0x16, 4096: 0x18, 8192: 0x1A}
GENERATION_VERSION = {
    "EV1": (0x01, 0x00, 0x01, 0x04),
    "EV2": (0x12, 0x00, 0x02, 0x00),
    "EV3": (0x33, 0x00, 0x03, 0x00),
}
MAJOR_GENERATION = {0x01: "EV1", 0x12: "EV2", 0x42: "EV2", 0x22: "EV2", 0x33: "EV3"}
KEY_LENGTHS = {"des": 8, "2tdea": 16, "3tdea": 24, "aes": 16}
HEX_RE = re.compile(r"(?:[0-9A-F]{2})(?: [0-9A-F]{2})*")


def compact_hex(value, field, lengths=None):
    if not isinstance(value, str):
        raise ConversionError(f"{field}: expected a hexadecimal string")
    compact = value.replace(" ", "").upper()
    if not compact or len(compact) % 2 or re.fullmatch(r"[0-9A-F]+", compact) is None:
        raise ConversionError(f"{field}: invalid hexadecimal octets")
    if lengths is not None and len(compact) // 2 not in lengths:
        expected = " or ".join(str(n) for n in lengths)
        raise ConversionError(f"{field}: expected {expected} octets")
    return compact


def spaced_hex(value, field, lengths=None):
    compact = compact_hex(value, field, lengths)
    return " ".join(compact[i:i + 2] for i in range(0, len(compact), 2))


def parse_integer(value, field, minimum=None, maximum=None):
    try:
        number = int(value) if isinstance(value, int) else int(value, 10)
    except (TypeError, ValueError) as exc:
        raise ConversionError(f"{field}: expected a decimal integer") from exc
    if minimum is not None and number < minimum:
        raise ConversionError(f"{field}: value is below {minimum}")
    if maximum is not None and number > maximum:
        raise ConversionError(f"{field}: value is above {maximum}")
    return number


def parse_dfc_fields(text):
    fields = {}
    order = []
    for line_number, raw in enumerate(text.splitlines(), 1):
        if not raw or raw.startswith("#"):
            continue
        if raw.endswith(" ") or ": " not in raw:
            raise ConversionError(f"line {line_number}: expected 'Key: Value'")
        key, value = raw.split(": ", 1)
        if not key or key.strip() != key or not value:
            raise ConversionError(f"line {line_number}: malformed field")
        if key in fields:
            raise ConversionError(f"line {line_number}: duplicate field {key!r}")
        fields[key] = value
        order.append(key)
    if order[:2] != ["Filetype", "Version"]:
        raise ConversionError("Filetype and Version must be the first two fields")
    return fields


class DfcReader:
    def __init__(self, text):
        self.fields = parse_dfc_fields(text)

    def take(self, name, required=True):
        value = self.fields.pop(name, None)
        if value is None and required:
            raise ConversionError(f"missing required field {name!r}")
        return value

    def integer(self, name, minimum=None, maximum=None, required=True):
        value = self.take(name, required)
        if value is None:
            return None
        return parse_integer(value, name, minimum, maximum)

    def hexa(self, name, lengths=None, required=True):
        value = self.take(name, required)
        if value is None:
            return None
        if HEX_RE.fullmatch(value) is None:
            raise ConversionError(f"{name}: expected uppercase hexadecimal octets")
        return compact_hex(value, name, lengths)

    def token(self, name, allowed):
        value = self.take(name)
        if value not in allowed:
            raise ConversionError(f"{name}: unsupported value {value!r}")
        return value

    def flag(self, name, required=True):
        value = self.take(name, required)
        if value is None:
            return None
        if value not in ("0", "1"):
            raise ConversionError(f"{name}: expected 0 or 1")
        return value == "1"


def key_type(ks2, keys):
    keys = list(keys)
    selector = int(ks2, 16) & 0xC0
    if selector == 0x80:
        return "aes"
    if selector == 0x40:
        return "3tdea"
    if keys and len(keys[0]["Key"]) == 16:
        return "des"
    return "2tdea"


def read_keys(reader, prefix, ks2):
    count = reader.integer(f"{prefix} Key Count", 0, 14)
    keys = {}
    expected_length = {0x40: 24, 0x80: 16}.get(int(ks2, 16) & 0xC0, 16)
    for index in range(count):
        name = f"{prefix} Key {index:02X}"
        keys[str(index)] = {
            "Key": reader.hexa(name, (expected_length,)),
            "Version": reader.hexa(f"{name} Version", (1,)),
        }
    return keys


def read_files(reader, prefix):
    files = {}
    count = reader.integer(f"{prefix} File Count", 0, 32)
    for index in range(count):
        base = f"{prefix} File {index:02X}"
        number = reader.hexa(f"{base} Number", (1,))
        type_name = reader.token(f"{base} Type", set(FILE_TYPES))
        raw, token = FILE_TYPES[type_name]
        comm = reader.hexa(f"{base} Communication Settings", (1,))
        comm_value = int(comm, 16)
        if comm_value not in COMM_BY_RAW:
            raise ConversionError(f"{base} Communication Settings: unsupported value {comm}")
        item = {
            "Type": token,
            "TypeRaw": f"{raw:02X}",
            "CommMode": COMM_BY_RAW[comm_value],
            "AccessRights": reader.hexa(f"{base} Access Rights", (2,)),
        }
        iso_id = reader.hexa(f"{base} ISO File ID", (2,), required=False)
        if iso_id is not None:
            item["ISOFileID"] = iso_id
        if raw in (0, 1):
            item["FileSize"] = reader.integer(f"{base} Size", 1, 0xFFFFFF)
            data = reader.hexa(f"{base} Data", required=False)
            complete = reader.flag(f"{base} Data Complete")
            if complete and (data is None or len(data) // 2 != item["FileSize"]):
                raise ConversionError(f"{base}: complete data must match the file size")
            item["Read"] = data is not None
            if data is not None:
                if len(data) // 2 > item["FileSize"]:
                    raise ConversionError(f"{base}: data is longer than the file")
                item["Data"] = data
        elif raw == 2:
            item["LowerLimit"] = reader.integer(f"{base} Value Lower Limit", -0x80000000, 0x7FFFFFFF)
            item["UpperLimit"] = reader.integer(f"{base} Value Upper Limit", -0x80000000, 0x7FFFFFFF)
            item["Value"] = reader.integer(f"{base} Value", item["LowerLimit"], item["UpperLimit"])
            item["LimitedCredit"] = reader.hexa(f"{base} Limited Credit", (1,))
            item["Read"] = True
        else:
            item["RecordSize"] = reader.integer(f"{base} Record Size", 1, 0xFFFFFF)
            item["MaxRecords"] = reader.integer(f"{base} Max Records", 1, 0xFFFFFF)
            item["CurRecords"] = reader.integer(f"{base} Record Count", 0, item["MaxRecords"])
            records = {}
            record_index = 0
            while f"{base} Record {record_index:02X}" in reader.fields:
                records[str(record_index)] = reader.hexa(
                    f"{base} Record {record_index:02X}", (item["RecordSize"],)
                )
                record_index += 1
            complete = reader.flag(f"{base} Record Complete")
            if complete and len(records) != item["CurRecords"]:
                raise ConversionError(f"{base}: complete records must match Record Count")
            item["Read"] = complete
            item["Records"] = records
        files[number] = item
    return files


def version_frames(generation, storage):
    if generation not in GENERATION_VERSION:
        raise ConversionError(f"Card Generation: {generation} is not representable")
    storage_code = STORAGE_CODES.get(storage)
    if storage_code is None:
        raise ConversionError(f"Card Storage: unsupported capacity {storage}")
    hw_major, hw_minor, sw_major, sw_minor = GENERATION_VERSION[generation]
    return (
        f"040101{hw_major:02X}{hw_minor:02X}{storage_code:02X}05",
        f"040101{sw_major:02X}{sw_minor:02X}{storage_code:02X}05",
    )


def dfc_to_json(text):
    reader = DfcReader(text)
    if reader.take("Filetype") != "DFC Credential" or reader.take("Version") != "4":
        raise ConversionError("only DFC Credential version 4 is supported")
    generation = reader.token("Card Generation", set(GENERATION_VERSION))
    storage = reader.integer("Card Storage", 1)
    uid = reader.hexa("UID", (4, 7, 10))
    reader.token("UID Provenance", {"Real", "Random", "Unknown"})
    signature = reader.hexa("Card Static Signature", (56,), required=False)
    picc_ks1 = reader.hexa("PICC Key Settings 1", (1,))
    picc_ks2 = reader.hexa("PICC Key Settings 2", (1,))
    reader.token("PICC Authentication Mode", {"D40", "ISO", "AES"})
    picc_keys = read_keys(reader, "PICC", picc_ks2)

    unsupported = (
        "PICC Random ID", "PICC Format Disabled", "PICC SM Disable",
        "PICC EV2 Card Capabilities", "PICC Proximity Key",
        "PICC Virtual Card Installation ID", "PICC DAM Authentication Key",
    )
    present = [name for name in unsupported if name in reader.fields]
    if present:
        raise ConversionError(f"{present[0]} has no mfdes v1 representation")
    ats = reader.hexa("PICC ATS", required=False) or "067577810280"
    sak = reader.hexa("PICC SAK", (1,), required=False) or "20"
    atqa = reader.hexa("PICC ATQA", (2,), required=False) or "4403"
    if reader.integer("PICC File Count", 0, 32) != 0:
        raise ConversionError("PICC-level files have no mfdes v1 representation")

    applications = {
        "000000": {
            "KeySettings": picc_ks1,
            "NumKeysRaw": picc_ks2,
            "NumKeys": int(picc_ks2, 16) & 0x1F,
            "KeyType": key_type(picc_ks2, picc_keys.values()),
            "Authenticated": bool(picc_keys),
            "Keys": picc_keys,
        }
    }
    app_count = reader.integer("Application Count", 0, 255)
    for index in range(app_count):
        prefix = f"Application {index:02X}"
        aid = reader.hexa(f"{prefix} AID", (3,))
        iso_id = reader.hexa(f"{prefix} ISO File ID", (2,), required=False)
        df_name = reader.hexa(f"{prefix} DF Name", required=False)
        ks1 = reader.hexa(f"{prefix} Key Settings 1", (1,))
        ks2 = reader.hexa(f"{prefix} Key Settings 2", (1,))
        reader.token(f"{prefix} Authentication Mode", {"D40", "ISO", "AES"})
        if f"{prefix} Key Set Count" in reader.fields:
            raise ConversionError(f"{prefix}: key sets have no mfdes v1 representation")
        keys = read_keys(reader, prefix, ks2)
        app = {
            "KeySettings": ks1,
            "NumKeysRaw": ks2,
            "NumKeys": int(ks2, 16) & 0x1F,
            "KeyType": key_type(ks2, keys.values()),
            "Authenticated": bool(keys),
            "Keys": keys,
            "Files": read_files(reader, prefix),
        }
        if iso_id is not None:
            app["ISOFileID"] = iso_id
        if df_name is not None:
            app["DFName"] = df_name
        applications[aid] = app

    if reader.fields:
        name = sorted(reader.fields)[0]
        raise ConversionError(f"{name}: unsupported DFC field")
    version_hw, version_sw = version_frames(generation, storage)
    card = {
        "UID": uid,
        "ATQA": atqa,
        "SAK": sak,
        "ATS": ats,
        "VersionHW": version_hw,
        "VersionSW": version_sw,
        "VersionProd": uid[:14].ljust(14, "0") + "00000000000124",
    }
    if signature is not None:
        card["Signature"] = signature
    return {
        "Created": "proxmark3 dfc_converter",
        "FileType": "mfdes v1",
        "Version": 1,
        "Card": card,
        "Applications": applications,
    }


def append_keys(lines, prefix, app):
    keys = app.get("Keys", {})
    known = []
    for index in range(14):
        item = keys.get(str(index))
        if not item or "Key" not in item:
            break
        known.append(item)
    lines.append(f"{prefix} Key Count: {len(known)}")
    key_type_name = app.get("KeyType", "2tdea")
    if key_type_name not in KEY_LENGTHS:
        raise ConversionError(f"{prefix} KeyType: unsupported value {key_type_name!r}")
    for index, item in enumerate(known):
        name = f"{prefix} Key {index:02X}"
        lines.append(f"{name}: {spaced_hex(item['Key'], name, (KEY_LENGTHS[key_type_name],))}")
        version = item.get("Version", "00")
        lines.append(f"{name} Version: {spaced_hex(version, name + ' Version', (1,))}")


def append_files(lines, prefix, app):
    files = app.get("Files", {})
    lines.append(f"{prefix} File Count: {len(files)}")
    for index, (number, item) in enumerate(sorted(files.items(), key=lambda pair: int(pair[0], 16))):
        base = f"{prefix} File {index:02X}"
        raw = int(compact_hex(item.get("TypeRaw", ""), base + " TypeRaw", (1,)), 16)
        if raw not in FILE_TYPES_BY_RAW:
            raise ConversionError(f"{base}: file type {raw:02X} has no DFC v4 representation")
        type_name, _ = FILE_TYPES_BY_RAW[raw]
        comm_token = item.get("CommMode")
        if comm_token not in COMM_BY_TOKEN:
            raise ConversionError(f"{base} CommMode: unsupported value {comm_token!r}")
        lines.extend([
            f"{base} Number: {spaced_hex(number, base + ' Number', (1,))}",
            f"{base} Type: {type_name}",
            f"{base} Communication Settings: {COMM_BY_TOKEN[comm_token]:02X}",
            f"{base} Access Rights: {spaced_hex(item['AccessRights'], base + ' Access Rights', (2,))}",
        ])
        if "ISOFileID" in item:
            lines.append(f"{base} ISO File ID: {spaced_hex(item['ISOFileID'], base + ' ISO File ID', (2,))}")
        if raw in (0, 1):
            size = parse_integer(item.get("FileSize"), base + " FileSize", 1, 0xFFFFFF)
            lines.append(f"{base} Size: {size}")
            data = item.get("Data") if item.get("Read") else None
            if data is not None:
                lines.append(f"{base} Data: {spaced_hex(data, base + ' Data')}")
            complete = data is not None and len(compact_hex(data, base + " Data")) // 2 == size
            lines.append(f"{base} Data Complete: {int(complete)}")
        elif raw == 2:
            for field, label in (("LowerLimit", "Value Lower Limit"), ("UpperLimit", "Value Upper Limit"), ("Value", "Value")):
                lines.append(f"{base} {label}: {parse_integer(item.get(field), base + ' ' + field, -0x80000000, 0x7FFFFFFF)}")
            lines.append(f"{base} Limited Credit: {spaced_hex(item['LimitedCredit'], base + ' Limited Credit', (1,))}")
        else:
            record_size = parse_integer(item.get("RecordSize"), base + " RecordSize", 1, 0xFFFFFF)
            max_records = parse_integer(item.get("MaxRecords"), base + " MaxRecords", 1, 0xFFFFFF)
            cur_records = parse_integer(item.get("CurRecords"), base + " CurRecords", 0, max_records)
            lines.extend([f"{base} Record Size: {record_size}", f"{base} Max Records: {max_records}", f"{base} Record Count: {cur_records}"])
            records = item.get("Records", {})
            for record_index, record in sorted(records.items(), key=lambda pair: int(pair[0])):
                lines.append(f"{base} Record {int(record_index):02X}: {spaced_hex(record, base + ' Record', (record_size,))}")
            lines.append(f"{base} Record Complete: {int(bool(item.get('Read')) and len(records) == cur_records)}")


def auth_mode(app):
    key_type_name = app.get("KeyType", "2tdea")
    if key_type_name == "aes":
        return "AES"
    ks2 = int(compact_hex(app.get("NumKeysRaw", "00"), "NumKeysRaw", (1,)), 16)
    return "ISO" if ks2 & 0x20 else "D40"


def json_to_dfc(image):
    if image.get("FileType") != "mfdes v1" or image.get("Version") != 1:
        raise ConversionError("only Proxmark3 mfdes v1 JSON is supported")
    card = image.get("Card", {})
    uid = compact_hex(card.get("UID", ""), "Card.UID", (4, 7, 10))
    version_hw = compact_hex(card.get("VersionHW", ""), "Card.VersionHW", (7,))
    generation = MAJOR_GENERATION.get(int(version_hw[6:8], 16))
    if generation is None:
        raise ConversionError(f"Card.VersionHW: unsupported generation byte {version_hw[6:8]}")
    storage = 1 << (int(version_hw[10:12], 16) >> 1)
    applications = image.get("Applications", {})
    picc = applications.get("000000")
    if not isinstance(picc, dict):
        raise ConversionError("Applications.000000: PICC application is required")
    lines = [
        "Filetype: DFC Credential", "Version: 4", f"Card Generation: {generation}",
        f"Card Storage: {storage}", f"UID: {spaced_hex(uid, 'Card.UID')}", "UID Provenance: Real",
    ]
    if "Signature" in card:
        lines.append(f"Card Static Signature: {spaced_hex(card['Signature'], 'Card.Signature', (56,))}")
    lines.extend([
        f"PICC Key Settings 1: {spaced_hex(picc['KeySettings'], 'PICC Key Settings 1', (1,))}",
        f"PICC Key Settings 2: {spaced_hex(picc['NumKeysRaw'], 'PICC Key Settings 2', (1,))}",
        f"PICC Authentication Mode: {auth_mode(picc)}",
    ])
    append_keys(lines, "PICC", picc)
    for field, label, lengths in (("ATS", "PICC ATS", None), ("SAK", "PICC SAK", (1,)), ("ATQA", "PICC ATQA", (2,))):
        if field in card:
            lines.append(f"{label}: {spaced_hex(card[field], label, lengths)}")
    lines.append("PICC File Count: 0")
    app_items = [(aid, app) for aid, app in applications.items() if aid != "000000"]
    lines.append(f"Application Count: {len(app_items)}")
    for index, (aid, app) in enumerate(sorted(app_items)):
        prefix = f"Application {index:02X}"
        lines.append(f"{prefix} AID: {spaced_hex(aid, prefix + ' AID', (3,))}")
        if "ISOFileID" in app:
            lines.append(f"{prefix} ISO File ID: {spaced_hex(app['ISOFileID'], prefix + ' ISO File ID', (2,))}")
        if "DFName" in app:
            lines.append(f"{prefix} DF Name: {spaced_hex(app['DFName'], prefix + ' DF Name')}")
        lines.extend([
            f"{prefix} Key Settings 1: {spaced_hex(app['KeySettings'], prefix + ' Key Settings 1', (1,))}",
            f"{prefix} Key Settings 2: {spaced_hex(app['NumKeysRaw'], prefix + ' Key Settings 2', (1,))}",
            f"{prefix} Authentication Mode: {auth_mode(app)}",
        ])
        append_keys(lines, prefix, app)
        append_files(lines, prefix, app)
    return "\n".join(lines) + "\n"


def convert(source, destination):
    source_suffix = source.suffix.lower()
    destination_suffix = destination.suffix.lower()
    if source_suffix == ".dfc" and destination_suffix == ".json":
        image = dfc_to_json(source.read_text(encoding="ascii"))
        destination.write_text(json.dumps(image, indent=2) + "\n", encoding="utf-8")
    elif source_suffix == ".json" and destination_suffix == ".dfc":
        image = json.loads(source.read_text(encoding="utf-8"))
        destination.write_text(json_to_dfc(image), encoding="ascii")
    else:
        raise ConversionError("conversion must be .dfc to .json or .json to .dfc")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=pathlib.Path, help="input .dfc or .json file")
    parser.add_argument("destination", type=pathlib.Path, help="output .json or .dfc file")
    args = parser.parse_args(argv)
    try:
        convert(args.source, args.destination)
    except (ConversionError, OSError, json.JSONDecodeError) as exc:
        parser.exit(1, f"dfc_converter: {exc}\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
