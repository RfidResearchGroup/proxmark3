"""Per-data-group decoders: dump directory in, :class:`PassportRecord` out.

Values are parsed from the binaries, never scraped from ``hf emrtd info``
stdout - TLV is stable, printed text is not.
"""

from __future__ import annotations

import logging
from pathlib import Path

from . import images, securityinfos, tlv
from .model import (
    ComInfo,
    DocumentDetails,
    DumpFile,
    FileState,
    OptionalDetails,
    PassportRecord,
    PersonalDetails,
    SecurityInfo,
    is_pesel,  # noqa: F401  - re-exported, DG13 is where it is used
)
from .mrz import MrzError, parse as parse_mrz

log = logging.getLogger(__name__)

#: Files pm3 writes, in the order the FILES tab lists them.  Mirrors
#: ``dg_table`` in ``client/src/cmdhfemrtd.c``.
DG_FILES: tuple[tuple[str, int, str, bool], ...] = (
    ("EF_COM", 0x60, "Header and Data Group Presence Information", False),
    ("EF_DG1", 0x61, "Details recorded in MRZ", False),
    ("EF_DG2", 0x75, "Encoded Face", False),
    ("EF_DG3", 0x63, "Encoded Finger(s)", True),
    ("EF_DG4", 0x76, "Encoded Eye(s)", True),
    ("EF_DG5", 0x65, "Displayed Portrait", False),
    ("EF_DG6", 0x66, "Reserved for Future Use", False),
    ("EF_DG7", 0x67, "Displayed Signature or Usual Mark", False),
    ("EF_DG8", 0x68, "Data Feature(s)", False),
    ("EF_DG9", 0x69, "Structure Feature(s)", False),
    ("EF_DG10", 0x6A, "Substance Feature(s)", False),
    ("EF_DG11", 0x6B, "Additional Personal Detail(s)", False),
    ("EF_DG12", 0x6C, "Additional Document Detail(s)", False),
    ("EF_DG13", 0x6D, "Optional Detail(s)", False),
    ("EF_DG14", 0x6E, "Security Options", False),
    ("EF_DG15", 0x6F, "Active Authentication Public Key Info", False),
    ("EF_DG16", 0x70, "Person(s) to Notify", False),
    ("EF_SOD", 0x77, "Document Security Object", False),
    ("EF_CardAccess", 0x00, "PACE SecurityInfos", False),
    ("EF_CardSecurity", 0x00, "PACE SecurityInfos for Chip Auth Mapping", False),
)

#: EF_COM's 5C tag list maps DG tags back to data-group numbers.
TAG_TO_DG: dict[int, int] = {
    0x61: 1,
    0x75: 2,
    0x63: 3,
    0x76: 4,
    0x65: 5,
    0x66: 6,
    0x67: 7,
    0x68: 8,
    0x69: 9,
    0x6A: 10,
    0x6B: 11,
    0x6C: 12,
    0x6D: 13,
    0x6E: 14,
    0x6F: 15,
    0x70: 16,
}


def read_dump_file(directory: Path, name: str) -> tuple[Path | None, bytes]:
    """Find ``name`` in ``directory``, accepting ``.bin`` or ``.BIN``."""
    for suffix in (".bin", ".BIN", ".Bin", ""):
        candidate = directory / f"{name}{suffix}"
        if candidate.is_file():
            try:
                return candidate, candidate.read_bytes()
            except OSError as exc:
                log.warning("cannot read %s: %s", candidate, exc)
                return candidate, b""
    return None, b""


# ---------------------------------------------------------------- EF_COM
def parse_com(data: bytes) -> ComInfo:
    nodes = tlv.parse(data)
    info = ComInfo()
    raw_lds = tlv.find_value(nodes, 0x5F01)
    raw_uni = tlv.find_value(nodes, 0x5F36)
    if raw_lds:
        info.lds_version = _dotted(tlv.text(raw_lds), 2)
    if raw_uni:
        info.unicode_version = _dotted(tlv.text(raw_uni), 2)
    taglist = tlv.find_value(nodes, 0x5C) or b""
    info.present_tags = list(taglist)
    info.present_dgs = sorted({TAG_TO_DG[t] for t in taglist if t in TAG_TO_DG})
    return info


def _dotted(digits: str, group: int) -> str:
    """``0107`` -> ``01.07``; ``040000`` -> ``04.00.00``."""
    clean = "".join(ch for ch in digits if ch.isdigit())
    if not clean:
        return digits
    return ".".join(clean[i : i + group] for i in range(0, len(clean), group))


# ---------------------------------------------------------------- EF_DG1
def parse_dg1(data: bytes):
    """Return the parsed MRZ from EF_DG1 (tag 61 -> 5F1F), or None."""
    nodes = tlv.parse(data)
    raw = tlv.find_value(nodes, 0x5F1F)
    if raw is None:
        return None
    text = tlv.text(raw).replace(" ", "")
    for width in (44, 36, 30):
        if len(text) % width == 0 and len(text) // width in (2, 3):
            lines = [text[i : i + width] for i in range(0, len(text), width)]
            try:
                return parse_mrz(lines)
            except MrzError:
                continue
    try:
        return parse_mrz(text)
    except MrzError as exc:
        log.warning("EF_DG1 does not contain a usable MRZ: %s", exc)
        return None


# --------------------------------------------------------------- EF_DG11
_DG11_TAGS = {
    0x5F0E: "full_name",
    0x5F10: "personal_number",
    0x5F11: "place_of_birth",
    0x5F2B: "full_date_of_birth",
    0x5F42: "address",
    0x5F12: "telephone",
    0x5F13: "profession",
    0x5F14: "title",
    0x5F15: "personal_summary",
    0x5F18: "custody_information",
}


def parse_dg11(data: bytes) -> PersonalDetails:
    nodes = tlv.parse(data)
    out = PersonalDetails()
    for tag, attr in _DG11_TAGS.items():
        hit = tlv.find(nodes, tag)
        if hit is None:
            continue
        value = _clean_field(hit.value, numeric=attr == "full_date_of_birth")
        setattr(out, attr, value)
    other = tlv.find(nodes, 0xA0)  # other names, wrapped in a count + 5F0F list
    if other is not None:
        out.other_names = [
            _clean_field(n.value) for n in other.find_all(0x5F0F) if n.value
        ]
    return out


# --------------------------------------------------------------- EF_DG12
_DG12_TAGS = {
    0x5F19: "issuing_authority",
    0x5F26: "date_of_issue",
    0x5F1B: "endorsements",
    0x5F1C: "tax_exit_requirements",
    0x5F55: "personalization_time",
    0x5F56: "personalization_device",
}


def parse_dg12(data: bytes) -> DocumentDetails:
    nodes = tlv.parse(data)
    out = DocumentDetails()
    for tag, attr in _DG12_TAGS.items():
        hit = tlv.find(nodes, tag)
        if hit is None:
            continue
        setattr(out, attr, _clean_field(hit.value, numeric=attr.startswith("date")))
    for tag, attr in ((0x5F1D, "image_of_front"), (0x5F1E, "image_of_rear")):
        hit = tlv.find(nodes, tag)
        if hit is not None:
            setattr(out, attr, hit.value)
    other = tlv.find(nodes, 0xA0)
    if other is not None:
        out.other_persons = [
            _clean_field(n.value) for n in other.find_all(0x5F1A) if n.value
        ]
    return out


def _clean_field(raw: bytes, *, numeric: bool = False) -> str:
    """Decode an LDS text field.  ``<`` is a separator, not a literal."""
    text = tlv.text(raw)
    if numeric:
        # Dates are sometimes BCD-packed rather than ASCII.
        if text and not text.strip("0123456789"):
            return text
        if len(raw) == 4:
            return raw.hex()
    return text.replace("<<", ", ").replace("<", " ").strip().rstrip(",").strip()


# --------------------------------------------------------------- EF_DG13
#: A tag list, enumerating what follows.  Metadata, not a field of its own.
_DG13_TAG_LIST = 0x5C


def parse_dg13(data: bytes) -> OptionalDetails:
    """Read DG13 as tagged values.  ICAO assigns it no meaning, so neither do we."""
    out = OptionalDetails()
    try:
        nodes = tlv.parse(data)
    except Exception:
        return out
    for node in nodes:
        for child in node.children:
            if child.constructed or child.tag == _DG13_TAG_LIST:
                continue
            out.fields.append((child.tag_hex, tlv.text(child.value)))
    return out


# ----------------------------------------------------------- EF_DG14/15
def parse_security(dg14: bytes, dg15: bytes, card_access: bytes = b"") -> SecurityInfo:
    out = SecurityInfo()
    if dg14:
        out.dg14_hex = dg14.hex().upper()
        out.protocols = [p.text for p in securityinfos.parse(dg14)]
    if dg15:
        out.dg15_hex = dg15.hex().upper()
        _describe_aa_key(dg15, out)
    if card_access:
        out.pace = [p.text for p in securityinfos.parse(card_access)]
    return out


def _describe_aa_key(dg15: bytes, out: SecurityInfo) -> None:
    """Decode the SubjectPublicKeyInfo in DG15 (tag 6F)."""
    nodes = tlv.parse(dg15)
    spki = nodes[0].value if nodes and nodes[0].tag == 0x6F else dg15
    out.aa_public_key_hex = spki.hex().upper()
    try:
        from cryptography.hazmat.primitives.serialization import load_der_public_key
    except ImportError:
        out.aa_algorithm = "install 'cryptography' to decode the AA public key"
        return
    try:
        key = load_der_public_key(spki)
    except Exception as exc:
        out.aa_algorithm = f"undecodable ({exc.__class__.__name__})"
        return
    out.aa_algorithm = type(key).__name__.replace("_", "").replace("PublicKey", "")
    size = getattr(key, "key_size", None)
    if size:
        out.aa_key_size = f"{size} bit"


# ---------------------------------------------------------------- images
def extract_image(data: bytes) -> bytes:
    """Carve the image out of a CBEFF-wrapped DG and return PNG bytes."""
    if not data:
        return b""
    png, blob = images.decode_to_png(data)
    if png is None and blob is not None:
        log.info(
            "found %s image at offset %d but no decoder produced a PNG",
            blob.fmt,
            blob.offset,
        )
    return png or b""


# ----------------------------------------------------------- whole dump
def load_dump(directory: Path) -> PassportRecord:
    """Parse a pm3 dump directory into a :class:`PassportRecord`."""
    directory = Path(directory)
    record = PassportRecord(source_dir=directory)
    raw: dict[str, bytes] = {}

    for name, _tag, note, eac in DG_FILES:
        path, data = read_dump_file(directory, name)
        entry = DumpFile(name=name, path=path, size=len(data), note=note, data=data)
        if data:
            entry.state = FileState.PRESENT
            raw[name] = data
        elif eac:
            entry.state = FileState.PROTECTED
        else:
            entry.state = FileState.ABSENT
        record.files.append(entry)

    if "EF_COM" in raw:
        record.com = parse_com(raw["EF_COM"])

    if not raw:
        # Naming DG1 here sends you after the wrong file: nothing was read.
        record.warnings.append("No files were read - the dump directory is empty.")
    elif "EF_DG1" in raw:
        record.mrz = parse_dg1(raw["EF_DG1"])
        if record.mrz is None:
            record.warnings.append(
                "EF_DG1 is present but its MRZ could not be decoded."
            )
            _mark(record, "EF_DG1", FileState.UNREADABLE)
    else:
        record.warnings.append("EF_DG1 is missing - no MRZ to render.")

    if "EF_DG2" in raw:
        record.portrait_png = extract_image(raw["EF_DG2"])
        if not record.portrait_png:
            record.warnings.append(
                "EF_DG2 is present but the portrait could not be decoded."
            )
    if "EF_DG5" in raw:
        record.displayed_portrait_png = extract_image(raw["EF_DG5"])
    if "EF_DG7" in raw:
        record.signature_png = extract_image(raw["EF_DG7"])

    if "EF_DG11" in raw:
        record.personal = parse_dg11(raw["EF_DG11"])
    if "EF_DG12" in raw:
        record.document = parse_dg12(raw["EF_DG12"])
    if "EF_DG13" in raw:
        record.optional = parse_dg13(raw["EF_DG13"])
    record.security = parse_security(
        raw.get("EF_DG14", b""),
        raw.get("EF_DG15", b""),
        raw.get("EF_CardAccess", b"") or raw.get("EF_CardSecurity", b""),
    )

    from .sod import parse_sod  # local import: optional dependencies

    record.sod = parse_sod(raw.get("EF_SOD", b""), raw)

    # EF_COM claims data groups that may not have been dumped: reconcile.
    for number in record.com.present_dgs:
        entry = record.file(f"EF_DG{number}")
        if entry is not None and entry.state == FileState.ABSENT:
            entry.state = (
                FileState.PROTECTED if number in (3, 4) else FileState.UNREADABLE
            )
            entry.note += "  (announced in EF_COM, not in dump)"

    return record


def _mark(record: PassportRecord, name: str, state: str) -> None:
    entry = record.file(name)
    if entry is not None:
        entry.state = state
