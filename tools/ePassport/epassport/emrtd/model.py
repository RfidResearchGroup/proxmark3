"""The single UI-facing object.

Everything the GUI renders comes from :class:`PassportRecord`.  Reading a card
and opening a saved dump produce the same object, so there is exactly one
rendering path.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from .mrz import FILLER, Mrz


class FileState:
    """Why a data group is or is not in the dump."""

    PRESENT = "present"
    ABSENT = "absent"
    PROTECTED = "protected"  # EAC / PACE - readable only with terminal auth
    UNREADABLE = "unreadable"  # present on the chip but the parse failed


@dataclass
class DumpFile:
    """One file from the dump directory, as shown in the FILES tab."""

    name: str
    path: Path | None
    size: int = 0
    state: str = FileState.ABSENT
    note: str = ""
    data: bytes = b""

    @property
    def state_label(self) -> str:
        return {
            FileState.PRESENT: "present",
            FileState.ABSENT: "not present",
            FileState.PROTECTED: "protected",
            FileState.UNREADABLE: "unreadable",
        }.get(self.state, self.state)


@dataclass
class PersonalDetails:
    """EF_DG11 - additional personal details."""

    full_name: str = ""
    other_names: list[str] = field(default_factory=list)
    personal_number: str = ""
    full_date_of_birth: str = ""
    place_of_birth: str = ""
    address: str = ""
    telephone: str = ""
    profession: str = ""
    title: str = ""
    personal_summary: str = ""
    custody_information: str = ""

    def is_empty(self) -> bool:
        return not any(vars(self).values())


@dataclass
class DocumentDetails:
    """EF_DG12 - additional document details."""

    issuing_authority: str = ""
    date_of_issue: str = ""
    other_persons: list[str] = field(default_factory=list)
    endorsements: str = ""
    tax_exit_requirements: str = ""
    image_of_front: bytes = b""
    image_of_rear: bytes = b""
    personalization_time: str = ""
    personalization_device: str = ""

    def is_empty(self) -> bool:
        return not any(v for k, v in vars(self).items() if not k.startswith("image_"))


def _mrz_personal_number(field: str) -> str:
    """The MRZ optional-data field read as a personal number.

    9303 replaces every space and special character in the number with ``<``
    and then pads the field with the same character, so the trailing run is
    padding while a filler inside the number stood for something we cannot
    recover.  A space is the closest we can put back.
    """
    return field.rstrip(FILLER).replace(FILLER, " ").strip()


#: Poland carries the PESEL, its national identity number, in this DG13 tag.
PESEL_TAG = "5F70"

_PESEL_WEIGHTS = (1, 3, 7, 9, 1, 3, 7, 9, 1, 3)


def is_pesel(value: str) -> bool:
    """11 digits whose PESEL check digit holds.

    DG13 is issuer-defined, so the checksum is what separates a PESEL from
    eleven digits that happen to sit under the same tag.
    """
    if len(value) != 11 or not value.isdigit():
        return False
    total = sum(int(digit) * weight for digit, weight in zip(value, _PESEL_WEIGHTS))
    return (10 - total % 10) % 10 == int(value[10])


@dataclass
class OptionalDetails:
    """EF_DG13 - optional details.  ICAO leaves the content to the issuer."""

    #: ``(tag, text)`` in the order they appear, with no meaning attached.
    fields: list[tuple[str, str]] = field(default_factory=list)


@dataclass
class SecurityInfo:
    """EF_DG14 / EF_DG15 - chip security options and AA public key."""

    protocols: list[str] = field(default_factory=list)
    pace: list[str] = field(default_factory=list)
    aa_algorithm: str = ""
    aa_key_size: str = ""
    aa_public_key_hex: str = ""
    dg14_hex: str = ""
    dg15_hex: str = ""


@dataclass
class SodHash:
    """One row of the EF_SOD data-group hash table."""

    dg: int
    expected: str
    actual: str = ""
    status: str = "not checked"  # "match" | "MISMATCH" | "not checked"


@dataclass
class SodInfo:
    """EF_SOD summary.  ``available`` is False when the parser is missing."""

    available: bool = False
    message: str = ""
    hash_algorithm: str = ""
    signature_algorithm: str = ""
    ldsversion: str = ""
    signer_subject: str = ""
    signer_issuer: str = ""
    signer_serial: str = ""
    valid_from: str = ""
    valid_to: str = ""
    hashes: list[SodHash] = field(default_factory=list)

    @property
    def mismatches(self) -> list[SodHash]:
        return [h for h in self.hashes if h.status == "MISMATCH"]


@dataclass
class ComInfo:
    """EF_COM - which data groups the chip claims to hold."""

    lds_version: str = ""
    unicode_version: str = ""
    present_tags: list[int] = field(default_factory=list)
    present_dgs: list[int] = field(default_factory=list)


@dataclass
class PassportRecord:
    """Everything the UI knows about one document."""

    source_dir: Path | None = None
    mrz: Mrz | None = None
    com: ComInfo = field(default_factory=ComInfo)
    personal: PersonalDetails = field(default_factory=PersonalDetails)
    document: DocumentDetails = field(default_factory=DocumentDetails)
    optional: OptionalDetails = field(default_factory=OptionalDetails)
    security: SecurityInfo = field(default_factory=SecurityInfo)
    sod: SodInfo = field(default_factory=SodInfo)
    files: list[DumpFile] = field(default_factory=list)
    portrait_png: bytes = b""
    signature_png: bytes = b""
    displayed_portrait_png: bytes = b""
    warnings: list[str] = field(default_factory=list)

    # -- derived, purely for display -------------------------------------
    @property
    def surname(self) -> str:
        return self.mrz.surname if self.mrz else ""

    @property
    def given_names(self) -> str:
        if self.mrz and self.mrz.given_names:
            return self.mrz.given_names
        return ""

    @property
    def display_name(self) -> str:
        parts = [self.given_names, self.surname]
        return " ".join(p for p in parts if p) or "UNKNOWN"

    # -- fields that live in optional data groups -------------------------
    #
    # DG11 and DG12 are optional, and plenty of real passports omit them
    # entirely - the data is printed on the page but never written to the
    # chip.  Distinguish "the chip does not carry this" from "empty", so the
    # page can say so instead of showing a bare dash.
    NOT_ON_CHIP = "not on chip"

    def _optional(self, value: str, dg: int) -> str:
        if value:
            return value
        return self.NOT_ON_CHIP if not self.has_dg(dg) else ""

    @property
    def place_of_birth(self) -> str:
        return self._optional(self.personal.place_of_birth, 11)

    @property
    def issuing_authority(self) -> str:
        return self._optional(self.document.issuing_authority, 12)

    @property
    def date_of_issue(self) -> str:
        formatted = _icao_long_date(self.document.date_of_issue)
        return self._optional(formatted, 12)

    @property
    def personal_number(self) -> str:
        """DG11's personal number, else the MRZ optional-data field.

        Several states - Sweden among them - put the national identity number
        in the MRZ optional-data field and ship no DG11 at all, so the value
        is recoverable even when the chip carries no personal details.
        """
        if self.personal.personal_number:
            return self.personal.personal_number
        if self.mrz is not None:
            optional = _mrz_personal_number(self.mrz.optional_data.value)
            if optional:
                return optional
        if self.dg13_personal_number:
            return self.dg13_personal_number
        return self._optional("", 11)

    @property
    def dg13_personal_number(self) -> str:
        """The PESEL, for the Polish documents that carry it and no DG11.

        Only for POL: DG13 means whatever the issuing state decided, so the
        same tag elsewhere is not a personal number and is left unnamed.
        """
        if self.mrz is None or self.mrz.nationality.strip() != "POL":
            return ""
        for tag, value in self.optional.fields:
            if tag == PESEL_TAG and is_pesel(value):
                return value
        return ""

    @property
    def personal_number_source(self) -> str:
        """Where :attr:`personal_number` came from, for an honest caption."""
        if self.personal.personal_number:
            return "DG11"
        if self.mrz is not None and _mrz_personal_number(self.mrz.optional_data.value):
            return "MRZ"
        if self.dg13_personal_number:
            return "DG13"
        return ""

    def is_missing(self, value: str) -> bool:
        return value == self.NOT_ON_CHIP

    @property
    def full_date_of_birth(self) -> str:
        """DG11's YYYYMMDD birth date if present, else the MRZ's."""
        long = _icao_long_date(self.personal.full_date_of_birth)
        if long:
            return long
        return self.mrz.dob_text if self.mrz else ""

    def file(self, name: str) -> DumpFile | None:
        for f in self.files:
            if f.name.upper() == name.upper():
                return f
        return None

    @property
    def is_empty(self) -> bool:
        """True when the dump held no files at all - the read got nothing."""
        return not any(f.state == FileState.PRESENT for f in self.files)

    def image_for(self, name: str) -> bytes:
        """The decoded PNG for a file that carries a picture, else empty."""
        return {
            "EF_DG2": self.portrait_png,
            "EF_DG5": self.displayed_portrait_png,
            "EF_DG7": self.signature_png,
        }.get(name.upper(), b"")

    def has_file(self, name: str) -> bool:
        entry = self.file(name)
        return entry is not None and entry.state == FileState.PRESENT

    @property
    def personal_files(self) -> list[str]:
        """The files the PERSONAL tab drew from, in file order.

        Naming them beats a fixed caption: plenty of documents carry no DG11,
        and the personal number can arrive from the MRZ or from DG13 instead.
        """
        out = []
        if self.personal_number_source == "MRZ":
            out.append("EF_DG1")
        if self.has_dg(11):
            out.append("EF_DG11")
        if self.personal_number_source == "DG13":
            out.append("EF_DG13")
        return out

    @property
    def document_files(self) -> list[str]:
        """The files the ISSUER tab drew from."""
        return ["EF_DG12"] if self.has_dg(12) else []

    @property
    def security_files(self) -> list[str]:
        """The files the SECURITY tab drew from."""
        return [
            name for name in ("EF_SOD", "EF_DG14", "EF_DG15") if self.has_file(name)
        ]

    def has_dg(self, number: int) -> bool:
        f = self.file(f"EF_DG{number}")
        return f is not None and f.state == FileState.PRESENT


_MONTHS = (
    "JAN",
    "FEB",
    "MAR",
    "APR",
    "MAY",
    "JUN",
    "JUL",
    "AUG",
    "SEP",
    "OCT",
    "NOV",
    "DEC",
)


def _icao_long_date(value: str) -> str:
    """``20200401`` -> ``01 APR 2020``.  Anything else passes through."""
    digits = "".join(ch for ch in value if ch.isdigit())
    if len(digits) != 8:
        return value
    year, month, day = digits[0:4], int(digits[4:6]), int(digits[6:8])
    if not 1 <= month <= 12:
        return value
    return f"{day:02d} {_MONTHS[month - 1]} {year}"
