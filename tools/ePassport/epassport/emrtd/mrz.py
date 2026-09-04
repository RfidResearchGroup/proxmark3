"""ICAO 9303 machine-readable zone parsing.

Supports TD1 (3x30), TD2 (2x36) and TD3 / MRV-A (2x44).  Everything is pure
logic so it is unit-testable without hardware, a GUI or a dump.
"""

from __future__ import annotations

import datetime as _dt
import re
from dataclasses import dataclass, field
from typing import Iterable

from .countries import country_name

FILLER = "<"
_WEIGHTS = (7, 3, 1)
_VALID_CHARS = re.compile(r"^[0-9A-Z<]*$")

#: Common OCR confusions, applied before validation.  Keys are what tesseract
#: tends to emit for a filler or a digit in an OCR-B strip.
OCR_CONFUSIONS: dict[str, str] = {
    "«": "<",
    "»": "<",
    "_": "<",
    "—": "<",
    "–": "<",
    "-": "<",
    "~": "<",
    "*": "<",
    " ": "",
    "\t": "",
}


class MrzError(ValueError):
    """Raised when a string cannot be interpreted as an MRZ at all."""


def char_value(ch: str) -> int:
    """Numeric weight of one MRZ character (``<``=0, digits, ``A``=10..``Z``=35)."""
    if ch == FILLER:
        return 0
    if ch.isdigit():
        return int(ch)
    if "A" <= ch <= "Z":
        return ord(ch) - ord("A") + 10
    raise MrzError(f"character {ch!r} is not valid in an MRZ")


def check_digit(data: str) -> str:
    """7-3-1 weighted modulo-10 check digit for ``data``."""
    total = 0
    for i, ch in enumerate(data):
        total += char_value(ch) * _WEIGHTS[i % 3]
    return str(total % 10)


def verify(data: str, digit: str) -> bool:
    """True when ``digit`` is the correct check digit for ``data``.

    A filler in the check position is accepted only when the field itself is
    entirely filler, which is how optional-data fields are left blank.
    """
    if digit == FILLER:
        return set(data) <= {FILLER}
    if not digit.isdigit():
        return False
    try:
        return check_digit(data) == digit
    except MrzError:
        return False


def clean_line(raw: str) -> str:
    """Normalise a single OCR'd line: upper-case, fix confusions, drop noise."""
    out = raw.strip().upper()
    for bad, good in OCR_CONFUSIONS.items():
        out = out.replace(bad, good)
    return "".join(ch for ch in out if ch.isalnum() or ch == FILLER)


def fix_numeric(field_text: str) -> str:
    """Coerce a field that must be digits (dates, check digits)."""
    table = {
        "O": "0",
        "Q": "0",
        "D": "0",
        "U": "0",
        "I": "1",
        "L": "1",
        "T": "1",
        "Z": "2",
        "A": "4",
        "S": "5",
        "G": "6",
        "B": "8",
        "R": "8",
    }
    return "".join(table.get(ch, ch) for ch in field_text)


def fix_alpha(field_text: str) -> str:
    """Coerce a field that must be letters (country codes, sex)."""
    table = {"0": "O", "1": "I", "2": "Z", "4": "A", "5": "S", "6": "G", "8": "B"}
    return "".join(table.get(ch, ch) for ch in field_text)


#: Per-format field maps: ``(line index, start, stop, kind)``.  ``kind`` is
#: "n" for digits-only, "a" for letters-only; unlisted spans are alphanumeric
#: and left alone.  These let OCR output be repaired by position, which is the
#: difference between reading "UT0" and reading "UTO".
FIELD_MAPS: dict[str, tuple[tuple[int, int, int, str], ...]] = {
    "TD3": (
        (0, 0, 2, "a"),
        (0, 2, 5, "a"),
        (1, 9, 10, "n"),
        (1, 10, 13, "a"),
        (1, 13, 19, "n"),
        (1, 19, 20, "n"),
        (1, 20, 21, "a"),
        (1, 21, 27, "n"),
        (1, 27, 28, "n"),
        (1, 42, 43, "n"),
        (1, 43, 44, "n"),
    ),
    "TD2": (
        (0, 0, 2, "a"),
        (0, 2, 5, "a"),
        (1, 9, 10, "n"),
        (1, 10, 13, "a"),
        (1, 13, 19, "n"),
        (1, 19, 20, "n"),
        (1, 20, 21, "a"),
        (1, 21, 27, "n"),
        (1, 27, 28, "n"),
        (1, 35, 36, "n"),
    ),
    "TD1": (
        (0, 0, 2, "a"),
        (0, 2, 5, "a"),
        (0, 14, 15, "n"),
        (1, 0, 6, "n"),
        (1, 6, 7, "n"),
        (1, 7, 8, "a"),
        (1, 8, 14, "n"),
        (1, 14, 15, "n"),
        (1, 15, 18, "a"),
        (1, 29, 30, "n"),
        (2, 0, 30, "a"),
    ),
}


def coerce_lines(lines: list[str], kind: str | None = None) -> list[str]:
    """Repair OCR confusions by field position.

    A digit-only field never legitimately contains ``O``; a country code never
    contains ``0``.  Applying that knowledge before validating turns a great
    many near-misses into clean reads.  Filler ``<`` is always left alone.
    """
    if kind is None:
        try:
            kind = detect_kind(lines)
        except MrzError:
            return lines
    spans = FIELD_MAPS.get(kind)
    if spans is None:
        return lines
    out = [list(line) for line in lines]
    for index, start, stop, mode in spans:
        if index >= len(out):
            continue
        row = out[index]
        if stop > len(row):
            continue
        fixer = fix_numeric if mode == "n" else fix_alpha
        for pos in range(start, stop):
            ch = row[pos]
            if ch != FILLER:
                row[pos] = fixer(ch)
    return ["".join(row) for row in out]


def blind_confusions() -> dict[str, set[str]]:
    """Character swaps the 7-3-1 check digits mathematically cannot detect.

    A check digit is a weighted sum taken modulo 10, and the weights 7, 3 and
    1 are all coprime with 10.  So substituting a character whose value
    differs by a multiple of 10 changes the sum by a multiple of 10 and leaves
    every check digit - including the composite - untouched, in any position.

    Character values are ``<``=0, ``0``-``9``=0-9, ``A``-``Z``=10-35, so the
    blind pairs are things like ``L``(21) for ``1``(1) and ``S``(28) for
    ``8``(8) - which are also precisely the swaps OCR is most likely to make.
    """
    alphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    out: dict[str, set[str]] = {}
    for a in alphabet:
        for b in alphabet:
            if a != b and (char_value(a) - char_value(b)) % 10 == 0:
                out.setdefault(a, set()).add(b)
    return out


#: The subset of :func:`blind_confusions` that a scanner realistically makes:
#: pairs that look alike *and* are invisible to the check digits.
VISUAL_BLIND_PAIRS: tuple[tuple[str, str], ...] = (
    ("L", "1"),
    ("S", "8"),
    ("G", "6"),
    ("Z", "5"),
    ("I", "8"),
    ("D", "3"),
    ("B", "1"),
    ("C", "2"),
    ("A", "0"),
    ("E", "4"),
)


def blind_characters() -> set[str]:
    """Characters involved in a visually plausible, undetectable swap."""
    out: set[str] = set()
    for a, b in VISUAL_BLIND_PAIRS:
        out.add(a)
        out.add(b)
    return out


def ambiguous_positions(value: str) -> list[int]:
    """Indices of ``value`` that a check digit could not vouch for."""
    blind = blind_characters()
    return [i for i, ch in enumerate(value) if ch in blind]


@dataclass
class Checked:
    """A field value plus the verdict of its check digit."""

    value: str
    digit: str = ""
    ok: bool | None = None  # None = no check digit defined for this field

    @property
    def badge(self) -> str:
        return "" if self.ok is None else ("OK" if self.ok else "BAD")


def _expand_year(yy: int, *, past: bool, today: _dt.date) -> int:
    """Sliding-window expansion of a two-digit ICAO year.

    Dates of birth are in the past, expiry dates are (usually) in the future;
    that is the only reliable disambiguation ICAO gives us.
    """
    century = today.year // 100 * 100
    year = century + yy
    if past:
        if year > today.year:
            year -= 100
    else:
        # Allow a modest amount of "already expired" before rolling back.
        if year < today.year - 20:
            year += 100
        elif year > today.year + 30:
            year -= 100
    return year


def parse_date(
    yymmdd: str, *, past: bool, today: _dt.date | None = None
) -> _dt.date | None:
    """Expand ``YYMMDD`` to a real date, or None when unparseable."""
    today = today or _dt.date.today()
    digits = fix_numeric(yymmdd)
    if len(digits) != 6 or not digits.isdigit():
        return None
    yy, mm, dd = int(digits[0:2]), int(digits[2:4]), int(digits[4:6])
    if not 1 <= mm <= 12 or not 1 <= dd <= 31:
        return None
    try:
        return _dt.date(_expand_year(yy, past=past, today=today), mm, dd)
    except ValueError:
        return None


def format_date(value: _dt.date | None, raw: str) -> str:
    """Passport-page style date: ``01 JAN 1989``.  Falls back to the raw digits."""
    if value is None:
        return raw
    return f"{value.day:02d} {value.strftime('%b').upper()} {value.year}"


def split_names(field_text: str) -> tuple[str, str]:
    """Split the MRZ name field into ``(surname, given names)``."""
    body = field_text.rstrip(FILLER)
    if "<<" in body:
        surname, _, given = body.partition("<<")
    else:
        surname, given = body, ""
    return (
        surname.replace(FILLER, " ").strip(),
        " ".join(part for part in given.replace(FILLER, " ").split() if part),
    )


@dataclass
class Mrz:
    """A fully decoded machine-readable zone."""

    kind: str  # "TD1" | "TD2" | "TD3"
    lines: list[str]
    document_code: str = ""
    issuing_state: str = ""
    surname: str = ""
    given_names: str = ""
    document_number: Checked = field(default_factory=Checked)
    nationality: str = ""
    date_of_birth: Checked = field(default_factory=Checked)
    sex: str = ""
    date_of_expiry: Checked = field(default_factory=Checked)
    optional_data: Checked = field(default_factory=Checked)
    optional_data2: str = ""
    composite: Checked = field(default_factory=Checked)
    dob: _dt.date | None = None
    expiry: _dt.date | None = None

    # -- convenience for the UI ------------------------------------------
    @property
    def raw(self) -> str:
        return "\n".join(self.lines)

    @property
    def issuing_state_name(self) -> str:
        return country_name(self.issuing_state)

    @property
    def nationality_name(self) -> str:
        return country_name(self.nationality)

    @property
    def sex_label(self) -> str:
        return {"M": "M", "F": "F", "X": "X", FILLER: "X", "": "X"}.get(
            self.sex, self.sex
        )

    @property
    def document_type(self) -> str:
        first = self.document_code[:1]
        return {
            "P": "PASSPORT",
            "I": "IDENTITY CARD",
            "A": "IDENTITY CARD",
            "C": "IDENTITY CARD",
            "V": "VISA",
            "D": "DIPLOMATIC",
        }.get(first, self.document_code or "DOCUMENT")

    @property
    def dob_text(self) -> str:
        return format_date(self.dob, self.date_of_birth.value)

    @property
    def expiry_text(self) -> str:
        return format_date(self.expiry, self.date_of_expiry.value)

    @property
    def all_checks_ok(self) -> bool:
        return all(
            c.ok is not False
            for c in (
                self.document_number,
                self.date_of_birth,
                self.date_of_expiry,
                self.optional_data,
                self.composite,
            )
        )

    def failed_checks(self) -> list[str]:
        names = {
            "document number": self.document_number,
            "date of birth": self.date_of_birth,
            "date of expiry": self.date_of_expiry,
            "optional data": self.optional_data,
            "composite": self.composite,
        }
        return [label for label, c in names.items() if c.ok is False]

    # -- what the pm3 client needs ---------------------------------------
    @property
    def bac_document_number(self) -> str:
        """Document number as pm3 wants it: <=9 chars, no trailing filler."""
        return self.document_number.value.rstrip(FILLER)[:9]

    @property
    def mrz_line2(self) -> str:
        """The 44/36-char second line for ``hf emrtd -m``, or "" for TD1."""
        return self.lines[1] if self.kind in ("TD2", "TD3") else ""


def _lines_of(text_or_lines: str | Iterable[str]) -> list[str]:
    if isinstance(text_or_lines, str):
        raw = re.split(r"[\r\n]+", text_or_lines)
    else:
        raw = list(text_or_lines)
    return [clean_line(line) for line in raw if clean_line(line)]


def detect_kind(lines: list[str]) -> str:
    lengths = [len(line) for line in lines]
    if len(lines) == 3 and all(n == 30 for n in lengths):
        return "TD1"
    if len(lines) == 2 and all(n == 36 for n in lengths):
        return "TD2"
    if len(lines) == 2 and all(n == 44 for n in lengths):
        return "TD3"
    raise MrzError(f"unrecognised MRZ geometry: {len(lines)} lines of {lengths}")


def _extended_document_number(
    number_field: str, digit: str, optional: str
) -> tuple[str, str, bool, str]:
    """Handle document numbers longer than 9 characters.

    ICAO encodes the overflow in the optional-data field: the check position
    of the number holds ``<`` and the optional field holds ``rest`` plus the
    real check digit.  Returns ``(number, digit, ok, remaining_optional)``.
    """
    if digit != FILLER:
        return number_field.rstrip(FILLER), digit, verify(number_field, digit), optional
    body = optional.rstrip(FILLER)
    if len(body) < 2:
        # Filler check digit with nothing to extend: nothing to verify.
        return number_field.rstrip(FILLER), digit, False, optional
    rest, real_digit = body[:-1], body[-1]
    full = number_field.rstrip(FILLER) + rest
    return full, real_digit, verify(full, real_digit), ""


def parse(text_or_lines: str | Iterable[str], *, today: _dt.date | None = None) -> Mrz:
    """Parse an MRZ.  Raises :class:`MrzError` only on structural problems.

    Bad check digits are recorded, never fatal - a real passport with a
    scanner-mangled digit must still render.
    """
    lines = _lines_of(text_or_lines)
    if not lines:
        raise MrzError("no MRZ lines given")
    kind = detect_kind(lines)
    for line in lines:
        if not _VALID_CHARS.match(line):
            raise MrzError("MRZ contains characters outside [0-9A-Z<]")

    if kind == "TD3":
        return _parse_td3(lines, today)
    if kind == "TD2":
        return _parse_td2(lines, today)
    return _parse_td1(lines, today)


def _finish(mrz: Mrz, today: _dt.date | None) -> Mrz:
    mrz.dob = parse_date(mrz.date_of_birth.value, past=True, today=today)
    mrz.expiry = parse_date(mrz.date_of_expiry.value, past=False, today=today)
    return mrz


def _parse_td3(lines: list[str], today: _dt.date | None) -> Mrz:
    l1, l2 = lines
    surname, given = split_names(l1[5:44])
    number, ndigit, number_ok, optional = _extended_document_number(
        l2[0:9], l2[9], l2[28:42]
    )
    mrz = Mrz(
        kind="TD3",
        lines=lines,
        document_code=l1[0:2].rstrip(FILLER),
        issuing_state=l1[2:5].rstrip(FILLER),
        surname=surname,
        given_names=given,
        document_number=Checked(number, ndigit, number_ok),
        nationality=l2[10:13].rstrip(FILLER),
        date_of_birth=Checked(l2[13:19], l2[19], verify(l2[13:19], l2[19])),
        sex=l2[20],
        date_of_expiry=Checked(l2[21:27], l2[27], verify(l2[21:27], l2[27])),
        # The value comes from what _extended_document_number left behind: a
        # long document number spills into this field, and that spill belongs
        # to the number, not to the State's optional data.  The check digit
        # still answers for the field as transmitted, overflow included.
        optional_data=Checked(
            optional.rstrip(FILLER), l2[42], verify(l2[28:42], l2[42])
        ),
        composite=Checked(
            "",
            l2[43],
            verify(l2[0:10] + l2[13:20] + l2[21:43], l2[43]),
        ),
    )
    return _finish(mrz, today)


def _parse_td2(lines: list[str], today: _dt.date | None) -> Mrz:
    l1, l2 = lines
    surname, given = split_names(l1[5:36])
    mrz = Mrz(
        kind="TD2",
        lines=lines,
        document_code=l1[0:2].rstrip(FILLER),
        issuing_state=l1[2:5].rstrip(FILLER),
        surname=surname,
        given_names=given,
        document_number=Checked(l2[0:9].rstrip(FILLER), l2[9], verify(l2[0:9], l2[9])),
        nationality=l2[10:13].rstrip(FILLER),
        date_of_birth=Checked(l2[13:19], l2[19], verify(l2[13:19], l2[19])),
        sex=l2[20],
        date_of_expiry=Checked(l2[21:27], l2[27], verify(l2[21:27], l2[27])),
        optional_data=Checked(l2[28:35].rstrip(FILLER)),
        composite=Checked("", l2[35], verify(l2[0:10] + l2[13:20] + l2[21:35], l2[35])),
    )
    return _finish(mrz, today)


def _parse_td1(lines: list[str], today: _dt.date | None) -> Mrz:
    l1, l2, l3 = lines
    surname, given = split_names(l3)
    number, ndigit, number_ok, optional = _extended_document_number(
        l1[5:14], l1[14], l1[15:30]
    )
    mrz = Mrz(
        kind="TD1",
        lines=lines,
        document_code=l1[0:2].rstrip(FILLER),
        issuing_state=l1[2:5].rstrip(FILLER),
        surname=surname,
        given_names=given,
        document_number=Checked(number, ndigit, number_ok),
        nationality=l2[15:18].rstrip(FILLER),
        date_of_birth=Checked(l2[0:6], l2[6], verify(l2[0:6], l2[6])),
        sex=l2[7],
        date_of_expiry=Checked(l2[8:14], l2[14], verify(l2[8:14], l2[14])),
        optional_data=Checked(optional.rstrip(FILLER) or l1[15:30].rstrip(FILLER)),
        optional_data2=l2[18:29].rstrip(FILLER),
        composite=Checked(
            "",
            l2[29],
            verify(l1[5:30] + l2[0:7] + l2[8:15] + l2[18:29], l2[29]),
        ),
    )
    return _finish(mrz, today)


def build_td3_line2(
    document_number: str,
    dob: str,
    expiry: str,
    *,
    nationality: str = "",
    sex: str = FILLER,
    optional: str = "",
) -> str:
    """Rebuild a TD3 line 2 from BAC inputs, for the ``hf emrtd -m`` path."""
    num = (document_number.upper().rstrip(FILLER) + FILLER * 9)[:9]
    nat = (nationality.upper() + FILLER * 3)[:3]
    opt = (optional.upper() + FILLER * 14)[:14]
    head = num + check_digit(num) + nat
    mid = dob + check_digit(dob) + (sex or FILLER)[0]
    tail = expiry + check_digit(expiry) + opt + check_digit(opt)
    line = head + mid + tail
    composite = check_digit(line[0:10] + line[13:20] + line[21:43])
    return line + composite
